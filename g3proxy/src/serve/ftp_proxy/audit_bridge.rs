/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! ICAP REQMOD audit bridge for FTP uploads.
//!
//! When `audit_upload` is enabled, every byte sent by the FTP client on
//! a data channel (STOR, APPE, STOU) is simultaneously:
//!   * forwarded to the upstream FTP server — verbatim,
//!   * sent to the ICAP server — wrapped inside a synthesized HTTP
//!     REQMOD body with chunked transfer encoding.
//!
//! The bridge never blocks uploads on ICAP failures: if the ICAP
//! connection drops or times out, the upstream transfer continues
//! without audit data.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinHandle;

use g3_io_ext::{IdleWheel, IdleWheelChecker, StreamCopyConfig};
use g3_types::net::TlsKeyLogBuffer;

use crate::config::server::ServerConfig;

/// Context needed to perform ICAP audit of a single FTP upload data
/// channel. Built by `handle_upload_data_channel` in `task.rs` from
/// server-level `CommonTaskContext` and the parsed FTP command.
pub(crate) struct FtpUploadAuditContext {
    pub(crate) icap_client: Arc<g3_icap_client::reqmod::IcapReqmodClient>,
    pub(crate) idle_wheel: Arc<g3_io_ext::IdleWheel>,
    pub(crate) copy_config: StreamCopyConfig,
    pub(crate) client_addr: Option<SocketAddr>,
    pub(crate) ftp_command: String,
    pub(crate) ftp_path: String,
    /// Data channel 5-tuple: (g3proxy local addr, FTP server addr)
    pub(crate) data_channel_tuple: Option<g3_icap_client::reqmod::ConnectionTuple>,
    /// TLS keylog buffer for the upstream TLS connection
    pub(crate) keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
}

/// Entry point for all FTP upload data channels.
///
/// * If `audit_ctx` is `Some`, build an `FtpUploadAdapter` and stream
///   through it (upload + ICAP audit simultaneously).
/// * If `audit_ctx` is `None`, fall back to a plain copy loop — no
///   extra allocations, no overhead.
pub(crate) async fn run_ftp_upload_audit_or_relay<CR, UW>(
    clt_r: &mut CR,
    ups_w: UW,
    idle_wheel: &Arc<IdleWheel>,
    max_idle_count: usize,
    audit_ctx: Option<FtpUploadAuditContext>,
) -> Option<u64>
where
    CR: AsyncRead + Send + Sync + Unpin,
    UW: AsyncWrite + Send + Sync + Unpin + 'static,
{
    match audit_ctx {
        Some(ac) => audit_and_forward(clt_r, ups_w, ac).await,
        None => raw_forward_with_idle(clt_r, ups_w, idle_wheel, max_idle_count).await,
    }
}

/// Bidirectional transfer for HTTP CONNECT tunnel mode.
/// Handles upload audit on client→upstream direction, while doing plain copy on upstream→client.
pub(crate) async fn run_ftp_upload_audit_or_relay_bidi<CR, CW, UR, UW>(
    clt_r: CR,
    clt_w: CW,
    ups_r: UR,
    ups_w: UW,
    idle_wheel: Arc<IdleWheel>,
    max_idle_count: usize,
    audit_ctx: Option<FtpUploadAuditContext>,
) -> Option<u64>
where
    CR: AsyncRead + Send + Sync + Unpin + 'static,
    CW: AsyncWrite + Send + Sync + Unpin + 'static,
    UR: AsyncRead + Send + Sync + Unpin + 'static,
    UW: AsyncWrite + Send + Sync + Unpin + 'static,
{
    if let Some(ac) = audit_ctx {
        let idle_wheel_clone = idle_wheel.clone();
        let upstream_to_client: JoinHandle<()> = tokio::spawn(async move {
            bidi_half_relay_with_idle(ups_r, clt_w, idle_wheel_clone, max_idle_count).await;
        });

        let mut clt_r = clt_r;
        let result = audit_and_forward(&mut clt_r, ups_w, ac).await;

        let _ = tokio::time::timeout(tokio::time::Duration::from_secs(10), upstream_to_client).await;

        result
    } else {
        let idle_wheel_clone = idle_wheel.clone();
        let client_to_up = tokio::spawn(async move {
            bidi_half_relay_with_idle(clt_r, ups_w, idle_wheel_clone, max_idle_count).await;
        });
        let up_to_client = tokio::spawn(async move {
            bidi_half_relay_with_idle(ups_r, clt_w, idle_wheel, max_idle_count).await;
        });
        let _ = tokio::join!(client_to_up, up_to_client);
        None
    }
}

async fn bidi_half_relay_with_idle<R, W>(
    r: R,
    w: W,
    idle_wheel: Arc<IdleWheel>,
    max_idle_count: usize,
)
where
    R: AsyncRead + Send + Sync + Unpin + 'static,
    W: AsyncWrite + Send + Sync + Unpin + 'static,
{
    // Decouple `r.read` from `w.write_all` so upstream backpressure on
    // `w` cannot stall the reader. Previously this loop did
    // `read -> write_all` serially in the same task; a slow upstream
    // socket send buffer would block the await, the client read would
    // stop, the kernel recv buffer on the client side would fill, and
    // the client kernel would advertise TCP ZeroWindow. With large
    // FTP uploads (>1 GiB) the client then stalled, retransmitted,
    // and looped forever.
    let (chunk_tx, chunk_rx) = flume::bounded::<bytes::Bytes>(8);

    let writer = tokio::spawn(async move {
        let mut w = w;
        let mut rx = chunk_rx;
        while let Ok(chunk) = rx.recv_async().await {
            if w.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = w.flush().await;
        let _ = w.shutdown().await;
    });

    let mut r = r;
    let mut idle_interval = idle_wheel.register();
    let mut idle_count = 0usize;
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        tokio::select! {
            biased;

            res = r.read(&mut buf) => {
                match res {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        idle_count = 0;
                        let chunk = bytes::Bytes::copy_from_slice(&buf[..n]);
                        if chunk_tx.send_async(chunk).await.is_err() {
                            // writer task already exited (write error);
                            // no point keeping the relay alive.
                            break;
                        }
                    }
                }
            }

            _ = idle_interval.tick() => {
                idle_count += 1;
                if idle_count >= max_idle_count {
                    break;
                }
            }
        }
    }
    // Drop the sender so the writer task sees EOF and finalizes
    // flush + shutdown of `w` once it has drained the channel.
    drop(chunk_tx);
    let _ = writer.await;
}

async fn raw_forward_with_idle<CR, UW>(
    clt_r: &mut CR,
    ups_w: UW,
    idle_wheel: &Arc<IdleWheel>,
    max_idle_count: usize,
) -> Option<u64>
where
    CR: AsyncRead + Send + Sync + Unpin,
    UW: AsyncWrite + Send + Sync + Unpin,
{
    let mut idle_interval = idle_wheel.register();
    let mut idle_count = 0usize;
    let mut buf = vec![0u8; 32 * 1024];
    let mut total: u64 = 0;
    let mut ups_w = ups_w;
    loop {
        tokio::select! {
            biased;

            res = clt_r.read(&mut buf) => {
                match res {
                    Ok(0) => break,
                    Ok(n) => {
                        idle_count = 0;
                        if ups_w.write_all(&buf[..n]).await.is_err() {
                            return Some(total);
                        }
                        total += n as u64;
                    }
                    Err(_) => return Some(total),
                }
            }

            _ = idle_interval.tick() => {
                idle_count += 1;
                if idle_count >= max_idle_count {
                    return Some(total);
                }
            }
        }
    }
    let _ = ups_w.flush().await;
    Some(total)
}

async fn raw_forward<CR, UW>(clt_r: &mut CR, ups_w: &mut UW) -> Option<u64>
where
    CR: AsyncRead + Send + Sync + Unpin,
    UW: AsyncWrite + Send + Sync + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut buf = vec![0u8; 32 * 1024];
    let mut total: u64 = 0;
    loop {
        match clt_r.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if ups_w.write_all(&buf[..n]).await.is_err() {
                    return Some(total);
                }
                total += n as u64;
            }
            Err(_) => return Some(total),
        }
    }
    let _ = ups_w.flush().await;
    Some(total)
}

async fn audit_and_forward<CR, UW>(
    clt_r: &mut CR,
    mut ups_w: UW,
    audit_ctx: FtpUploadAuditContext,
) -> Option<u64>
where
    CR: AsyncRead + Send + Sync + Unpin,
    UW: AsyncWrite + Send + Sync + Unpin + 'static,
{
    let idle_checker = IdleWheelChecker::new(audit_ctx.idle_wheel);
    let mut adapter = match audit_ctx
        .icap_client
        .ftp_upload_audit_adapter(audit_ctx.copy_config, idle_checker)
        .await
    {
        Ok(a) => a,
        Err(_) => return raw_forward(clt_r, &mut ups_w).await,
    };
    if let Some(addr) = audit_ctx.client_addr {
        adapter.set_client_addr(addr);
    }
    /* added for connection tuple - data channel 5-tuple */
    if let Some(tuple) = audit_ctx.data_channel_tuple {
        adapter.set_connection_tuple(tuple);
    }
    /* added for TLS keylog */
    if let Some(keylog) = audit_ctx.keylog_buffer {
        adapter.set_keylog_buffer(keylog);
    }

    let mut state = g3_icap_client::reqmod::ftp::new_adaptation_run_state();
    let end_state = adapter
        .audit_and_forward(
            &mut state,
            clt_r,
            ups_w, // moved into the spawned audit writer task
            &audit_ctx.ftp_command,
            &audit_ctx.ftp_path,
        )
        .await;

    // The audit writer task now owns `ups_w` and handles its flush +
    // shutdown internally, so we just return the byte count.
    match end_state {
        g3_icap_client::reqmod::ftp::FtpAdaptationEndState::OriginalTransferred { bytes, .. }
        | g3_icap_client::reqmod::ftp::FtpAdaptationEndState::OriginalTransferredAfterFallback { bytes, .. }
        | g3_icap_client::reqmod::ftp::FtpAdaptationEndState::AuditOnly { bytes, .. } => Some(bytes),
    }
}

/// Convenience constructor: builds an `FtpUploadAuditContext` from the
/// shared `CommonTaskContext` if an ICAP client is configured.
pub(crate) fn build_audit_context(
    ctx: &super::task::CommonTaskContext,
    ftp_command: &str,
    ftp_path: &str,
    data_channel_tuple: Option<g3_icap_client::reqmod::ConnectionTuple>,
    keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
) -> Option<FtpUploadAuditContext> {
    let icap_client = ctx.icap_client.as_ref()?.clone();

    Some(FtpUploadAuditContext {
        icap_client,
        idle_wheel: ctx.idle_wheel.clone(),
        copy_config: ctx.server_config.limited_copy_config(),
        client_addr: Some(ctx.cc_info.client_addr()),
        ftp_command: ftp_command.to_string(),
        ftp_path: ftp_path.to_string(),
        data_channel_tuple,
        keylog_buffer,
    })
}
