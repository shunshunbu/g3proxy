/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use g3_io_ext::{IdleCheck, LimitedWriteExt, StreamCopyConfig};

use super::{ConnectionTuple, IcapReqmodClient, TlsKeyLogBuffer};
use crate::reqmod::mail::ReqmodAdaptationRunState;
use crate::service::IcapClientConnection;
use crate::{IcapClientReader, IcapClientWriter, IcapServiceClient, IcapServiceOptions};

mod error;
pub use error::FtpAdaptationError;

/// Bounded channel capacity (in chunks) for the upstream writer task.
/// At the default 32 KiB copy buffer this is ~8 MiB of in-flight data.
const UPSTREAM_CHANNEL_CAPACITY: usize = 256;

/// Bounded channel capacity (in chunks) for the ICAP writer task.
/// At the default 32 KiB copy buffer this is ~32 MiB of in-flight data.
/// Larger capacity gives the ICAP server more time to recover from
/// transient slowdowns before fail-open kicks in, at the cost of higher
/// peak memory per concurrent upload (~32 MiB worst case).
const ICAP_CHANNEL_CAPACITY: usize = 1024;

/// Classification of adaptation failures, used by callers to decide
/// whether they can still deliver the original payload to upstream.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FtpAdaptationErrorKind {
    /// Failure reading the FTP client data channel.  The transfer must
    /// be aborted entirely - there is no data left to forward.
    ClientRead,
    /// Failure writing to the upstream FTP server.  The transfer must
    /// be aborted entirely.
    UpstreamWrite,
    /// Failure writing only to the ICAP service.  The original payload
    /// may still be forwarded to upstream; the audit was best-effort.
    IcapWrite,
    /// Failure reading the ICAP verdict.  The audit verdict is unknown
    /// but the original payload has already been forwarded (if any).
    IcapRead,
    /// External request to abort (idle force-quit, user blocked).
    ForceQuit,
    /// Internal / configuration failures.
    Internal,
}

/// Final audit verdict from the ICAP server for an uploaded file.
#[derive(Debug)]
pub enum FtpAdaptationEndState {
    /// Audit completed successfully and the original data was already
    /// forwarded to the upstream FTP server.
    OriginalTransferred {
        icap_status_code: u16,
        icap_reason: String,
        bytes: u64,
    },
    /// ICAP responded, but we were operating in audit-only mode (no
    /// upstream forwarding configured).  The audit verdict is provided
    /// but no bytes were forwarded.
    AuditOnly {
        icap_status_code: u16,
        icap_reason: String,
        bytes: u64,
    },
    /// ICAP adaptation failed in a way that did NOT prevent us from
    /// forwarding data upstream.  This is the "never block upload"
    /// safety net for enterprise ICAP auditing.
    OriginalTransferredAfterFallback {
        bytes: u64,
        icap_error: String,
    },
}

impl IcapReqmodClient {
    /// Build a new streaming FTP upload auditor.  The returned adapter
    /// binds an ICAP connection from the pool (or opens a new one),
    /// so it should only be constructed when a data transfer actually
    /// begins.
    ///
    /// This adapter is designed to be reused by both native FTP proxy
    /// data channels and HTTP CONNECT-tunnelled FTP traffic detected
    /// in-band by g3proxy.
    pub async fn ftp_upload_audit_adapter<I: IdleCheck>(
        &self,
        copy_config: StreamCopyConfig,
        idle_checker: I,
    ) -> anyhow::Result<FtpUploadAdapter<I>> {
        let icap_client = self.inner.clone();
        let (icap_connection, icap_options) = icap_client.fetch_connection().await?;
        Ok(FtpUploadAdapter {
            icap_client,
            icap_connection: Some(icap_connection),
            icap_options,
            copy_config,
            idle_checker,
            client_addr: None,
            connection_tuple: None,
            keylog_buffer: None,
        })
    }

    /// Convenience accessor: callers may need the raw service client
    /// for metrics/monitoring or to fall back to manual pool save.
    pub fn ftp_service_client(&self) -> &Arc<IcapServiceClient> {
        &self.inner
    }
}

pub struct FtpUploadAdapter<I: IdleCheck> {
    icap_client: Arc<IcapServiceClient>,
    /// Wrapped in `Option` so it can be moved into a spawned task that
    /// drives the ICAP body write / response read / connection save.
    /// `Some` from construction until the adapter is consumed; `None`
    /// after `audit_and_forward` / `audit_only` have taken it.
    icap_connection: Option<IcapClientConnection>,
    #[allow(dead_code)]
    icap_options: Arc<IcapServiceOptions>,
    copy_config: StreamCopyConfig,
    idle_checker: I,
    client_addr: Option<SocketAddr>,
    /* added for connection tuple */
    connection_tuple: Option<ConnectionTuple>,
    /* added for TLS keylog */
    keylog_buffer: Option<Arc<TlsKeyLogBuffer>>,
}

impl<I: IdleCheck> FtpUploadAdapter<I> {
    /// Record the client address; sent to the ICAP server as
    /// X-Client-IP / X-Client-Port headers so the audit service can
    /// correlate streams with users.
    pub fn set_client_addr(&mut self, addr: SocketAddr) {
        self.client_addr = Some(addr);
    }

    /* added for connection tuple - data channel 5-tuple */
    pub fn set_connection_tuple(&mut self, tuple: ConnectionTuple) {
        self.connection_tuple = Some(tuple);
    }

    /* added for TLS keylog */
    pub fn set_keylog_buffer(&mut self, buffer: Arc<TlsKeyLogBuffer>) {
        self.keylog_buffer = Some(buffer);
    }

    fn build_http_header(&self, ftp_cmd: &str, ftp_path: &str) -> Vec<u8> {
        let mut header = Vec::with_capacity(256);
        // Use PUT <path> with synthetic FTP/1.0 pseudo-version, which
        // keeps ICAP parsers happy while carrying the original path.
        let _ = write!(
            header,
            "PUT {} FTP/1.0\r\n\
             Content-Type: application/octet-stream\r\n\
             X-FTP-Command: {}\r\n\
             Transfer-Encoding: chunked\r\n\
             \r\n",
            ftp_path, ftp_cmd
        );
        header
    }

    fn push_extended_headers(&self, data: &mut Vec<u8>) {
        data.put_slice(b"X-Transformed-From: FTP\r\n");
        if let Some(addr) = self.client_addr {
            crate::serialize::add_client_addr(data, addr);
        }
        /* added for connection tuple - data channel 5-tuple */
        if let Some(ref tuple) = self.connection_tuple {
            crate::serialize::add_connection_tuple(data, tuple);
        }
        /* added for TLS keylog */
        if let Some(ref keylog) = self.keylog_buffer {
            crate::serialize::add_keylog_headers(data, keylog);
        }
    }

    /// Stream the data channel from `clt_r` to both `ups_w` (the
    /// upstream FTP server) and the ICAP server.  ICAP failures never
    /// abort the upstream forward; callers receive an
    /// `FtpAdaptationEndState` describing what happened.
    ///
    /// The main loop only does `clt_r.read → send to channels`. Two
    /// independent writer tasks drain their own channels:
    ///   - `run_ups_writer`: writes raw bytes to `ups_w`. Uses a large
    ///     bounded channel (256 chunks). Backpressure here is the
    ///     target upload rate.
    ///   - `run_icap_writer`: writes chunked body to ICAP. Uses a
    ///     smaller bounded channel (64 chunks). The main loop uses
    ///     `try_send` (non-blocking) — if the ICAP channel is full
    ///     (ICAP can't keep up), the ICAP side is closed for the rest
    ///     of the upload (fail-open audit). The ICAP writer sends the
    ///     `0\r\n\r\n` terminator on channel close, so c-icap sees a
    ///     valid (but possibly shorter) chunked body.
    ///
    /// This split is critical: a previous version used a single writer
    /// task that wrote to both `ups_w` and `icap_writer` sequentially.
    /// When the ICAP server was slow to read (c-icap per-chunk
    /// processing, or its TCP receive buffer filled), `write_icap_chunk`
    /// blocked, the channel filled up, `send_async` blocked,
    /// `clt_r.read` stopped, and TCP ZeroWindow was advertised to the
    /// client — causing large file uploads (e.g. 14 MiB) to hang while
    /// small files (<1 KiB) worked fine.
    pub async fn audit_and_forward<CR, UW>(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        clt_r: &mut CR,
        ups_w: UW,
        ftp_cmd: &str,
        ftp_path: &str,
    ) -> FtpAdaptationEndState
    where
        CR: AsyncRead + Send + Sync + Unpin,
        UW: AsyncWrite + Send + Sync + Unpin + 'static,
    {
        // 1) Build and send ICAP REQMOD header + encapsulated HTTP
        //    header.  This is the only place we touch the ICAP writer
        //    with a vectorized write; the remainder is chunked body.
        let http_header = self.build_http_header(ftp_cmd, ftp_path);
        let mut icap_header = Vec::with_capacity(self.icap_client.partial_request_header.len() + 64);
        icap_header.extend_from_slice(&self.icap_client.partial_request_header);
        self.push_extended_headers(&mut icap_header);
        let _ = write!(
            icap_header,
            "Encapsulated: req-hdr=0, req-body={}\r\n\r\n",
            http_header.len()
        );

        let header_send_result = {
            let conn = self
                .icap_connection
                .as_mut()
                .expect("icap_connection must be Some after fetch");
            conn.writer
                .write_all_vectored([io::IoSlice::new(&icap_header), io::IoSlice::new(&http_header)])
                .await
        };
        if let Err(e) = header_send_result {
            return self.fallback_forward_only(clt_r, ups_w, state, e).await;
        }

        // 2) Take ownership of the ICAP connection so we can move it
        //    into the spawned ICAP writer task.
        let icap_connection = self
            .icap_connection
            .take()
            .expect("icap_connection must be Some after fetch");

        // 3) Spawn a concurrent ICAP response reader. This drains ICAP
        //    responses to prevent TCP flow-control deadlock where the
        //    ICAP server stops accepting our writes because its receive
        //    window is full of unread response data.
        let (icap_reader, icap_writer) = icap_connection.split();
        tokio::spawn(async move {
            run_icap_response_reader(icap_reader).await;
        });

        // 4) TWO independent channels + TWO independent writer tasks.
        //    This is the critical fix: previously a single writer task
        //    wrote to both upstream and ICAP sequentially, so a slow
        //    ICAP server could block upstream forwarding and eventually
        //    stall the client read (TCP ZeroWindow).
        //
        //    - ups_channel: UPSTREAM_CHANNEL_CAPACITY chunks (≈ 8 MiB),
        //      blocking send. Upstream backpressure is the rate we want.
        //    - icap_channel: ICAP_CHANNEL_CAPACITY chunks (≈ 32 MiB),
        //      non-blocking try_send. If full, close ICAP for the rest
        //      of the upload (fail-open audit).
        let (ups_tx, ups_rx) = flume::bounded::<bytes::Bytes>(UPSTREAM_CHANNEL_CAPACITY);
        let (icap_tx, icap_rx) = flume::bounded::<bytes::Bytes>(ICAP_CHANNEL_CAPACITY);

        let ups_task = tokio::spawn(run_ups_writer(ups_w, ups_rx));
        let icap_task = tokio::spawn(run_icap_writer(icap_writer, icap_rx));

        // 5) Main loop: read client, fan out to both writer tasks.
        //    The ONLY blocking send is to `ups_tx` (upstream rate).
        //    The ICAP send is `try_send` (non-blocking) — ICAP
        //    slowness never blocks `clt_r.read`.
        let buf_size = self.copy_config.buffer_size().max(16 * 1024);
        let mut buf = vec![0u8; buf_size];
        let mut total_bytes: u64 = 0;
        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0usize;
        let mut icap_tx_opt = Some(icap_tx);

        loop {
            tokio::select! {
                biased;

                n = clt_r.read(&mut buf) => {
                    match n {
                        Ok(0) => break,
                        Ok(n) => {
                            total_bytes += n as u64;
                            idle_count = 0;
                            let chunk = bytes::Bytes::copy_from_slice(&buf[..n]);
                            // Always send to upstream — backpressure
                            // here is OK (upstream rate is the target).
                            // If the upstream writer has exited (write
                            // error), stop reading.
                            if ups_tx.send_async(chunk.clone()).await.is_err() {
                                break;
                            }
                            // Best-effort send to ICAP — never block
                            // the client read. If the ICAP channel is
                            // full, close the ICAP side for the rest
                            // of this upload (fail-open audit).
                            if let Some(ref tx) = icap_tx_opt {
                                match tx.try_send(chunk) {
                                    Ok(()) => {}
                                    Err(flume::TrySendError::Full(_)) => {
                                        // ICAP can't keep up — close
                                        // ICAP for rest of upload.
                                        icap_tx_opt = None;
                                    }
                                    Err(flume::TrySendError::Disconnected(_)) => {
                                        // ICAP writer task exited.
                                        icap_tx_opt = None;
                                    }
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }

                _ = idle_interval.tick() => {
                    idle_count += 1;
                    // Use the idle checker's quit policy instead of
                    // breaking unconditionally. IdleWheelChecker (used
                    // for FTP sub-tasks) always returns false, so this
                    // loop will never exit due to idle — the lifecycle
                    // is controlled by the outer relay. The previous
                    // `=> break` was a bug: any transient backpressure
                    // on `ups_tx.send_async` (e.g., FTPS TLS encode
                    // stall) would let a pending tick fire and abort
                    // the whole upload, even though data was still
                    // flowing. With a 60s server-level tick, this
                    // caused uploads to die after the first stall.
                    if self.idle_checker.check_quit(idle_count) {
                        break;
                    }
                }
            }
        }

        state.clt_read_finished = true;

        // Drop senders so writer tasks see channel close and finalize.
        drop(ups_tx);
        drop(icap_tx_opt);

        // Wait for both writer tasks to finish.
        let _ = ups_task.await;
        let _ = icap_task.await;

        FtpAdaptationEndState::OriginalTransferred {
            icap_status_code: 0,
            icap_reason: String::new(),
            bytes: total_bytes,
        }
    }

    /// Audit-only mode: stream the data channel only to ICAP, no
    /// upstream forwarding.  Used by callers who already forward the
    /// data themselves (e.g. HTTP CONNECT tunnel handlers where the
    /// entire data copy is already happening) but want an audit copy.
    ///
    /// Uses `try_send` (non-blocking) to the ICAP writer task. If the
    /// ICAP channel is full (ICAP can't keep up), the ICAP side is
    /// closed for the rest of the upload (fail-open audit) and the
    /// client data is drained to prevent stalling the caller's pipe.
    pub async fn audit_only<CR>(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        clt_r: &mut CR,
        ftp_cmd: &str,
        ftp_path: &str,
    ) -> FtpAdaptationEndState
    where
        CR: AsyncRead + Send + Sync + Unpin,
    {
        let http_header = self.build_http_header(ftp_cmd, ftp_path);
        let mut icap_header = Vec::with_capacity(self.icap_client.partial_request_header.len() + 64);
        icap_header.extend_from_slice(&self.icap_client.partial_request_header);
        self.push_extended_headers(&mut icap_header);
        let _ = write!(
            icap_header,
            "Encapsulated: req-hdr=0, req-body={}\r\n\r\n",
            http_header.len()
        );

        let header_send_result = {
            let conn = self
                .icap_connection
                .as_mut()
                .expect("icap_connection must be Some after fetch");
            conn.writer
                .write_all_vectored([io::IoSlice::new(&icap_header), io::IoSlice::new(&http_header)])
                .await
        };
        if header_send_result.is_err() {
            // Best-effort drain so the caller doesn't stall because we
            // refused to read.
            let mut buf = [0u8; 16 * 1024];
            let mut total_bytes = 0u64;
            loop {
                match clt_r.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => total_bytes += n as u64,
                }
            }
            return FtpAdaptationEndState::OriginalTransferredAfterFallback {
                bytes: total_bytes,
                icap_error: "icap header write failed".to_string(),
            };
        }

        let icap_connection = self
            .icap_connection
            .take()
            .expect("icap_connection must be Some after fetch");

        // ICAP channel: ICAP_CHANNEL_CAPACITY chunks (≈ 32 MiB).
        // try_send (non-blocking) — if full, close ICAP and drain
        // client data (fail-open).
        let (icap_tx, icap_rx) = flume::bounded::<bytes::Bytes>(ICAP_CHANNEL_CAPACITY);
        let (icap_reader, icap_writer) = icap_connection.split();
        tokio::spawn(async move {
            run_icap_response_reader(icap_reader).await;
        });
        let icap_task = tokio::spawn(run_icap_writer(icap_writer, icap_rx));

        let buf_size = self.copy_config.buffer_size().max(16 * 1024);
        let mut buf = vec![0u8; buf_size];
        let mut total_bytes: u64 = 0;
        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0usize;
        let mut icap_tx_opt = Some(icap_tx);

        loop {
            tokio::select! {
                biased;
                n = clt_r.read(&mut buf) => {
                    match n {
                        Ok(0) => break,
                        Ok(n) => {
                            total_bytes += n as u64;
                            idle_count = 0;
                            if let Some(ref tx) = icap_tx_opt {
                                let chunk = bytes::Bytes::copy_from_slice(&buf[..n]);
                                match tx.try_send(chunk) {
                                    Ok(()) => {}
                                    Err(flume::TrySendError::Full(_)) => {
                                        // ICAP can't keep up — close ICAP
                                        // and continue draining client.
                                        icap_tx_opt = None;
                                    }
                                    Err(flume::TrySendError::Disconnected(_)) => {
                                        // ICAP writer task exited.
                                        icap_tx_opt = None;
                                    }
                                }
                            }
                            // If ICAP is closed, keep reading to drain
                            // the client so the caller's pipe doesn't
                            // stall waiting on us to read.
                        }
                        Err(_) => break,
                    }
                }
                _ = idle_interval.tick() => {
                    idle_count += 1;
                    if self.idle_checker.check_quit(idle_count) {
                        break;
                    }
                }
            }
        }

        state.clt_read_finished = true;
        drop(icap_tx_opt);

        let _ = icap_task.await;

        FtpAdaptationEndState::AuditOnly {
            icap_status_code: 0,
            icap_reason: String::new(),
            bytes: total_bytes,
        }
    }

    /// Forward path used when ICAP header send fails immediately.
    /// Guarantees the client data is still delivered to upstream so
    /// the FTP upload succeeds.
    async fn fallback_forward_only<CR, UW>(
        mut self,
        clt_r: &mut CR,
        ups_w: UW,
        state: &mut ReqmodAdaptationRunState,
        first_err: io::Error,
    ) -> FtpAdaptationEndState
    where
        CR: AsyncRead + Send + Sync + Unpin,
        UW: AsyncWrite + Send + Sync + Unpin,
    {
        // The ICAP connection is effectively dead - just drop it.
        drop(self.icap_connection.take());

        // Take ownership of ups_w; this plain forward loop drives it
        // directly without spawning a writer task (we're in the
        // fallback path and don't need decoupling).
        let mut ups_w = ups_w;

        let buf_size = self.copy_config.buffer_size().max(16 * 1024);
        let mut buf = vec![0u8; buf_size];
        let mut total_bytes: u64 = 0;
        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0usize;

        loop {
            tokio::select! {
                biased;
                n = clt_r.read(&mut buf) => {
                    match n {
                        Ok(0) => break,
                        Ok(n) => {
                            total_bytes += n as u64;
                            idle_count = 0;
                            if ups_w.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                _ = idle_interval.tick() => {
                    idle_count += 1;
                    if self.idle_checker.check_quit(idle_count) {
                        break;
                    }
                }
            }
        }

        let _ = ups_w.flush().await;
        let _ = ups_w.shutdown().await;
        state.clt_read_finished = true;

        FtpAdaptationEndState::OriginalTransferredAfterFallback {
            bytes: total_bytes,
            icap_error: format!("icap header write failed: {first_err}"),
        }
    }
}

/// Send a single chunk to ICAP in `<hex-size>\r\n<data>\r\n` form
/// (HTTP/1.1 chunked transfer encoding per RFC 7230 §4.1).
async fn write_icap_chunk<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> io::Result<()> {
    let chunk_header = format!("{:x}\r\n", data.len());
    writer.write_all(chunk_header.as_bytes()).await?;
    writer.write_all(data).await?;
    writer.write_all(b"\r\n").await
}

/// Spawned ICAP response reader task. Runs concurrently with the body writer
/// to drain ICAP responses and prevent TCP flow-control deadlock where the
/// ICAP server stops accepting our writes because its receive window is full.
/// The response body is simply discarded — no parsing, no outcome reporting.
async fn run_icap_response_reader(icap_reader: IcapClientReader) {
    // Read and discard ICAP responses. Using a simple read loop instead of
    // tokio::io::copy to avoid any potential issues with BufReader + copy.
    let mut reader = icap_reader;
    let mut buf = [0u8; 8192];
    loop {
        match tokio::io::AsyncReadExt::read(&mut reader, &mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_n) => {}
        }
    }
}

/// Spawned upstream writer task. Writes raw bytes to the upstream FTP
/// server. Has its own bounded channel so upstream backpressure is
/// decoupled from both `clt_r.read` and ICAP writes.
///
/// On channel close (= main loop done): flush + half-close `ups_w` so
/// the upstream FTP server sees EOF.
/// On write error: exit; the main loop will detect channel disconnect.
async fn run_ups_writer<UW: AsyncWriteExt + Unpin>(
    mut ups_w: UW,
    chunk_rx: flume::Receiver<bytes::Bytes>,
) {
    while let Ok(chunk) = chunk_rx.recv_async().await {
        if ups_w.write_all(&chunk).await.is_err() {
            break;
        }
    }
    let _ = ups_w.flush().await;
    let _ = ups_w.shutdown().await;
}

/// Spawned ICAP writer task. Writes chunked body to the ICAP server at
/// its own pace. Has its own bounded channel so ICAP backpressure is
/// fully decoupled from both `clt_r.read` and upstream writes.
///
/// On channel close (= main loop done, or ICAP closed due to slow):
///   write the ICAP chunked terminator `0\r\n\r\n` + flush.
/// On write error: exit; the main loop will detect channel disconnect.
async fn run_icap_writer(
    mut icap_writer: IcapClientWriter,
    chunk_rx: flume::Receiver<bytes::Bytes>,
) {
    while let Ok(chunk) = chunk_rx.recv_async().await {
        if write_icap_chunk(&mut icap_writer, &chunk).await.is_err() {
            break;
        }
    }
    // Send chunked terminator on close (best-effort).
    let _ = icap_writer.write_all(b"0\r\n\r\n").await;
    let _ = icap_writer.flush().await;
    // The concurrent reader task drains the response; drop writer to signal EOF.
    drop(icap_writer);
}

/// A cheap builder/helper for creating a [`ReqmodAdaptationRunState`]
/// in FTP callers that don't have a mail module state tracker.
pub fn new_adaptation_run_state() -> ReqmodAdaptationRunState {
    ReqmodAdaptationRunState::new(Instant::now())
}
