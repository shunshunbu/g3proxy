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
use crate::{IcapServiceClient, IcapServiceOptions};

mod error;
pub use error::FtpAdaptationError;

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
            icap_connection,
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
    icap_connection: IcapClientConnection,
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
    /// Memory behaviour: a single fixed-size buffer is used for every
    /// read/duplicate/write cycle, so the heap footprint does not grow
    /// with file size.
    pub async fn audit_and_forward<CR, UW>(
        mut self,
        state: &mut ReqmodAdaptationRunState,
        clt_r: &mut CR,
        ups_w: &mut UW,
        ftp_cmd: &str,
        ftp_path: &str,
    ) -> FtpAdaptationEndState
    where
        CR: AsyncRead + Send + Sync + Unpin,
        UW: AsyncWrite + Send + Sync + Unpin,
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

        let header_sent = self
            .icap_connection
            .writer
            .write_all_vectored([io::IoSlice::new(&icap_header), io::IoSlice::new(&http_header)])
            .await;

        if let Err(e) = header_sent {
            return self.fallback_forward_only(clt_r, ups_w, state, e).await;
        }

        // 2) Streaming loop: read -> chunked-write to ICAP, raw-write
        //    to upstream.  We intentionally do NOT flush on every
        //    iteration; ICAP writer flushing happens once after body
        //    terminator.  If ICAP writes fail partway through we switch
        //    to "forward-only" mode so the upload is not lost.
        let buf_size = self.copy_config.buffer_size().max(16 * 1024);
        let mut buf = vec![0u8; buf_size];
        let mut total_bytes: u64 = 0;
        let mut icap_alive = true;
        let mut last_icap_err: Option<io::Error> = None;
        let mut idle_interval = self.idle_checker.interval_timer();

        loop {
            tokio::select! {
                biased;

                n = clt_r.read(&mut buf) => {
                    match n {
                        Ok(0) => break,
                        Ok(n) => {
                            total_bytes += n as u64;

                            // Always forward to upstream first.
                            if ups_w.write_all(&buf[..n]).await.is_err() {
                                // Upstream gone: nothing we can do.  Treat as
                                // end-of-stream; ICAP termination follows.
                                break;
                            }

                            if icap_alive {
                                if write_icap_chunk(&mut self.icap_connection.writer, &buf[..n])
                                    .await
                                    .is_err()
                                {
                                    icap_alive = false;
                                    last_icap_err = Some(io::Error::new(
                                        io::ErrorKind::BrokenPipe,
                                        "icap body write failed",
                                    ));
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }

                _ = idle_interval.tick() => break,
            }
        }

        state.clt_read_finished = true;

        // 3) Flush upstream.  This ensures the FTP server data channel
        //    has received everything before we close.  Failure here is
        //    a real upload failure (reported to caller as zero bytes
        //    forwarded).
        let _ = ups_w.flush().await;

        if !icap_alive {
            return FtpAdaptationEndState::OriginalTransferredAfterFallback {
                bytes: total_bytes,
                icap_error: last_icap_err
                    .map(|e| format!("{e}"))
                    .unwrap_or_else(|| "icap write failed".to_string()),
            };
        }

        // 4) Terminating chunk ("0\r\n\r\n") + flush ICAP writer.
        let terminator_sent = self
            .icap_connection
            .writer
            .write_all(b"0\r\n\r\n")
            .await;
        let terminator_sent = match terminator_sent {
            Ok(()) => self.icap_connection.writer.flush().await,
            Err(e) => Err(e),
        };
        self.icap_connection.mark_writer_finished();

        if terminator_sent.is_err() {
            return FtpAdaptationEndState::OriginalTransferredAfterFallback {
                bytes: total_bytes,
                icap_error: "icap terminator write failed".to_string(),
            };
        }

        // 5) Read ICAP response.  This is only an audit verdict - it
        //    does NOT block upload delivery.  All failures here just
        //    lose audit information, never the upload.
        let (icap_code, icap_reason) =
            match crate::reqmod::response::ReqmodResponse::parse(
                &mut self.icap_connection.reader,
                self.icap_client.config.icap_max_header_size,
                &self.icap_client.config.respond_shared_names,
            )
            .await
            {
                Ok(rsp) => (rsp.code, rsp.reason),
                Err(_) => {
                    self.icap_connection.mark_reader_finished();
                    let _ = self.icap_client.save_connection(self.icap_connection);
                    return FtpAdaptationEndState::OriginalTransferredAfterFallback {
                        bytes: total_bytes,
                        icap_error: "icap response parse failed".to_string(),
                    };
                }
            };

        self.icap_connection.mark_reader_finished();
        let _ = self.icap_client.save_connection(self.icap_connection);

        FtpAdaptationEndState::OriginalTransferred {
            icap_status_code: icap_code,
            icap_reason,
            bytes: total_bytes,
        }
    }

    /// Audit-only mode: stream the data channel only to ICAP, no
    /// upstream forwarding.  Used by callers who already forward the
    /// data themselves (e.g. HTTP CONNECT tunnel handlers where the
    /// entire data copy is already happening) but want an audit copy.
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

        let header_sent = self
            .icap_connection
            .writer
            .write_all_vectored([io::IoSlice::new(&icap_header), io::IoSlice::new(&http_header)])
            .await;

        if header_sent.is_err() {
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

        let buf_size = self.copy_config.buffer_size().max(16 * 1024);
        let mut buf = vec![0u8; buf_size];
        let mut total_bytes: u64 = 0;
        let mut idle_interval = self.idle_checker.interval_timer();

        loop {
            tokio::select! {
                biased;
                n = clt_r.read(&mut buf) => {
                    match n {
                        Ok(0) => break,
                        Ok(n) => {
                            total_bytes += n as u64;
                            if write_icap_chunk(&mut self.icap_connection.writer, &buf[..n])
                                .await
                                .is_err()
                            {
                                // Drain rest so reader isn't blocked;
                                // caller already got the bytes on its
                                // own path.
                                let mut tail = [0u8; 16 * 1024];
                                loop {
                                    match clt_r.read(&mut tail).await {
                                        Ok(0) | Err(_) => break,
                                        Ok(m) => total_bytes += m as u64,
                                    }
                                }
                                return FtpAdaptationEndState::OriginalTransferredAfterFallback {
                                    bytes: total_bytes,
                                    icap_error: "icap body write failed".to_string(),
                                };
                            }
                        }
                        Err(_) => break,
                    }
                }
                _ = idle_interval.tick() => break,
            }
        }

        state.clt_read_finished = true;

        let _ = self.icap_connection.writer.write_all(b"0\r\n\r\n").await;
        let _ = self.icap_connection.writer.flush().await;
        self.icap_connection.mark_writer_finished();

        let (icap_code, icap_reason) =
            match crate::reqmod::response::ReqmodResponse::parse(
                &mut self.icap_connection.reader,
                self.icap_client.config.icap_max_header_size,
                &self.icap_client.config.respond_shared_names,
            )
            .await
            {
                Ok(rsp) => (rsp.code, rsp.reason),
                Err(_) => {
                    self.icap_connection.mark_reader_finished();
                    let _ = self.icap_client.save_connection(self.icap_connection);
                    return FtpAdaptationEndState::OriginalTransferredAfterFallback {
                        bytes: total_bytes,
                        icap_error: "icap response parse failed".to_string(),
                    };
                }
            };

        self.icap_connection.mark_reader_finished();
        let _ = self.icap_client.save_connection(self.icap_connection);

        FtpAdaptationEndState::AuditOnly {
            icap_status_code: icap_code,
            icap_reason,
            bytes: total_bytes,
        }
    }

    /// Forward path used when ICAP header send fails immediately.
    /// Guarantees the client data is still delivered to upstream so
    /// the FTP upload succeeds.
    async fn fallback_forward_only<CR, UW>(
        self,
        clt_r: &mut CR,
        ups_w: &mut UW,
        state: &mut ReqmodAdaptationRunState,
        first_err: io::Error,
    ) -> FtpAdaptationEndState
    where
        CR: AsyncRead + Send + Sync + Unpin,
        UW: AsyncWrite + Send + Sync + Unpin,
    {
        // The ICAP connection is effectively dead - just drop it.
        drop(self.icap_connection);

        let buf_size = self.copy_config.buffer_size().max(16 * 1024);
        let mut buf = vec![0u8; buf_size];
        let mut total_bytes: u64 = 0;
        let mut idle_interval = self.idle_checker.interval_timer();

        loop {
            tokio::select! {
                biased;
                n = clt_r.read(&mut buf) => {
                    match n {
                        Ok(0) => break,
                        Ok(n) => {
                            total_bytes += n as u64;
                            if ups_w.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                _ = idle_interval.tick() => break,
            }
        }

        let _ = ups_w.flush().await;
        state.clt_read_finished = true;

        FtpAdaptationEndState::OriginalTransferredAfterFallback {
            bytes: total_bytes,
            icap_error: format!("icap header write failed: {first_err}"),
        }
    }
}

/// Send a single chunk to ICAP in `<hex-size>\r\n<data>\r\n` form.
async fn write_icap_chunk<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> io::Result<()> {
    let mut hex = itoa::Buffer::new();
    let hex_s = hex.format(data.len());
    writer.write_all(hex_s.as_bytes()).await?;
    writer.write_all(b"\r\n").await?;
    writer.write_all(data).await?;
    writer.write_all(b"\r\n").await
}

/// A cheap builder/helper for creating a [`ReqmodAdaptationRunState`]
/// in FTP callers that don't have a mail module state tracker.
pub fn new_adaptation_run_state() -> ReqmodAdaptationRunState {
    ReqmodAdaptationRunState::new(Instant::now())
}
