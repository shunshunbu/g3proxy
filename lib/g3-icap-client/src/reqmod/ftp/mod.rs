/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BufMut;
use flume;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, sink, empty};
use tokio::time::Instant;

use g3_io_ext::{IdleCheck, LimitedWriteExt, OnceBufReader, StreamCopyConfig};

use log::{warn, debug};

use super::{ConnectionTuple, IcapReqmodClient, TlsKeyLogBuffer};
use crate::reqmod::mail::ReqmodAdaptationRunState;
use crate::service::{IcapClientConnection, IcapClientReader, IcapClientWriter};
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
    /// ICAP audit is being processed in the background.  The upload
    /// data has already been forwarded to the upstream FTP server.
    /// The audit verdict will be available asynchronously.
    OriginalTransferredInBackground {
        bytes: u64,
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
        let _ = write!(
            header,
            "PUT {} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/octet-stream\r\n\
             X-FTP-Command: {}\r\n\
             \r\n",
            ftp_path, ftp_cmd
        );
        header
    }

    fn push_extended_headers(&self, data: &mut Vec<u8>) {
        data.put_slice(b"Allow: 204\r\n");
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
        if let Err(e) = self.send_icap_header(ftp_cmd, ftp_path).await {
            warn!("FTP ICAP header send failed, fallback to forward-only: {}", e);
            return self.fallback_forward_only(clt_r, ups_w, state, e).await;
        }

        let (total_bytes, icap_ok, icap_handle) = match self.run_relay_loop(clt_r, ups_w).await {
            Ok((bytes, ok, handle)) => (bytes, ok, handle),
            Err(bytes) => {
                return FtpAdaptationEndState::OriginalTransferredAfterFallback {
                    bytes,
                    icap_error: "upstream write failed".to_string(),
                };
            }
        };

        state.clt_read_finished = true;

        let _ = ups_w.flush().await;
        let _ = ups_w.shutdown().await;

        if !icap_ok {
            let _ = icap_handle.await;
            return FtpAdaptationEndState::OriginalTransferredAfterFallback {
                bytes: total_bytes,
                icap_error: "icap aborted due to slow write".to_string(),
            };
        }

        let icap_client = self.icap_client.clone();

        tokio::spawn(async move {
            // Overall timeout for the background ICAP response processing.
            // Prevents resource leaks if the ICAP server hangs.
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(300),
                async {
                    let (icap_result, icap_writer, icap_reader, rsp_header_buf) = match icap_handle.await {
                        Ok((result, writer, reader, header_buf)) => (result, writer, reader, header_buf),
                        Err(_) => {
                            warn!("FTP ICAP background task panicked");
                            return;
                        }
                    };

                    if let Err(e) = icap_result {
                        warn!("FTP ICAP write failed ({}), audit incomplete", e);
                        return;
                    }

                    let mut icap_connection = IcapClientConnection::placeholder();
                    icap_connection.writer = icap_writer;
                    icap_connection.reader = if rsp_header_buf.is_empty() {
                        icap_reader
                    } else {
                        // Prepend the response header captured during drain
                        // so that ReqmodResponse::parse can read the status
                        // line and headers that were otherwise consumed and
                        // discarded by the anti-deadlock drain loop.
                        let prefixed = OnceBufReader::with_bytes(
                            icap_reader.into_inner(),
                            bytes::Bytes::from(rsp_header_buf),
                        );
                        BufReader::new(Box::new(prefixed))
                    };
                    icap_connection.mark_writer_finished();

                    let icap_max_header_size = icap_client.config.icap_max_header_size;
                    let respond_shared_names = icap_client.config.respond_shared_names.clone();

                    // Parse the ICAP response first. The response headers
                    // are available once the write side is done (the server
                    // sends them after receiving the complete request).
                    let parse_result = crate::reqmod::response::ReqmodResponse::parse(
                        &mut icap_connection.reader,
                        icap_max_header_size,
                        &respond_shared_names,
                    ).await;

                    let rsp = match parse_result {
                        Ok(rsp) => rsp,
                        Err(e) => {
                            warn!("FTP ICAP response parse failed: {}", e);
                            // Do not save a connection with partial/unparsed response
                            return;
                        }
                    };

                    debug!(
                        "FTP ICAP response: code={}, reason={}, keep_alive={}",
                        rsp.code, rsp.reason, rsp.keep_alive
                    );

                    // Drain any remaining response body data (e.g. from echo
                    // services that echo back the request body).
                    // Skip draining for responses with no body (e.g. 204 No Content).
                    let drain_clean = if !rsp.has_body() {
                        true
                    } else {
                        let mut drain_buf = [0u8; 65536];
                        let mut clean = false;
                        loop {
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(5),
                                icap_connection.reader.read(&mut drain_buf),
                            )
                            .await
                            {
                                Ok(Ok(0)) => {
                                    clean = true;
                                    break;
                                }
                                Ok(Ok(_)) => continue,
                                Ok(Err(_)) | Err(_) => break,
                            }
                        }
                        clean
                    };

                    icap_connection.mark_reader_finished();

                    // Only save the connection for reuse if the response indicates
                    // success, keep-alive is enabled, and the body was cleanly
                    // drained (no leftover data or read errors).
                    if drain_clean && rsp.keep_alive && rsp.code >= 200 && rsp.code < 300 {
                        let _ = icap_client.save_connection(icap_connection);
                    } else {
                        warn!(
                            "FTP ICAP connection discarded (code={}, keep_alive={}, drain_clean={})",
                            rsp.code, rsp.keep_alive, drain_clean
                        );
                    }
                },
            )
            .await;
        });

        FtpAdaptationEndState::OriginalTransferredInBackground {
            bytes: total_bytes,
        }
    }

    async fn send_icap_header(
        &mut self,
        ftp_cmd: &str,
        ftp_path: &str,
    ) -> io::Result<()> {
        let http_header = self.build_http_header(ftp_cmd, ftp_path);
        let mut icap_header = Vec::with_capacity(self.icap_client.partial_request_header.len() + 64);
        icap_header.extend_from_slice(&self.icap_client.partial_request_header);
        self.push_extended_headers(&mut icap_header);
        let _ = write!(
            icap_header,
            "Encapsulated: req-hdr=0, req-body={}\r\n\r\n",
            http_header.len()
        );

        debug!(
            "FTP ICAP request header ({} bytes, http_header {} bytes):\n{}",
            icap_header.len(),
            http_header.len(),
            String::from_utf8_lossy(&icap_header)
        );

        self.icap_connection
            .writer
            .write_all_vectored([io::IoSlice::new(&icap_header), io::IoSlice::new(&http_header)])
            .await?;
        self.icap_connection.writer.flush().await
    }

    async fn run_relay_loop<CR, UW>(
        &mut self,
        clt_r: &mut CR,
        ups_w: &mut UW,
    ) -> Result<(u64, bool, tokio::task::JoinHandle<(Result<u64, &'static str>, IcapClientWriter, IcapClientReader, Vec<u8>)>), u64>
    where
        CR: AsyncRead + Send + Sync + Unpin,
        UW: AsyncWrite + Send + Sync + Unpin,
    {
        // Use a 256 KiB buffer to cut the number of syscalls for large
        // files (1 GiB would otherwise need 65536 x 16 KiB copies).
        let buf_size = self.copy_config.buffer_size().max(256 * 1024);
        let mut buf = vec![0u8; buf_size];
        let mut total_bytes: u64 = 0;

        let mut idle_interval = self.idle_checker.interval_timer();
        let mut idle_count = 0usize;

        // ICAP buffering: channel with backpressure
        // When ICAP is slower than the upstream, send_async blocks
        // and naturally throttles the client read rate.
        const CHANNEL_CAPACITY: usize = 64;
        let (chunk_tx, chunk_rx) = flume::bounded::<bytes::Bytes>(CHANNEL_CAPACITY);

        // Take both the ICAP writer and reader. The writer is used to
        // send chunked body data; the reader is concurrently drained to
        // prevent deadlock with echo-style ICAP services that start
        // sending back the response while we are still uploading.
        let icap_writer = std::mem::replace(&mut self.icap_connection.writer, Box::new(sink()));
        let icap_reader = std::mem::replace(
            &mut self.icap_connection.reader,
            BufReader::new(Box::new(empty())),
        );
        let max_header_size = self.icap_client.config.icap_max_header_size;

        let icap_handle = tokio::spawn(async move {
            let mut write_buf = bytes::BytesMut::with_capacity(4 * 1024 * 1024);
            let mut icap_writer = icap_writer;
            let mut icap_reader = icap_reader;
            let mut total_written: u64 = 0;
            let mut pending_chunks: usize = 0;
            let mut drain_buf = [0u8; 65536];
            let mut reader_closed = false;
            // Capture the ICAP response header during drain so it can be
            // replayed for parsing.  Echo-style ICAP servers send the full
            // response (header + body) while the upload is still in
            // progress; without this capture the header is consumed and
            // discarded by the drain, causing parse to fail.
            let mut rsp_header_buf: Vec<u8> = Vec::new();
            let mut rsp_header_done = false;

            // Combined write + drain loop.
            // "biased" ensures we prioritise writing chunks over draining
            // so that the request body is delivered as fast as possible.
            loop {
                if reader_closed {
                    // Reader is closed; only process remaining chunks.
                    match chunk_rx.recv_async().await {
                        Ok(chunk) => {
                            total_written += chunk.len() as u64;
                            append_chunk_header(&mut write_buf, chunk.len());
                            write_buf.extend_from_slice(&chunk);
                            write_buf.extend_from_slice(b"\r\n");
                            pending_chunks += 1;

                            if pending_chunks >= 16 || write_buf.len() >= 4 * 1024 * 1024 {
                                if icap_writer.write_all(&write_buf).await.is_err() {
                                    return (Err("icap write failed"), icap_writer, icap_reader, Vec::new());
                                }
                                if icap_writer.flush().await.is_err() {
                                    return (Err("icap flush failed"), icap_writer, icap_reader, Vec::new());
                                }
                                write_buf.clear();
                                pending_chunks = 0;
                            }
                        }
                        Err(_) => break,
                    }
                    continue;
                }

                tokio::select! {
                    biased;
                    chunk = chunk_rx.recv_async() => {
                        match chunk {
                            Ok(chunk) => {
                                total_written += chunk.len() as u64;
                                // Write hex length + CRLF + data + CRLF
                                // into write_buf in one pass to avoid
                                // per-chunk String allocation.
                                append_chunk_header(&mut write_buf, chunk.len());
                                write_buf.extend_from_slice(&chunk);
                                write_buf.extend_from_slice(b"\r\n");
                                pending_chunks += 1;

                                if pending_chunks >= 16 || write_buf.len() >= 4 * 1024 * 1024 {
                                    if icap_writer.write_all(&write_buf).await.is_err() {
                                        return (Err("icap write failed"), icap_writer, icap_reader, Vec::new());
                                    }
                                    if icap_writer.flush().await.is_err() {
                                        return (Err("icap flush failed"), icap_writer, icap_reader, Vec::new());
                                    }
                                    write_buf.clear();
                                    pending_chunks = 0;
                                }
                            }
                            Err(_) => {
                                // Channel closed — all request data has been sent.
                                break;
                            }
                        }
                    }
                    // Drain the ICAP reader concurrently.  This is critical
                    // for echo services that start streaming the response
                    // body back before the request body is complete.  Without
                    // this drain, the TCP receive buffer fills up, the ICAP
                    // server blocks on writing, then stops reading our data,
                    // and the whole pipeline deadlocks.
                    n = icap_reader.read(&mut drain_buf) => {
                        match n {
                            Ok(0) | Err(_) => {
                                // Connection closed / error — stop draining
                                // to avoid busy-looping on a closed reader.
                                reader_closed = true;
                            }
                            Ok(read_len) => {
                                // Capture the ICAP response header so it
                                // can be replayed for parsing after the
                                // upload finishes.  Echo-style ICAP servers
                                // send the full response while we are still
                                // uploading; without this capture the header
                                // is lost and parsing fails with
                                // "not long enough".
                                if !rsp_header_done {
                                    rsp_header_buf.extend_from_slice(&drain_buf[..read_len]);
                                    if let Some(pos) = find_icap_header_end(&rsp_header_buf) {
                                        rsp_header_buf.truncate(pos + 4);
                                        rsp_header_done = true;
                                    } else if rsp_header_buf.len() >= max_header_size {
                                        rsp_header_done = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Flush remaining write buffer
            if !write_buf.is_empty() {
                let _ = icap_writer.write_all(&write_buf).await;
                let _ = icap_writer.flush().await;
            }

            let _ = icap_writer.write_all(b"0\r\n\r\n").await;
            let _ = icap_writer.flush().await;

            (Ok(total_written), icap_writer, icap_reader, rsp_header_buf)
        });

        let mut icap_alive = true;

        loop {
            tokio::select! {
                biased;
                res = clt_r.read(&mut buf) => {
                    match res {
                        Ok(0) => break,
                        Ok(n) => {
                            idle_count = 0;
                            total_bytes += n as u64;

                            if ups_w.write_all(&buf[..n]).await.is_err() {
                                drop(chunk_tx);
                                return Err(total_bytes);
                            }

                            if icap_alive {
                                let chunk = bytes::Bytes::copy_from_slice(&buf[..n]);
                                match chunk_tx.send_async(chunk).await {
                                    Ok(_) => {}
                                    Err(_) => {
                                        warn!("FTP ICAP channel closed");
                                        icap_alive = false;
                                    }
                                }
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

        drop(chunk_tx);
        Ok((total_bytes, icap_alive, icap_handle))
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
        let mut write_buf = bytes::BytesMut::with_capacity(4096);

        let mut idle_count = 0usize;

        loop {
            tokio::select! {
                biased;
                n = clt_r.read(&mut buf) => {
                    match n {
                        Ok(0) => break,
                        Ok(n) => {
                            idle_count = 0;
                            total_bytes += n as u64;
                            if write_icap_chunk(&mut self.icap_connection.writer, &buf[..n], &mut write_buf)
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
                _ = idle_interval.tick() => {
                    idle_count += 1;
                    if self.idle_checker.check_quit(idle_count) {
                        break;
                    }
                }
            }
        }

        state.clt_read_finished = true;

        let _ = self.icap_connection.writer.write_all(b"0\r\n\r\n").await;
        let _ = self.icap_connection.writer.flush().await;
        self.icap_connection.mark_writer_finished();

        let rsp = match crate::reqmod::response::ReqmodResponse::parse(
            &mut self.icap_connection.reader,
            self.icap_client.config.icap_max_header_size,
            &self.icap_client.config.respond_shared_names,
        )
        .await
        {
            Ok(rsp) => rsp,
            Err(_) => {
                warn!("FTP ICAP response parse failed");
                self.icap_connection.mark_reader_finished();
                return FtpAdaptationEndState::OriginalTransferredAfterFallback {
                    bytes: total_bytes,
                    icap_error: "icap response parse failed".to_string(),
                };
            }
        };

        // Drain any remaining response body data so the connection can be
        // safely reused.  Without this, leftover bytes would corrupt the
        // next ICAP request on the same connection.
        // Skip draining for responses with no body (e.g. 204 No Content),
        // where there is nothing to read and a 5s timeout would be wasted.
        let drain_clean = if !rsp.has_body() {
            true
        } else {
            let mut drain_buf = [0u8; 65536];
            let mut clean = false;
            loop {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    self.icap_connection.reader.read(&mut drain_buf),
                )
                .await
                {
                    Ok(Ok(0)) => {
                        clean = true;
                        break;
                    }
                    Ok(Ok(_)) => continue,
                    Ok(Err(_)) | Err(_) => break,
                }
            }
            clean
        };

        self.icap_connection.mark_reader_finished();

        if drain_clean && rsp.keep_alive && rsp.code >= 200 && rsp.code < 300 {
            let _ = self.icap_client.save_connection(self.icap_connection);
        } else {
            warn!(
                "FTP ICAP connection discarded (code={}, keep_alive={}, drain_clean={})",
                rsp.code, rsp.keep_alive, drain_clean
            );
        }

        FtpAdaptationEndState::AuditOnly {
            icap_status_code: rsp.code,
            icap_reason: rsp.reason,
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

/// Find the position of `\r\n\r\n` (end of ICAP/HTTP headers) in `buf`.
/// Returns the index of the first byte of the match.
fn find_icap_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Append `<hex-size>\r\n` to the buffer without heap allocation.
fn append_chunk_header(buf: &mut bytes::BytesMut, len: usize) {
    // Maximum hex digits for usize on 64-bit: 16
    const HEX: &[u8; 16] = b"0123456789abcdef";

    // Calculate number of hex digits needed
    let mut num_digits = 0usize;
    let mut n = len;
    if n == 0 {
        num_digits = 1;
    } else {
        while n > 0 {
            num_digits += 1;
            n >>= 4;
        }
    }

    // Use stack-based buffer: hex digits + "\r\n"
    let total_len = num_digits + 2;
    let mut tmp = [0u8; 18]; // 16 hex digits max + "\r\n"

    // Write hex digits from right to left within the digit region
    let mut pos = num_digits;
    n = len;
    while n > 0 {
        pos -= 1;
        tmp[pos] = HEX[n & 0xf];
        n >>= 4;
    }
    if len == 0 {
        tmp[0] = b'0';
    }

    // Add "\r\n" after hex digits
    tmp[num_digits] = b'\r';
    tmp[num_digits + 1] = b'\n';

    buf.extend_from_slice(&tmp[..total_len]);
}

/// Send a single chunk to ICAP in `<hex-size>\r\n<data>\r\n` form.
/// Reuses the caller-provided `BytesMut` buffer to avoid per-chunk allocations.
async fn write_icap_chunk<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
    buf: &mut bytes::BytesMut,
) -> io::Result<()> {
    buf.clear();
    append_chunk_header(buf, data.len());
    buf.extend_from_slice(data);
    buf.extend_from_slice(b"\r\n");
    writer.write_all(buf).await
}

/// A cheap builder/helper for creating a [`ReqmodAdaptationRunState`]
/// in FTP callers that don't have a mail module state tracker.
pub fn new_adaptation_run_state() -> ReqmodAdaptationRunState {
    ReqmodAdaptationRunState::new(Instant::now())
}

#[cfg(test)]
mod tests {
    use super::append_chunk_header;

    #[test]
    fn test_append_chunk_header_zero() {
        let mut buf = bytes::BytesMut::new();
        append_chunk_header(&mut buf, 0);
        assert_eq!(buf.as_ref(), b"0\r\n");
    }

    #[test]
    fn test_append_chunk_header_single_digit() {
        let mut buf = bytes::BytesMut::new();
        append_chunk_header(&mut buf, 5);
        assert_eq!(buf.as_ref(), b"5\r\n");
    }

    #[test]
    fn test_append_chunk_header_two_digits() {
        let mut buf = bytes::BytesMut::new();
        append_chunk_header(&mut buf, 255);
        assert_eq!(buf.as_ref(), b"ff\r\n");
    }

    #[test]
    fn test_append_chunk_header_three_digits() {
        let mut buf = bytes::BytesMut::new();
        append_chunk_header(&mut buf, 4096);
        assert_eq!(buf.as_ref(), b"1000\r\n");
    }

    #[test]
    fn test_append_chunk_header_large() {
        let mut buf = bytes::BytesMut::new();
        append_chunk_header(&mut buf, 0x10000);
        assert_eq!(buf.as_ref(), b"10000\r\n");
    }

    #[test]
    fn test_append_chunk_header_usize_max() {
        let mut buf = bytes::BytesMut::new();
        append_chunk_header(&mut buf, usize::MAX);
        // usize::MAX on 64-bit = 0xffffffffffffffff = 16 f's
        if cfg!(target_pointer_width = "64") {
            assert_eq!(buf.as_ref(), b"ffffffffffffffff\r\n");
        } else {
            assert_eq!(buf.as_ref(), b"ffffffff\r\n");
        }
    }
}
