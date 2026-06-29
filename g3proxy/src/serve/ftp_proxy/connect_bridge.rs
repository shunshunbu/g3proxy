/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! FTP over HTTP CONNECT tunnel bridge.
//!
//! When an HTTP CONNECT tunnel carries FTP traffic, this bridge:
//!   1. intercepts the control channel to detect PASV/EPSV responses
//!      (rewriting them to point at a locally-bound data listener),
//!   2. detects STOR/STOU/APPE commands and copies the data channel
//!      through the shared ICAP REQMOD audit pipeline.
//!
//! This bridges reuses the same `run_ftp_upload_audit_or_relay`
//! function used by the native FTP proxy — keeping the audit path
//! consistent across both proxy modes.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use slog::Logger;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use g3_daemon::server::ClientConnectionInfo;
use g3_io_ext::IdleWheel;

use super::audit_bridge::{FtpUploadAuditContext, run_ftp_upload_audit_or_relay};
use super::ctl_common::{
    is_data_channel_command, is_epsv_command, is_pasv_command, is_upload_command,
    parse_pasv_response, read_ftp_response, rewrite_epsv_response, rewrite_pasv_response,
};
use super::stats::FtpProxyServerStats;
use crate::audit::AuditContext;
use crate::config::server::ftp_proxy::FtpProxyServerConfig;
use crate::config::server::ServerConfig;
use crate::serve::ServerTaskNotes;

#[allow(dead_code)]
pub(crate) struct FtpOverConnectBridge {
    server_config: Arc<FtpProxyServerConfig>,
    #[allow(dead_code)]
    server_stats: Arc<FtpProxyServerStats>,
    icap_client: Option<Arc<g3_icap_client::reqmod::IcapReqmodClient>>,
    idle_wheel: Arc<IdleWheel>,
    cc_info: ClientConnectionInfo,
    #[allow(dead_code)]
    task_logger: Option<Logger>,
    upstream_ip: Ipv4Addr,
    #[allow(dead_code)]
    task_notes: ServerTaskNotes,
}

#[allow(dead_code)]
impl FtpOverConnectBridge {
    pub(crate) fn new(
        server_config: Arc<FtpProxyServerConfig>,
        server_stats: Arc<FtpProxyServerStats>,
        idle_wheel: Arc<IdleWheel>,
        cc_info: ClientConnectionInfo,
        upstream_ip: Ipv4Addr,
        task_logger: Option<Logger>,
        audit_ctx: &AuditContext,
        task_notes: ServerTaskNotes,
    ) -> Self {
        let icap_client = if server_config.audit_upload {
            audit_ctx
                .handle()
                .and_then(|h| h.icap_reqmod_client().cloned())
                .map(Arc::new)
        } else {
            None
        };

        FtpOverConnectBridge {
            server_config,
            server_stats,
            icap_client,
            idle_wheel,
            cc_info,
            task_logger,
            upstream_ip,
            task_notes,
        }
    }

    /// Relay a CONNECT tunnel carrying FTP traffic. Control channel
    /// traffic is passed through verbatim, except for PASV/EPSV
    /// responses (rewritten) and STOR/APPE/STOU commands that trigger
    /// an audited data channel.
    pub(crate) async fn relay<CR, CW, UR, UW>(
        &self,
        clt_r: CR,
        mut clt_w: CW,
        ups_r: UR,
        ups_w: UW,
    )
    where
        CR: AsyncRead + Send + Sync + Unpin + 'static,
        CW: AsyncWrite + Send + Sync + Unpin + 'static,
        UR: AsyncRead + Send + Sync + Unpin + 'static,
        UW: AsyncWrite + Send + Sync + Unpin + 'static,
    {
        // Forward the server greeting if it arrives before any command.
        let mut clt_reader = tokio::io::BufReader::new(clt_r);
        let mut ups_reader = ups_r;
        let mut ups_writer = ups_w;
        let mut clt_line: Vec<u8> = Vec::with_capacity(256);
        let mut pending_data: Option<(Arc<TcpListener>, SocketAddr)> = None;
        let mut ups_buf = vec![0u8; 2048];

        loop {
            clt_line.clear();

            tokio::select! {
                biased;

                n = clt_reader.read_until(b'\n', &mut clt_line) => {
                    match n {
                        Ok(0) => break,
                        Ok(_n) => {
                            if is_upload_command(&clt_line) {
                                // Forward the STOR/APPE upstream and wait for
                                // the "150 opening..." reply.
                                if ups_writer.write_all(&clt_line).await.is_err() {
                                    break;
                                }
                                if let Some(resp) = read_ftp_response(&mut ups_reader).await {
                                    let _ = clt_w.write_all(&resp).await;
                                }

                                // Drain the data channel through the audit pipeline.
                                if let Some((listener, ups_data_addr)) = pending_data.take() {
                                    let _ = self.process_upload(listener, ups_data_addr).await;
                                }

                                // Forward the "226 transfer complete..." reply.
                                if let Some(resp) = read_ftp_response(&mut ups_reader).await {
                                    let _ = clt_w.write_all(&resp).await;
                                }
                            } else if is_data_channel_command(&clt_line) {
                                // STOR/APPE/STOU/LIST/NLST/RETR all need the data channel.
                                // Forward the command and wait for the server's 150 reply.
                                if ups_writer.write_all(&clt_line).await.is_err() {
                                    break;
                                }
                                if let Some(resp) = read_ftp_response(&mut ups_reader).await {
                                    let _ = clt_w.write_all(&resp).await;
                                }

                                // Consume the pending listener and relay data.
                                if let Some((listener, ups_data_addr)) = pending_data.take() {
                                    if is_upload_command(&clt_line) {
                                        // Upload: client → server, audit-enabled path.
                                        let _ = self.process_upload(listener, ups_data_addr).await;
                                    } else {
                                        // Download/List: server → client, plain relay path.
                                        let _ = process_download(listener, ups_data_addr).await;
                                    }
                                }

                                // Forward the server's 226 "transfer complete" response.
                                if let Some(resp) = read_ftp_response(&mut ups_reader).await {
                                    let _ = clt_w.write_all(&resp).await;
                                }
                            } else if is_pasv_command(&clt_line) {
                                // Client requests passive mode: open a listener and rewrite
                                // the server's reply to point at us.
                                if pending_data.is_none() {
                                    if ups_writer.write_all(&clt_line).await.is_err() {
                                        break;
                                    }
                                    if let Some(resp_bytes) = read_ftp_response(&mut ups_reader).await {
                                        if let Some(ups_data_addr) = parse_pasv_response(&resp_bytes, self.upstream_ip) {
                                            let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
                                            if let Ok(listener) = TcpListener::bind(bind_addr).await {
                                                if let Ok(local_addr) = listener.local_addr() {
                                                    let rewritten = if is_epsv_command(&clt_line) {
                                                        // EPSV: keep the (|||port|) pipe format, just replace port.
                                                        rewrite_epsv_response(&resp_bytes, local_addr.port())
                                                    } else {
                                                        // PASV: replace with proxy IP + listener port.
                                                        let proxy_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, local_addr.port()));
                                                        rewrite_pasv_response(&resp_bytes, Some(proxy_addr))
                                                    };
                                                    let _ = clt_w.write_all(&rewritten).await;
                                                    pending_data = Some((Arc::new(listener), ups_data_addr));
                                                    continue;
                                                }
                                            }
                                        }
                                        // Fall through: forward the original response if anything failed.
                                        let _ = clt_w.write_all(&resp_bytes).await;
                                    }
                                    continue;
                                } else if ups_writer.write_all(&clt_line).await.is_err() {
                                    break;
                                }
                            } else if ups_writer.write_all(&clt_line).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }

                n = ups_reader.read(&mut ups_buf) => {
                    match n {
                        Ok(0) => break,
                        Ok(n) => {
                            if clt_w.write_all(&ups_buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    }

    async fn process_upload(&self, listener: Arc<TcpListener>, ups_data_addr: SocketAddr) {
        let (mut clt_conn, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => return,
        };

        let mut ups_conn = match TcpStream::connect(ups_data_addr).await {
            Ok(c) => c,
            Err(_) => return,
        };

        // Build audit context: use ICAP if available, else raw forward.
        let audit_ctx = self.icap_client.as_ref().map(|client| FtpUploadAuditContext {
            icap_client: client.clone(),
            idle_wheel: self.idle_wheel.clone(),
            copy_config: self.server_config.limited_copy_config(),
            client_addr: Some(self.cc_info.client_addr()),
            ftp_command: "STOR".to_string(),
            ftp_path: "ftp-over-connect".to_string(),
            data_channel_tuple: None,  // Not available in native FTP proxy mode
        });

        use std::time::Duration;
        let idle_wheel = IdleWheel::spawn(Duration::from_secs(1));
        let max_idle_count = 60;
        let _ = run_ftp_upload_audit_or_relay(&mut clt_conn, &mut ups_conn, &idle_wheel, max_idle_count, audit_ctx).await;
        let _ = ups_conn.shutdown().await;
    }
}

/// Download / directory-list data channel relay: server → client.
/// Used for LIST, NLST, RETR commands which read data from the FTP server.
async fn process_download(listener: Arc<TcpListener>, ups_data_addr: SocketAddr) {
    let (mut clt_conn, _) = match listener.accept().await {
        Ok(s) => s,
        Err(_) => return,
    };

    let mut ups_conn = match TcpStream::connect(ups_data_addr).await {
        Ok(c) => c,
        Err(_) => return,
    };

    // Server → client: copy all data from upstream to client.
    let _ = tokio::io::copy(&mut ups_conn, &mut clt_conn).await;
    let _ = clt_conn.shutdown().await;
}
