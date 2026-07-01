/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! FTP proxy task: native FTP control/data channel interception.
//!
//! The control channel is relayed verbatim with two special cases:
//!   * PASV / EPSV responses from upstream are rewritten to point at a
//!     local listener we open, so the data channel flows through us.
//!   * STOR / APPE / STOU triggers a data channel that is optionally
//!     audited via ICAP REQMOD before being forwarded upstream.

use std::net::Ipv4Addr;
use std::sync::Arc;

use slog::Logger;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use g3_daemon::stat::task::TcpStreamTaskStats;
use g3_daemon::server::ClientConnectionInfo;
use g3_openssl::SslConnector;
use g3_types::net::{OpensslClientConfig, UpstreamAddr};

use super::audit_bridge::{build_audit_context, run_ftp_upload_audit_or_relay};
use super::ctl_common::{
    is_data_channel_command, is_epsv_command, is_pasv_command, is_upload_command,
    parse_pasv_response, read_ftp_response, read_line_limited, rewrite_epsv_response,
    rewrite_pasv_response,
};
use super::stats::{FtpProxyServerStats, FtpProxyControlTaskAliveGuard};
use crate::audit::AuditContext;
use crate::config::server::ftp_proxy::{FtpProxyServerConfig, TlsUpstreamType};
use crate::escape::ArcEscaper;
use crate::module::tcp_connect::{TcpConnectTaskConf, TcpConnectTaskNotes, TlsConnectTaskConf};
use crate::serve::{ServerTaskError, ServerTaskNotes, ServerTaskStage};

pub(crate) struct CommonTaskContext {
    pub(crate) server_config: Arc<FtpProxyServerConfig>,
    pub(crate) server_stats: Arc<FtpProxyServerStats>,
    pub(crate) _server_quit_policy: Arc<g3_daemon::server::ServerQuitPolicy>,
    pub(crate) idle_wheel: Arc<g3_io_ext::IdleWheel>,
    pub(crate) escaper: ArcEscaper,
    pub(crate) cc_info: ClientConnectionInfo,
    pub(crate) _task_logger: Option<Logger>,
    pub(crate) icap_client: Option<Arc<g3_icap_client::reqmod::IcapReqmodClient>>,
    pub(crate) tls_upstream_config: Option<Arc<OpensslClientConfig>>,
    pub(crate) tls_upstream_type: TlsUpstreamType,
}

struct PendingDataChannel {
    listener: Arc<tokio::net::TcpListener>,
    upstream_data_addr: std::net::SocketAddr,
}

pub(crate) struct FtpProxyTask {
    ctx: CommonTaskContext,
    upstream: UpstreamAddr,
    tcp_notes: TcpConnectTaskNotes,
    task_notes: ServerTaskNotes,
    task_stats: Arc<TcpStreamTaskStats>,
    _audit_ctx: AuditContext,
    _task_guard: FtpProxyControlTaskAliveGuard,
    max_idle_count: usize,
    /// Upstream FTP server IPv4 address, resolved after TCP connection.
    /// Used to resolve EPSV ports (EPSV returns only port; IP from 4-tuple).
    upstream_ip: std::net::Ipv4Addr,
    started: bool,
}

impl Drop for FtpProxyTask {
    fn drop(&mut self) {
        if self.started {
            // mirrors other proxy tasks
        }
    }
}

impl FtpProxyTask {
    pub(crate) fn new(
        server_config: Arc<FtpProxyServerConfig>,
        server_stats: Arc<FtpProxyServerStats>,
        server_quit_policy: Arc<g3_daemon::server::ServerQuitPolicy>,
        idle_wheel: Arc<g3_io_ext::IdleWheel>,
        escaper: ArcEscaper,
        cc_info: ClientConnectionInfo,
        upstream: UpstreamAddr,
        audit_ctx: AuditContext,
        task_logger: Option<Logger>,
        tls_upstream_config: Option<Arc<OpensslClientConfig>>,
        tls_upstream_type: TlsUpstreamType,
    ) -> Self {
        let icap_client = if server_config.audit_upload {
            audit_ctx
                .handle()
                .and_then(|h| h.icap_reqmod_client().cloned())
                .map(Arc::new)
        } else {
            None
        };

        let task_notes = ServerTaskNotes::new(cc_info.clone(), None, std::time::Duration::ZERO);
        let task_stats = Arc::new(TcpStreamTaskStats::default());
        let task_guard = server_stats.add_control_task();
        let max_idle_count = server_config.task_idle_max_count;

        FtpProxyTask {
            ctx: CommonTaskContext {
                server_config,
                server_stats,
                _server_quit_policy: server_quit_policy,
                idle_wheel,
                escaper,
                cc_info,
                _task_logger: task_logger,
                icap_client,
                tls_upstream_config,
                tls_upstream_type,
            },
            upstream,
            tcp_notes: TcpConnectTaskNotes::default(),
            task_notes,
            task_stats,
            _audit_ctx: audit_ctx,
            _task_guard: task_guard,
            max_idle_count,
            upstream_ip: std::net::Ipv4Addr::UNSPECIFIED,
            started: false,
        }
    }

    pub(crate) async fn into_running<CR, CW>(mut self, clt_r: CR, clt_w: CW)
    where
        CR: AsyncRead + Send + Sync + Unpin + 'static,
        CW: AsyncWrite + Send + Sync + Unpin + 'static,
    {
        self.started = true;
        self.task_notes.stage = ServerTaskStage::Connecting;

        // Resolve the upstream FTP server IPv4 from tcp_notes.
        // This is needed for EPSV port resolution (EPSV returns port only;
        // the IP is inherited from the control TCP 4-tuple).
        let upstream_ip = self.tcp_notes.next.and_then(|next| {
            if let std::net::SocketAddr::V4(v4) = next {
                Some(*v4.ip())
            } else {
                None
            }
        });

        // Open the upstream control channel. On failure we silently return —
        // the client will see the connection reset.
        let (ups_r, ups_w) = match self.connect_upstream().await {
            Some(conn) => conn,
            None => return,
        };

        self.upstream_ip = upstream_ip.unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);

        self.task_notes.stage = ServerTaskStage::Relaying;
        let _ = self.relay_control(clt_r, clt_w, ups_r, ups_w).await;
    }

    /// Connect to upstream FTP server based on tls_upstream_type.
    /// Returns boxed trait objects to avoid lifetime issues with different stream types.
    async fn connect_upstream(
        &mut self,
    ) -> Option<(
        Box<dyn tokio::io::AsyncRead + Send + Sync + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Sync + Unpin>,
    )> {
        match self.ctx.tls_upstream_type {
            TlsUpstreamType::PlainFtp => self.connect_plain_ftp().await,
            TlsUpstreamType::ExplicitFtps => self.connect_explicit_ftps().await,
            TlsUpstreamType::ImplicitFtps => self.connect_implicit_ftps().await,
        }
    }

    /// Connect to upstream using plain TCP.
    async fn connect_plain_ftp(
        &mut self,
    ) -> Option<(
        Box<dyn tokio::io::AsyncRead + Send + Sync + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Sync + Unpin>,
    )> {
        let task_conf = TcpConnectTaskConf {
            upstream: &self.upstream,
        };

        let conn = self
            .ctx
            .escaper
            .tcp_setup_connection(
                &task_conf,
                &mut self.tcp_notes,
                &self.task_notes,
                self.task_stats.clone(),
                &mut self._audit_ctx,
            )
            .await
            .ok()?;

        Some(conn)
    }

    /// Connect to upstream using implicit FTPS (direct TLS connection).
    async fn connect_implicit_ftps(
        &mut self,
    ) -> Option<(
        Box<dyn tokio::io::AsyncRead + Send + Sync + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Sync + Unpin>,
    )> {
        let tls_config = self.ctx.tls_upstream_config.as_ref()?;
        let tls_name = self.upstream.host();
        let task_conf = TlsConnectTaskConf {
            tcp: TcpConnectTaskConf {
                upstream: &self.upstream,
            },
            tls_config,
            tls_name,
        };

        let conn = self
            .ctx
            .escaper
            .tls_setup_connection(
                &task_conf,
                &mut self.tcp_notes,
                &self.task_notes,
                self.task_stats.clone(),
                &mut self._audit_ctx,
            )
            .await
            .ok()?;

        // tls_setup_connection returns already split streams (Box<dyn AsyncRead>, Box<dyn AsyncWrite>)
        Some(conn)
    }

    /// Connect to upstream using explicit FTPS (AUTH TLS handshake).
    /// For explicit FTPS, we need to bypass the escaper's stream splitting
    /// because we need to send AUTH TLS before TLS handshake.
    async fn connect_explicit_ftps(
        &mut self,
    ) -> Option<(
        Box<dyn tokio::io::AsyncRead + Send + Sync + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Sync + Unpin>,
    )> {
        let tls_config = self.ctx.tls_upstream_config.as_ref()?;
        let upstream = &self.upstream;

        // Step 1: Resolve hostname and connect to upstream port 21 (plain TCP)
        // For explicit FTPS, we need a single stream to send AUTH TLS
        let port = upstream.port();
        let host_str = upstream.host_str();
        let addr = tokio::net::lookup_host((host_str.as_ref(), port))
            .await
            .ok()?
            .next()?;
        let mut tcp_stream = tokio::net::TcpStream::connect(addr).await.ok()?;

        // Step 2: Read server greeting
        let _ = read_ftp_response(&mut tcp_stream).await;

        // Step 3: Send AUTH TLS command
        tcp_stream
            .write_all(b"AUTH TLS\r\n")
            .await
            .ok()?;

        // Step 4: Read response - expect 234 (Ready for TLS)
        let resp = read_ftp_response(&mut tcp_stream).await?;
        if !resp.starts_with(b"234 ") {
            // Not a 234 response, TLS negotiation not accepted
            return None;
        }

        // Step 5: Perform TLS handshake
        let tls_name = upstream.host();
        let ssl = tls_config.build_ssl(tls_name, port).ok()?;
        let ssl_connector = SslConnector::new(ssl, tcp_stream).ok()?;
        let ssl_stream = ssl_connector.connect().await.ok()?;

        // Step 6: Split the SSL stream for relay
        let (ups_r, ups_w) = tokio::io::split(ssl_stream);
        Some((Box::new(ups_r), Box::new(ups_w)))
    }

    /// Relay the FTP control channel between client and upstream.
    async fn relay_control<CR, CW, UR, UW>(
        &mut self,
        clt_r: CR,
        mut clt_w: CW,
        mut ups_r: UR,
        mut ups_w: UW,
    ) -> Result<(), ServerTaskError>
    where
        CR: AsyncRead + Send + Sync + Unpin + 'static,
        CW: AsyncWrite + Send + Sync + Unpin + 'static,
        UR: AsyncRead + Send + Sync + Unpin + 'static,
        UW: AsyncWrite + Send + Sync + Unpin + 'static,
    {
        // Forward server greeting (220) if it arrives quickly.
        if let Some(greeting) = read_ftp_response(&mut ups_r).await {
            self.ctx.server_stats.add_control_out_bytes(greeting.len() as u64);
            let _ = clt_w.write_all(&greeting).await;
        }

        let mut clt_reader = tokio::io::BufReader::new(clt_r);
        let mut clt_line: Vec<u8> = Vec::with_capacity(256);
        let mut idle_interval = self.ctx.idle_wheel.register();
        let mut idle_count: usize = 0;
        let mut pending_data: Option<PendingDataChannel> = None;
        let mut ups_buf = vec![0u8; 2048];

        loop {
            clt_line.clear();

            tokio::select! {
                biased;

                n = read_line_limited(&mut clt_reader, &mut clt_line) => {
                    match n {
                        Ok(0) => return Ok(()),
                        Ok(n) => {
                            self.ctx.server_stats.add_control_in_bytes(n as u64);
                            idle_count = 0;

                            if is_upload_command(&clt_line) {
                                if ups_w.write_all(&clt_line).await.is_err() {
                                    return Ok(());
                                }
                                handle_upload_data_channel(
                                    &mut clt_w,
                                    &mut ups_r,
                                    &self.ctx,
                                    self.max_idle_count,
                                    pending_data.take(),
                                    &clt_line,
                                ).await;
                                continue;
                            } else if is_data_channel_command(&clt_line) {
                                // LIST / NLST / RETR: need data channel, server → client direction.
                                if ups_w.write_all(&clt_line).await.is_err() {
                                    return Ok(());
                                }
                                // Forward the server's 150/125 "starting data connection" response.
                                if let Some(resp) = read_ftp_response(&mut ups_r).await {
                                    let _ = clt_w.write_all(&resp).await;
                                }
                                if let Some(pending) = pending_data.take() {
                                    handle_download_data_channel(
                                        pending,
                                        self.ctx.idle_wheel.clone(),
                                        self.max_idle_count,
                                    ).await;
                                }
                                // Forward the server's 226 "transfer complete" response.
                                if let Some(resp) = read_ftp_response(&mut ups_r).await {
                                    let _ = clt_w.write_all(&resp).await;
                                }
                                continue;
                            } else if is_pasv_command(&clt_line) {
                                if pending_data.is_none() {
                                    if ups_w.write_all(&clt_line).await.is_err() {
                                        return Ok(());
                                    }
                                    if let Some(resp_bytes) = read_ftp_response(&mut ups_r).await {
                                        if let Some(ups_data_addr) = parse_pasv_response(&resp_bytes, self.upstream_ip) {
                                            if let Some(listener) = open_local_data_listener().await {
                                                let rewritten = if is_epsv_command(&clt_line) {
                                                    // EPSV: keep (|||port|) format, just rewrite port.
                                                    rewrite_epsv_response(&resp_bytes, listener.local_addr().map(|a| a.port()).unwrap_or(0))
                                                } else {
                                                    // PASV: rewrite with proxy IP + listener port.
                                                    let proxy_addr = std::net::SocketAddr::V4(
                                                        std::net::SocketAddrV4::new(
                                                            Ipv4Addr::LOCALHOST,
                                                            listener.local_addr().map(|a| a.port()).unwrap_or(0),
                                                        ),
                                                    );
                                                    rewrite_pasv_response(&resp_bytes, Some(proxy_addr))
                                                };
                                                let _ = clt_w.write_all(&rewritten).await;
                                                pending_data = Some(PendingDataChannel {
                                                    listener: Arc::new(listener),
                                                    upstream_data_addr: ups_data_addr,
                                                });
                                                continue;
                                            }
                                        }
                                        let _ = clt_w.write_all(&resp_bytes).await;
                                    }
                                    continue;
                                } else if ups_w.write_all(&clt_line).await.is_err() {
                                    return Ok(());
                                }
                            } else if ups_w.write_all(&clt_line).await.is_err() {
                                return Ok(());
                            }
                        }
                        Err(_) => return Ok(()),
                    }
                }

                n = ups_r.read(&mut ups_buf) => {
                    match n {
                        Ok(0) => return Ok(()),
                        Ok(n) => {
                            self.ctx.server_stats.add_control_out_bytes(n as u64);
                            if clt_w.write_all(&ups_buf[..n]).await.is_err() {
                                return Ok(());
                            }
                        }
                        Err(_) => return Ok(()),
                    }
                }

                _ = idle_interval.tick() => {
                    idle_count += 1;
                    if idle_count >= self.max_idle_count {
                        return Ok(());
                    }
                    if self.ctx._server_quit_policy.force_quit() {
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Opens a local listener on a random ephemeral port for the data channel.
async fn open_local_data_listener() -> Option<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind("0.0.0.0:0").await.ok()
}

/// Extracts the FTP command (STOR / APPE / STOU) and the path from a client
/// command line. Used to forward rich metadata to the ICAP adapter.
fn extract_cmd_path(line: &[u8]) -> (String, String) {
    let trimmed: Vec<u8> = line
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace() || *b != b'\r' && *b != b'\n')
        .collect();
    let mut parts = trimmed.splitn(2, |b| *b == b' ');
    let cmd = parts
        .next()
        .map(|s| String::from_utf8_lossy(s).to_string())
        .unwrap_or_else(|| "STOR".to_string());
    let path = parts
        .next()
        .map(|s| String::from_utf8_lossy(s).trim().to_string())
        .unwrap_or_default();
    (cmd, path)
}

/// Intercept an upload data channel: accept the client's PASV connection,
/// optionally audit the bytes through ICAP, and forward everything upstream.
async fn handle_upload_data_channel<CW, UR>(
    clt_w: &mut CW,
    ups_r: &mut UR,
    ctx: &CommonTaskContext,
    max_idle_count: usize,
    pending: Option<PendingDataChannel>,
    upload_cmd: &[u8],
) where
    CW: AsyncWrite + Send + Sync + Unpin,
    UR: AsyncRead + Send + Sync + Unpin,
{
    let Some(pdc) = pending else { return };

    let (cmd, path) = extract_cmd_path(upload_cmd);

    let (mut clt_conn, clt_addr) = match pdc.listener.accept().await {
        Ok(s) => s,
        Err(_) => return,
    };

    let mut ups_conn = match tokio::net::TcpStream::connect(pdc.upstream_data_addr).await {
        Ok(s) => s,
        Err(_) => return,
    };

    let server_addr = match ups_conn.local_addr() {
        Ok(a) => a,
        Err(_) => pdc.upstream_data_addr,
    };
    let data_tuple = g3_icap_client::reqmod::ConnectionTuple {
        server_addr: clt_addr,
        remote_addr: server_addr,
        protocol: g3_icap_client::reqmod::ConnectionProtocol::Tcp,
    };

    let audit_ctx = build_audit_context(ctx, &cmd, &path, Some(data_tuple), None);

    let _ = run_ftp_upload_audit_or_relay(
        &mut clt_conn,
        &mut ups_conn,
        &ctx.idle_wheel,
        max_idle_count,
        audit_ctx,
    ).await;

    let _ = ups_conn.shutdown().await;
    let _ = clt_conn.shutdown().await;

    if let Some(final_resp) = read_ftp_response(ups_r).await {
        let _ = clt_w.write_all(&final_resp).await;
    }
}

/// Handle a download data channel: accept the client's PASV connection,
/// and relay data from the upstream FTP server to the client.
/// Used for LIST, NLST, RETR commands.
async fn handle_download_data_channel(
    pending: PendingDataChannel,
    idle_wheel: Arc<g3_io_ext::IdleWheel>,
    max_idle_count: usize,
) {
    let (mut clt_conn, _) = match pending.listener.accept().await {
        Ok(s) => s,
        Err(_) => return,
    };

    let mut ups_conn = match tokio::net::TcpStream::connect(pending.upstream_data_addr).await {
        Ok(s) => s,
        Err(_) => return,
    };

    let mut idle_interval = idle_wheel.register();
    let mut idle_count = 0usize;
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        tokio::select! {
            biased;

            res = ups_conn.read(&mut buf) => {
                match res {
                    Ok(0) => break,
                    Ok(n) => {
                        idle_count = 0;
                        if clt_conn.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
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
    let _ = clt_conn.flush().await;
    let _ = clt_conn.shutdown().await;
    let _ = ups_conn.shutdown().await;
}
