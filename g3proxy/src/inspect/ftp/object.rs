/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! FTP protocol inspection for HTTP CONNECT tunnel mode.
//!
//! This module handles FTP control channel inspection in HTTP CONNECT mode.
//! Upload commands (STOR/APPE) are detected and marked in global state
//! for ICAP audit in the subsequent data channel connection.

use std::time::Duration;

use anyhow::anyhow;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

use g3_daemon::server::ServerQuitPolicy;
use g3_dpi::ProtocolInspectAction;
use g3_io_ext::{IdleInterval, OnceBufReader, StreamCopyConfig};
use g3_slog_types::{LtUpstreamAddr, LtUuid};
use g3_types::net::UpstreamAddr;

use crate::config::server::ServerConfig;
use crate::inspect::{
    BoxAsyncRead, BoxAsyncWrite, StartTlsProtocol, StreamInspectContext, StreamInspection,
    StreamTransitTask,
};
use crate::log::task::TaskEvent;
use crate::serve::ftp_proxy::ctl_common::{is_auth_tls_command, is_upload_command, read_ftp_response};
use crate::serve::ftp_proxy::upload_state::get_ftp_upload_state;
use crate::serve::{ServerTaskError, ServerTaskResult};

macro_rules! intercept_log {
    ($obj:tt, $($args:tt)+) => {
        if let Some(logger) = $obj.ctx.intercept_logger() {
            slog::info!(logger, $($args)+;
                "intercept_type" => "FtpConnection",
                "task_id" => LtUuid($obj.ctx.server_task_id()),
                "depth" => $obj.ctx.inspection_depth,
                "upstream" => LtUpstreamAddr(&$obj.upstream),
            );
        }
    };
}

struct FtpIo {
    pub(crate) clt_r: BoxAsyncRead,
    pub(crate) clt_w: BoxAsyncWrite,
    pub(crate) ups_r: OnceBufReader<BoxAsyncRead>,
    pub(crate) ups_w: BoxAsyncWrite,
}

pub(crate) struct FtpInterceptObject<SC: ServerConfig> {
    io: Option<FtpIo>,
    ctx: StreamInspectContext<SC>,
    upstream: UpstreamAddr,
    /// Whether this connection comes from a TLS interception (FTPS MITM)
    from_starttls: bool,
}

enum FtpNextAction {
    StartTls {
        clt_r: BoxAsyncRead,
        clt_w: BoxAsyncWrite,
        ups_r: OnceBufReader<BoxAsyncRead>,
        ups_w: BoxAsyncWrite,
    },
    Finish,
}

impl<SC: ServerConfig> FtpInterceptObject<SC> {
    pub(crate) fn new(ctx: StreamInspectContext<SC>, upstream: UpstreamAddr) -> Self {
        FtpInterceptObject {
            io: None,
            ctx,
            upstream,
            from_starttls: false,
        }
    }

    pub(crate) fn set_from_starttls(&mut self) {
        self.from_starttls = true;
    }

    pub(crate) fn set_io(
        &mut self,
        clt_r: BoxAsyncRead,
        clt_w: BoxAsyncWrite,
        ups_r: OnceBufReader<BoxAsyncRead>,
        ups_w: BoxAsyncWrite,
    ) {
        let io = FtpIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        };
        self.io = Some(io);
    }

    fn log_partial_shutdown(&self, task_event: TaskEvent) {
        if let Some(logger) = self.ctx.intercept_logger() {
            slog::info!(logger, "";
                "intercept_type" => "FtpConnection",
                "task_id" => LtUuid(self.ctx.server_task_id()),
                "task_event" => task_event.as_str(),
                "depth" => self.ctx.inspection_depth,
                "upstream" => LtUpstreamAddr(&self.upstream),
            );
        }
    }

    fn ftp_inspect_action(&self) -> ProtocolInspectAction {
        ProtocolInspectAction::Intercept
    }
}

impl<SC: ServerConfig> StreamTransitTask for FtpInterceptObject<SC> {
    fn copy_config(&self) -> StreamCopyConfig {
        self.ctx.server_config.limited_copy_config()
    }

    fn idle_check_interval(&self) -> IdleInterval {
        self.ctx.idle_wheel.register()
    }

    fn max_idle_count(&self) -> usize {
        self.ctx.max_idle_count
    }

    fn log_client_shutdown(&self) {
        self.log_partial_shutdown(TaskEvent::ClientShutdown)
    }

    fn log_upstream_shutdown(&self) {
        self.log_partial_shutdown(TaskEvent::UpstreamShutdown)
    }

    fn log_periodic(&self) {
        // TODO
    }

    fn log_flush_interval(&self) -> Option<Duration> {
        self.ctx.server_config.task_log_flush_interval()
    }

    fn quit_policy(&self) -> &ServerQuitPolicy {
        self.ctx.server_quit_policy.as_ref()
    }

    fn user(&self) -> Option<&crate::auth::User> {
        self.ctx.user()
    }
}

impl<SC> FtpInterceptObject<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    pub(crate) async fn intercept(mut self) -> ServerTaskResult<Option<StreamInspection<SC>>> {
        let r = match self.ftp_inspect_action() {
            ProtocolInspectAction::Intercept => self.do_intercept().await,
            ProtocolInspectAction::Bypass => self.do_bypass().await.map(|_| None),
            ProtocolInspectAction::Block => self.do_block().await.map(|_| None),
            #[cfg(feature = "quic")]
            ProtocolInspectAction::Detour => self.do_detour().await.map(|_| None),
        };
        match r {
            Ok(obj) => {
                intercept_log!(self, "finished");
                Ok(obj)
            }
            Err(e) => {
                intercept_log!(self, "{e}");
                Err(e)
            }
        }
    }

    async fn do_bypass(&mut self) -> ServerTaskResult<()> {
        let FtpIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        } = self.io.take().unwrap();

        self.transit_transparent(clt_r, clt_w, ups_r, ups_w).await
    }

    async fn do_block(&mut self) -> ServerTaskResult<()> {
        let FtpIo {
            clt_r: _,
            mut clt_w,
            ups_r: _,
            mut ups_w,
        } = self.io.take().unwrap();

        tokio::spawn(async move {
            let _ = ups_w.shutdown().await;
        });

        clt_w
            .write_all(b"421 Service not available\r\n")
            .await
            .map_err(ServerTaskError::ClientTcpWriteFailed)?;
        clt_w
            .shutdown()
            .await
            .map_err(ServerTaskError::ClientTcpWriteFailed)?;
        Err(ServerTaskError::InternalAdapterError(
            anyhow!("ftp blocked by inspection policy"),
        ))
    }

    #[cfg(feature = "quic")]
    async fn do_detour(&mut self) -> ServerTaskResult<()> {
        self.do_bypass().await
    }

    async fn do_intercept(&mut self) -> ServerTaskResult<Option<StreamInspection<SC>>> {
        let FtpIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        } = self.io.take().unwrap();

        match self.relay_control_channel(clt_r, clt_w, ups_r, ups_w).await? {
            FtpNextAction::Finish => Ok(None),
            FtpNextAction::StartTls {
                clt_r,
                clt_w,
                ups_r,
                ups_w,
            } => {
                if let Some(tls_interception) = self.ctx.tls_interception() {
                    let mut start_tls_obj =
                        crate::inspect::start_tls::StartTlsInterceptObject::new(
                            self.ctx.clone(),
                            self.upstream.clone(),
                            tls_interception,
                            StartTlsProtocol::Ftp,
                        );
                    start_tls_obj.set_io(clt_r, clt_w, Box::new(ups_r), ups_w);
                    Ok(Some(StreamInspection::StartTls(start_tls_obj)))
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Relay the FTP control channel through an HTTP CONNECT tunnel.
    /// Handles upload commands (STOR/APPE) by marking them for ICAP audit.
    ///
    /// Key differences from native FTP proxy:
    /// - No PASV response rewriting (client connects directly to FTP server)
    /// - Upload commands are marked in global state for data channel detection
    async fn relay_control_channel(
        &self,
        clt_r: BoxAsyncRead,
        mut clt_w: BoxAsyncWrite,
        ups_r: OnceBufReader<BoxAsyncRead>,
        ups_w: BoxAsyncWrite,
    ) -> ServerTaskResult<FtpNextAction> {
        let mut clt_reader = tokio::io::BufReader::new(clt_r);
        let mut ups_reader = ups_r;
        let mut ups_writer = ups_w;
        let mut clt_line: Vec<u8> = Vec::with_capacity(256);
        let mut ups_buf = vec![0u8; 2048];

        const MAX_LINE_LENGTH: usize = 8192;

        let client_ip = self.ctx.task_notes.client_addr.ip();
        let ftp_server_ip = self.ctx.connect_notes.server_addr.ip();

        let mut idle_interval = self.idle_check_interval();
        let mut idle_count = 0usize;
        let max_idle_count = self
            .user()
            .and_then(|u| u.task_max_idle_count())
            .unwrap_or(self.max_idle_count());

        loop {
            clt_line.clear();

            tokio::select! {
                biased;

                n = Self::read_line_limited(&mut clt_reader, &mut clt_line, MAX_LINE_LENGTH) => {
                    match n {
                        Ok(0) => break,
                        Ok(_n) => {
                            idle_count = 0;

                            if is_upload_command(&clt_line) {
                                let cmd_str = std::str::from_utf8(&clt_line)
                                    .map(str::trim)
                                    .unwrap_or("");
                                let mut parts = cmd_str.split_whitespace();
                                let cmd_name = parts.next().unwrap_or("STOR").to_string();
                                let ftp_path = parts.next().unwrap_or("").to_string();

                                get_ftp_upload_state().mark_upload(
                                    client_ip,
                                    ftp_server_ip,
                                    &cmd_name,
                                    &ftp_path,
                                    0,
                                );

                                if ups_writer.write_all(&clt_line).await.is_err() {
                                    break;
                                }
                            } else if is_auth_tls_command(&clt_line) {
                                if ups_writer.write_all(&clt_line).await.is_err() {
                                    break;
                                }
                                if let Some(resp) = read_ftp_response(&mut ups_reader).await {
                                    let _ = clt_w.write_all(&resp).await;
                                    if resp.starts_with(b"234") {
                                        let clt_r = clt_reader.into_inner();
                                        let ups_r = ups_reader;
                                        let ups_w = ups_writer;
                                        return Ok(FtpNextAction::StartTls {
                                            clt_r,
                                            clt_w,
                                            ups_r,
                                            ups_w,
                                        });
                                    }
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
                            idle_count = 0;
                            if clt_w.write_all(&ups_buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }

                _ = idle_interval.tick() => {
                    idle_count += 1;

                    if let Some(user) = self.user() {
                        if user.is_blocked() {
                            return Err(ServerTaskError::CanceledAsUserBlocked);
                        }
                    }

                    if idle_count >= max_idle_count {
                        return Err(ServerTaskError::Idle(idle_interval.period(), idle_count));
                    }

                    if self.quit_policy().force_quit() {
                        return Err(ServerTaskError::CanceledAsServerQuit)
                    }
                }
            }
        }

        Ok(FtpNextAction::Finish)
    }

    async fn read_line_limited<R>(
        reader: &mut R,
        buf: &mut Vec<u8>,
        max_len: usize,
    ) -> Result<usize, std::io::Error>
    where
        R: tokio::io::AsyncBufRead + Unpin,
    {
        let mut total = 0usize;
        loop {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                return Ok(total);
            }

            if let Some(pos) = available.iter().position(|&b| b == b'\n') {
                let take = pos + 1;
                if total + take > max_len {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "FTP line too long",
                    ));
                }
                buf.extend_from_slice(&available[..take]);
                reader.consume(take);
                return Ok(total + take);
            }

            let avail_len = available.len();
            if total + avail_len > max_len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "FTP line too long",
                ));
            }
            buf.extend_from_slice(available);
            reader.consume(avail_len);
            total += avail_len;
        }
    }
}