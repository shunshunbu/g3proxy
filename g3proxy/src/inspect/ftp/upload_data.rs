/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! FTP upload data channel interception for ICAP audit.
//!
//! This module handles FTPS upload data channels after TLS interception.
//! When a data channel is identified as an upload (after STOR/APPE command),
//! it triggers ICAP audit on the decrypted data.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use g3_icap_client::reqmod::{ConnectionProtocol, ConnectionTuple};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::server::ServerConfig;
use crate::inspect::{BoxAsyncRead, BoxAsyncWrite, StreamInspectContext};
use crate::serve::ftp_proxy::audit_bridge::{
    FtpUploadAuditContext, run_ftp_upload_audit_or_relay_bidi,
};
use crate::serve::ftp_proxy::upload_state::{get_ftp_upload_state, PendingUploadInfo};
use crate::serve::{ServerTaskError, ServerTaskResult};

struct FtpUploadDataIo {
    clt_r: BoxAsyncRead,
    clt_w: BoxAsyncWrite,
    ups_r: BoxAsyncRead,
    ups_w: BoxAsyncWrite,
}

pub(crate) struct FtpUploadDataInterceptObject<SC: ServerConfig> {
    io: Option<FtpUploadDataIo>,
    ctx: StreamInspectContext<SC>,
    upload_info: Option<PendingUploadInfo>,
    data_channel_tuple: Option<ConnectionTuple>,
}

impl<SC: ServerConfig> FtpUploadDataInterceptObject<SC> {
    pub(crate) fn new(
        ctx: StreamInspectContext<SC>,
        upload_info: PendingUploadInfo,
        data_channel_tuple: Option<ConnectionTuple>,
    ) -> Self {
        FtpUploadDataInterceptObject {
            io: None,
            ctx,
            upload_info: Some(upload_info),
            data_channel_tuple,
        }
    }

    pub(crate) fn set_io(
        &mut self,
        clt_r: BoxAsyncRead,
        clt_w: BoxAsyncWrite,
        ups_r: BoxAsyncRead,
        ups_w: BoxAsyncWrite,
    ) {
        let io = FtpUploadDataIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        };
        self.io = Some(io);
    }
}

impl<SC> FtpUploadDataInterceptObject<SC>
where
    SC: ServerConfig + Send + Sync + 'static,
{
    pub(crate) async fn intercept(mut self) -> crate::serve::ServerTaskResult<()> {
        let io = match self.io.take() {
            Some(io) => io,
            None => return Ok(()),
        };

        let upload_info = match self.upload_info.take() {
            Some(info) => info,
            None => return Self::intercept_pending(self.ctx, io).await,
        };

        let icap_client = match self.ctx.audit_handle.icap_reqmod_client().cloned() {
            Some(client) => Arc::new(client),
            None => {
                let _ = run_ftp_upload_audit_or_relay_bidi(
                    io.clt_r, io.clt_w, io.ups_r, io.ups_w,
                    self.ctx.idle_wheel.clone(),
                    self.ctx.max_idle_count,
                    None,
                ).await;
                return Ok(());
            }
        };

        let audit_ctx = FtpUploadAuditContext {
            icap_client,
            idle_wheel: self.ctx.idle_wheel.clone(),
            copy_config: self.ctx.server_config.limited_copy_config(),
            client_addr: Some(self.ctx.task_notes.client_addr),
            ftp_command: upload_info.ftp_command,
            ftp_path: upload_info.ftp_path,
            data_channel_tuple: self.data_channel_tuple,
        };

        let _ = run_ftp_upload_audit_or_relay_bidi(
            io.clt_r,
            io.clt_w,
            io.ups_r,
            io.ups_w,
            self.ctx.idle_wheel.clone(),
            self.ctx.max_idle_count,
            Some(audit_ctx),
        ).await;

        Ok(())
    }

    async fn intercept_pending(
        ctx: StreamInspectContext<SC>,
        io: FtpUploadDataIo,
    ) -> ServerTaskResult<()> {
        let FtpUploadDataIo {
            clt_r,
            clt_w,
            ups_r,
            ups_w,
        } = io;

        let mut clt_r = clt_r;
        let mut clt_w = clt_w;
        let mut ups_r = ups_r;
        let mut ups_w = ups_w;

        let mut clt_buf = vec![0u8; 4096];
        let mut ups_buf = vec![0u8; 4096];

        let mut idle_interval = ctx.idle_wheel.register();
        let mut idle_count = 0usize;
        let max_idle_count = ctx.max_idle_count;

        loop {
            tokio::select! {
                biased;

                res = clt_r.read(&mut clt_buf) => {
                    match res {
                        Ok(0) => {
                            let _ = ups_w.shutdown().await;
                            let _ = tokio::time::timeout(
                                tokio::time::Duration::from_secs(5),
                                Self::drain_and_close_half(&mut ups_r, &mut clt_w),
                            ).await;
                            let _ = clt_w.shutdown().await;
                            break;
                        }
                        Ok(n) => {
                            if let Some(upload_info) = check_ftp_upload_data(
                                ctx.task_notes.client_addr,
                                ctx.connect_notes.server_addr,
                            ) {
                                let icap_client = match ctx.audit_handle.icap_reqmod_client().cloned() {
                                    Some(client) => Arc::new(client),
                                    None => {
                                        let _ = ups_w.write_all(&clt_buf[..n]).await;
                                        let _ = run_ftp_upload_audit_or_relay_bidi(
                                            clt_r, clt_w, ups_r, ups_w,
                                            ctx.idle_wheel.clone(),
                                            ctx.max_idle_count,
                                            None,
                                        ).await;
                                        break;
                                    }
                                };

                                let data_channel_tuple = ConnectionTuple {
                                    server_addr: ctx.task_notes.client_addr,
                                    remote_addr: ctx.connect_notes.server_addr,
                                    protocol: ConnectionProtocol::Tcp,
                                };

                                let audit_ctx = FtpUploadAuditContext {
                                    icap_client,
                                    idle_wheel: ctx.idle_wheel.clone(),
                                    copy_config: ctx.server_config.limited_copy_config(),
                                    client_addr: Some(ctx.task_notes.client_addr),
                                    ftp_command: upload_info.ftp_command,
                                    ftp_path: upload_info.ftp_path,
                                    data_channel_tuple: Some(data_channel_tuple),
                                };

                                let clt_r = io::Cursor::new(clt_buf[..n].to_vec()).chain(clt_r);
                                let _ = run_ftp_upload_audit_or_relay_bidi(
                                    Box::new(clt_r),
                                    clt_w,
                                    ups_r,
                                    ups_w,
                                    ctx.idle_wheel.clone(),
                                    ctx.max_idle_count,
                                    Some(audit_ctx),
                                ).await;
                            } else {
                                let _ = ups_w.write_all(&clt_buf[..n]).await;
                                let _ = run_ftp_upload_audit_or_relay_bidi(
                                    clt_r, clt_w, ups_r, ups_w,
                                    ctx.idle_wheel.clone(),
                                    ctx.max_idle_count,
                                    None,
                                ).await;
                            }
                            break;
                        }
                        Err(_) => {
                            let _ = ups_w.shutdown().await;
                            let _ = clt_w.shutdown().await;
                            break;
                        }
                    }
                }

                res = ups_r.read(&mut ups_buf) => {
                    match res {
                        Ok(0) => {
                            let _ = clt_w.shutdown().await;
                            let _ = tokio::time::timeout(
                                tokio::time::Duration::from_secs(5),
                                Self::drain_and_close_half(&mut clt_r, &mut ups_w),
                            ).await;
                            let _ = ups_w.shutdown().await;
                            break;
                        }
                        Ok(n) => {
                            let ups_r = io::Cursor::new(ups_buf[..n].to_vec()).chain(ups_r);
                            let _ = run_ftp_upload_audit_or_relay_bidi(
                                clt_r,
                                clt_w,
                                Box::new(ups_r),
                                ups_w,
                                ctx.idle_wheel.clone(),
                                ctx.max_idle_count,
                                None,
                            ).await;
                            break;
                        }
                        Err(_) => {
                            let _ = clt_w.shutdown().await;
                            let _ = ups_w.shutdown().await;
                            break;
                        }
                    }
                }

                _ = idle_interval.tick() => {
                    idle_count += 1;

                    if idle_count >= max_idle_count {
                        let _ = clt_w.shutdown().await;
                        let _ = ups_w.shutdown().await;
                        return Err(ServerTaskError::Idle(idle_interval.period(), idle_count));
                    }

                    if ctx.server_quit_policy.force_quit() {
                        let _ = clt_w.shutdown().await;
                        let _ = ups_w.shutdown().await;
                        return Err(ServerTaskError::CanceledAsServerQuit);
                    }
                }
            }
        }

        Ok(())
    }

    async fn drain_and_close_half<R, W>(r: &mut R, w: &mut W)
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let mut buf = vec![0u8; 8192];
        loop {
            match r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = w.flush().await;
    }
}

pub(crate) fn check_ftp_upload_data(
    client_addr: SocketAddr,
    server_addr: SocketAddr,
) -> Option<PendingUploadInfo> {
    get_ftp_upload_state().consume_upload(client_addr.ip(), server_addr.ip())
}

/// Get FTPS server domain for TLS interception
pub(crate) fn get_ftps_domain(
    client_addr: SocketAddr,
    server_addr: SocketAddr,
) -> Option<String> {
    get_ftp_upload_state().get_ftps_domain(client_addr.ip(), server_addr.ip())
}