/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::anyhow;
use arc_swap::{ArcSwap, ArcSwapOption};
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::broadcast;

use g3_daemon::listen::{AcceptQuicServer, AcceptTcpServer, ListenStats, ListenTcpRuntime};
use g3_daemon::server::{BaseServer, ClientConnectionInfo, ServerExt, ServerReloadCommand};
use g3_io_ext::IdleWheel;
use g3_types::acl::{AclAction, AclNetworkRule};
use g3_types::collection::{SelectiveVec, SelectiveVecBuilder};
use g3_types::metrics::NodeName;

use super::stats::FtpProxyServerStats;
use super::task::FtpProxyTask;
use crate::audit::AuditHandle;
use crate::config::server::ftp_proxy::FtpProxyServerConfig;
use crate::config::server::{AnyServerConfig, ServerConfig};
use crate::escape::ArcEscaper;
use crate::serve::{
    ArcServer, ArcServerInternal, ArcServerStats, Server, ServerInternal, ServerQuitPolicy,
    ServerRegistry, ServerStats, WrapArcServer,
};

pub(crate) struct FtpProxyServer {
    config: Arc<FtpProxyServerConfig>,
    server_stats: Arc<FtpProxyServerStats>,
    listen_stats: Arc<ListenStats>,
    upstream: SelectiveVec<g3_types::net::WeightedUpstreamAddr>,
    ingress_net_filter: Option<AclNetworkRule>,
    reload_sender: broadcast::Sender<ServerReloadCommand>,
    task_logger: Option<slog::Logger>,

    escaper: ArcSwap<ArcEscaper>,
    audit_handle: ArcSwapOption<AuditHandle>,
    quit_policy: Arc<ServerQuitPolicy>,
    idle_wheel: Arc<IdleWheel>,
    reload_version: usize,
}

impl FtpProxyServer {
    fn new(
        config: Arc<FtpProxyServerConfig>,
        server_stats: Arc<FtpProxyServerStats>,
        listen_stats: Arc<ListenStats>,
        version: usize,
    ) -> anyhow::Result<FtpProxyServer> {
        let reload_sender = crate::serve::new_reload_notify_channel();

        let mut nodes_builder = SelectiveVecBuilder::new();
        for node in &config.upstream {
            nodes_builder.insert(node.clone());
        }
        let upstream = nodes_builder
            .build()
            .ok_or_else(|| anyhow!("no upstream ftp server set"))?;

        let ingress_net_filter = config
            .ingress_net_filter
            .as_ref()
            .map(|builder| builder.build());

        let task_logger = config.get_task_logger();
        let idle_wheel = IdleWheel::spawn(config.task_idle_check_duration);

        let escaper = Arc::new(crate::escape::get_or_insert_default(config.escaper()));
        let audit_handle = ArcSwapOption::from(config.get_audit_handle().ok().flatten());

        server_stats.set_extra_tags(config.extra_metrics_tags.clone());

        let server = FtpProxyServer {
            config,
            server_stats,
            listen_stats,
            upstream,
            ingress_net_filter,
            reload_sender,
            task_logger,
            escaper: ArcSwap::new(escaper),
            audit_handle,
            quit_policy: Arc::new(ServerQuitPolicy::default()),
            idle_wheel,
            reload_version: version,
        };

        Ok(server)
    }

    #[allow(private_interfaces)]
    pub(crate) fn prepare_initial(
        config: FtpProxyServerConfig,
    ) -> anyhow::Result<ArcServerInternal> {
        let config = Arc::new(config);
        let server_stats = FtpProxyServerStats::new(config.name());
        let listen_stats = Arc::new(ListenStats::new(config.name()));

        let server = FtpProxyServer::new(config, server_stats, listen_stats, 1)?;
        Ok(Arc::new(server))
    }

    fn prepare_reload(&self, config: AnyServerConfig) -> anyhow::Result<FtpProxyServer> {
        if let AnyServerConfig::FtpProxy(config) = config {
            let config = Arc::new(config);
            let server_stats = Arc::clone(&self.server_stats);
            let listen_stats = Arc::clone(&self.listen_stats);

            let server = FtpProxyServer::new(config, server_stats, listen_stats, self.reload_version + 1)?;
            Ok(server)
        } else {
            Err(anyhow!(
                "config type mismatch: expect {}, actual {}",
                self.config.r#type(),
                config.r#type()
            ))
        }
    }

    fn drop_early(&self, client_addr: SocketAddr) -> bool {
        if let Some(ingress_net_filter) = &self.ingress_net_filter {
            let (_, action) = ingress_net_filter.check(client_addr.ip());
            match action {
                AclAction::Permit | AclAction::PermitAndLog => {}
                AclAction::Forbid | AclAction::ForbidAndLog => {
                    self.listen_stats.add_dropped();
                    return true;
                }
            }
        }
        false
    }

    fn audit_context(&self) -> crate::audit::AuditContext {
        crate::audit::AuditContext::new(self.audit_handle.load_full())
    }

    async fn run_task_with_stream<T>(&self, stream: T, cc_info: ClientConnectionInfo)
    where
        T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
    {
        // Pick the upstream FTP server
        let upstream = self
            .select_consistent(
                &self.upstream,
                g3_types::collection::SelectivePickPolicy::Random,
                &cc_info,
            )
            .inner()
            .clone();

        let escaper = self.escaper.load().as_ref().clone();
        let idle_wheel = self.idle_wheel.clone();
        let task_logger = self.task_logger.clone();
        let server_config = self.config.clone();
        let server_stats = self.server_stats.clone();
        let quit_policy = self.quit_policy.clone();

        // Build TLS upstream config if configured
        let tls_upstream_config = self.config.tls_upstream.as_ref().map(|builder| {
            // Error here means config validation failed at load time, which shouldn't happen
            let config = builder.build().expect("tls_upstream config build failed");
            Arc::new(config)
        });
        let tls_upstream_type = self.config.tls_upstream_type;

        let (clt_r, clt_w) = tokio::io::split(stream);

        let audit_ctx = self.audit_context();

        let task = FtpProxyTask::new(
            server_config,
            server_stats,
            quit_policy,
            idle_wheel,
            escaper,
            cc_info,
            upstream,
            audit_ctx,
            task_logger,
            tls_upstream_config,
            tls_upstream_type,
        );

        task.into_running(clt_r, clt_w).await;
    }
}

impl ServerInternal for FtpProxyServer {
    fn _clone_config(&self) -> AnyServerConfig {
        AnyServerConfig::FtpProxy(self.config.as_ref().clone())
    }

    fn _depend_on_server(&self, _name: &NodeName) -> bool {
        false
    }

    fn _reload_config_notify_runtime(&self) {
        let cmd = ServerReloadCommand::ReloadVersion(self.reload_version);
        let _ = self.reload_sender.send(cmd);
    }

    fn _update_next_servers_in_place(&self) {}

    fn _update_escaper_in_place(&self) {
        let escaper = crate::escape::get_or_insert_default(self.config.escaper());
        self.escaper.store(Arc::new(escaper));
    }

    fn _update_user_group_in_place(&self) {}

    fn _update_audit_handle_in_place(&self) -> anyhow::Result<()> {
        let audit_handle = self.config.get_audit_handle()?;
        self.audit_handle.store(audit_handle);
        Ok(())
    }

    fn _reload_with_old_notifier(
        &self,
        config: AnyServerConfig,
        _registry: &mut ServerRegistry,
    ) -> anyhow::Result<ArcServerInternal> {
        let mut server = self.prepare_reload(config)?;
        server.reload_sender = self.reload_sender.clone();
        Ok(Arc::new(server))
    }

    fn _reload_with_new_notifier(
        &self,
        config: AnyServerConfig,
        _registry: &mut ServerRegistry,
    ) -> anyhow::Result<ArcServerInternal> {
        let server = self.prepare_reload(config)?;
        Ok(Arc::new(server))
    }

    fn _start_runtime(&self, server: ArcServer) -> anyhow::Result<()> {
        let Some(listen_config) = &self.config.listen else {
            return Ok(());
        };
        let listen_stats = server.get_listen_stats();
        let runtime = ListenTcpRuntime::new(WrapArcServer(server), listen_stats);
        runtime
            .run_all_instances(
                listen_config,
                self.config.listen_in_worker,
                &self.reload_sender,
            )
            .map(|_| self.server_stats.set_online())
    }

    fn _abort_runtime(&self) {
        let _ = self.reload_sender.send(ServerReloadCommand::QuitRuntime);
        self.server_stats.set_offline();
    }
}

impl BaseServer for FtpProxyServer {
    #[inline]
    fn name(&self) -> &NodeName {
        self.config.name()
    }

    #[inline]
    fn r#type(&self) -> &'static str {
        self.config.r#type()
    }

    #[inline]
    fn version(&self) -> usize {
        self.reload_version
    }
}

impl ServerExt for FtpProxyServer {}

#[async_trait]
impl AcceptTcpServer for FtpProxyServer {
    async fn run_tcp_task(&self, stream: TcpStream, cc_info: ClientConnectionInfo) {
        let client_addr = cc_info.client_addr();
        self.server_stats.add_conn(client_addr);
        if self.drop_early(client_addr) {
            return;
        }
        self.run_task_with_stream(stream, cc_info).await
    }
}

#[async_trait]
impl AcceptQuicServer for FtpProxyServer {
    async fn run_quic_task(&self, _connection: quinn::Connection, _cc_info: ClientConnectionInfo) {}
}

#[async_trait]
impl Server for FtpProxyServer {
    fn escaper(&self) -> &NodeName {
        self.config.escaper()
    }

    fn user_group(&self) -> &NodeName {
        Default::default()
    }

    fn auditor(&self) -> &NodeName {
        self.config.auditor()
    }

    fn get_server_stats(&self) -> Option<ArcServerStats> {
        Some(self.server_stats.clone())
    }

    fn get_listen_stats(&self) -> Arc<ListenStats> {
        Arc::clone(&self.listen_stats)
    }

    fn alive_count(&self) -> i32 {
        self.server_stats.get_alive_count()
    }

    #[inline]
    fn quit_policy(&self) -> &Arc<ServerQuitPolicy> {
        &self.quit_policy
    }

    async fn run_rustls_task(&self, stream: tokio_rustls::server::TlsStream<TcpStream>, cc_info: ClientConnectionInfo) {
        let client_addr = cc_info.client_addr();
        self.server_stats.add_conn(client_addr);
        if self.drop_early(client_addr) {
            return;
        }
        self.run_task_with_stream(stream, cc_info).await
    }

    async fn run_openssl_task(&self, stream: g3_openssl::SslStream<TcpStream>, cc_info: ClientConnectionInfo) {
        let client_addr = cc_info.client_addr();
        self.server_stats.add_conn(client_addr);
        if self.drop_early(client_addr) {
            return;
        }
        self.run_task_with_stream(stream, cc_info).await
    }
}
