/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};
use ascii::AsciiString;
use yaml_rust::{Yaml, yaml};

use g3_types::acl::AclNetworkRuleBuilder;
use g3_types::metrics::{MetricTagMap, NodeName};
use g3_types::net::{OpensslClientConfigBuilder, TcpListenConfig, TcpMiscSockOpts, TcpSockSpeedLimitConfig, WeightedUpstreamAddr};
use g3_yaml::YamlDocPosition;

use super::{
    AnyServerConfig, IDLE_CHECK_DEFAULT_DURATION, IDLE_CHECK_DEFAULT_MAX_COUNT,
    IDLE_CHECK_MAXIMUM_DURATION, ServerConfig, ServerConfigDiffAction,
};

const SERVER_CONFIG_TYPE: &str = "FtpProxy";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TlsUpstreamType {
    PlainFtp,
    ExplicitFtps,
    ImplicitFtps,
}

impl Default for TlsUpstreamType {
    fn default() -> Self {
        TlsUpstreamType::PlainFtp
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FtpProxyServerConfig {
    name: NodeName,
    position: Option<YamlDocPosition>,
    pub(crate) escaper: NodeName,
    pub(crate) auditor: NodeName,
    pub(crate) shared_logger: Option<AsciiString>,
    pub(crate) listen: Option<TcpListenConfig>,
    pub(crate) listen_in_worker: bool,
    pub(crate) ingress_net_filter: Option<AclNetworkRuleBuilder>,
    pub(crate) upstream: Vec<WeightedUpstreamAddr>,
    pub(crate) tcp_sock_speed_limit: TcpSockSpeedLimitConfig,
    pub(crate) task_idle_check_duration: Duration,
    pub(crate) task_idle_max_count: usize,
    pub(crate) flush_task_log_on_created: bool,
    pub(crate) flush_task_log_on_connected: bool,
    pub(crate) task_log_flush_interval: Option<Duration>,
    pub(crate) tcp_misc_opts: TcpMiscSockOpts,
    pub(crate) audit_upload: bool,
    pub(crate) tls_upstream: Option<OpensslClientConfigBuilder>,
    pub(crate) tls_upstream_type: TlsUpstreamType,
    pub(crate) extra_metrics_tags: Option<Arc<MetricTagMap>>,
}

impl FtpProxyServerConfig {
    fn new(position: Option<YamlDocPosition>) -> Self {
        FtpProxyServerConfig {
            name: NodeName::default(),
            position,
            escaper: NodeName::default(),
            auditor: NodeName::default(),
            shared_logger: None,
            listen: None,
            listen_in_worker: false,
            ingress_net_filter: None,
            upstream: Vec::new(),
            tcp_sock_speed_limit: TcpSockSpeedLimitConfig::default(),
            task_idle_check_duration: IDLE_CHECK_DEFAULT_DURATION,
            task_idle_max_count: IDLE_CHECK_DEFAULT_MAX_COUNT,
            flush_task_log_on_created: false,
            flush_task_log_on_connected: false,
            task_log_flush_interval: None,
            tcp_misc_opts: Default::default(),
            audit_upload: true,
            tls_upstream: None,
            tls_upstream_type: TlsUpstreamType::PlainFtp,
            extra_metrics_tags: None,
        }
    }

    pub(crate) fn parse(
        map: &yaml::Hash,
        position: Option<YamlDocPosition>,
    ) -> anyhow::Result<Self> {
        let mut server = FtpProxyServerConfig::new(position);

        g3_yaml::foreach_kv(map, |k, v| server.set(k, v))?;

        server.check()?;
        Ok(server)
    }

    fn set(&mut self, k: &str, v: &Yaml) -> anyhow::Result<()> {
        match g3_yaml::key::normalize(k).as_str() {
            super::CONFIG_KEY_SERVER_TYPE => Ok(()),
            super::CONFIG_KEY_SERVER_NAME => {
                self.name = g3_yaml::value::as_metric_node_name(v)?;
                Ok(())
            }
            "escaper" => {
                self.escaper = g3_yaml::value::as_metric_node_name(v)?;
                Ok(())
            }
            "auditor" => {
                self.auditor = g3_yaml::value::as_metric_node_name(v)?;
                Ok(())
            }
            "shared_logger" => {
                let name = g3_yaml::value::as_ascii(v)?;
                self.shared_logger = Some(name);
                Ok(())
            }
            "extra_metrics_tags" => {
                let tags = g3_yaml::value::as_static_metrics_tags(v)
                    .context(format!("invalid static metrics tags value for key {k}"))?;
                self.extra_metrics_tags = Some(Arc::new(tags));
                Ok(())
            }
            "listen" => {
                let config = g3_yaml::value::as_tcp_listen_config(v)
                    .context(format!("invalid tcp listen config value for key {k}"))?;
                self.listen = Some(config);
                Ok(())
            }
            "listen_in_worker" => {
                self.listen_in_worker = g3_yaml::value::as_bool(v)?;
                Ok(())
            }
            "ingress_network_filter" | "ingress_net_filter" => {
                let filter = g3_yaml::value::acl::as_ingress_network_rule_builder(v)
                    .context(format!("invalid ingress network acl rule value for key {k}"))?;
                self.ingress_net_filter = Some(filter);
                Ok(())
            }
            "upstream" | "proxy_pass" | "ftp_server" => {
                self.upstream = g3_yaml::value::as_list(v, |v| {
                    g3_yaml::value::as_weighted_upstream_addr(v, 21)
                })
                .context(format!("invalid weighted upstream address value for key {k}"))?;
                Ok(())
            }
            "tcp_sock_speed_limit" => {
                self.tcp_sock_speed_limit = g3_yaml::value::as_tcp_sock_speed_limit(v)
                    .context(format!("invalid tcp socket speed limit value for key {k}"))?;
                Ok(())
            }
            "tcp_misc_opts" => {
                self.tcp_misc_opts = g3_yaml::value::as_tcp_misc_sock_opts(v)
                    .context(format!("invalid tcp misc sock opts value for key {k}"))?;
                Ok(())
            }
            "task_idle_check_duration" => {
                self.task_idle_check_duration = g3_yaml::humanize::as_duration(v)
                    .context(format!("invalid humanize duration value for key {k}"))?;
                Ok(())
            }
            "task_idle_max_count" => {
                self.task_idle_max_count = g3_yaml::value::as_usize(v)
                    .context(format!("invalid usize value for key {k}"))?;
                Ok(())
            }
            "flush_task_log_on_created" => {
                self.flush_task_log_on_created = g3_yaml::value::as_bool(v)?;
                Ok(())
            }
            "flush_task_log_on_connected" => {
                self.flush_task_log_on_connected = g3_yaml::value::as_bool(v)?;
                Ok(())
            }
            "task_log_flush_interval" => {
                let interval = g3_yaml::humanize::as_duration(v)
                    .context(format!("invalid humanize duration value for key {k}"))?;
                self.task_log_flush_interval = Some(interval);
                Ok(())
            }
            "audit_upload" => {
                self.audit_upload = g3_yaml::value::as_bool(v)?;
                Ok(())
            }
            "tls_upstream" => {
                if let Yaml::Boolean(enable) = v {
                    if *enable {
                        self.tls_upstream =
                            Some(OpensslClientConfigBuilder::with_cache_for_one_site());
                    }
                } else {
                    let lookup_dir = g3_daemon::config::get_lookup_dir(self.position.as_ref())?;
                    let builder = g3_yaml::value::as_to_one_openssl_tls_client_config_builder(
                        v,
                        Some(lookup_dir),
                    )
                    .context(format!(
                        "invalid openssl tls upstream config value for key {k}"
                    ))?;
                    self.tls_upstream = Some(builder);
                }
                Ok(())
            }
            "tls_upstream_type" => {
                let value = g3_yaml::value::as_ascii(v)?;
                self.tls_upstream_type = match value.as_str() {
                    "plain_ftp" | "plain" | "ftp" => TlsUpstreamType::PlainFtp,
                    "explicit_ftps" | "explicit" | "auth_tls" => TlsUpstreamType::ExplicitFtps,
                    "implicit_ftps" | "implicit" => TlsUpstreamType::ImplicitFtps,
                    _ => {
                        return Err(anyhow!(
                            "invalid tls_upstream_type value: {}, expected plain_ftp, explicit_ftps, or implicit_ftps",
                            value
                        ));
                    }
                };
                Ok(())
            }
            _ => Err(anyhow!("invalid key {k}")),
        }
    }

    fn check(&mut self) -> anyhow::Result<()> {
        if self.name.is_empty() {
            return Err(anyhow!("name is not set"));
        }
        if self.escaper.is_empty() {
            return Err(anyhow!("escaper is not set"));
        }
        if self.upstream.is_empty() {
            return Err(anyhow!("upstream is not set"));
        }
        if self.task_idle_check_duration > IDLE_CHECK_MAXIMUM_DURATION {
            self.task_idle_check_duration = IDLE_CHECK_MAXIMUM_DURATION;
        }
        match self.tls_upstream_type {
            TlsUpstreamType::PlainFtp => {}
            TlsUpstreamType::ExplicitFtps | TlsUpstreamType::ImplicitFtps => {
                if self.tls_upstream.is_none() {
                    return Err(anyhow!(
                        "tls_upstream must be set when tls_upstream_type is {:?}",
                        self.tls_upstream_type
                    ));
                }
                if let Some(builder) = &mut self.tls_upstream {
                    builder.check()?;
                }
            }
        }
        Ok(())
    }
}

impl ServerConfig for FtpProxyServerConfig {
    fn name(&self) -> &NodeName {
        &self.name
    }

    fn position(&self) -> Option<YamlDocPosition> {
        self.position.clone()
    }

    fn r#type(&self) -> &'static str {
        SERVER_CONFIG_TYPE
    }

    fn escaper(&self) -> &NodeName {
        &self.escaper
    }

    fn user_group(&self) -> &NodeName {
        Default::default()
    }

    fn auditor(&self) -> &NodeName {
        &self.auditor
    }

    fn diff_action(&self, new: &AnyServerConfig) -> ServerConfigDiffAction {
        let AnyServerConfig::FtpProxy(new) = new else {
            return ServerConfigDiffAction::SpawnNew;
        };

        if self.eq(new) {
            return ServerConfigDiffAction::NoAction;
        }

        if self.listen != new.listen {
            return ServerConfigDiffAction::ReloadAndRespawn;
        }

        ServerConfigDiffAction::ReloadNoRespawn
    }

    fn shared_logger(&self) -> Option<&str> {
        self.shared_logger.as_ref().map(|s| s.as_str())
    }

    fn task_log_flush_interval(&self) -> Option<Duration> {
        self.task_log_flush_interval
    }

    fn limited_copy_config(&self) -> g3_io_ext::StreamCopyConfig {
        g3_io_ext::StreamCopyConfig::default()
    }

    fn task_max_idle_count(&self) -> usize {
        self.task_idle_max_count
    }
}
