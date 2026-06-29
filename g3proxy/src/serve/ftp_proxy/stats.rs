/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! FTP proxy server statistics.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

use arc_swap::ArcSwapOption;
use g3_types::metrics::{MetricTagMap, NodeName};
use g3_types::stats::{StatId, TcpIoSnapshot, TcpIoStats};

use crate::serve::{ServerForbiddenSnapshot, ServerForbiddenStats, ServerStats};

pub(crate) struct FtpProxyServerStats {
    name: NodeName,
    id: StatId,
    extra_metrics_tags: Arc<ArcSwapOption<MetricTagMap>>,

    online: std::sync::atomic::AtomicIsize,
    task_alive_control: AtomicI32,
    task_total: AtomicU64,

    tcp_control: TcpIoStats,

    pub(crate) forbidden: ServerForbiddenStats,
}

impl FtpProxyServerStats {
    pub(crate) fn new(name: &NodeName) -> Arc<Self> {
        Arc::new(FtpProxyServerStats {
            name: name.clone(),
            id: StatId::new_unique(),
            extra_metrics_tags: Arc::new(ArcSwapOption::new(None)),
            online: std::sync::atomic::AtomicIsize::new(0),
            task_alive_control: AtomicI32::new(0),
            task_total: AtomicU64::new(0),
            tcp_control: TcpIoStats::default(),
            forbidden: ServerForbiddenStats::default(),
        })
    }

    pub(crate) fn set_online(&self) {
        self.online.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn set_offline(&self) {
        self.online.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn set_extra_tags(&self, tags: Option<Arc<MetricTagMap>>) {
        self.extra_metrics_tags.store(tags);
    }

    #[inline]
    pub(crate) fn add_control_in_bytes(&self, size: u64) {
        self.tcp_control.add_in_bytes(size);
    }

    #[inline]
    pub(crate) fn add_control_out_bytes(&self, size: u64) {
        self.tcp_control.add_out_bytes(size);
    }

    #[must_use]
    pub(crate) fn add_control_task(self: &Arc<Self>) -> FtpProxyControlTaskAliveGuard {
        self.task_total.fetch_add(1, Ordering::Relaxed);
        self.task_alive_control.fetch_add(1, Ordering::Relaxed);
        FtpProxyControlTaskAliveGuard(self.clone())
    }

    pub(crate) fn add_conn(&self, _addr: SocketAddr) {
        // FTP proxy: one TCP control connection per incoming TCP accept.
        self.task_total.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) struct FtpProxyControlTaskAliveGuard(Arc<FtpProxyServerStats>);

impl Drop for FtpProxyControlTaskAliveGuard {
    fn drop(&mut self) {
        self.0.task_alive_control.fetch_sub(1, Ordering::Relaxed);
    }
}

impl ServerStats for FtpProxyServerStats {
    #[inline]
    fn name(&self) -> &NodeName {
        &self.name
    }

    #[inline]
    fn stat_id(&self) -> StatId {
        self.id
    }

    #[inline]
    fn load_extra_tags(&self) -> Option<Arc<MetricTagMap>> {
        self.extra_metrics_tags.load_full()
    }

    #[inline]
    fn share_extra_tags(&self) -> &Arc<ArcSwapOption<MetricTagMap>> {
        &self.extra_metrics_tags
    }

    fn is_online(&self) -> bool {
        self.task_alive_control.load(Ordering::Relaxed) > 0
    }

    fn get_conn_total(&self) -> u64 {
        self.task_total.load(Ordering::Relaxed)
    }

    fn get_task_total(&self) -> u64 {
        self.task_total.load(Ordering::Relaxed)
    }

    fn get_alive_count(&self) -> i32 {
        self.task_alive_control.load(Ordering::Relaxed)
    }

    fn tcp_io_snapshot(&self) -> Option<TcpIoSnapshot> {
        // Combine control and upload channel stats — sum in/out bytes
        let ctrl = self.tcp_control.snapshot();
        Some(ctrl)
    }

    #[inline]
    fn forbidden_stats(&self) -> ServerForbiddenSnapshot {
        self.forbidden.snapshot()
    }
}
