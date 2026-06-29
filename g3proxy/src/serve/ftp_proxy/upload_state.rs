/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

//! FTP upload state sharing across HTTP CONNECT connections.
//!
//! In HTTP CONNECT mode, control channel and data channel are separate TCP connections.
//! This module provides a mechanism to share state between them:
//! - Control channel detects STOR/APPE command and marks the pending upload
//! - Data channel checks the mark and only performs ICAP audit if marked as upload

use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

type ClientServerPair = (IpAddr, IpAddr);

/// Information about a pending upload operation
#[derive(Clone, Debug)]
pub(crate) struct PendingUploadInfo {
    /// FTP command (STOR, APPE, STOU)
    pub(crate) ftp_command: String,
    /// File path being uploaded
    pub(crate) ftp_path: String,
    /// When this entry was created (for cleanup)
    created_at: Instant,
}

struct FtpsDomainEntry {
    domain: String,
    created_at: Instant,
}

/// Global state for tracking pending FTP uploads across connections
pub(crate) struct FtpUploadState {
    /// Per (client, server) pair FIFO queue of pending uploads.
    /// Supports concurrent uploads from the same client.
    pending_uploads: Mutex<HashMap<ClientServerPair, VecDeque<PendingUploadInfo>>>,
    /// FTPS server domains with creation time for TTL-based expiry
    ftps_domains: Mutex<HashMap<ClientServerPair, FtpsDomainEntry>>,
    /// TTL for pending upload entries
    upload_ttl: Duration,
    /// TTL for FTPS domain entries
    domain_ttl: Duration,
    /// Maximum pending uploads per (client, server) pair (DoS protection)
    max_pending_per_pair: usize,
    /// Maximum number of FTPS domain entries (DoS protection)
    max_domains: usize,
    /// Approximate counter for lazy cleanup trigger
    ops_since_cleanup: Mutex<u32>,
    /// Cleanup interval in number of operations
    cleanup_interval: u32,
}

impl FtpUploadState {
    pub(crate) fn new() -> Self {
        FtpUploadState {
            pending_uploads: Mutex::new(HashMap::new()),
            ftps_domains: Mutex::new(HashMap::new()),
            upload_ttl: Duration::from_secs(120),
            domain_ttl: Duration::from_secs(3600),
            max_pending_per_pair: 16,
            max_domains: 4096,
            ops_since_cleanup: Mutex::new(0),
            cleanup_interval: 1000,
        }
    }

    fn cleanup_expired_uploads(
        map: &mut HashMap<ClientServerPair, VecDeque<PendingUploadInfo>>,
        now: Instant,
        ttl: Duration,
    ) {
        map.retain(|_, queue| {
            while let Some(front) = queue.front() {
                if now.saturating_duration_since(front.created_at) >= ttl {
                    queue.pop_front();
                } else {
                    break;
                }
            }
            !queue.is_empty()
        });
    }

    fn cleanup_expired_domains(
        map: &mut HashMap<ClientServerPair, FtpsDomainEntry>,
        now: Instant,
        ttl: Duration,
    ) {
        map.retain(|_, entry| now.saturating_duration_since(entry.created_at) < ttl);
    }

    fn maybe_trigger_cleanup(&self) {
        let should_cleanup = if let Ok(mut count) = self.ops_since_cleanup.lock() {
            *count = count.saturating_add(1);
            if *count >= self.cleanup_interval {
                *count = 0;
                true
            } else {
                false
            }
        } else {
            false
        };

        if should_cleanup {
            let now = Instant::now();
            if let Ok(mut uploads) = self.pending_uploads.lock() {
                Self::cleanup_expired_uploads(&mut uploads, now, self.upload_ttl);
            }
            if let Ok(mut domains) = self.ftps_domains.lock() {
                Self::cleanup_expired_domains(&mut domains, now, self.domain_ttl);
            }
        }
    }

    /// Mark a pending upload for a data channel.
    /// Called when control channel detects STOR/APPE command.
    pub(crate) fn mark_upload(
        &self,
        client_ip: IpAddr,
        ftp_server_ip: IpAddr,
        ftp_command: &str,
        ftp_path: &str,
        _pasv_port: u16,
    ) {
        let key = (client_ip, ftp_server_ip);
        let info = PendingUploadInfo {
            ftp_command: ftp_command.to_string(),
            ftp_path: ftp_path.to_string(),
            created_at: Instant::now(),
        };

        if let Ok(mut map) = self.pending_uploads.lock() {
            let queue = map.entry(key).or_default();
            if queue.len() >= self.max_pending_per_pair {
                return;
            }
            queue.push_back(info);
        }

        self.maybe_trigger_cleanup();
    }

    /// Consume and return the oldest pending upload info for a (client, server) pair.
    /// FIFO order: first upload command marked is first consumed by data channel.
    pub(crate) fn consume_upload(
        &self,
        client_ip: IpAddr,
        ftp_server_ip: IpAddr,
    ) -> Option<PendingUploadInfo> {
        let key = (client_ip, ftp_server_ip);
        let result = if let Ok(mut map) = self.pending_uploads.lock() {
            let queue = map.get_mut(&key)?;
            let now = Instant::now();

            while let Some(front) = queue.front() {
                if now.saturating_duration_since(front.created_at) >= self.upload_ttl {
                    queue.pop_front();
                } else {
                    break;
                }
            }

            let info = queue.pop_front()?;
            if queue.is_empty() {
                map.remove(&key);
            }
            Some(info)
        } else {
            None
        };

        self.maybe_trigger_cleanup();
        result
    }

    /// Mark a server as FTPS server with its domain.
    /// Called when FTPS control channel is established.
    pub(crate) fn mark_ftps_domain(&self, client_ip: IpAddr, ftp_server_ip: IpAddr, domain: &str) {
        let key = (client_ip, ftp_server_ip);
        if let Ok(mut map) = self.ftps_domains.lock() {
            if !map.contains_key(&key) && map.len() >= self.max_domains {
                return;
            }
            map.insert(
                key,
                FtpsDomainEntry {
                    domain: domain.to_string(),
                    created_at: Instant::now(),
                },
            );
        }

        self.maybe_trigger_cleanup();
    }

    /// Get the FTPS server domain, or None if expired or not found.
    pub(crate) fn get_ftps_domain(&self, client_ip: IpAddr, ftp_server_ip: IpAddr) -> Option<String> {
        let key = (client_ip, ftp_server_ip);
        let result = if let Ok(map) = self.ftps_domains.lock() {
            let entry = map.get(&key)?;
            if Instant::now().saturating_duration_since(entry.created_at) >= self.domain_ttl {
                None
            } else {
                Some(entry.domain.clone())
            }
        } else {
            None
        };

        self.maybe_trigger_cleanup();
        result
    }
}

/// Global shared state instance
static FTP_UPLOAD_STATE: OnceLock<Arc<FtpUploadState>> = OnceLock::new();

/// Get the global FTP upload state
pub(crate) fn get_ftp_upload_state() -> Arc<FtpUploadState> {
    FTP_UPLOAD_STATE.get_or_init(|| Arc::new(FtpUploadState::new())).clone()
}
