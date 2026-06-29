/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! FTP proxy server module.
//!
//! Handles native FTP protocol:
//!   * Control channel interception (PASV/EPSV rewriting)
//!   * Data channel interception for upload auditing via ICAP REQMOD
//!   * Graceful shutdown and stats tracking

pub(crate) mod audit_bridge;
pub(crate) mod ctl_common;
#[allow(dead_code)]
pub(crate) mod connect_bridge;
pub(crate) mod stats;
pub(crate) mod task;
pub(crate) mod server;
pub(crate) mod upload_state;

pub(crate) use server::FtpProxyServer;
