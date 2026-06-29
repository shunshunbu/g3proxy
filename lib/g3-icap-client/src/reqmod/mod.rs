/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::net::SocketAddr;
use std::sync::Arc;

use crate::IcapServiceClient;

mod error;
pub use error::IcapReqmodParseError;

mod payload;
use payload::IcapReqmodResponsePayload;

mod response;

pub mod h1;
pub mod h2;

pub mod mail;

pub mod imap;
pub mod smtp;
pub mod ftp;

/* added by wming for repid audit */
pub struct ConnectionTuple {
    pub server_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub protocol: ConnectionProtocol,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionProtocol {
    Tcp = 6,
    Udp = 17,
}

#[derive(Clone)]
pub struct IcapReqmodClient {
    inner: Arc<IcapServiceClient>,
}

impl IcapReqmodClient {
    pub fn new(inner: Arc<IcapServiceClient>) -> IcapReqmodClient {
        IcapReqmodClient { inner }
    }

    pub fn bypass(&self) -> bool {
        self.inner.config.bypass
    }

    /// Get a reference to the inner service client, used by protocol adapters.
    pub fn service_client(&self) -> &Arc<IcapServiceClient> {
        &self.inner
    }
}
