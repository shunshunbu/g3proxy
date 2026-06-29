/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::io;

use thiserror::Error;

use super::FtpAdaptationErrorKind;
use crate::reqmod::IcapReqmodParseError;

#[derive(Debug, Error)]
pub enum FtpAdaptationError {
    #[error("write to icap server failed: {0:?}")]
    IcapServerWriteFailed(io::Error),
    #[error("read from icap server failed: {0:?}")]
    IcapServerReadFailed(io::Error),
    #[error("icap server connection closed")]
    IcapServerConnectionClosed,
    #[error("invalid response from icap server: {0}")]
    InvalidIcapServerResponse(#[from] IcapReqmodParseError),
    #[error("read from ftp client failed: {0:?}")]
    FtpClientReadFailed(io::Error),
    #[error("write to ftp upstream failed: {0:?}")]
    FtpUpstreamWriteFailed(io::Error),
    #[error("internal server error: {0}")]
    InternalServerError(&'static str),
    #[error("force quit from idle checker")]
    IdleForceQuit,
    #[error("idle while reading from ftp client")]
    FtpClientReadIdle,
    #[error("idle while writing to ftp upstream")]
    FtpUpstreamWriteIdle,
    #[error("idle while reading from icap server")]
    IcapServerReadIdle,
    #[error("idle while writing to icap server")]
    IcapServerWriteIdle,
    #[error("not implemented feature: {0}")]
    NotImplemented(&'static str),
}

#[allow(dead_code)]
impl FtpAdaptationError {
    pub(crate) fn kind(&self) -> FtpAdaptationErrorKind {
        match self {
            FtpAdaptationError::FtpClientReadFailed(_)
            | FtpAdaptationError::FtpClientReadIdle => FtpAdaptationErrorKind::ClientRead,
            FtpAdaptationError::FtpUpstreamWriteFailed(_)
            | FtpAdaptationError::FtpUpstreamWriteIdle => FtpAdaptationErrorKind::UpstreamWrite,
            FtpAdaptationError::IcapServerWriteFailed(_)
            | FtpAdaptationError::IcapServerWriteIdle => FtpAdaptationErrorKind::IcapWrite,
            FtpAdaptationError::IcapServerReadFailed(_)
            | FtpAdaptationError::IcapServerReadIdle
            | FtpAdaptationError::IcapServerConnectionClosed
            | FtpAdaptationError::InvalidIcapServerResponse(_) => FtpAdaptationErrorKind::IcapRead,
            FtpAdaptationError::IdleForceQuit => FtpAdaptationErrorKind::ForceQuit,
            FtpAdaptationError::InternalServerError(_)
            | FtpAdaptationError::NotImplemented(_) => FtpAdaptationErrorKind::Internal,
        }
    }
}
