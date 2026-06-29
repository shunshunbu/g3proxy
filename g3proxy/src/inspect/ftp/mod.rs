/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2024-2025 ByteDance and/or its affiliates.
 */

pub(crate) mod object;
pub(crate) use object::FtpInterceptObject;

pub(crate) mod upload_data;
pub(crate) use upload_data::{check_ftp_upload_data, get_ftps_domain, FtpUploadDataInterceptObject};