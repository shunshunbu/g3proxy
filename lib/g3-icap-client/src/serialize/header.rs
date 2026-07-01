/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::io::Write;
use std::net::SocketAddr;

use base64::prelude::*;
use bytes::BufMut;

use g3_types::net::{HttpHeaderMap, TlsKeyLogBuffer};

/* added by wming for repid audit */
use crate::reqmod::ConnectionTuple;

pub fn add_connection_tuple(buf: &mut Vec<u8>, tuple: &ConnectionTuple) {
    let _ = write!(buf, "X-Proxy-IP: {}\r\n", tuple.server_addr.ip());
    let _ = write!(buf, "X-Proxy-PORT: {}\r\n", tuple.server_addr.port());
    let _ = write!(buf, "X-Remote-IP: {}\r\n", tuple.remote_addr.ip());
    let _ = write!(buf, "X-Remote-PORT: {}\r\n", tuple.remote_addr.port());
    let _ = write!(buf, "X-Proto-P: {}\r\n", tuple.protocol as u8);
}

/// Add TLS keylog entries as ICAP headers.
/// Each keylog line is sent as a separate X-TLS-KeyLog header.
pub fn add_keylog_headers(buf: &mut Vec<u8>, keylog: &TlsKeyLogBuffer) {
    if keylog.is_empty() {
        return;
    }
    if let Some(version) = keylog.tls_version() {
        let _ = write!(buf, "X-TLS-VERSION: {}\r\n", version.as_str());
    }
    if let Some(cipher) = keylog.cipher_suite() {
        let _ = write!(buf, "X-TLS-CIPHER: {}\r\n", cipher);
    }
    if let Some(server_random) = keylog.server_random() {
        let _ = write!(buf, "X-TLS-SERVER_RANDOM: {}\r\n", server_random);
    }
    for (name, value) in keylog.to_icap_headers() {
        buf.put_slice(name.as_bytes());
        buf.put_slice(b": ");
        buf.put_slice(value.as_bytes());
        buf.put_slice(b"\r\n");
    }
}

pub(crate) fn add_client_addr(buf: &mut Vec<u8>, addr: SocketAddr) {
    let _ = write!(buf, "X-Client-IP: {}\r\n", addr.ip());
    let _ = write!(buf, "X-Client-Port: {}\r\n", addr.port());
}

pub(crate) fn add_client_username(buf: &mut Vec<u8>, user: &str) {
    buf.put_slice(b"X-Client-Username: ");
    buf.put_slice(user.as_bytes());
    buf.put_slice(b"\r\n");

    buf.put_slice(b"X-Authenticated-User: ");
    let v = BASE64_STANDARD.encode(format!("Local://{user}"));
    buf.put_slice(v.as_bytes());
    buf.put_slice(b"\r\n");
}

pub(crate) fn add_shared(buf: &mut Vec<u8>, headers: &HttpHeaderMap) {
    headers.for_each(|name, value| {
        buf.put_slice(name.as_str().as_bytes());
        buf.put_slice(b": ");
        buf.put_slice(value.as_bytes());
        buf.put_slice(b"\r\n");
    });
}
