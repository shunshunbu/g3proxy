/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

//! TLS KeyLog management for capturing SSLKEYLOGFILE format lines.
//!
//! This module provides thread-safe keylog buffer management for capturing
//! TLS session keys during handshake. The keylog data can be used by
//! tools like Wireshark to decrypt TLS traffic.
//!
//! # NSS KeyLog Format
//!
//! Each line in the keylog file follows the NSS format:
//! `<Label> <ClientRandom> <Secret>`
//!
//! Supported labels:
//! - CLIENT_RANDOM: Full TLS session secrets
//! - CLIENT_HANDSHAKE_TRAFFIC_SECRET: TLS 1.3 handshake secret (client side)
//! - SERVER_HANDSHAKE_TRAFFIC_SECRET: TLS 1.3 handshake secret (server side)
//! - CLIENT_TRAFFIC_SECRET_0: TLS 1.3 application data secret (client side)
//! - SERVER_TRAFFIC_SECRET_0: TLS 1.3 application data secret (server side)

use std::sync::Mutex;

use super::TlsVersion;

/// Maximum number of keylog entries per connection to prevent memory exhaustion
const MAX_KEYLOG_ENTRIES_PER_CONNECTION: usize = 128;

/// TLS KeyLog entry following NSS SSLKEYLOGFILE format
#[derive(Clone, Debug)]
pub struct TlsKeyLogEntry {
    /// The label identifying the type of key (e.g., "CLIENT_RANDOM")
    pub label: String,
    /// The client random in hex format
    pub client_random: String,
    /// The secret in hex format
    pub secret: String,
}

impl TlsKeyLogEntry {
    /// Create a new keylog entry
    pub fn new(label: String, client_random: String, secret: String) -> Self {
        TlsKeyLogEntry {
            label,
            client_random,
            secret,
        }
    }

    /// Parse a NSS keylog format line
    /// Format: `<Label> <ClientRandom> <Secret>`
    pub fn parse(line: &str) -> Option<Self> {
        let mut parts = line.split_whitespace();
        let label = parts.next()?.to_string();
        let client_random = parts.next()?.to_string();
        let secret = parts.next()?.to_string();

        Some(TlsKeyLogEntry {
            label,
            client_random,
            secret,
        })
    }

    /// Convert to NSS keylog format line
    pub fn to_keylog_line(&self) -> String {
        format!("{} {} {}", self.label, self.client_random, self.secret)
    }
}

/// Buffer to collect TLS keylog entries for a single connection.
/// Thread-safe and bounded to prevent memory exhaustion.
pub struct TlsKeyLogBuffer {
    entries: Mutex<Vec<TlsKeyLogEntry>>,
    max_entries: usize,
    tls_version: Mutex<Option<TlsVersion>>,
    cipher_suite: Mutex<Option<u16>>,
    server_random: Mutex<Option<String>>,
}

impl TlsKeyLogBuffer {
    /// Create a new empty keylog buffer.
    pub fn new_empty() -> Self {
        TlsKeyLogBuffer {
            entries: Mutex::new(Vec::with_capacity(MAX_KEYLOG_ENTRIES_PER_CONNECTION)),
            max_entries: MAX_KEYLOG_ENTRIES_PER_CONNECTION,
            tls_version: Mutex::new(None),
            cipher_suite: Mutex::new(None),
            server_random: Mutex::new(None),
        }
    }

    /// Create a new empty keylog buffer with custom max entries.
    pub fn new_with_max(max_entries: usize) -> Self {
        let max = max_entries.min(MAX_KEYLOG_ENTRIES_PER_CONNECTION);
        TlsKeyLogBuffer {
            entries: Mutex::new(Vec::with_capacity(max)),
            max_entries: max,
            tls_version: Mutex::new(None),
            cipher_suite: Mutex::new(None),
            server_random: Mutex::new(None),
        }
    }

    /// Create a new keylog buffer with the given client random.
    /// Kept for backward compatibility.
    pub fn new(_client_random: String) -> Self {
        TlsKeyLogBuffer {
            entries: Mutex::new(Vec::with_capacity(MAX_KEYLOG_ENTRIES_PER_CONNECTION)),
            max_entries: MAX_KEYLOG_ENTRIES_PER_CONNECTION,
            tls_version: Mutex::new(None),
            cipher_suite: Mutex::new(None),
            server_random: Mutex::new(None),
        }
    }

    /// Create a new keylog buffer with custom max entries.
    /// Kept for backward compatibility.
    pub fn with_max_entries(_client_random: String, max_entries: usize) -> Self {
        let max = max_entries.min(MAX_KEYLOG_ENTRIES_PER_CONNECTION);
        TlsKeyLogBuffer {
            entries: Mutex::new(Vec::with_capacity(max)),
            max_entries: max,
            tls_version: Mutex::new(None),
            cipher_suite: Mutex::new(None),
            server_random: Mutex::new(None),
        }
    }

    /// Set the negotiated TLS version.
    pub fn set_tls_version(&self, version: TlsVersion) {
        *self.tls_version.lock().unwrap() = Some(version);
    }

    /// Get the negotiated TLS version.
    pub fn tls_version(&self) -> Option<TlsVersion> {
        *self.tls_version.lock().unwrap()
    }

    /// Set the negotiated cipher suite (protocol ID).
    pub fn set_cipher_suite(&self, cipher: u16) {
        *self.cipher_suite.lock().unwrap() = Some(cipher);
    }

    /// Get the negotiated cipher suite (protocol ID).
    pub fn cipher_suite(&self) -> Option<u16> {
        *self.cipher_suite.lock().unwrap()
    }

    /// Set the server random (hex format).
    pub fn set_server_random(&self, random: String) {
        *self.server_random.lock().unwrap() = Some(random);
    }

    /// Get the server random (hex format).
    pub fn server_random(&self) -> Option<String> {
        self.server_random.lock().unwrap().clone()
    }

    /// Add a keylog entry. Non-blocking, returns false if buffer is full.
    pub fn add_entry(&self, entry: TlsKeyLogEntry) -> bool {
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= self.max_entries {
            return false;
        }
        entries.push(entry);
        true
    }

    /// Add a keylog entry from parsed components.
    /// Returns false if buffer is full.
    pub fn add(&self, label: String, client_random: String, secret: String) -> bool {
        self.add_entry(TlsKeyLogEntry::new(label, client_random, secret))
    }

    /// Get the client random associated with this buffer.
    /// Returns the client random from the first entry, or empty string if no entries.
    pub fn client_random(&self) -> String {
        let entries = self.entries.lock().unwrap();
        entries
            .first()
            .map(|e| e.client_random.clone())
            .unwrap_or_default()
    }

    /// Get all collected keylog entries.
    pub fn entries(&self) -> Vec<TlsKeyLogEntry> {
        self.entries.lock().unwrap().clone()
    }

    /// Get all collected keylog entries as ICAP header name-value pairs.
    /// Header name format: X-TLS-{LABEL}, value: {client_random} {secret}
    pub fn to_icap_headers(&self) -> Vec<(String, String)> {
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .map(|e| {
                let name = format!("X-TLS-{}", e.label);
                let value = format!("{} {}", e.client_random, e.secret);
                (name, value)
            })
            .collect()
    }

    /// Get the number of entries currently stored.
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// Check if buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.lock().unwrap().is_empty()
    }

    /// Clear all entries.
    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}
