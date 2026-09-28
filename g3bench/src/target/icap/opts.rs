/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, anyhow};
use clap::{Arg, ArgAction, ArgMatches, Command};

use g3_types::net::UpstreamAddr;

const ICAP_ARG_TARGET: &str = "target";
const ICAP_ARG_SERVICE: &str = "service";
const ICAP_ARG_METHOD: &str = "method";
const ICAP_ARG_FILE_SIZE: &str = "file-size";
const ICAP_ARG_CHUNK_SIZE: &str = "chunk-size";
const ICAP_ARG_TIMEOUT: &str = "timeout";
const ICAP_ARG_CONNECT_TIMEOUT: &str = "connect-timeout";
const ICAP_ARG_DRAIN_RESPONSE: &str = "drain-response";

#[derive(Clone)]
pub(super) struct BenchIcapArgs {
    pub(super) target: UpstreamAddr,
    pub(super) service: String,
    pub(super) method: String,
    pub(super) file_size: usize,
    pub(super) chunk_size: usize,
    pub(super) timeout: Duration,
    pub(super) connect_timeout: Duration,
    pub(super) drain_response: bool,
}

impl BenchIcapArgs {
    fn new(target: UpstreamAddr) -> Self {
        BenchIcapArgs {
            target,
            service: "echo".to_string(),
            method: "REQMOD".to_string(),
            file_size: 1024 * 1024,
            chunk_size: 64 * 1024,
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            drain_response: true,
        }
    }
}

pub(super) fn add_icap_args(app: Command) -> Command {
    app.arg(
        Arg::new(ICAP_ARG_TARGET)
            .help("Target ICAP server address (host:port)")
            .required(true)
            .num_args(1),
    )
    .arg(
        Arg::new(ICAP_ARG_SERVICE)
            .help("ICAP service name")
            .default_value("echo")
            .long(ICAP_ARG_SERVICE)
            .short('s')
            .num_args(1),
    )
    .arg(
        Arg::new(ICAP_ARG_METHOD)
            .help("ICAP method (REQMOD or RESPMOD)")
            .default_value("REQMOD")
            .long(ICAP_ARG_METHOD)
            .short('m')
            .num_args(1)
            .value_parser(["REQMOD", "RESPMOD"]),
    )
    .arg(
        Arg::new(ICAP_ARG_FILE_SIZE)
            .help("Upload file size per request (in bytes, supports k/M/G suffix)")
            .default_value("1M")
            .long(ICAP_ARG_FILE_SIZE)
            .short('f')
            .num_args(1),
    )
    .arg(
        Arg::new(ICAP_ARG_CHUNK_SIZE)
            .help("Chunk size for transfer (in bytes, supports k/M suffix)")
            .default_value("64K")
            .long(ICAP_ARG_CHUNK_SIZE)
            .num_args(1),
    )
    .arg(
        Arg::new(ICAP_ARG_TIMEOUT)
            .help("ICAP request timeout")
            .default_value("30s")
            .long(ICAP_ARG_TIMEOUT)
            .num_args(1),
    )
    .arg(
        Arg::new(ICAP_ARG_CONNECT_TIMEOUT)
            .help("TCP connect timeout")
            .default_value("10s")
            .long(ICAP_ARG_CONNECT_TIMEOUT)
            .num_args(1),
    )
    .arg(
        Arg::new(ICAP_ARG_DRAIN_RESPONSE)
            .help("Drain ICAP response body (needed for echo-like services)")
            .action(ArgAction::SetTrue)
            .long(ICAP_ARG_DRAIN_RESPONSE),
    )
}

fn parse_size(s: &str) -> anyhow::Result<usize> {
    let s = s.trim();
    if s.is_empty() {
        return Err(anyhow!("empty size"));
    }

    let lower = s.to_ascii_lowercase();
    let (num_str, multiplier) = if lower.ends_with('g') {
        (&lower[..lower.len() - 1], 1024 * 1024 * 1024usize)
    } else if lower.ends_with('m') {
        (&lower[..lower.len() - 1], 1024 * 1024)
    } else if lower.ends_with('k') {
        (&lower[..lower.len() - 1], 1024)
    } else {
        (lower.as_str(), 1usize)
    };

    let num: f64 = num_str
        .parse()
        .map_err(|e| anyhow!("invalid size number {num_str}: {e}"))?;
    Ok((num * multiplier as f64) as usize)
}

pub(super) fn parse_icap_args(args: &ArgMatches) -> anyhow::Result<BenchIcapArgs> {
    let target_str = args
        .get_one::<String>(ICAP_ARG_TARGET)
        .ok_or_else(|| anyhow!("no target set"))?;
    let target =
        UpstreamAddr::from_str(target_str).context("invalid ICAP server address")?;
    let mut icap_args = BenchIcapArgs::new(target);

    if let Some(s) = args.get_one::<String>(ICAP_ARG_SERVICE) {
        icap_args.service = s.clone();
    }
    if let Some(s) = args.get_one::<String>(ICAP_ARG_METHOD) {
        icap_args.method = s.clone();
    }
    if let Some(s) = args.get_one::<String>(ICAP_ARG_FILE_SIZE) {
        icap_args.file_size = parse_size(s).context("invalid file size")?;
    }
    if let Some(s) = args.get_one::<String>(ICAP_ARG_CHUNK_SIZE) {
        icap_args.chunk_size = parse_size(s).context("invalid chunk size")?;
    }
    if let Some(timeout) = g3_clap::humanize::get_duration(args, ICAP_ARG_TIMEOUT)? {
        icap_args.timeout = timeout;
    }
    if let Some(timeout) = g3_clap::humanize::get_duration(args, ICAP_ARG_CONNECT_TIMEOUT)? {
        icap_args.connect_timeout = timeout;
    }
    if args.get_flag(ICAP_ARG_DRAIN_RESPONSE) {
        icap_args.drain_response = true;
    }

    Ok(icap_args)
}
