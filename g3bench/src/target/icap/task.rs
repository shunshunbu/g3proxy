/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2023-2025 ByteDance and/or its affiliates.
 */

use std::sync::Arc;

use anyhow::anyhow;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;

use super::{BenchIcapArgs, BenchTaskContext, IcapHistogramRecorder, IcapRuntimeStats};
use crate::target::BenchError;

pub(super) struct IcapTaskContext {
    args: Arc<BenchIcapArgs>,
    runtime_stats: Arc<IcapRuntimeStats>,
    histogram_recorder: IcapHistogramRecorder,
}

impl IcapTaskContext {
    pub(super) fn new(
        args: &Arc<BenchIcapArgs>,
        runtime_stats: &Arc<IcapRuntimeStats>,
        histogram_recorder: IcapHistogramRecorder,
    ) -> anyhow::Result<Self> {
        Ok(IcapTaskContext {
            args: Arc::clone(args),
            runtime_stats: Arc::clone(runtime_stats),
            histogram_recorder,
        })
    }

    async fn connect(&self) -> anyhow::Result<TcpStream> {
        self.runtime_stats.add_conn_attempt();
        let target = format!("{}:{}", self.args.target.host_str(), self.args.target.port());
        let addrs = tokio::net::lookup_host(&target)
            .await
            .map_err(|e| anyhow!("failed to resolve {target}: {e}"))?;
        let addr = addrs
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("no resolved address for {target}"))?;
        let stream = tokio::time::timeout(self.args.connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow!("connect timed out"))?
            .map_err(|e| anyhow!("connect failed: {e}"))?;
        self.runtime_stats.add_conn_success();
        Ok(stream)
    }

    async fn run_one(&self) -> anyhow::Result<()> {
        let stream = self.connect().await?;
        let (read_half, mut write_half) = stream.into_split();

        let drain_response = self.args.drain_response;
        let total_bytes = self.args.file_size;
        let chunk_size = self.args.chunk_size;
        let method = &self.args.method;
        let service = &self.args.service;
        let target_host = self.args.target.host();

        // Spawn reader task to drain the response concurrently
        let runtime_stats = Arc::clone(&self.runtime_stats);
        let reader_handle = tokio::spawn(async move {
            let mut reader = read_half;
            let mut total_read: u64 = 0;
            let mut first_line = String::new();
            let mut drain_buf = [0u8; 65536];
            loop {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    reader.read(&mut drain_buf),
                )
                .await
                {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => {
                        total_read += n as u64;
                        if first_line.is_empty() {
                            if let Ok(s) = std::str::from_utf8(&drain_buf[..n.min(200)]) {
                                first_line = s.lines().next().unwrap_or("").to_string();
                            }
                        }
                        if !drain_response {
                            break;
                        }
                    }
                    Ok(Err(_)) => break,
                    Err(_) => break,
                }
            }
            runtime_stats.add_read_bytes(total_read as usize);
            (total_read, first_line)
        });

        // Build ICAP request
        let http_header = "PUT /test.bin FTP/1.0\r\n\
             Content-Type: application/octet-stream\r\n\
             X-FTP-Command: STOR\r\n\
             Transfer-Encoding: chunked\r\n\
             \r\n";
        let icap_header = format!(
            "{} icap://{}/{} ICAP/1.0\r\n\
             Host: {}\r\n\
             Encapsulated: req-hdr=0, req-body={}\r\n\
             Allow: 204\r\n\
             \r\n",
            method,
            target_host,
            service,
            target_host,
            http_header.len()
        );

        write_half
            .write_all(icap_header.as_bytes())
            .await
            .map_err(|e| anyhow!("write icap header: {e}"))?;
        write_half
            .write_all(http_header.as_bytes())
            .await
            .map_err(|e| anyhow!("write http header: {e}"))?;
        write_half
            .flush()
            .await
            .map_err(|e| anyhow!("flush header: {e}"))?;

        // Send body chunks
        let mut remaining = total_bytes;
        let data = vec![0x41u8; chunk_size];
        let mut header_buf = [0u8; 32];

        while remaining > 0 {
            let this_chunk = remaining.min(chunk_size);
            // Write hex chunk header
            let header_len = write_hex_len(&mut header_buf, this_chunk);
            write_half
                .write_all(&header_buf[..header_len])
                .await
                .map_err(|e| anyhow!("write chunk header: {e}"))?;
            write_half
                .write_all(&data[..this_chunk])
                .await
                .map_err(|e| anyhow!("write chunk data: {e}"))?;
            write_half
                .write_all(b"\r\n")
                .await
                .map_err(|e| anyhow!("write chunk crlf: {e}"))?;
            remaining -= this_chunk;
        }

        write_half
            .write_all(b"0\r\n\r\n")
            .await
            .map_err(|e| anyhow!("write terminator: {e}"))?;
        let _ = write_half.shutdown().await;

        let header_bytes = icap_header.len() + http_header.len() + 5;
        self.runtime_stats.add_write_bytes(total_bytes + header_bytes);

        // Wait for reader to drain the response
        let (_, first_line) = reader_handle
            .await
            .map_err(|e| anyhow!("reader task panicked: {e}"))?;

        if first_line.is_empty() {
            return Err(anyhow!("no ICAP response received"));
        }
        if !first_line.starts_with("ICAP/1.0 2") {
            return Err(anyhow!("unexpected ICAP response: {first_line}"));
        }

        Ok(())
    }
}

fn write_hex_len(buf: &mut [u8; 32], len: usize) -> usize {
    // Maximum hex digits for usize on 64-bit: 16, plus "\r\n" = 18 bytes.
    // Write from the end of the buffer backwards.
    let mut pos = buf.len() - 2; // reserve "\r\n" at the end
    buf[buf.len() - 2] = b'\r';
    buf[buf.len() - 1] = b'\n';
    let mut n = len;
    if n == 0 {
        pos -= 1;
        buf[pos] = b'0';
    } else {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        while n > 0 {
            pos -= 1;
            buf[pos] = HEX[n & 0xf];
            n >>= 4;
        }
    }
    buf.len() - pos
}

impl BenchTaskContext for IcapTaskContext {
    fn mark_task_start(&self) {
        self.runtime_stats.add_task_total();
        self.runtime_stats.inc_task_alive();
    }

    fn mark_task_passed(&self) {
        self.runtime_stats.add_task_passed();
        self.runtime_stats.dec_task_alive();
    }

    fn mark_task_failed(&self) {
        self.runtime_stats.add_task_failed();
        self.runtime_stats.dec_task_alive();
    }

    async fn run(&mut self, _task_id: usize, time_started: Instant) -> Result<(), BenchError> {
        let result = tokio::time::timeout(self.args.timeout, self.run_one()).await;

        match result {
            Ok(Ok(())) => {
                let total_time = time_started.elapsed();
                self.histogram_recorder.record_total_time(total_time);
                Ok(())
            }
            Ok(Err(e)) => {
                eprintln!("DEBUG task failed: {e}");
                Err(BenchError::Task(e))
            }
            Err(_) => Err(BenchError::Task(anyhow!("request timed out"))),
        }
    }
}
