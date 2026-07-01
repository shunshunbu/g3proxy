# FTP/ICAP Upload Audit — Bug Fixes and Diagnostics

This document records the bugs found, fixes applied, diagnostic methodology, and
future optimization directions for the FTP/FTPS upload audit feature introduced
in commit `c44df7e` ("支持 http/https 代理上行带载荷送 icap 审计,
ftp/ftps 代理上传文件带载荷送 icap 审计, icap 中携带 5 元祖,
icap 中携带 sslkeylog 相关信息").

The affected source trees are:

- `g3proxy/src/inspect/ftp/` — FTP control / data channel interception
- `g3proxy/src/serve/ftp_proxy/` — FTP proxy server, audit bridge
- `lib/g3-icap-client/src/reqmod/ftp/` — ICAP REQMOD adapter for FTP uploads

All three fixes target the **non-blocking delivery** property promised by the
audit feature: ICAP failures or upstream slowness must NEVER stall the actual
upload to the FTP server.

---

## 1. Bug: chunk-size written in decimal, c-icap rejects body

### Symptom

c-icap logs both:

```
[ERROR] audit_check_preview_handler#################################
Error parsing chunks!
```

The first line is noise from the audit module's preview handler being called
with a zero-byte preview (see §4 below). The second line is the real failure.

### Root cause

`lib/g3-icap-client/src/reqmod/ftp/mod.rs` used `itoa::Buffer::format()` to
serialize the chunk size, which produces **decimal** output:

```rust
// before
let mut hex = itoa::Buffer::new();       // misnamed: itoa is decimal-only
let hex_s = hex.format(data.len());
writer.write_all(hex_s.as_bytes()).await?;
writer.write_all(b"\r\n").await?;
writer.write_all(data).await?;
writer.write_all(b"\r\n").await
```

RFC 7230 §4.1 requires `chunk-size = 1*HEXDIG`, so the body parser in c-icap
saw values like `100\r\n`, parsed them as hex `0x100 = 256`, tried to read 256
bytes, found only 100, and reported `Error parsing chunks!` once alignment
slipped past the first chunk.

All other ICAP body writers in this codebase already use `format!("{:x}\r\n", ...)`
(`reqmod/h1/forward_body.rs`, `reqmod/h1/preview.rs`, `respmod/h1/forward_body.rs`,
`reqmod/imap/append/mod.rs`). The FTP adapter was the odd one out.

### Fix

```rust
// after
async fn write_icap_chunk<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> io::Result<()> {
    let chunk_header = format!("{:x}\r\n", data.len());
    writer.write_all(chunk_header.as_bytes()).await?;
    writer.write_all(data).await?;
    writer.write_all(b"\r\n").await
}
```

The terminating chunk `0\r\n\r\n` is correct in both decimal and hex (zero is
zero), so no change needed there.

---

## 2. Bug: `intercept_pending` blocks on synchronous upstream write

### Symptom

Plain FTP uploads (no ICAP) of large files (>1 GiB) hang and trigger TCP
retransmits from the client, looping forever. Disabling ICAP did not help.

### Root cause (first attempt — incomplete)

`g3proxy/src/inspect/ftp/upload_data.rs::intercept_pending` is reached when
the data channel arrives before the FTP control channel has been parsed for
STOR/APPE (`upload_info` is `None` at that point). It reads the first chunk
into `clt_buf`, then synchronously wrote it to `ups_w` before spawning the
relay tasks:

```rust
// before (both no-ICAP branches)
Ok(n) => {
    // ...
    let _ = ups_w.write_all(&clt_buf[..n]).await;   // <-- blocks here
    let _ = run_ftp_upload_audit_or_relay_bidi(...).await;
    break;
}
```

If upstream backpressured this 4 KiB write, the relay tasks were never
spawned, `clt_r` had no reader, the client kernel recv buffer filled, and
TCP ZeroWindow was advertised.

### Fix (necessary but not sufficient)

Mirror what the ICAP branch already did: prepend the just-read chunk to the
stream via `Cursor::chain`, so the relay task sees a continuous stream from
byte 0 and the synchronous `ups_w.write_all` is removed:

```rust
// after
Ok(n) => {
    let clt_r = io::Cursor::new(clt_buf[..n].to_vec()).chain(clt_r);
    // pass clt_r into run_ftp_upload_audit_or_relay_bidi(...)
    // no ups_w.write_all anywhere in this branch
}
```

This unblocks the relay startup. It does **not** address per-chunk writes
inside the relay — see §3.

### Why FTPS didn't show this symptom

The data-channel TLS path constructs `FtpUploadDataInterceptObject` directly
with `upload_info` already set
(`g3proxy/src/inspect/tls/mod.rs:549-573`), bypassing `intercept_pending`
entirely. So the FTPS symptom is only "slow" (TLS/MITM CPU cost), not "hang".

---

## 3. Bug: `bidi_half_relay_with_idle` couples `r.read` and `w.write_all`

### Symptom

Even after the §2 fix, plain FTP uploads still hung. Packet capture
(`tcpdump`) showed the receiver (g3) advertising **TCP ZeroWindow** to the
client shortly after the upload started. The same symptom appeared on small
files (7 MiB) and large files (>1 GiB), ruling out total-size effects.

### Root cause

`g3proxy/src/serve/ftp_proxy/audit_bridge.rs::bidi_half_relay_with_idle` ran
the relay loop in a single task:

```rust
// before
loop {
    res = r.read(&mut buf) => {              // ① read client
        if w.write_all(&buf[..n]).await.is_err() { break; }  // ② write upstream
    }
}
```

`write_all` awaits until all bytes are in the upstream socket's kernel send
buffer. Whenever that buffer filled (upstream slow disk, rate-limited peer,
transient stall), the await blocked. During the block, `clt_r` was not
read, the client kernel recv buffer filled, g3 advertised ZeroWindow, the
client stopped, and TCP retransmits started. The kernel TCP buffers
(~64 KiB receive / ~200 KiB send) fill in milliseconds at typical upload
rates, which is why even 7 MiB uploads reproduce this.

### Fix

Decouple the read and write via a bounded `flume` channel and a separate
writer task. The reader's only blocking point becomes the channel `send`
(which is non-blocking until the channel is full), so the client stream is
read as continuously as the kernel allows:

```rust
// after
async fn bidi_half_relay_with_idle<R, W>(r: R, w: W, idle_wheel: Arc<IdleWheel>, max_idle_count: usize)
where
    R: AsyncRead + Send + Sync + Unpin + 'static,
    W: AsyncWrite + Send + Sync + Unpin + 'static,
{
    let (chunk_tx, chunk_rx) = flume::bounded::<bytes::Bytes>(8);

    let writer = tokio::spawn(async move {
        let mut w = w;
        let mut rx = chunk_rx;
        while let Ok(chunk) = rx.recv_async().await {
            if w.write_all(&chunk).await.is_err() { break; }
        }
        let _ = w.flush().await;
        let _ = w.shutdown().await;
    });

    let mut r = r;
    let mut idle_interval = idle_wheel.register();
    let mut idle_count = 0usize;
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        tokio::select! {
            biased;
            res = r.read(&mut buf) => {
                match res {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        idle_count = 0;
                        let chunk = bytes::Bytes::copy_from_slice(&buf[..n]);
                        if chunk_tx.send_async(chunk).await.is_err() { break; }
                    }
                }
            }
            _ = idle_interval.tick() => {
                idle_count += 1;
                if idle_count >= max_idle_count { break; }
            }
        }
    }
    drop(chunk_tx);
    let _ = writer.await;
}
```

In-flight capacity becomes: `clt_r kernel recv buffer` + `flume channel`
+ `ups_w kernel send buffer`, totalling hundreds of KiB to several MiB on
Linux defaults. Far more headroom than the single task had.

Signature change: `R`/`W` now require `+ 'static` because the writer is
spawned. All call sites in `run_ftp_upload_audit_or_relay_bidi` already
have `'static` on their generics, so this is backward-compatible.

### Verification

- 1 MiB FTPS upload: still succeeds (regression check on small traffic).
- 7 MiB plain FTP: no TCP ZeroWindow in packet capture.
- 1 GiB+ plain FTP: completes; observed throughput improvement matches
  expectation that the read no longer stalls behind upstream writes.

---

## 4. Side finding: `audit_check_preview_handler` ERROR is noise

When c-icap is configured, the log shows:

```
[ERROR] audit_check_preview_handler#################################
```

This is from the audit module's own `LOG_ERROR` inside its preview handler
(`/home/lj/forwardproxy/libicap_audit/http_audit.cc:824`). The audit module
explicitly disables preview at init:

```cpp
ci_service_set_preview(srv_xdata, -1);   // 关闭 preview
```

Yet the service struct still registers a preview handler:

```cpp
CI_DECLARE_MOD_DATA ci_service_module_t service = {
    ...
    audit_check_preview_handler,
    ...
};
```

c-icap calls the registered preview handler with `preview_len = 0` even when
preview is disabled; the handler logs the misleading ERROR and returns
`CI_MOD_CONTINUE`. Request processing is unaffected.

Implications for g3:

- g3 does **not** need to implement the preview flow for this audit module.
  The FTP adapter's current "send full body, no Preview header" behavior is
  correct against this server.
- If g3 ever talks to a server that genuinely requires preview (e.g., a
  commercial DLP/AV ICAP), the same preview path used by `H1ReqmodAdapter`
  (`lib/g3-icap-client/src/reqmod/h1/preview.rs`) should be lifted into the
  FTP adapter. See §6.

---

## 5. Diagnostic methodology (for next time)

A practical recipe that worked here:

1. **Capture both sides**: get the c-icap server log AND a client-side
   packet capture for the failing flow.
2. **Distinguish two failure modes**:
   - `Error parsing chunks!` → chunk-size / body framing issue (§1).
   - TCP ZeroWindow advertised by the receiver → coupling between the
     reader and a slow downstream writer (§2, §3).
3. **Disable components to isolate**: turn ICAP off to confirm the issue is
   in the relay; turn TLS off to confirm TLS overhead vs hang.
4. **Don't trust the first log line**: c-icap-style modules log noise from
   internal handlers (`audit_check_preview_handler`) that look like errors
   but return success. Read multiple lines together.
5. **Trace ownership**: when "the relay task isn't reading the client",
   ask whether the task was even spawned. If yes, ask what it's blocked on.

---

## 6. Future optimization directions

Listed in priority order; each is small and self-contained.

### 6.1 ICAP task split for `audit_and_forward` / `audit_only`

`lib/g3-icap-client/src/reqmod/ftp/mod.rs::audit_and_forward` still has the
same coupled-read/write pattern as §3 — only the writer that can block
is ICAP, not upstream:

```rust
ups_w.write_all(&buf[..n]).await?;             // upstream (less likely to stall)
if write_icap_chunk(...).await.is_err() { ... }  // ICAP (the actual likely stall)
```

Apply the same `flume::bounded(8)` + spawned writer pattern as §3. The
c-icap audit module's end-of-data handler synchronously pushes to Kafka /
MinIO / HTTP 4-tuple reporter, so ICAP backpressure is expected and
frequent for large bodies.

Estimated effort: +50–80 lines, identical architecture to §3.

### 6.2 Configurable flume channel capacity

The current 8-chunk capacity (≈256 KiB at 32 KiB chunks) is sufficient for
typical disk-rate stalls. For very bursty upstream / very fast local links,
expose the capacity as a constant or config knob. Watch out:

- Larger capacity ⇒ more in-flight memory; ratio is roughly
  `capacity × chunk_size` plus whatever the kernel buffers add.
- Smaller capacity ⇒ faster backpressure response, more stutter risk.

### 6.3 Configurable socket buffer sizes

For both `clt_r` (server side of data connection) and `ups_w` (client side
of upstream connection), bumping `SO_RCVBUF` / `SO_SNDBUF` via
`set_send_buffer_size` (`lib/g3-socket/src/raw/mod.rs:38`) widens the
kernel-level in-flight budget. Requires `net.core.wmem_max` /
`net.core.rmem_max` to allow it, otherwise the `setsockopt` silently caps.

### 6.4 Total-deadline / progress timeout

`g3-io-ext::LimitedCopyConfig` exposes `total_timeout` for similar copy
loops. `bidi_half_relay_with_idle` and `audit_and_forward` only have an
**idle** timeout (`max_idle_count` on the `IdleWheel`). A permanently
hung peer (not slow, just stuck) will block forever today. Adding a wall-
clock total deadline on top of idle would close this gap.

### 6.5 Lazy ICAP preview support

If/when g3 talks to ICAP servers that actually use preview
(commercial DLP, some AV scanners), port the `H1ReqmodAdapter::xfer_with_preview`
flow (`lib/g3-icap-client/src/reqmod/h1/preview.rs`) into the FTP adapter.
Pattern: read up to `icap_options.preview_size` bytes, send with
`Preview: <N>` header + first chunked body, wait for `100 Continue`, then
stream the rest. Wrap the same `audit_only` body for the no-upstream path.

### 6.6 Server-side flow for non-streamed uploads

Some FTP servers close the data connection only after the disk write
completes. `up_to_client` in `run_ftp_upload_audit_or_relay_bidi` blocks on
`ups_r.read` until the server sends FIN. If a server stalls here, the whole
`tokio::join!` stalls. Consider an explicit "data connection closed by
client → wait at most N seconds for upstream FIN → force shutdown" policy.
Today this is partially handled by `tokio::time::timeout` only on the
ICAP branch.

---

## 7. Verification checklist

When changing any of the above, run:

```bash
cargo build --release -p g3proxy --bin g3proxy
# only g3proxy needs to be redeployed; lib changes are statically linked.
```

| Scenario | Expected behavior |
|---|---|
| 1 MiB FTPS upload, ICAP on | completes; c-icap logs only the (noise) preview line |
| 7 MiB plain FTP, ICAP off | completes; no TCP ZeroWindow |
| 1 GiB+ plain FTP, ICAP off | completes; throughput ~line rate |
| 1 GiB+ plain FTP, ICAP on | after §6.1: completes; before §6.1: works but may ZeroWindow on slow ICAP |
| ICAP server killed mid-upload | upload completes; `OriginalTransferredAfterFallback` logged |

---

## 8. Commit message template

```
g3proxy: <one-line summary>

Context: <bug found by / fix for symptom>
Root cause: <one paragraph>
Fix: <one paragraph>
Verification: <what was tested>

Co-Authored-By: Claude <noreply@anthropic.com>
```