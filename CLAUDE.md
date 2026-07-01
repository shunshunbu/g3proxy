# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
cargo build --release                    # Build all default members
cargo test --workspace --lib --examples  # Run tests
cargo clippy --tests -- --deny warnings  # Lint
just check                               # cargo check --workspace
just qa                                  # check + test + clippy
```

Single test:
```bash
cargo test -p <package> <test_name>
```

Run a specific binary (example for `g3proxy`):
```bash
./target/release/g3proxy -c <config_path>
# Useful g3proxy flags:
#   --test-config           load + validate config and exit (no daemon)
#   --output-graphviz-graph dump config graph as graphviz dot to stdout
#   --output-mermaid-graph  dump config graph as mermaid to stdout
#   --output-plantuml-graph dump config graph as plantuml to stdout
```

### Cargo Features

Per-app `Cargo.toml` exposes non-default features that materially change the build:

- **TLS backends** — pick at most one: `rustls-ring` (default), `rustls-aws-lc`, `rustls-aws-lc-fips`.
  `rustls` requires one of these or the build fails to compile (see `g3proxy/src/main.rs`).
- **Vendored SSL** — `vendored-openssl`, `vendored-tongsuo` (TLCP / SM2-SM3-SM4),
  `vendored-boringssl`, `vendored-aws-lc`, `vendored-aws-lc-fips`. See `doc/openssl-variants.md`.
- **DNS resolver** — `c-ares` (default) or `vendored-c-ares` to build c-ares from source.
- **Scripting** — `python` (default), and one of `lua54` (default), `lua53`, or `luajit`.
- **QUIC** — `quic` (default) pulls in `quinn`/`h3`.

Examples:
```bash
# Static musl build with vendored deps
cargo build --target=x86_64-unknown-linux-musl --no-default-features \
  --features vendored-openssl,vendored-c-ares

# Build against Tongsuo for TLCP support
cargo build --features vendored-tongsuo
```

### Release Profiles

The workspace defines three custom profiles in `Cargo.toml` in addition to the stock `release`:
`release-lto` (strip + LTO), `release-dbg` (debug info, no debug-assertions),
`release-z` (`opt-level=z`, LTO, panic=abort, strip — for size).

### Regenerating Cap'n Proto Bindings

After editing any `*.capnp` schema under `<app>/proto/schema/`, regenerate the Rust bindings:

```bash
cargo run -p capnp-generate -- <path-to-proto-dir>
# e.g. cargo run -p capnp-generate -- g3proxy/proto
```

## Architecture

### Workspace Structure

**Applications** (binaries in the workspace root): `g3proxy`, `g3statsd`, `g3tiles`,
`g3bench`, `g3mkcert`, `g3fcgen`, `g3iploc`, `g3keymess`.

**Shared Libraries** (`lib/`): ~45 internal crates under `g3-*`. The most-trafficked:
- `g3-types` — core types (ACL, auth, config, metrics, routing, async-log traits)
- `g3-yaml` — deserializers; pulling features here (e.g. `resolve`, `dpi`, `geoip`,
  `acl-rule`, `http`, `route`, `histogram`) turns on the matching g3-* sub-modules
- `g3-resolver` — DNS resolution (c-ares / hickory, QUIC for DoQ)
- `g3-tls-cert` / `g3-openssl` / `g3-tls-ticket` — TLS infrastructure
- `g3-http` / `g3-h2` — HTTP/1 and HTTP/2 protocol handling
- `g3-socket` / `g3-io-ext` / `g3-io-sys` — network and async I/O
- `g3-dpi` — deep packet inspection
- `g3-icap-client` — ICAP for content adaptation
- `g3-ftp-client` / `g3-smtp-proto` / `g3-imap-proto` — protocol parsers
- `g3-daemon` — daemonization, signal handling, control-plane glue
- `g3-build-env` — build-script helper (set in `[build-dependencies]` of each app)

### Application Structure (e.g., g3proxy)

Each app follows the same internal layout under `src/`:
- `main.rs` — entry point. Pairs with `build.rs` (uses `g3-build-env` to embed
  build metadata), `opts.rs` (clap-based CLI parser), `signal.rs` (SIGUSR/SIGTERM
  handlers), and `lib.rs` (re-exports submodules).
- `serve/` — listener types. One module per protocol/port kind (e.g. `http_proxy`,
  `socks_proxy`, `sni_proxy`, `tcp_tproxy`, `tls_stream`, `plain_tls_port`,
  `plain_quic_port`). Each listener registers itself in `registry.rs` and has its
  own accept loop in `task.rs`.
- `escape/` — egress forwarding: pick an upstream, dial, relay bytes.
- `inspect/` — wire-protocol parsers (HTTP/1, HTTP/2, IMAP, SMTP) and the
  interception/MITM hooks.
- `config/` — YAML config types. Loading is split per-listener and per-escape;
  the top-level config has a `graphviz_graph()` / `mermaid_graph()` /
  `plantuml_graph()` helper exposed via `--output-*-graph` flags for debugging.
- `control/` — daemon control surface (see RPC below).
- `audit/`, `log/`, `stat/` — audit pipeline, slog setup, stat aggregation threads.
- `auth/` — authentication handlers.
- `resolve/` — DNS resolution integration (wraps `g3-resolver`).
- `module/` — task-specific worker modules (e.g. ICAP, geoip).

Config samples for `g3proxy` live under `etc/g3proxy/` (referenced in the project
README; the in-tree `编译运行.md` is a terse Chinese cheatsheet).

### RPC Communication

Daemon-to-daemon and CLI-to-daemon control planes use **Cap'n Proto RPC**
(`capnproto` crate). Each app that has a control surface has a sibling `proto/`
crate; schemas live in `proto/schema/*.capnp` and generated code in `proto/gen/`.

### TLS Stack

Multiple TLS backends via feature flags on each app's `Cargo.toml`:
- OpenSSL (default, via the `variant-ssl` rename of `openssl`/`openssl-sys`)
- BoringSSL, AWS-LC, AWS-LC-FIPS, Tongsuo (TLCP / SM2-SM3-SM4) — vendored variants
- rustls (ring by default; `rustls-aws-lc` / `rustls-aws-lc-fips` for AWS-LC backends)

### Key Dependencies

- **Async runtime**: tokio
- **HTTP**: `http`, `h2`, `h3-quinn`/`h3`, `quinn` (QUIC)
- **DNS**: `c-ares` / `c-ares-resolver`, `hickory-proto` / `hickory-client`
- **Serialization**: serde, `yaml-rust2`, `rmp-serde`/`rmp`, capnp
- **Logging**: slog (primary), `log` crate (feature-gated levels), tracing is not used
- **Scripting**: `mlua` (Lua), `pyo3` (Python) — both optional, feature-gated

## Development Notes

- Minimum Rust version: **1.86** (CI matrix tests 1.86, stable, beta, nightly).
- Workspace uses edition 2024, resolver = "3".
- CI branches: `master` and `lts/**`. See `doc/long-term_support.md` for the
  long-term-support policy.
- PRs use **"Squash and Commit"** with subject prefix `<area>: <message>`
  (e.g. `g3proxy: fix H2 stream reset race`). See `CONTRIBUTING.md`.
- Code must comply with the standards catalogued in `doc/standards.md` (RFCs
  for HTTP, TLS, DNS, SMTP, IMAP, ICAP, etc.).
- System dependencies for a Debian build host:
  `gcc pkgconf make capnproto libssl-dev libc-ares-dev lua5.4-dev libpython3-dev`
  plus the python3 packages listed in `doc/dev-setup.md`. macOS / Windows /
  BSD / OmniOS notes are also in that doc.
- Scripts under `scripts/` use Python 3 (coverage, packaging, license bundling,
  release tarballs). The `scripts/release/` directory holds `build_tarball.sh`,
  `prepare_package.sh`, and license/manifest tooling.
- `sphinx/` holds the per-app reference-doc sources (built by Read the Docs).
- HTML docs reference: <https://g3-project.readthedocs.io/>.
- **Linux only** is fully supported; FreeBSD/NetBSD/OpenBSD/macOS/Windows compile
  but are not regularly tested.

### Protocol-Specific Notes

- **FTP/ICAP upload audit** (FTP/FTPS proxy with REQMOD audit on upload data
  channel) has three recent bug fixes and a backlog of follow-ups.
  See `doc/ftp-icap-upload-fixes.md` before changing anything in
  `g3proxy/src/inspect/ftp/`, `g3proxy/src/serve/ftp_proxy/`, or
  `lib/g3-icap-client/src/reqmod/ftp/`. The key invariant: ICAP or upstream
  slowness must NEVER stall the actual upload to the FTP server.

## Security

Report vulnerabilities through ByteDance Security
(<https://security.bytedance.com/src> or `sec@bytedance.com`) — **do not** open
a public GitHub issue. See `README.md` for full disclosure policy.
</content>
</invoke>