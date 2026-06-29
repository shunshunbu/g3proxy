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

Run a specific binary:
```bash
./target/release/g3proxy -c <config_path>
```

## Architecture

### Workspace Structure

**Applications** (binaries): `g3proxy`, `g3statsd`, `g3tiles`, `g3bench`, `g3mkcert`, `g3fcgen`, `g3iploc`, `g3keymess`

**Shared Libraries** (`lib/`): 45 internal crates providing common functionality. Key ones:
- `g3-types` — Core types (ACL, auth, config, metrics, routing)
- `g3-resolver` — DNS resolution with c-ares and hickory
- `g3-tls-cert` / `g3-openssl` / `g3-tls-ticket` — TLS infrastructure
- `g3-http` / `g3-h2` — HTTP protocol handling
- `g3-socket` — Network socket abstractions
- `g3-io-ext` — Async I/O extensions
- `g3-dpi` — Deep packet inspection
- `g3-icap-client` — ICAP protocol client for content adaptation
- `g3-ftp-client` / `g3-smtp-proto` / `g3-imap-proto` — Protocol parsers

### Application Structure (e.g., g3proxy)

Each application follows a similar pattern:
- `src/main.rs` — Entry point with signal/subsystem setup
- `src/serve/` — Protocol servers (tcp, tls, http, etc.)
- `src/escape/` — Traffic forwarding/relaying logic
- `src/inspect/` — Content inspection and protocol parsing
- `src/config/` — Configuration loading and types
- `src/control/` — Daemon control interface (capnproto RPC)
- `src/audit/` — Audit/logging subsystem
- `src/auth/` — Authentication handlers
- `src/resolve/` — DNS resolution integration
- `src/module/` — Task-specific worker modules

### RPC Communication

Applications use **Cap'n Proto RPC** (`capnproto` crate) for daemon-to-daemon and control-plane communication. Control interfaces are defined in `*/proto/` subdirectories.

### TLS Stack

The project supports multiple TLS backends via feature flags:
- OpenSSL (default, via `variant-ssl`)
- BoringSSL, AWS-LC, AWS-LC-FIPS, Tongsuo
- rustls (partial support)

### Key Dependencies

- **Async Runtime**: tokio
- **HTTP**: h2, h3-quinn, hyper
- **DNS**: c-ares, hickory-proto
- **Serialization**: serde, yaml-rust2, rmp-serde, capnp
- **Logging**: slog, tracing

## Development Notes

- Minimum Rust version: 1.86
- Uses edition 2024
- Code must comply with standards in `doc/standards.md` (RFCs for HTTP, TLS, DNS, SMTP, IMAP, etc.)
- System dependencies: OpenSSL, c-ares, lua, python3, capnproto
- Scripts use Python 3 for packaging and release tasks