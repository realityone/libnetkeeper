# libnetkeeper

[![CI](https://github.com/realityone/libnetkeeper/actions/workflows/ci.yml/badge.svg)](https://github.com/realityone/libnetkeeper/actions/workflows/ci.yml)

Rust implementations of network authentication algorithms used by several campus and ISP clients.

The crate keeps protocol implementations in memory-safe Rust and supports cross-compilation to
targets such as MIPS and ARM.

## State

The default feature set enables all supported algorithms:

- [SingleNet](https://github.com/singlenet/Anti_teNelgniS)
- Netkeeper
- Netkeeper 4
- [DrCOM](https://github.com/drcoms/drcom-generic)
- SRun3k
- GHCA
- IPClient

## Documents

> TBD

## Develop

Install Rust with [rustup](https://rustup.rs/). The checked-in `rust-toolchain.toml` selects the
nightly channel and installs `rustfmt` and Clippy. The crate uses Rust 2024 and declares Rust 1.85
as its minimum supported compiler version.

### Quality checks

```shell
cargo build --all-features
cargo test --all-features
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

### Issue or Pull Request

Open an issue for protocol questions or submit a pull request with tests for behavior changes.

### Security

Several supported wire protocols require legacy primitives such as MD4, MD5, SHA-1, or AES-ECB.
Use this crate only for interoperability with those protocols, not for designing new security
systems.

### License

`libnetkeeper` is licensed under GPLv3.
