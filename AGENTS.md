# Repository Guidelines

## Project Structure & Module Organization

This repository is a Rust library crate. `src/lib.rs` exposes feature-gated protocol modules: `netkeeper`, `netkeeper4`, `singlenet`, `drcom`, `ghca`, `srun3k`, and `ipclient`. Shared byte parsing, dialing, and utility code lives in `src/common/`; cryptographic helpers live in `src/crypto/`. Protocol implementations generally separate responsibilities into `dialer.rs`, `heartbeater.rs`, and `mod.rs`. Tests are co-located with their modules in `tests.rs` files or inline `#[cfg(test)]` modules. Treat `target/` as generated output.

## Build, Test, and Development Commands

`rust-toolchain.toml` selects the nightly toolchain with `rustfmt` and Clippy. Rustup installs the configured components automatically.

- `cargo build --all-features` compiles every supported protocol module.
- `cargo build --release` creates an optimized library under `target/release/`.
- `cargo test --all-features` runs the complete unit and documentation test suite.
- `cargo test singlenet` runs tests whose names or module paths match one protocol.
- `cargo fmt --all -- --check` verifies formatting without modifying files; run `cargo fmt --all` to apply it.
- `cargo clippy --all-targets --all-features -- -D warnings` enforces warning-free modern Rust style.

## Coding Style & Naming Conventions

Use Rust 2024 idioms, four-space indentation, and let `rustfmt.toml` define formatting details. Follow standard Rust naming: `snake_case` for modules, functions, and test names; `CamelCase` for structs, enums, and traits; `SCREAMING_SNAKE_CASE` for constants. Unsafe code is forbidden. Keep protocol-specific behavior inside its protocol directory, and move reusable packet or byte-handling logic into `common`. Preserve existing feature gates when adding optional modules.

## Testing Guidelines

Add focused unit tests beside the code they exercise. Name tests descriptively with a `test_` prefix, such as `test_netkeeper_heartbeat_parse`. For packet encoders and decoders, assert exact byte output and round-trip parsing where practical. No coverage threshold is configured, but new behavior and bug fixes should include regression tests. Run formatting and the all-feature test suite before opening a pull request.

## Commit & Pull Request Guidelines

Recent commits use brief, lowercase, imperative subjects, for example `upgrade dependency close #14` and `setup rustfmt`. Keep each commit scoped to one logical change and include an issue reference when applicable. Pull requests should explain the affected protocol, summarize observable behavior, link relevant issues, and list tests run. Highlight compatibility or wire-format changes explicitly; screenshots are unnecessary for this library.

## Security & Test Data

Do not commit real account credentials, shared keys, MAC addresses, or production packet captures. Use clearly synthetic values in fixtures and examples.
