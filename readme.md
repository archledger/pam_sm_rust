# pamsm (maintenance fork)

> This repository is the GitHub-only fork of `pamsm` maintained for
> [irlume](https://github.com/archledger/irlume). It preserves upstream history
> and GPL-3.0-only licensing while carrying audited hardening changes for
> Linux-PAM module safety. It is **not** published to crates.io. See
> [IRLUME-MAINTENANCE.md](IRLUME-MAINTENANCE.md) before consuming a fork revision.

[![CI](https://github.com/archledger/pam_sm_rust/actions/workflows/ci.yml/badge.svg)](https://github.com/archledger/pam_sm_rust/actions/workflows/ci.yml)
[![Crates.io license shield](https://img.shields.io/crates/l/pamsm.svg)](https://crates.io/crates/pamsm)

Rust FFI wrapper to implement PAM service modules for Linux.

**[Documentation](https://docs.rs/pamsm/) -**
**[Upstream Cargo package](https://crates.io/crates/pamsm) -**
**[Maintained fork](https://github.com/archledger/pam_sm_rust) -**
**[Original repository](https://github.com/rcatolino/pam_sm_rust)**

## Features

This crate supports the following optional features:
* `libpam`: enables the extension trait `PamLibExt` and links against native `libpam.so` for the platform implementation.

## Default branch policy

- `master` follows upstream history only.
- `irlume-patches` is the maintained branch for irlume hardening work.
- This fork keeps CI-focused checks in place and pins audit-critical changes to
  explicit commits in [IRLUME-MAINTENANCE.md](IRLUME-MAINTENANCE.md).

## Development

### Requirements

- Rust toolchain (stable recommended)
- Linux with glibc and PAM headers
- Optional for PAM wrapper integration checks:
  `libpam-wrapper`, `pamtester`

### Common commands

```bash
# Full crate checks
cargo test --all-targets

# Full formatting + lint checks
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings -A clippy::incompatible-msrv

# PAM fixture module and symbol validation
cargo build --example test_module --features libpam
bash tests/symbols.sh
```

### PAM wrapper checks (optional)

Install `libpam-wrapper` and `pamtester` for your distro, then run:

```bash
cargo test --test pamwrap -- --include-ignored --test-threads=1
```

The six PAM entrypoint integration tests are `#[ignore]` when optional host tools are
missing so CI remains deterministic and still validates the integration compile path.

## License

Licensed under **GPL-3.0-only**.
