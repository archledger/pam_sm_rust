# PAM SM

> This is the public, GitHub-only fork maintained for
> [irlume](https://github.com/archledger/irlume). It preserves the original
> project's history and GPL-3.0-only terms while carrying audited Linux-PAM
> boundary changes. It is not published to crates.io. See
> [IRLUME-MAINTENANCE.md](IRLUME-MAINTENANCE.md) before consuming a fork
> revision.

[![Crates.io version shield](https://img.shields.io/crates/v/pamsm.svg)](https://crates.io/crates/pamsm)
[![Crates.io license shield](https://img.shields.io/crates/l/pamsm.svg)](https://crates.io/crates/pamsm)

Rust FFI wrapper to implement PAM service modules for Linux.

**[Documentation](https://docs.rs/pamsm/) -**
**[Upstream Cargo package](https://crates.io/crates/pamsm) -**
**[Maintained fork](https://github.com/archledger/pam_sm_rust) -**
**[Original repository](https://github.com/rcatolino/pam_sm_rust)**

## Features

This crate supports the following optional features:
 * `libpam`: this enables the extension trait `PamLibExt` and linking against `libpam.so` for its native implementation.
