# Contributing

This is the irlume-maintained fork of [rcatolino/pam_sm_rust](https://github.com/rcatolino/pam_sm_rust).
It exists to hold reviewed downstream hardening for the Linux-PAM Rust
binding; it is not a general-purpose fork and does not publish to crates.io.

## Ground rules

- Development happens on pull-request branches against `irlume-patches`.
  Direct pushes to `irlume-patches` and `master` are blocked.
- Every commit is GPG-signed and carries exactly one `Signed-off-by` trailer
  (DCO). `git commit -S -s` produces both.
- Linear history only; review threads must be resolved before merge.
- All eight required checks must pass; administrators are not exempt.

## What gets accepted

- Security hardening and FFI correctness fixes for the exposed binding.
- Fixes for defects that affect consumers of this fork.
- Upstream imports: upstream changes land on `master` first; moving
  `irlume-patches` to a new upstream base requires a dedicated pull request
  with a separated upstream/downstream diff and a full API review.

## What does not

- New public API without a concrete service-module use case, a documented
  safety contract, and tests.
- Anything that weakens fail-closed behavior at the authentication boundary.
- Crates.io publication, renaming, or moving dependency selectors (irlume
  pins exact commit OIDs).

## Development

```bash
cargo test --all-features
cargo test --test pamwrap -- --include-ignored --test-threads=1
bash tests/symbols.sh
bash tests/workflow_contract.sh
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

The pam_wrapper integration needs `libpam0g-dev`, `libpam-wrapper`, and
`pamtester` installed. MSRV is Rust 1.88.
