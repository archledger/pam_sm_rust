# Security Policy

## Supported branches

Only the [`irlume-patches`](https://github.com/archledger/pam_sm_rust/tree/irlume-patches)
branch receives security fixes. It carries the downstream hardening on top of
upstream pamsm `0.5.5` and is the only branch consumed by irlume. `master`
mirrors upstream for reference and is not supported.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/archledger/pam_sm_rust/security/advisories/new).
Do not open a public issue for anything that could weaken an authentication
boundary, expose secrets, or simplify memory-safety exploitation.

Include where possible: a minimal reproducer, the affected commit OID, the
entrypoint or wrapper involved, and observed versus expected behavior.

## Scope

This fork is a Linux-PAM Rust binding used in a privileged authentication
path. In scope:

- memory safety or undefined behavior in any `unsafe` block or FFI boundary;
- panics or unwinds crossing the C ABI (`pam_sm_*` entrypoints, cleanup callbacks);
- secret handling: zeroization gaps, secret exposure in formatting or logs;
- fail-open behavior: error paths that yield success or permissive defaults;
- FFI declaration drift against supported Linux-PAM releases;
- CI/workflow weaknesses that gate the above.

Out of scope: vulnerabilities in upstream pamsm code paths that this fork has
removed or never exposes to consumers (report those upstream), and issues in
consumers such as irlume.

## Expectations

- Reports are acknowledged within 7 days.
- Fixes land on `irlume-patches` through a pull request that passes every
  required check; a signed annotated tag follows the fix.
- This fork does not publish to crates.io; consumers pin exact git OIDs, so
  advisories name the fixing commit and tag rather than a registry version.
