# Irlume maintenance contract

This repository is the public, GitHub-only pamsm fork maintained for
[irlume](https://github.com/archledger/irlume). It is not a crates.io
publication and does not replace or claim ownership of the upstream `pamsm`
package.

## Upstream baseline

- Original repository: <https://github.com/rcatolino/pam_sm_rust>
- Upstream tag: `0.5.5`
- Upstream commit: `a51131ebaa252a9c77727f65d962d33d8a632e87`
- crates.io package: `pamsm 0.5.5`
- crates.io checksum:
  `aad7ddca63c73e80eb4ace88e130c9b513da6ec1284becd9fc1fc385a9a72a64`
- License: GPL-3.0-only; original copyright and license text are preserved

The Cargo metadata spelling changed from deprecated `GPL-3.0` to
`GPL-3.0-only`. That describes the existing license accurately and does not
relicense the code or add an “or later” grant.

## Branches and consumption

- `master` mirrors the original upstream and carries no irlume-only commits.
- `irlume-patches` is the maintained default branch.
- Development happens on pull-request branches based on `irlume-patches`.
- Irlume consumes only a reviewed full 40-character commit OID. It never pins a
  branch, tag, abbreviated hash, or generated archive URL.
- Signed annotated `irlume-0.5.5-patch.N` tags identify audited human
  checkpoints, but tags are not Cargo dependency selectors.

The current development branch is not an approved dependency checkpoint. Do
not point irlume at this fork until the initial entrypoint, handle, secret,
FFI, real-PAM, sanitizer, CodeQL, DCO, and workflow-security hardening is
complete and a signed checkpoint tag exists.

## Downstream change ledger

### Irlume PAM token boundary

Source product change:
[`a4e6ba59548dd427632c0c2d8f80a52ef96a7a39`](https://github.com/archledger/irlume/commit/a4e6ba59548dd427632c0c2d8f80a52ef96a7a39),
merged through [irlume PR #502](https://github.com/archledger/irlume/pull/502).
The enclosing fork commit is named `feat: own irlume PAM token boundary`.

- Add `PamLibExt::clear_authtok`, backed by
  `pam_set_item(PAM_AUTHTOK, NULL)`.
- Add response-free `PamLibExt::info`, backed by
  `pam_prompt(PAM_TEXT_INFO, NULL, "%s", message)`.
- Remove the generic borrowed-response `conv` wrapper and its invalid pointer
  dereferences.
- Normalize one pre-existing macro expression to the Rust 1.88 formatter;
  behavior is unchanged.

Later downstream changes must add their exact commit, rationale, affected API,
tests, and originating irlume issue or pull request to this ledger.

### Checked PAM entrypoint dispatch

Design source:
[irlume PR #503](https://github.com/archledger/irlume/pull/503), merged as
[`8862672c7a9063f3fe648c15e91f48c7d4f6a031`](https://github.com/archledger/irlume/commit/8862672c7a9063f3fe648c15e91f48c7d4f6a031).
The enclosing fork commit is named `fix: validate PAM entrypoint pointers`.

- Export the PAM callback handle with its real raw-pointer C ABI.
- Route all six `pam_sm_*` symbols through one checked dispatcher.
- Reject null handles, negative or oversized argument counts, null arrays,
  null elements, and invalid UTF-8 before the Rust hook runs.
- Bound module arguments at 256 and preserve their order.
- Convert hook and panic-payload destructor panics to `PAM_ABORT` without
  unwinding across the C boundary.
- Cover the dispatcher with focused unit tests and all six macro-expanded
  entrypoints with an integration test.

### Callback-scoped PAM handles and forward-compatible flags

Design source:
[irlume PR #503](https://github.com/archledger/irlume/pull/503), merged as
[`8862672c7a9063f3fe648c15e91f48c7d4f6a031`](https://github.com/archledger/irlume/commit/8862672c7a9063f3fe648c15e91f48c7d4f6a031).
The enclosing fork commit is named `refactor: confine PAM handles to callbacks`.

- Remove `PamSendRef`, `Pam::as_send_ref`, and the manual `unsafe impl Send` so
  a PAM transaction handle cannot escape its callback thread through the safe
  public API.
- Keep `Pam` compiler-derived `!Send + !Sync` with a private zero-sized marker;
  this has no runtime storage cost and requires no unsafe auto-trait claim.
- Upgrade to bitflags 2 while preserving `PamFlags`' prior standard traits.
- Retain unknown PAM flag bits at the checked callback boundary so newer PAM
  flags remain visible to downstream modules.
- Cover callback-thread confinement with compile-fail documentation and verify
  unknown-bit delivery through a macro-expanded PAM entrypoint.

### Zeroizing PAM module secrets

Design source:
[irlume PR #503](https://github.com/archledger/irlume/pull/503), merged as
[`8862672c7a9063f3fe648c15e91f48c7d4f6a031`](https://github.com/archledger/irlume/commit/8862672c7a9063f3fe648c15e91f48c7d4f6a031).
The enclosing fork commit is named `fix: zeroize PAM module secrets`.

- Replace plain `Vec<u8>` module storage with opaque `PamSecretBytes`, explicit
  borrowed exposure, and redacted `Debug` output.
- Zeroize the initialized bytes and full spare capacity before releasing a
  secret allocation.
- Add owned `send_secret` and transaction-borrowed `get_secret`; failed secret
  and generic typed-data registrations reclaim immediately, while secret
  retrieval rejects errors and null success outputs before constructing a
  reference.
- Remove `send_bytes`, `retrieve_bytes`, `PamByteData`, and `PamCleanupCb` so no
  public non-zeroizing byte-storage alternative remains.
- Contain stored-value, cleanup-observer, and panic-payload destructor panics;
  tolerate null cleanup pointers and free accepted allocations exactly once
  on replacement or transaction end.
- Cover redaction, explicit exposure, zeroization sabotage, ownership transfer,
  null/error retrieval, replacement/end cleanup, and panic containment with
  focused tests; migrate the example module to the secret API.

### Audited Linux-PAM FFI and checked outputs

Design source:
[irlume PR #503](https://github.com/archledger/irlume/pull/503), merged as
[`8862672c7a9063f3fe648c15e91f48c7d4f6a031`](https://github.com/archledger/irlume/commit/8862672c7a9063f3fe648c15e91f48c7d4f6a031).
The enclosing fork commit is named `fix: validate Linux-PAM FFI outputs`.

Declaration sources are Linux-PAM's official
[`_pam_types.h`](https://github.com/linux-pam/linux-pam/blob/master/libpam/include/security/_pam_types.h),
[`pam_modules.h`](https://github.com/linux-pam/linux-pam/blob/master/libpam/include/security/pam_modules.h),
and
[`pam_ext.h`](https://github.com/linux-pam/linux-pam/blob/master/libpam/include/security/pam_ext.h).
The checked Rust signatures also matched bindgen 0.72.1 output from the locally
installed Linux-PAM 1.7.2 headers.

- Keep every raw symbol inside one private `ffi` module and expose only checked
  `PamResult` wrappers.
- Represent mutable and const opaque PAM handles separately, and declare
  `pam_syslog` with its actual C `void` return.
- Inspect return status before any output pointer. Preserve optional null PAM
  items, but map successful missing user, authentication-token, and module-data
  outputs to `PAM_SYSTEM_ERR`.
- Inject `pam_get_item`, `pam_get_user`, `pam_get_authtok`, `pam_set_item`, and
  `pam_putenv` through one private function table; keep the variadic
  response-free `pam_prompt` behind a non-variadic helper.
- Retain `PAM_DATA_SILENT` in cleanup flags, expose its named flag alongside
  `PAM_DATA_REPLACE`, and keep the low PAM result byte out of the flag domain.
- Remove unused conversation-layout types and unused raw declarations left
  behind when the response-returning conversation API was retired.
- Deny improper FFI types, improper FFI definitions, and implicit unsafe
  operations inside unsafe functions; cover error-before-pointer, required
  null, valid output, status propagation, handle mutability, and cleanup flags
  with focused tests.

### Real PAM integration and exported symbols

Fork commits `test: add PAM wrapper integration for all PAM hooks` and the
fixture/symbol audit it introduced.

- Build a test-only `cdylib` from the fork exercising all six `pam_sm_*`
  entrypoints and the hardened wrappers, and run it through pam_wrapper plus
  pamtester with per-case generated service files under a private temporary
  directory.
- Audit exported symbols with `nm -D --defined-only`: the fixture must export
  exactly the six `pam_sm_*` names and nothing else.
- Fixed dummy token `fixed-ci-dummy` only; captured output, debug formatting,
  and retained artifacts must never contain it. The CI job fails if it
  appears in captured harness logs.
- The pam_wrapper lane runs serially (`--test-threads=1`) because PAM
  process-global state is shared.

### Governance, CI, sanitizers, and workflow security

Fork commits `ci: replace travis with GitHub Actions and refresh readme` through
the governance checkpoint; superseded the interim soft-gated CI.

- Replace the inherited Travis CI with GitHub Actions. Eight required check
  names: `fmt · clippy · build · test`, `pam_wrapper integration`,
  `AddressSanitizer (test suite)`, `Analyze (rust)`,
  `cargo-deny (advisories · licenses · sources)`,
  `actionlint (workflow correctness)`, `zizmor (workflow security)`, and
  `DCO (exactly one trailer)`.
- SHA-pin every action, disable persisted checkout credentials, keep default
  permissions at `contents: read`, and run MSRV 1.88.0 alongside stable.
  The pam_wrapper lane is a hard gate (no `continue-on-error`).
- `tests/workflow_contract.sh` statically enforces the pin/permission/check
  name/MSRV/sanitizer/no-publication rules on every change.
- Declare `rust-version = "1.88"` and `edition = "2021"`; align `.clippy.toml`
  msrv to 1.88; drop the advisory-laden `time` 0.2 dev-dependency and rewrite
  the crate doc example without it. Edition 2021 required `crate::`-qualified
  internal imports, C-string literals in the prompt helpers, and inlined
  format args in tests; both Rust 1.88.0 and current stable clippy run clean.
- Remove the unused `env_token` harness parameter; document the fail-closed
  `Ok(None)`-never-produced `get_user` semantics on the trait.
- `SECURITY.md` (private vulnerability reporting scope),
  `CONTRIBUTING.md` (PR flow, signed+DCO, no publication), `deny.toml`,
  CODEOWNERS, dependabot, actionlint config, and the zizmor lane.
- `Cargo.lock` remains untracked (upstream convention); the readme no longer
  instructs `--locked`.

### History integrity repair

- Rebuilt the downstream range on top of upstream `a51131eb` so every commit
  is GPG-signed and carries exactly one `Signed-off-by` trailer; the resulting
  tree is byte-identical to the previously pushed tree (verified by empty
  `git diff` before the force-push). Done before any consumer pinned the
  branch or tag existed.

## Updating from upstream

1. Fetch the original `master` into the fork's `master` without downstream
   commits or history rewriting.
2. Review the complete upstream range, tags, dependency changes, unsafe code,
   and public API before moving `irlume-patches` to a new base.
3. Use a dedicated pull request that keeps the imported upstream range separate
   from downstream adaptations.
4. Run the fork's complete required checks and irlume's PAM integration suite.
5. Move irlume's exact commit pin only after installed KDE acceptance passes.

Never merge upstream directly into the protected patch branch without the
separate review and verification above. Never force-push `master` or
`irlume-patches`.
