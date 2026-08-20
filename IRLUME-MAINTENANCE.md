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
