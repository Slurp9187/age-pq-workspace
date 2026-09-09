# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Interop tests can no longer route through our own age plugin.** Cargo puts
  `target/debug` on `PATH` for test processes, so `age-plugin-pq` was reachable
  whenever these ran. The identities used are native (`AGE-SECRET-KEY-PQ-`), so
  age handled them itself — verified by re-running with the plugin hidden — but
  nothing *enforced* that. Had the identity format ever changed, the test would
  have quietly stopped being cross-implementation evidence while still passing.

  `age` is now invoked with every directory containing an `age-plugin-*` binary
  stripped from `PATH`, and the test asserts the native identity format.
  `plugin_free_path_actually_removes_the_plugin` guards the guard by asserting a
  plugin *is* reachable before filtering, so the filter cannot pass vacuously.


### Changed (BREAKING)

- **Crate renamed `age-recipient-pq` → `age-pq-keys`.** Import paths change from
  `age_recipient_pq::` to `age_pq_keys::`. No wire-format
  change: stanza tag, HRPs and algorithm identifiers are untouched, so existing
  keys and ciphertexts are unaffected. See the workspace `CHANGELOG.md`.


### Fixed

- **Interop tests no longer pass without running.** Both age-CLI interop tests
  began with `eprintln!("SKIPPED"); return;` when the `age` binary was absent,
  and a skipped test reports as **passed** — so the only cross-implementation
  coverage in the workspace was green whether or not it executed.

  The test that genuinely shells out is now `#[ignore]`d, so a normal
  `cargo test` reports it as **ignored** — in the result line and the count,
  where libtest cannot swallow it. CI runs it with `--include-ignored`, and at
  that point a missing binary is a hard failure.

  An earlier attempt gated this on an `AGE_INTEROP_REQUIRED` environment
  variable and skipped otherwise. That was still wrong locally: libtest captures
  stderr for passing tests, so the `SKIPPED` notice was never displayed and a
  developer without the binary saw a plain `ok`. `#[ignore]` is the built-in
  mechanism for exactly this and needs no custom machinery.

  Separately, `test_decrypt_lorem_encrypted_with_age_cli` **never invoked the
  `age` binary at all** — it decrypts a stored Go age CLI v1.3.1 fixture using
  this crate. Its gate discarded genuine interop coverage for no reason and has
  been removed; that test now always runs.


### Security

- **Stanza validation hardened to match the age specification.** A stanza
  carrying the `mlkem768x25519` tag must now have exactly one argument, a
  canonical-base64 `enc` of 1120 bytes, and a 32-byte body — the body length is
  checked *before* any decryption is attempted, which is the partitioning-oracle
  mitigation the spec requires. Failures of this kind now produce a fatal
  `InvalidHeader` instead of `None`; returning `None` meant "not addressed to
  this identity", so tampered headers were silently skipped rather than
  rejected. Decapsulation failure is fatal while AEAD-open failure remains a
  skip, matching age-go's `pq.go`. Six C2SP CCTV vectors covered this. See
  `docs/design/cctv-conformance.md` and issue #13.

### Removed (BREAKING)

- **The legacy two-argument stanza form is no longer accepted.** Stanzas that
  repeated the tag as `args[0]` were previously tolerated for "backward
  compatibility with older PQ implementations". No age implementation emits that
  form, and accepting it diverged from the spec (CCTV `hybrid_extra_argument`).

### Added

- **C2SP CCTV conformance harness** (`tests/testkit.rs`) running the 19
  `hybrid_*` / `armor_hybrid` vectors through `age::Decryptor`. 19/19 pass.

### Changed (BREAKING)

- **`secrecy` and `zeroize` replaced by `secure-gate`.** Both direct dependencies
  are gone. `secrecy` still appears in the source, but only as `age`'s own
  re-export: `FileKey` is `age`'s type and keeps `age`'s accessor, which is not
  ours to change. Everything this crate owns is now a secure-gate wrapper, and
  the aliases live in the new `src/aliases.rs` per the workspace convention.

  | Was | Now |
  |-----|-----|
  | `HybridIdentity { seed: SecretBox<[u8; 32]> }` | `Seed32` |
  | `Zeroizing<Vec<u8>>` seed/file-key scratch | `SeedBytes` / `FileKeyBytes` |
  | `Zeroizing<String>` bech32 buffer | `IdentityEncoding` |

- **`HybridIdentity::to_string` returns `String`, not `SecretString`.** Public API
  outputs are native Rust types per the workspace wire-boundary rule. **The
  returned `String` is the private key and is not zeroized on drop** — wrap it
  yourself if that matters:

  ```rust
  let encoded: secure_gate::Dynamic<String> = secure_gate::Dynamic::new(identity.to_string());
  ```

  Migration: drop the `.expose_secret()` at the call site.

### Fixed

- The crate-level documentation block used `///` and so attached itself to the
  following `use` statement rather than the crate. It produced four identical
  doctests and never appeared as crate docs. Converted to `//!`.

### Removed

- The doc claim that this crate avoids `secure-gate` "to maximize adoption
  chances" for upstream `rage`. Upstream has its own post-quantum work in a
  pre-release branch, so the constraint that motivated it no longer applies.

## [0.0.5] - 2026-05-10

### Changed

- Test tree uses current naming (`mlkem768x25519`, etc.); no legacy `age-xwing` strings remain under `tests/`.
- Consolidated `src/bech32.rs` and `src/pq.rs` into `src/lib.rs`; tests import `HybridRecipient` / `HybridIdentity` from the crate root (only `src/lib.rs` remains).
- Joined the parent Cargo workspace (`age-pq-hpke`, `age-pq-keys`, `age-plugin-pq`): one root `Cargo.lock`, no `Cargo.lock` inside this crate directory. Local builds use workspace root `[patch."https://github.com/Slurp9187/age-pq-hpke"]` so the published-style git dependency resolves to the sibling `age-pq-hpke` crate.
- Aligned `examples/pq-keygen.rs` reported CLI version with package version (`0.0.5`).
- `age-pq-hpke` dependency switched from `{ git = "...", tag = "v0.0.5" }` to `{ path = "../age-pq-hpke" }` for in-workspace development; the workspace `[patch]` table keeps the published git reference valid for downstream consumers.

### Security

- Closed four un-zeroized intermediate buffers between secret extraction and re-wrap. `HybridRecipient::generate`, `HybridIdentity::parse`, `HybridIdentity::to_string`, and `AgeIdentity::unwrap_stanza` all previously held private-key seed bytes or decrypted file-key bytes in plain `Vec<u8>` / `String` heap buffers between the moment the bytes were produced and the moment they were copied into `SecretBox` / `SecretString` / `FileKey`. Each intermediate is now wrapped in `zeroize::Zeroizing<...>` so the heap buffer is zeroized when it drops. `HybridIdentity::to_string` additionally switches `to_ascii_uppercase()` (which produced a second plain `String`) to `make_ascii_uppercase()` (in-place mutation) to avoid the second unprotected copy.
- Added `zeroize = "1.8"` as a direct dependency (previously transitive via `secrecy` and `age-pq-hpke`). No new code in the dependency graph.

### Fixed

- `tests/data/lorem.txt` was stored with CRLF line endings (Windows git autocrlf), causing `test_decrypt_lorem_encrypted_with_age_cli` to fail because the encrypted fixture was created from the LF version. File re-written as pure LF; workspace `.gitattributes` now marks `age-pq-keys/tests/data/**` as `binary` to prevent future conversion on any platform.

### Docs

- `docs/age-pq-keys-upgrade-instructions.md` still contains legacy `pq_xwing_hpke` import examples; migrate using `age_pq_hpke` and the paths in `src/lib.rs` instead.

### Upstream `age-pq-hpke` v0.0.4 (consumer summary)

This crate still depends on `age-pq-hpke` (git tag `v0.0.4`). Notable upstream changes in that release:

- Docs cite `draft-ietf-hpke-pq-03` for the hybrid HPKE-PQ construction.
- Internal rename `expand_seed` → `expand_key` (`pub(crate)`); test `test_expand_key_determinism`; docs on X25519 clamping (no Go-style retry loop for an all-zero raw seed, per RFC 7748).
- Removed unused `LABEL` from `kem/common.rs` (combiner label remains `X_WING_LABEL` in `kem/combiner.rs`).
- Crate rename `pq-xwing-hpke` → `age-pq-hpke` (`age_pq_hpke`); combiner moved under `src/kem/`; `rust-version = "1.70"` and `unicode-ident` cap; `libcrux-ml-kem` 0.0.8; CI on Rust 1.70 with `--locked`.
- Security posture unchanged in intent: hybrid PQ design, `SharedSecret` zeroization, constant-time checks via `subtle` where applicable (see upstream `CHANGELOG.md` for full detail).

## [0.0.4] - 2026-03-23

### Added

- `include` entries in `Cargo.toml` so the published crate ships `src`, `examples`, `CHANGELOG.md`, `LICENSE*`, and `README.md` only.

### Changed

- Updated `age-pq-hpke` dependency to tag `v0.0.4`.
- Refreshed `Cargo.lock` for the new HPKE revision.
- Increased `HybridRecipientBech32::CODE_LENGTH` from 4096 to 8192 for long hybrid public keys.

## [0.0.3] - 2026-03-23

### Changed

- Declared `rust-version = "1.70"` to align with `age`/`age-core` 0.11 compatibility targets.
- Switched HPKE dependency from `pq-xwing-hpke` to `age-pq-hpke` and pinned it to tag `v0.0.3`.
- Updated internal imports and crate docs to use the new `age-pq-hpke` crate name.
- Moved `time` from runtime dependencies to dev-dependencies (used by examples/tests).
- Updated the `pq-keygen` example version string to `0.0.3`.

### Fixed

- Replaced `std::io::Error::other(...)` with `std::io::Error::new(std::io::ErrorKind::Other, ...)` for Rust 1.70 compatibility.
- Added an explicit `unicode-ident` upper bound (`<1.0.23`) to avoid transitive MSRV bumps beyond Rust 1.70.

## [0.0.2] - 2026-01-28

### Changed

- Updated crate version metadata from `0.1.0` to `0.0.2` to match release/tag numbering.
- Pinned `pq-xwing-hpke` to tag `v0.0.2` for reproducible dependency resolution.
- Refreshed dependencies and lockfile.
- Updated the `pq-keygen` example version string to `0.0.2`.

## [0.0.1] - 2026-01-09

### Added

- Initial release of `age-pq-keys`, a Rust library providing post-quantum hybrid recipients and identities compatible with the age encryption format.
- Implementation of ML-KEM-768 combined with X25519 for quantum-resistant encryption.
- Key generation, serialization, and parsing APIs for `HybridRecipient` and `HybridIdentity`.
- Full compatibility with age file format and Rage conventions (using `secrecy` crate for secret handling).
- Comprehensive test suite:
  - Unit tests for key operations, encryption/decryption roundtrips, and serialization.
  - Low-level PQ stanza wrapping/unwrapping and error handling tests.
  - CLI interoperability tests requiring age CLI >= v1.3.0 (skips gracefully if unavailable).
- Test data files in `tests/data/` for interop verification (lorem.txt, encrypted, and PQ keys).
- Shared test utilities in `tests/common.rs` for version checks and skips.
- README.md with installation, usage, security notes, and testing instructions.
- CHANGELOG.md for tracking changes.
- Custom Bech32 checksum implementation with extended code length (4096) to support encoding of PQ public keys longer than standard limits.

### Security

- Post-quantum security via NIST-standardized ML-KEM-768.
- Hybrid design with X25519 for efficiency and backward compatibility.
- Warning: Not independently audited; use at own risk.

### Compatibility

- Requires Rust and age library dependencies.
- CLI interop tests need age CLI >= v1.3.0 installed.
- Bech32 handling uses `rust-bitcoin/rust-bech32` for keys exceeding standard length limits.
