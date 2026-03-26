# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Test tree uses current naming (`mlkem768x25519`, etc.); no legacy `age-xwing` strings remain under `tests/`.
- Consolidated `src/bech32.rs` and `src/pq.rs` into `src/lib.rs`; tests import `HybridRecipient` / `HybridIdentity` from the crate root (only `src/lib.rs` remains).
- Joined the parent Cargo workspace (`age-hpke-pq`, `age-recipient-pq`, `age-plugin-pq`): one root `Cargo.lock`, no `Cargo.lock` inside this crate directory. Local builds use workspace root `[patch."https://github.com/Slurp9187/age-hpke-pq"]` so the published-style git dependency resolves to the sibling `age-hpke-pq` crate.
- Aligned `examples/pq-keygen.rs` reported CLI version with package version (`0.0.5-dev`).

### Docs

- `docs/pq-recipient-upgrade-instructions.md` still contains legacy `pq_xwing_hpke` import examples; migrate using `age_hpke_pq` and the paths in `src/lib.rs` instead.

### Upstream `age-hpke-pq` v0.0.4 (consumer summary)

This crate still depends on `age-hpke-pq` (git tag `v0.0.4`). Notable upstream changes in that release:

- Docs cite `draft-ietf-hpke-pq-03` for the hybrid HPKE-PQ construction.
- Internal rename `expand_seed` → `expand_key` (`pub(crate)`); test `test_expand_key_determinism`; docs on X25519 clamping (no Go-style retry loop for an all-zero raw seed, per RFC 7748).
- Removed unused `LABEL` from `kem/common.rs` (combiner label remains `X_WING_LABEL` in `kem/combiner.rs`).
- Crate rename `pq-xwing-hpke` → `age-hpke-pq` (`age_hpke_pq`); combiner moved under `src/kem/`; `rust-version = "1.70"` and `unicode-ident` cap; `libcrux-ml-kem` 0.0.8; CI on Rust 1.70 with `--locked`.
- Security posture unchanged in intent: hybrid PQ design, `SharedSecret` zeroization, constant-time checks via `subtle` where applicable (see upstream `CHANGELOG.md` for full detail).

## [0.0.4] - 2026-03-23

### Added

- `include` entries in `Cargo.toml` so the published crate ships `src`, `examples`, `CHANGELOG.md`, `LICENSE*`, and `README.md` only.

### Changed

- Updated `age-hpke-pq` dependency to tag `v0.0.4`.
- Refreshed `Cargo.lock` for the new HPKE revision.
- Increased `HybridRecipientBech32::CODE_LENGTH` from 4096 to 8192 for long hybrid public keys.

## [0.0.3] - 2026-03-23

### Changed

- Declared `rust-version = "1.70"` to align with `age`/`age-core` 0.11 compatibility targets.
- Switched HPKE dependency from `pq-xwing-hpke` to `age-hpke-pq` and pinned it to tag `v0.0.3`.
- Updated internal imports and crate docs to use the new `age-hpke-pq` crate name.
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

- Initial release of `age-recipient-pq`, a Rust library providing post-quantum hybrid recipients and identities compatible with the age encryption format.
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
