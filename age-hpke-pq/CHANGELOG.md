# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.7] - 2026-05-10

Internal secure-gate hardening pass. No public API changes — every method
signature, trait method, and return type at the crate boundary is identical
to `0.0.6-dev`. Internal call chains were tightened to eliminate
unzeroized intermediate buffers, lift seed/scalar plumbing into wrappers
end-to-end, and capture the HPKE exporter secret as a `KdfBytes` wrapper
inside the export closure instead of cloning to a raw `Vec<u8>`.

### Changed (internal)

- `src/aead.rs`: `ChaCha20Poly1305Aead::aead` now constructs the cipher via
  `ChaCha20Poly1305::new_from_slice(key.expose_secret())`, eliminating the
  non-`Zeroize` `ChaKey` (`GenericArray`) outer binding that previously held
  the key bytes after the `with_secret` scope closed. `ChaChaCipher::seal`
  and `::open` drop the wrap-unwrap-rewrap dance in favor of
  `ChaNonce::from_slice(nonce.expose_secret())`.
- `src/kdf.rs`: HKDF `labeled_extract` flattens the nested
  `salt.with_secret(... labeled_ikm.with_secret(...))` to two Tier-2
  `expose_secret` calls at the `Hkdf::extract` boundary; the PRK lands
  directly in a `Zeroizing<Vec<u8>>` sized via the macro `$size` and
  finalizes as `KdfBytes`. `labeled_expand` wraps the previously-bare
  `labeled_info: Vec<u8>` as `LabeledInfo` and drops the
  `LabeledOkm::new(...).into_inner().into_zeroizing()` round-trip — the
  `Zeroizing` → `core::mem::take` → `KdfBytes::new` idiom is sufficient.
- `src/kem/x25519.rs`, `src/kem/x448.rs`: leaf helpers take wrapped seeds
  (`X25519Secret32` / `X448Secret56`) by value and return wrapped shared
  secrets (`SharedSecret32` / `SharedSecret56`). `static_secret_from_seed`
  clamps in place via `with_secret_mut` on the wrapper, then consumes via
  `into_inner` (Tier-3) where the inner array size permits.
- `src/kem/ml_kem/*.rs`: `encapsulate_with_seed` uses `into_inner` (Tier-3)
  for `Seed32` randomness; `keypair_from_seed` is Tier-2 (forced) for the
  64-byte `MlKemSeed64` because `[u8; 64]` lacks `Default` on MSRV 1.70.
  Both return `SharedSecret32` instead of raw `[u8; 32]`.
- `src/kem/common.rs`: `expand_seed(seed: &Seed32)` returns
  `(MlKemSeed64, X25519Secret32)` with both halves written directly into
  wrapper storage via `new_with`, eliminating the intermediate `[u8; 64]`
  and `[u8; 32]` stack arrays. `shake256_labeled_derive` returns `KdfBytes`
  and is demoted from `pub` to `pub(crate)` (no external callers in the
  workspace).
- `src/kem/mlkem768x25519.rs`: `DecapsulationKey.seed` is now `Seed32`
  (was `[u8; 32]` with manual `Zeroize`/`ZeroizeOnDrop` derive). `expand_key`
  takes `&Seed32`. `encapsulate_inner` takes owned `Seed32` +
  `X25519Secret32` constructed at the entry points (`encapsulate(rng)` via
  `from_rng`, `encapsulate_derand` via `new_with`). `derive_key_pair`
  bridges via `dk.with_secret(|bytes| self.new_private_key(bytes))` —
  derived bytes never live as a bare `Vec<u8>`.
- `src/hpke.rs`: the HPKE exporter secret captured by `Context::export` is
  now a `KdfBytes` wrapper rather than a raw `Vec<u8>` clone. The wrapper
  drops with the closure (and thus the Context), zeroizing the exporter
  secret. Applies symmetrically to both SHAKE one-stage and HKDF
  two-stage paths.

### Added

- `src/aliases.rs`: `MlKemSeed64` (`Fixed<[u8; 64]>`), `LabeledInfo`
  (`Dynamic<Vec<u8>>` for HKDF-Expand info parameter), `SharedSecret56`
  (`Fixed<[u8; 56]>` for X448 DH output).
- `Plaintext` and `KdfBytes` aliases are re-exported `pub` so callers can
  opt into wrapping their own bytes when their threat model warrants
  (redacted `Debug`, drop-zeroization). The public API itself returns
  raw `Vec<u8>` — the wrappers are opt-in.

### Removed

- Unused `LabeledOkm` alias (the `*::into_inner().into_zeroizing()` round-trip
  it served is gone).
- `pub` on `shake256_labeled_derive` — demoted to `pub(crate)`.

### Security

- HPKE exporter secret no longer leaks into the export closure as a raw
  `Vec<u8>` for the lifetime of the Context.
- AEAD key never materializes in a non-`Zeroize` `GenericArray` outside
  a wrapper scope.
- ML-KEM `d || z` seed and X25519 scalar seed exit `expand_seed` as
  wrapped values; the previous shape leaked them as raw `[u8; 64]` and
  `[u8; 32]` on the stack.
- `DecapsulationKey.seed` is wrapped in `Seed32` for its entire
  in-process lifetime.

### Known constraints

- `into_inner` (Tier-3 secure-gate consumption) requires `Default` on the
  inner type. On MSRV 1.70, stdlib provides `Default for [T; N]` only for
  `N ≤ 32`. Wrappers above 32 bytes (`MlKemSeed64` = 64, `X448Secret56` =
  56) cannot use Tier-3 and fall back to Tier-2 `with_secret(|b| *b)` at
  the FFI hand-off — same drop-zeroize end state, marked at each call
  site with `// Tier-2 (forced): [u8; N] lacks Default on MSRV 1.70.`

### Plan reference

- `docs/plans/age-hpke-pq-secure-gate-hardening.md` (PRs 1–5).

## [0.0.5] - 2026-03-25

### Added

- Dependency: `secure-gate = "=0.8.0-rc.4"` with features `["rand", "ct-eq"]`.
- New `src/aliases.rs` module with size-suffixed fixed aliases and dynamic aliases for HPKE buffers and contexts.
- New integration test file `tests/secure_gate_tests.rs` covering wrapper debug redaction and an HPKE round-trip regression.

### Changed

- Crate version advanced to `0.0.5-dev` pending the next tag.
- **CI workflow** updated: removed `--locked` flag; `cargo update -p half --precise 2.4.1` now pins the one MSRV-incompatible transitive dependency directly in the workflow, eliminating the need for a committed `Cargo.lock`.
- **`half` transitive dependency** (`secure-gate` → `half`): `half v2.5.0+` requires rustc ≥ 1.81. Added `half = { version = ">=2.0, <2.5", default-features = false }` as a direct phantom dependency in `Cargo.toml` so the resolver caps it automatically on every `cargo update`, matching the `unicode-ident` pattern.
- Internal secret handling now uses `secure-gate::Fixed` and `secure-gate::Dynamic` wrappers across KEM, KDF, AEAD, and HPKE paths with scoped `with_secret` / `with_secret_mut` access patterns.
- Constant-time key validation now uses `secure_gate::ConstantTimeEq` for X25519 all-zero checks.
- Caller-provided RNG paths now use `::from_rng()` for KEM encapsulation randomness and decapsulation-key seed generation instead of manual zero-init plus fill.
- MSRV remains Rust `1.70`. The `half` version cap in `Cargo.toml` (`<2.5`) keeps the resolver within MSRV bounds automatically; no manual pin needed after `cargo update`.
- Public trait impl surface was tightened for secret-bearing types.
- Improved `Error` enum with more specific variants (`ExporterLengthTooLarge`, `SequenceNumberOverflow`, `EncryptionFailed`). `CipherAead::seal` now returns `Result` (replacing internal `expect` panic) for consistency with the rest of the crate. Added sequence number overflow protection and updated exporter length error.
- `hpke::Context` no longer stores a dead `suite_id` field, and `#[allow(dead_code)]` was removed from the struct.
- `suite_id()` now returns a fixed `[u8; 10]` array; `src/hpke.rs` and `src/kdf.rs` now use named HPKE constants (`HPKE_SUITE_PREFIX`, `HPKE_VERSION_LABEL`) to make the RFC 9180 label split explicit.
- HPKE nonce generation now uses `compute_nonce()` directly in sender/recipient paths; the allocation-heavy `Context::next_nonce()` helper was removed.
- `Recipient::open` now mirrors `Sender::seal` with a flat scoped secret-exposure pattern for consistency.
- HKDF SHA-256/384/512 implementations now share one macro-backed implementation of `labeled_extract` / `labeled_expand` to remove copy-pasted logic.
- `EncapsulationKey::encapsulate` and `encapsulate_derand` now share a private `encapsulate_inner` path to remove duplicated KEM/DH/combiner logic.
- `DecapsulationKey::bytes()` now returns `[u8; 32]` (fixed-size) internally; trait-object `PrivateKey::bytes()` remains `Vec<u8>` at the external interface.
- One-shot HPKE APIs are now `seal(..., aad, plaintext)` and `open(..., aad, ciphertext)` so callers can authenticate associated data.

### Removed

- Direct `subtle` dependency (constant-time trait now comes from `secure-gate`).
- `Clone` impls / derives from `SharedSecret`, `EncapsulationKey`, `Ciphertext`, and `DecapsulationKey`.
- Dead alias wrappers removed from `src/aliases.rs`: `EncapsulationKey1216`, `Ciphertext1120`, `Hkdf256Output32`, `Hkdf384Output48`, `Hkdf512Output64`, `CiphertextPayload`, `TestingRandomness`, and `CombinedHpkeCiphertext`.

### Security

- `SharedSecret` now has redacted `Debug` output and constant-time equality instead of derived raw-byte `Debug` / `PartialEq`.
- `DecapsulationKey` now derives `Zeroize` and `ZeroizeOnDrop`, and its seed field is no longer publicly exposed.

## [0.0.4] - 2026-03-23

### Changed

- Updated crate docs to cite `draft-ietf-hpke-pq-03` for the implemented hybrid HPKE-PQ construction.
- Renamed internal helper `expand_seed` to `expand_key` and tightened visibility to `pub(crate)` to better reflect internal-only usage and improve spec/go cross-referencing during audits.
- Added explicit inline documentation in key expansion about why no Go-style retry loop is required for an all-zero raw X25519 seed (RFC 7748 clamping guarantees a non-zero scalar).
- Renamed integration test `test_expand_seed_determinism` to `test_expand_key_determinism` for consistency.

### Removed

- Unused and incorrect `LABEL` constant from `src/kem/common.rs` (the active combiner label remains `X_WING_LABEL` in `src/kem/combiner.rs`).

## [0.0.3] - 2026-03-23

### Added

- GitHub Actions workflow (Rust 1.70) running `cargo check --locked` and `cargo test --locked`.
- `Cargo.lock` checked into the repository for reproducible builds in this workspace; `.gitignore` no longer excludes it.

### Changed

- Renamed crate and GitHub repository from `pq-xwing-hpke` to `age-hpke-pq` (import as `age_hpke_pq`); `repository` URL and docs aligned with the new name.
- README: experimental git-dependency install (milestone tags), MSRV note, and corrected KEM / HPKE examples.
- Package `description` scoped to ML-KEM-768 + X25519 (current implementation).
- Moved combiner implementation from `src/combiner.rs` to `src/kem/combiner.rs` to colocate X-Wing KEM internals with the `kem` module.
- Updated module wiring and imports for the combiner move (`src/lib.rs`, `src/kem/mod.rs`, `src/kem/mlkem768x25519.rs`, and `tests/combiner_tests.rs`).
- Declared `rust-version = "1.70"` to align with `age 0.11.2`'s MSRV; capped `unicode-ident` to `<1.0.23` since that release bumped its `rust-version` to `1.71`.
- Updated `libcrux-ml-kem` to 0.0.8 with `default-features = false` and features `mlkem768`, `rand` (keeps ML-KEM-768-only usage and avoids default-feature resolution issues around optional `tls_codec`).

### Fixed

- Resolved ambiguous `aead` re-export by using `crate::aead` so the local module does not clash with the `aead` dependency crate.

## [0.0.2] - 2026-01-28

### Changed

- Updated `libcrux-ml-kem` dependency from 0.0.4 to 0.0.6.

## [0.0.1] - 2026-01-08

### Added

- Initial project setup and core crate structure.
- HPKE implementation with X-Wing KEM support (ML-KEM-768 hybrid with X25519).
- Comprehensive test suite for AEAD (ChaCha20-Poly1305), KDF (HKDF-SHA256/SHA384), KEM, and full HPKE.
- `public_key_size` method to the `Kem` trait.
- Necessary dependencies: `libcrux-ml-kem`, `x25519-dalek`, `hpke-rs-libcrux`, etc.
- Basic error handling and formatting improvements across modules.
- Feature flags for ML-KEM variants, with `MlKem768X25519` as the default.
- Implementation of the `MlKem1024X25519` hybrid KEM variant.
- `MlKem1024X448` KEM implementation with `Any` trait support for `PublicKey`.
- Placeholder support for additional ML-KEM-1024 hybrid variants (later refined).
- Initial `README.md` and this `CHANGELOG.md` for better project documentation.
- `pq-xwing-hpke-upgrade-instructions.md` for migration guidance.

### Changed

- Renamed combiner function and updated references for clarity.
- Refactored KDF and AEAD tests to simplify error handling.
- Removed unused imports and improved code formatting in `hpke.rs`.
- Restructured the KEM module for better organization and clarity.
- Renamed variables (e.g., `pk_t` to `ek_t`) in the combiner function for improved readability.
- Optimized ciphertext construction in KEM implementations.
- Simplified code by removing unnecessary clones and dead code.
- Moved test vectors to a dedicated `data` directory.
- Removed support for certain ML-KEM-1024 variants to focus on core hybrids.
- Updated RNG traits to use `TryCryptoRng` and `TryRngCore` for better compatibility.
- Exposed `new_sender_with_testing_randomness` in the public API.
- Added HPKE nonce computation support for sequence numbers.
- Incorporated draft-ietf-tls-ecdhe-mlkem-03 for hybrid key agreement in TLS 1.3 context.
- Renamed "X-Wing KEM" to `MlKem768X25519` for consistency with standards.

### Removed

- Support for AES-GCM in favor of ChaCha20-Poly1305.
- `ZeroizeOnDrop` from private key implementations to streamline zeroization.
- Cross-crate tests and disabled certain `xwing1024x448` tests for focus.

### Security

- In all versions: Pinned cryptographic dependencies for reproducibility and security.
- Hybrid post-quantum design mitigates against quantum threats while maintaining classical security.
- Added automatic zeroization (`ZeroizeOnDrop`) to the `SharedSecret` type to ensure sensitive shared secrets are securely cleared from memory when they go out of scope.
- Replaced non-constant-time equality checks with constant-time validation using the `subtle` crate for X25519 public key and ciphertext validation, preventing potential timing side-channel attacks.
