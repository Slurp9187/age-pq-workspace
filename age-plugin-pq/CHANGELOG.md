# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `rand` dependency upgraded from `0.8` to `0.9`.

### Fixed

- Update `hpke_pq.rs` for Secure-Gate / `KdfBytes` compatibility (use `RevealSecret::with_secret` for `Dynamic<Vec<u8>>` values in `labeled_*` calls, `extend_from_slice`, and `copy_from_slice`).

### Security

- Zeroize intermediates between secret extraction and re-wrap in `RecipientPlugin::wrap_file_keys`
  and `unwrap_file_keys` (feed AEAD key via `new_from_slice` so the only live copy after
  `key_bytes` zeroizes is inside the cipher), `IdentityPlugin::add_identity` (stack seed after
  `from_seed`), `unwrap_file_keys` plaintext (`Zeroizing<Vec<u8>>` for decrypted file keys),
  `keygen` (`Zeroizing` seed, identity, and output strings; `make_ascii_uppercase` in place),
  and `convert_native_identities` (stdin buffer, decoded bytes, per-line seeds, and re-encoded
  plugin identity strings).

## [0.0.1] - 2026-03-24

Pre-release / experimental crate versioning (`0.0.x`).

### Added

- This `CHANGELOG.md`.
- Post-quantum `age-plugin-pq` binary: `RecipientPluginV1` and `IdentityPluginV1` for ML-KEM-768 + X25519 hybrid recipients compatible with the official age plugin protocol (`mlkem768x25519` stanzas, `postquantum` label).
- CLI: `--keygen`, `--keygen-native`, `--identity` (native `AGE-SECRET-KEY-PQ-` → plugin `AGE-PLUGIN-PQ-`), `--version`, and `--age-plugin` state-machine mode with `AGEPLUGIN_HALF_PLUGIN` split modes.
- `src/hpke_pq.rs`: HPKE base-mode key schedule (HKDF-SHA256, ChaCha20-Poly1305 suite) wired to `age-hpke-pq`’s KDF, matching the Go reference plugin’s wire format.
- Integration tests under `tests/` (encrypt/decrypt cycle, identity conversion; optional age CLI when present).
- Workspace membership with `age-hpke-pq` and `age-recipient-pq`; root `Cargo.lock` is authoritative (per-crate `Cargo.lock` not used).

### Changed

- Dependency: `pq-xwing-hpke` (broken `../pq-xwing-hpke` path) replaced with `age-hpke-pq = { path = "../age-hpke-pq" }`.
- `bech32` upgraded from 0.9 to 0.11; long hybrid public keys use a custom `HybridRecipientBech32` checksum (`CODE_LENGTH = 8192`), aligned with `age-recipient-pq` and official age v1.3+ encodings.
- `secrecy` removed as a direct dependency (secrets accessed via `age_core::secrecy`).
- `rust-version = "1.70"` and repository URL set to `https://github.com/Slurp9187/age-plugin-pq`.
- `.gitignore`: `Cargo.lock` commented out so the workspace lockfile applies.

### Fixed

- Build failure caused by the missing `pq-xwing-hpke` sibling directory.
