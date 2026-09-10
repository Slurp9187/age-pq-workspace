# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

---

## [0.2.0-rc.1] - 2026-09-10

**Part of the MSRV 1.85 cohort bump (issue #2).** The workspace moves to rustc
1.85, edition 2024 and Cargo resolver 3. See the root `CHANGELOG.md` for the
full rationale, the per-pin decisions, and what was deliberately not taken.
**The wire format does not change.**

### Changed

- **`rand` 0.9 -> 0.10.** `rand::rngs::OsRng` becomes `rand::rngs::SysRng` at
  the import and both use sites (recipient encapsulation and identity-seed
  generation). The crate relies on rand's **default** features for `sys_rng`;
  adding `default-features = false` later would silently remove `SysRng` and
  break key generation.

- **`secure-gate` moves to git `main` (0.9.0-rc.9)** with no call-site changes —
  `Case::Upper` still produces the `AGE-PLUGIN-PQ-` identity string.

- **`time` now inherits the workspace entry** rather than declaring
  `time = "0.3"` locally. The local declaration bypassed the workspace's MSRV
  cap, so nothing was actually holding `time` below the version that requires
  rustc 1.88.

### Added

- `#![forbid(unsafe_code)]` at the crate root, plus `[lints] workspace = true`
  so the workspace's `unsafe_code = "forbid"` governs this crate.

### Unchanged

- The binary name stays `age-plugin-pq`, and the identity HRP stays
  `AGE-PLUGIN-PQ-`. Plugin discovery depends on both, and
  `identity_hrp_matches_the_binary_name_age_will_look_for` still guards the
  coupling.

---

## [0.1.0-rc.1] - 2026-09-10

**Release candidate for the frozen MSRV-1.70 line.** This crate now inherits
`version.workspace = true`, so its number jumps from the `0.0.x` series to the
unified workspace version shared by `age-pq-hpke`, `age-pq-keys` and
`age-plugin-pq`. The three are released together under the single git tag
`v0.1.0-rc.1`; see the root `CHANGELOG.md` for why they share one number and why
`0.0.x` was not kept.

Everything listed under this heading was developed on the `0.0.x` series; the
renumbering is the release event, not a change in the code.

### Changed

- **bech32 encoding moved to secure-gate** (#11), removing a `bech32::Checksum`
  impl that was byte-identical to the one in `age-pq-keys` — the duplication the
  issue was about. Encoded output is unchanged. `bech32` is no longer a direct
  dependency, and the dead `SeedBytes` alias went with it.
- `--identity` conversion now decodes via `Seed32::try_from_bech32`, which
  validates the length in the same step and never materialises the seed in a
  heap `Vec`.
- Identity case is applied inside the encoder (`Case::Upper`) rather than as a
  separate `make_ascii_uppercase` step, so there is no second buffer and no
  separate step for a refactor to drop.


### Added

- **`identity_hrp_matches_the_binary_name_age_will_look_for`** — asserts the
  built binary is named what age will actually search for. age locates a plugin
  by constructing `"age-plugin-" + name` from the identity HRP, so a rename of
  either side breaks discovery *silently* (age reports plugin-not-found rather
  than failing to build). The test derives one from the other, needs no age
  binary, and turns a documented hazard into an executable assertion.

### Fixed

- **Integration tests no longer pass without running.** Both tests began by
  hunting for the binary in `target/debug/` or on `PATH` and returning early if
  they found neither — reporting success either way. They now use
  `CARGO_BIN_EXE_age-plugin-pq`, which Cargo guarantees, so they always run. The
  one test that shells out to the real age CLI is `#[ignore]`d, so it reports as
  *ignored* rather than passing; CI runs it with `--include-ignored`.
- **Scratch files no longer written into the fixture directory.** The round-trip
  test wrote `tests/data/temp_*` under fixed names, which is not parallel-safe
  and leaks the files when an assertion fires before cleanup. Now a `TempDir`.


### Changed (BREAKING, internal)

- **`zeroize` replaced by `secure-gate`.** The direct dependency is gone; aliases
  live in the new `src/aliases.rs`. `secrecy` still appears only as `age`'s
  re-export for `FileKey`.

  The decrypt loop is where this pays: `unwrap_file_keys` exits through
  `continue` on six different paths, and each one previously needed its own
  hand-written `.zeroize()` call on the shared secret and the AEAD key, kept in
  sync by hand. Wrappers cover every exit on drop, so those six calls are gone
  and cannot fall out of sync.

- `keygen` now fills the seed with `Seed32::from_rng(&mut OsRng)` instead of
  `OsRng.try_fill_bytes` into a `Zeroizing<[u8; 32]>`, so the seed is written
  straight into the wrapper's storage and never exists as a bare local.

- `hpke_pq::derive_key_and_nonce` returns `AeadKey32` rather than `[u8; 32]`.
  This is a crate-internal helper, not a published API.

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
- `src/hpke_pq.rs`: HPKE base-mode key schedule (HKDF-SHA256, ChaCha20-Poly1305 suite) wired to `age-pq-hpke`’s KDF, matching the Go reference plugin’s wire format.
- Integration tests under `tests/` (encrypt/decrypt cycle, identity conversion; optional age CLI when present).
- Workspace membership with `age-pq-hpke` and `age-pq-keys`; root `Cargo.lock` is authoritative (per-crate `Cargo.lock` not used).

### Changed

- Dependency: `pq-xwing-hpke` (broken `../pq-xwing-hpke` path) replaced with `age-pq-hpke = { path = "../age-pq-hpke" }`.
- `bech32` upgraded from 0.9 to 0.11; long hybrid public keys use a custom `HybridRecipientBech32` checksum (`CODE_LENGTH = 8192`), aligned with `age-pq-keys` and official age v1.3+ encodings.
- `secrecy` removed as a direct dependency (secrets accessed via `age_core::secrecy`).
- `rust-version = "1.70"` and repository URL set to `https://github.com/Slurp9187/age-plugin-pq`.
- `.gitignore`: `Cargo.lock` commented out so the workspace lockfile applies.

### Fixed

- Build failure caused by the missing `pq-xwing-hpke` sibling directory.
