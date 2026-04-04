# Changelog — age-pq-workspace

All notable changes to the workspace itself are documented here.
Individual crate changes live in each member's own `CHANGELOG.md`.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Fixed

- `age-recipient-pq/tests/data/lorem.txt` re-written as pure LF (was committed with CRLF on
  Windows), fixing `test_decrypt_lorem_encrypted_with_age_cli` which compared decrypted bytes
  against the on-disk reference (the encrypted fixture was created from the LF version).
- `age-plugin-pq`: `rand` dependency corrected from `0.8` to `0.9` to match the rest of the
  workspace (was the sole outlier still on the old series).
- `age-hpke-pq/tests/error_tests.rs`: explicit type annotations (`0usize..2000usize`,
  `rng.random::<u8>()`) resolve type-inference ambiguity introduced by the `rand 0.9` API.

### Added

- `.gitattributes`: `* text=auto` baseline with `binary` overrides for
  `age-recipient-pq/tests/data/**` and `age-hpke-pq/tests/data/**` so encrypted fixtures and
  plaintext references are never subject to line-ending conversion on any platform.

### Changed
- `secure-gate` workspace dependency bumped to `=0.8.0-rc.8` (includes latest type-safety
  aliases, memory-hygiene improvements, and fixes for `RevealSecret` / `KdfBytes` usage
  across `age-hpke-pq`, `age-plugin-pq`, and tests).
- `age-recipient-pq/Cargo.toml`: `age-hpke-pq` dependency switched from
  `{ git = "...", tag = "v0.0.5" }` to `{ path = "../age-hpke-pq" }` for in-workspace
  development; the workspace `[patch]` table keeps the published git reference valid for
  downstream consumers without requiring changes to member `Cargo.toml` files.

---

## [0.1.0] - 2026-03-25

Initial creation of the unified `age-pq-workspace` monorepo, consolidating three previously
independent crates into a single Cargo workspace.

### Added

- Root `Cargo.toml` establishing the workspace with three members:
  `age-hpke-pq`, `age-recipient-pq`, and `age-plugin-pq`.
- `resolver = "2"` (required for MSRV 1.70; upgrade to `"3"` when MSRV rises to 1.85+).
- `[workspace.package]` block: shared `rust-version`, `edition`, `license`,
  `repository`, `homepage`, `authors`, `description`, `keywords`, `categories`,
  and `include` inherited by all members, eliminating per-crate duplication.
- `[patch."https://github.com/Slurp9187/age-hpke-pq"]`: redirects any member's published-style
  git dependency on `age-hpke-pq` to the local sibling path, enabling cross-crate development
  without modifying member `Cargo.toml` files.
- `[profile.dev] opt-level = 2`: avoids unusably slow crypto-math in debug builds.
- `[profile.bench] debug = true`: retains symbols for flamegraph / profiling workflows.
- `[workspace.lints.rust]` and `[workspace.lints.clippy]`: shared lint governance modelled on
  the RustCrypto/KEMs style (`missing_docs`, `unsafe_code = "deny"`, cast lints, etc.).
- `[workspace.dependencies]`:
  - `secure-gate = "=0.8.0-rc.4"` with features `["rand", "ct-eq"]` — pinned across all members.
  - `clap = "=4.4.18"` with `["derive"]` — single pinned CLI parser version.
  - `half = ">=2.0, <2.5"` (phantom cap): `half 2.5.0+` requires rustc ≥ 1.81; the upper bound
    keeps the resolver within MSRV 1.70 automatically on every `cargo update`.
  - `unicode-ident = ">=1.0, <1.0.23"` (phantom cap): `unicode-ident 1.0.23+` bumped its
    `rust-version` to 1.71; the cap prevents silent MSRV drift.
  - `proptest`, `tempfile`, `time` — pinned dev-dependency versions shared across members.
- Root `Cargo.lock` checked in as the authoritative lockfile; per-crate `Cargo.lock` files are
  not used.
- `.gitignore` scoped for Rust workspace conventions (target/, IDE files, per-crate lock files).

### Members brought in (via `git subtree`)

| Crate | Source tag | Notes |
|---|---|---|
| `age-hpke-pq` | `98316d9` (squashed) | Post-quantum HPKE core (ML-KEM-768 + X25519) |
| `age-recipient-pq` | `a9a51a0` (squashed) | age recipient/identity wrapper |
| `age-plugin-pq` | `7a99b0c` (squashed) | age plugin binary |

Each subtree history was squashed into a single merge commit; full per-crate history is
preserved in the individual crate `CHANGELOG.md` files.
