# Changelog — age-pq-workspace

All notable changes to the workspace itself are documented here.
Individual crate changes live in each member's own `CHANGELOG.md`.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Changed (BREAKING)

- **`age-hpke-pq`'s public API no longer exposes secure-gate types.** Eight
  boundaries changed — see that crate's changelog for the table and migration
  notes. Downstream effects inside this workspace: `age-plugin-pq`'s
  `hpke_pq::derive_key_and_nonce` now parks each `Kdf` output in
  `zeroize::Zeroizing` on arrival instead of reaching through `with_secret`,
  and `age-plugin-pq` no longer imports `RevealSecret` at all — it consumes
  `encap`, `decap`, and the `Kdf` trait without touching secure-gate's access
  API. `age-recipient-pq` was unaffected; it never used these types.

### Changed

- **`secure-gate` bumped `=0.8.0-rc.10` → `=0.8.0-rc.11`.** The one breaking
  change that reaches this workspace is rc.11's #156, which moves `len()` /
  `byte_len()` / `is_empty()` off `RevealSecret` onto a new `SecretLen` trait so
  `RevealSecret` can be implemented for every inner type. Libraries, binaries,
  and doctests were unaffected; three `age-hpke-pq` test files needed the new
  trait in scope. rc.11's other two breaking changes are inert here — no
  secure-gate encoding method is called anywhere in the workspace, and no
  `EncodedSecret` is ever constructed.
- **`CLAUDE.md`: corrected the `into_inner` rules.** The MSRV-1.70 table claimed
  `Fixed<[u8; N]>` with `N > 32` could not use Tier-3 because `into_inner`
  required `Self::Inner: Default`. secure-gate rc.10 replaced that bound with
  `SentinelValue`, whose array impl bounds the *element* type, so the ceiling
  has been gone for a release. Replaced the table, recorded the history so a
  stale `// Tier-2 (forced)` marker on an old branch is recognisable, documented
  that `InnerSecret` has no `DerefMut`, refreshed the pinned-version line, and
  split the `x448` row of the Tier-2 inventory into its Tier-3 (`Secret::from`)
  and Tier-2 (`as_diffie_hellman`) halves.
- **`CLAUDE.md`: new *Length metadata — `SecretLen`, not `RevealSecret`*
  section** covering the rc.11 trait split and the import it requires.

### Security

- rc.11 carries two upstream fixes relevant to patterns this workspace
  documents, though neither has a live call site here: #152 (`io::Write` on
  `Dynamic<Vec<u8>>` left the plaintext in the old allocation when the buffer
  grew — the exact `Plaintext::new(Vec::new())` + `io::copy` shape the
  *IO with `Dynamic<Vec<u8>>`* rule recommends) and #146 (`InnerSecret::clone()`
  resolved through `Deref` to `T::clone` and silently produced an unzeroized
  bare value).

### Added

- `.gitattributes`: `* text=auto` baseline with `binary` overrides for
  `age-recipient-pq/tests/data/**` and `age-hpke-pq/tests/data/**` so encrypted fixtures and
  plaintext references are never subject to line-ending conversion on any platform.
- `rust-toolchain.toml` pinning the workspace to channel `1.70` with `cargo`, `rustc`,
  `rust-std`, `clippy`, and `rustfmt` (minimal profile), so contributors get the MSRV toolchain
  automatically.

### Changed

- `secure-gate` workspace dependency bumped to `=0.8.0-rc.10` (supersedes `rc.9`; pinned
  across `age-hpke-pq`, `age-plugin-pq`, and tests).
- `Cargo.toml` `include` patterns rewritten as workspace-rooted absolute paths
  (`/CHANGELOG.md`, `/LICENSE*`, `/README.md`) so packaging picks up the workspace files
  unambiguously regardless of member-crate cwd.
- `age-recipient-pq/Cargo.toml`: `age-hpke-pq` dependency switched from
  `{ git = "...", tag = "v0.0.5" }` to `{ path = "../age-hpke-pq" }` for in-workspace
  development; the workspace `[patch]` table keeps the published git reference valid for
  downstream consumers without requiring changes to member `Cargo.toml` files.

### Fixed

- `age-recipient-pq/tests/data/lorem.txt` re-written as pure LF (was committed with CRLF on
  Windows), fixing `test_decrypt_lorem_encrypted_with_age_cli` which compared decrypted bytes
  against the on-disk reference (the encrypted fixture was created from the LF version).
- `age-plugin-pq`: `rand` dependency corrected from `0.8` to `0.9` to match the rest of the
  workspace (was the sole outlier still on the old series).
- `age-hpke-pq/tests/error_tests.rs`: explicit type annotations (`0usize..2000usize`,
  `rng.random::<u8>()`) resolve type-inference ambiguity introduced by the `rand 0.9` API.

### Security

- `age-plugin-pq`: wrap private-key and file-key intermediates in `Zeroizing<...>` across
  `wrap_file_keys` / `unwrap_file_keys`, `add_identity`, `keygen`, and
  `convert_native_identities` (ChaCha20-Poly1305 key setup, decrypted file keys, bech32
  strings, and stack seed copies).

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
