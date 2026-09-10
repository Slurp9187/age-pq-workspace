# Changelog — age-pq-workspace

All notable changes to the workspace itself are documented here.
Individual crate changes live in each member's own `CHANGELOG.md`.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- **Differential oracle against the Go `age` CLI** (issue #15).
  `age-pq-keys/tests/differential_age_go.rs` checks this crate against the real
  binary over many cases instead of the single checked-in fixture: 64
  deterministic key-derivation cases (`age-keygen -y`), 8 fresh Go keypairs fed
  back through our decoder (`age-keygen -pq`), and 22 payload cases in each
  direction (we encrypt → `age -d`, `age -e` → we decrypt) across age's 64 KiB
  STREAM chunk boundary.

  Cases are a pure function of their index — `seed(i) = SHA-256(domain ‖ i)` —
  because the input that reproduces a failure is a private key. A randomised
  oracle would force a choice between an unreproducible failure and printing key
  material into a CI log; deriving the cases removes the choice. Failure
  messages carry a case index, a differential name and lengths, and nothing
  else. **No new dependency: `Cargo.lock` is unchanged.**

  What it deliberately does not prove — plugin routing, ciphertext bytes,
  anything version-specific — and the rationale for each mechanism is in
  [`docs/design/age-go-differential-oracle.md`](docs/design/age-go-differential-oracle.md).

- **Anti-gutting guard for the oracle**, as two steps in the `msrv` CI job. A
  test target with zero `#[test]` functions prints `running 0 tests … ok` and
  **exits 0**, so a job that merely names the file catches its deletion and not
  its gutting. The first step asserts a floor on the *declared* count. The
  second asserts on **evidence a body must produce**: each differential prints a
  `D1:`…`D4:` banner only after it has successfully spawned the age binary, and
  all four are required, because counting is not enough — six `#[test]` fns with
  their names kept and every body replaced by `{}` still reports `6 passed`. It
  also re-runs the target *without* `--include-ignored` and requires a floor
  there, which is the only way to see a file whose tests have all been
  `#[ignore]`d away. Two binary-free tests cover what neither can see — a matrix
  shrunk below its floor, a generator weakened, or the crate's identity encoder
  drifting from the oracle's.

### Changed (BREAKING)

- **Crates renamed to a consistent `age-pq-*` prefix.**

  | Was | Now | Why |
  |---|---|---|
  | `age-hpke-pq` | `age-pq-hpke` | prefix consistency |
  | `age-recipient-pq` | `age-pq-keys` | "recipient" named one of five responsibilities, and the public half of a keypair at that — the crate also owns identities, key generation, the bech32 formats and the stanza wire format |
  | `age-plugin-pq` | **unchanged** | protocol-mandated, see below |

  `age-plugin-pq` keeps its name deliberately. age discovers plugins by
  constructing the binary path as `"age-plugin-" + name`, where `name` comes
  from the identity HRP (`AGE-PLUGIN-PQ-`). Renaming the binary would break
  plugin discovery, and the failure is silent — age reports plugin-not-found
  rather than failing to build.

  Library paths change accordingly: `age_hpke_pq::` → `age_pq_hpke::` and
  `age_recipient_pq::` → `age_pq_keys::`.

  **No wire-format change.** Stanza tag, HRPs, KEM/KDF/AEAD identifiers and key
  encodings are all untouched; existing keys and ciphertexts are unaffected.


### Fixed

- **`cargo fetch` works again on MSRV 1.70.** It failed on every branch,
  including `main`: three transitive crates in the WASI dependency chain
  (`wit-bindgen`, `wit-bindgen-core`, `wasip2`) are edition 2024, which Cargo
  1.70 cannot parse, so any all-target prefetch aborted. Ordinary
  `cargo check` / `build` / `test` were unaffected because those crates are
  target-gated to WASI and never compile here — which is why this went unnoticed.

  Pinned in `Cargo.lock`: `getrandom` 0.3.4 → 0.3.1 (drops `wasi` 0.14 for 0.13,
  removing `wasip2`) and `uuid` 1.22.0 → 1.11.0 (drops `getrandom` 0.4, removing
  the `wit-bindgen-*` and `wit-component` chain). Both are lockfile-only; no
  manifest requirement changed, and the 1.85 bump can simply drop the pins.

- **Child-process helpers resolve `age` and `age-keygen` to an absolute path**
  before applying the plugin-free `PATH` (`age-pq-keys/tests/common.rs`).
  Program resolution and plugin blocking are two different jobs, and conflating
  them was a live hazard: the WinGet `age` package ships
  `age-plugin-batchpass.exe` in the same directory as `age.exe`, so the filter
  removed the only directory holding age itself. It worked anyway because Rust
  on Windows falls back to the parent's `PATH` — a fallback Unix does not make
  once the environment is overridden. The filtered `PATH` now governs only what
  the child sees when *it* looks for a plugin.

- **`common::safe_stderr` filters identity strings out of child stderr** before
  it can reach a panic message, and the existing CLI round-trip test was routed
  through it. `age-keygen -y` echoes the **entire** identity when it cannot
  parse one; `age -d -i FILE` does not, naming the file instead. Filtering at
  the single place bytes become a message beats reasoning about the asymmetry
  per call site. The `docs/design/pre-freeze-audit.md` entry that recorded this
  leak as "not reproduced" is corrected there — it had measured only the second
  path.

### Changed

- **`panic = "unwind"` is now stated explicitly** in `[profile.dev]` and
  `[profile.release]`. It was already the effective behaviour via Rust's
  default, but it is a security property rather than a preference: `panic =
  "abort"` skips destructors, which skips secure-gate's zeroization, leaving
  secrets in memory past a panic. Spelling it out means a later size-motivated
  switch has to be a deliberate edit.



- **`publish = false` on all three crates**, inherited from `[workspace.package]`.
  These are experimental and distributed by git tag; none has ever been on
  crates.io. Nothing previously said so in the manifests, so `cargo publish` was
  permitted — now it is a hard error rather than a convention.

- **`secure-gate` moved to a git dependency on `release/0.8` (`0.8.0-rc.12`).**
  rc.12 is not on crates.io, which costs nothing here given the line above.
  `Cargo.lock` pins the exact rev regardless of the branch.

  Two rc.12 changes reach this workspace:

  - **`into_inner` returns the plain value; `InnerSecret<T>` is deleted.** Six
    call sites drop their `let owned = …; f(*owned)` dance for a direct
    `f(x.into_inner())`. Protection now ends at that call rather than following
    the value into the caller — which is what those sites wanted anyway, since
    each hands off to an API taking the array by value, and the two curve sites
    hand off to `StaticSecret` / `x448::Secret`, both zeroize-on-drop. CLAUDE.md's
    Tier-3 section is rewritten accordingly: `into_inner` is now best read as a
    greppable boundary marker — "this secret is leaving wrapper protection here".
  - **Every encoder returns `EncodedSecret`; the `*_zeroizing` twins are gone.**
    No call sites here (this workspace uses the `bech32` crate directly), but it
    settles an open API question — see below.

  Not adopted yet, and worth its own change: rc.12 adds `try_to_bech32_sized::<N>`
  / `Bech32Sized`, a caller-chosen bech32 code length. Both `age-pq-keys` and
  `age-plugin-pq` hand-roll a `Checksum` impl at `CODE_LENGTH = 8192` for exactly
  this reason, and that duplication now has an upstream answer.

### Changed (BREAKING)

- **`age-pq-hpke`'s public API no longer exposes secure-gate types.** Eight
  boundaries changed — see that crate's changelog for the table and migration
  notes. Downstream effects inside this workspace: `age-plugin-pq`'s
  `hpke_pq::derive_key_and_nonce` now parks each `Kdf` output in
  `zeroize::Zeroizing` on arrival instead of reaching through `with_secret`,
  and `age-plugin-pq` no longer imports `RevealSecret` at all — it consumes
  `encap`, `decap`, and the `Kdf` trait without touching secure-gate's access
  API. `age-pq-keys` was unaffected; it never used these types.

### Changed

- **`secure-gate` bumped `=0.8.0-rc.10` → `=0.8.0-rc.11`.** The one breaking
  change that reaches this workspace is rc.11's #156, which moves `len()` /
  `byte_len()` / `is_empty()` off `RevealSecret` onto a new `SecretLen` trait so
  `RevealSecret` can be implemented for every inner type. Libraries, binaries,
  and doctests were unaffected; three `age-pq-hpke` test files needed the new
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
  `age-pq-keys/tests/data/**` and `age-pq-hpke/tests/data/**` so encrypted fixtures and
  plaintext references are never subject to line-ending conversion on any platform.
- `rust-toolchain.toml` pinning the workspace to channel `1.70` with `cargo`, `rustc`,
  `rust-std`, `clippy`, and `rustfmt` (minimal profile), so contributors get the MSRV toolchain
  automatically.

### Changed

- `secure-gate` workspace dependency bumped to `=0.8.0-rc.10` (supersedes `rc.9`; pinned
  across `age-pq-hpke`, `age-plugin-pq`, and tests).
- `Cargo.toml` `include` patterns rewritten as workspace-rooted absolute paths
  (`/CHANGELOG.md`, `/LICENSE*`, `/README.md`) so packaging picks up the workspace files
  unambiguously regardless of member-crate cwd.
- `age-pq-keys/Cargo.toml`: `age-pq-hpke` dependency switched from
  `{ git = "...", tag = "v0.0.5" }` to `{ path = "../age-pq-hpke" }` for in-workspace
  development; the workspace `[patch]` table keeps the published git reference valid for
  downstream consumers without requiring changes to member `Cargo.toml` files.

### Fixed

- `age-pq-keys/tests/data/lorem.txt` re-written as pure LF (was committed with CRLF on
  Windows), fixing `test_decrypt_lorem_encrypted_with_age_cli` which compared decrypted bytes
  against the on-disk reference (the encrypted fixture was created from the LF version).
- `age-plugin-pq`: `rand` dependency corrected from `0.8` to `0.9` to match the rest of the
  workspace (was the sole outlier still on the old series).
- `age-pq-hpke/tests/error_tests.rs`: explicit type annotations (`0usize..2000usize`,
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
  `age-pq-hpke`, `age-pq-keys`, and `age-plugin-pq`.
- `resolver = "2"` (required for MSRV 1.70; upgrade to `"3"` when MSRV rises to 1.85+).
- `[workspace.package]` block: shared `rust-version`, `edition`, `license`,
  `repository`, `homepage`, `authors`, `description`, `keywords`, `categories`,
  and `include` inherited by all members, eliminating per-crate duplication.
- `[patch."https://github.com/Slurp9187/age-pq-hpke"]`: redirects any member's published-style
  git dependency on `age-pq-hpke` to the local sibling path, enabling cross-crate development
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
| `age-pq-hpke` | `98316d9` (squashed) | Post-quantum HPKE core (ML-KEM-768 + X25519) |
| `age-pq-keys` | `a9a51a0` (squashed) | age recipient/identity wrapper |
| `age-plugin-pq` | `7a99b0c` (squashed) | age plugin binary |

Each subtree history was squashed into a single merge commit; full per-crate history is
preserved in the individual crate `CHANGELOG.md` files.
