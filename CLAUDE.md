# Project Rules — age-pq-workspace

Workspace-wide rules for `age-pq-hpke`, `age-pq-keys`, and `age-plugin-pq`.
Every rule below applies to every crate in this workspace unless a section
explicitly scopes itself.

## How to read this file

Rules carry one of two markers, and the distinction is the point of the file:

> **Enforced by** *`<test / lint / CI step>`* — something fails if you break it.
>
> **Convention** — nothing checks this. Care is the only mechanism.

Both are real rules. Only one will catch you.

That distinction exists because this workspace has a documented history of the
opposite: a CI workflow at a path GitHub never read, tests that printed
`SKIPPED` into a stream libtest swallows and passed, a test target that exits 0
with zero tests, a `validate_public_key` that validated nothing, a
`XWING_DRAFT_VERSION` asserting conformance the code lacked, and — in this very
file — `#![forbid(unsafe_code)]` "at every crate root. No exceptions." while two
of three roots lacked it. Confident phrasing is not evidence. If a rule below is
marked **Convention**, treat its confident wording as an aspiration with a
person behind it, not a guarantee with a machine behind it.

A sweep in 2026-09 checked all 173 assertions in this file against the code and
found 42 false or stale. What survives has been re-verified; where a claim could
not be, it now says so.

---

## Workspace overview

| Crate | Role |
|-------|------|
| `age-pq-hpke` | Post-quantum hybrid HPKE primitives — X-Wing KEM (ML-KEM-768 + X25519), HPKE Base-mode key schedule (RFC 9180 + draft-ietf-hpke-pq), ChaCha20-Poly1305 AEAD. Library only. |
| `age-pq-keys` | The key layer over `age-pq-hpke`: recipient **and** identity types, keypair generation, the bech32 key formats and their HRPs, and the `mlkem768x25519` stanza wire format (wrap/unwrap plus its validation). Implements `age::Recipient` / `age::Identity`. |
| `age-plugin-pq` | `age-plugin-*` binary that exposes the recipient layer over the age plugin protocol (stdio, newline-delimited base64). |
| `conformance/` | **Not a workspace member.** In-process differential tests against rage, with its own `Cargo.lock`. `cargo test --workspace` does not reach it — see the section below. |

**All three crates use `secure-gate`, inherited from the workspace.** This was
previously split (`secrecy` + `zeroize` in the two upper crates) and is now
unified — the secure-gate sections below bind every crate in full.

| Crate | Secret handling |
|-------|-----------------|
| `age-pq-hpke` | `secure-gate = { workspace = true }` |
| `age-pq-keys` | `secure-gate = { workspace = true }` |
| `age-plugin-pq` | `secure-gate = { workspace = true }` |

The workspace pin is a git dependency, not a registry version:

```toml
secure-gate = { git = "https://github.com/Slurp9187/secure-gate", branch = "main", features = ["rand", "ct-eq"] }
```

`main` is the line now: `0.9.0-rc.9`, edition 2024, `rust-version = 1.85`. The
`release/0.8` backport existed solely to hold MSRV 1.70 and is **retired** — do
not send fixes there, and read `main`'s changelog when planning anything.

Note that the base workspace pin enables no encoding feature; `age-pq-keys` and
`age-plugin-pq` add `features = ["encoding-bech32", "std"]` on top, which is
what issue #11 moved the hand-rolled bech32 onto.

One trap worth knowing if you meet it in an old branch or a stale cargo cache:
`0.9.0-rc.8` was cut *before* the `Case` work landed, so it has no `Case`, no
`bech32_code_length` / `*_sized` encoders, and `into_inner` returning
`InnerSecret<T>`. `rc.9` forward-ported all of it. Since uppercase bech32 is
what produces the `AGE-SECRET-KEY-PQ-` / `AGE-PLUGIN-PQ-` identity strings,
rc.8 would be a wire-format regression. Anything below rc.9 on `main` is wrong
for this workspace.

`secrecy` still appears in `age-pq-keys`'s source, but only as `age`'s own
re-export: `FileKey` is `age`'s type and keeps `age`'s accessor. Neither
`secrecy` nor `zeroize` is a direct dependency of any crate here. `zeroize`
appears once as an `x25519-dalek` feature, not as an API this workspace calls.

---

## Build rules — non-negotiable, workspace-wide

- **`#![forbid(unsafe_code)]`** at every crate root. No exceptions.

  **Enforced by** `[workspace.lints.rust] unsafe_code = "forbid"` in the root
  manifest, plus `[lints] workspace = true` in all three member manifests —
  belt and braces with the attribute at each root. Every `unsafe` token in the
  workspace is itself one of those attributes; there are four, one per crate
  root plus one in a test target.

  It was documentation-only until `0.2.0-rc.1`: two of three roots lacked the
  attribute while this file said "no exceptions". That is why the marker
  convention above exists.

  **That member opt-in is the whole mechanism.** `[workspace.lints]` is inert
  without it — an earlier version of these tables existed with no member
  carrying `[lints]`, and governed nothing for its entire life. If you add a
  fourth crate, it needs that line or it is silently unlinted.

  **A fourth package now exists, and it needs the opposite treatment.**
  `conformance/` is `exclude`d from the workspace, so it cannot inherit
  `[workspace.lints]` at all and `[lints] workspace = true` there would fail to
  resolve. It carries its own `[lints.rust]` table, a hand-maintained copy of
  the root one. Verified load-bearing rather than decorative by deleting the
  crate's `#![forbid(unsafe_code)]` attribute and compiling an `unsafe` block:
  it still failed, with `requested on the command line with -F unsafe-code`,
  which only the Cargo table produces. **Nothing keeps the two tables in step** —
  if you change `[workspace.lints.rust]`, change `conformance/Cargo.toml` too.

  The clippy cast lints (`cast_possible_truncation` and friends) are
  deliberately *not* in the table: they fire on the `usize as u16` RFC 9180
  length prefixes in `age-pq-hpke`, which is real work on wire-format-adjacent
  code and belongs in its own change. Do not "enable and blanket-`#![allow]`" —
  that is exactly how the tables became decorative last time. (A hand-counted
  figure lived here and had drifted; counts in prose rot, so it is gone.)
- **`age-plugin-pq` must keep that exact binary name.** The other two crates use
  an `age-pq-*` prefix; this one deliberately does not, and it is not an
  oversight to tidy up. age locates a plugin by *constructing* the path:

  ```go
  path := "age-plugin-" + name   // age-go plugin/client.go
  ```

  where `name` comes from the identity HRP (`AGE-PLUGIN-PQ-` → `pq`). Rename the
  binary and plugin discovery breaks silently: age reports plugin-not-found
  rather than failing to build. The Cargo *package* could be renamed while
  `[[bin]] name` stays put, but package ≠ binary is a trap for the next person,
  so both stay as they are.

  All three halves of that coupling are now guarded rather than merely
  documented (the third arrived with the `age` 0.12 migration, below):

  - Change the **HRP** and `identity_hrp_matches_the_binary_name_age_will_look_for`
    (`age-plugin-pq/tests/integration.rs`) fails, naming the binary age would
    then look for. It derives the expected name from the HRP the plugin itself
    emits, so it needs no age binary.
  - Rename the **bin target** and the same test fails to compile, because
    `env!("CARGO_BIN_EXE_age-plugin-pq")` no longer resolves.
  - Change the **case** of either HRP and one of
    `plugin_identity_hrp_is_uppercase_as_age_0_12_requires` /
    `plugin_recipient_hrp_is_lowercase_as_age_0_12_requires` (same file) fails.
    This is the constraint the 0.12 migration discovered: `age-plugin` 0.7 and
    `age` 0.12 both match plugin HRPs with a case-**sensitive** `starts_with`
    (`AGE-PLUGIN-` for identities, `age1` for recipients), and `bech32` 0.9 →
    0.11 made `Hrp` case-preserving where 0.9's `decode` pre-lowercased it.
    age-go does the same (`plugin/encode.go`; only the bech32 *data* part is
    folded). So the identity emitters at `age-plugin-pq/src/main.rs:439` and
    `:489` must stay `Case::Upper`, and the recipient emitter at `:426` must
    stay `Case::Lower`. Flip any one and you still get valid bech32 that still
    round trips through our own parser, while every 0.12-generation client
    rejects it as an invalid HRP — silently, in the same plugin-not-found shape
    as a rename. All three sites are mutation-checked. (`age::x25519` is
    unaffected: it compares `Hrp == Hrp`, and that `PartialEq` is explicitly
    case-insensitive. The narrowing is to the *plugin* prefix tests only.)

- **Never let an interop test reach our own plugin.** If a test in
  `age-pq-keys` handed `age` an `AGE-PLUGIN-PQ-` identity, age would spawn *our*
  plugin and "interoperability with the Go age CLI" would silently become
  "interoperability with our own code" — still green, proving nothing. It is
  reachable whenever someone has `cargo install`ed the plugin, and on Windows
  additionally from the build directory (see the platform note below).

  `age-pq-keys/tests/common.rs::age_command_without_plugins` strips every
  directory containing an `age-plugin-*` binary from the child's `PATH`, and
  the interop test asserts its identity is the native `AGE-SECRET-KEY-PQ-`
  form. `plugin_free_path_removes_directories_holding_plugins` guards the
  guard against synthetic directories, so a filter that silently matched
  nothing would fail rather than pass.

  **`PATH` is the only lever needed** — verified against both implementations
  rather than assumed. age-go resolves plugins solely with
  `exec.Command("age-plugin-" + name)` (`plugin/client.go`) and rage with
  `which::which` (`age/src/plugin.rs`). Neither consults an environment
  variable, a plugin directory, or a config file; there is no search path to
  miss. On Go 1.19+ `exec` also stopped resolving silently from the working
  directory. The match is case-insensitive because Windows and macOS
  filesystems are, and prefix-based so it covers `PATHEXT` variants and the
  `.exe` form rage looks for under WSL.

  The other route to a plugin is `age -j <name>`, which names one explicitly.
  No test here uses it.

  **Platform note, learned the hard way.** Cargo adds the build output directory
  to the *dynamic library* search path for test processes. That is `PATH` on
  Windows but `LD_LIBRARY_PATH` on Unix, so `target/debug` is on `PATH` for
  Windows test runs and **not** for Linux ones. A test that relies on it passes
  locally on Windows and fails in CI. `age-plugin-pq`'s round trip therefore
  prepends the plugin's directory to `PATH` explicitly rather than depending on
  Cargo — which is also better, since it guarantees age spawns this run's build
  instead of a globally installed one.

  `age-plugin-pq`'s own round trip does **not** rely on Cargo for this either.
  It prepends the plugin's directory to `PATH` explicitly, so age spawns this
  run's build rather than a stale global install. Do not "fix" that by
  installing the plugin system-wide.

  (An earlier version of this paragraph said the plugin's tests deliberately
  relied on Cargo's `PATH` behaviour. That was the approach that *caused* the
  Linux CI failure described above, and it was replaced; the sentence outlived
  the code by several releases and contradicted the paragraph directly above
  it.)
- **MSRV is `1.85`** (workspace `rust-toolchain.toml`), edition **2024**, Cargo
  `resolver = "3"`. The 1.70 line is frozen at `v0.1.0-rc.1` and the cohort bump
  (issue #2) landed in `0.2.0-rc.1`; `docs/plans/msrv-1.85-cohort-bump.md`
  records what shipped. Boundary-type decisions that constrained it:
  [`docs/design/api-boundary-types.md`](docs/design/api-boundary-types.md).

  What that bump settled, so it is not re-litigated:

  | Item | Was (1.70) | Now |
  |------|-----------|-----|
  | `secure-gate` | git `release/0.8` (`0.8.0-rc.12`) backport | git `main` (`0.9.0-rc.9`) |
  | `rand` / `rand_core` | `0.9` | `0.10` |
  | `libcrux-ml-kem` | `0.0.8` | `0.0.10` |
  | `half`, `unicode-ident` | capped for MSRV | **caps gone**; `half` left the graph with secure-gate 0.8 |
  | `clap`, `proptest`, `tempfile` | exact `=` pins | carets |
  | `time` | `=0.3.40` | **still capped**, `>=0.3.40, <0.3.46` — see below |
  | Cargo `resolver` | `"2"` | `"3"` |
  | Edition | 2021 | 2024 |
  | Workspace lint tables | omitted | present, **with member opt-in** |

  **`time` is the one cap that survived the bump.** `time` 0.3.46+ requires
  rustc 1.88, which is above this workspace's floor, so the cap is load-bearing
  and is not scaffolding to clean up. Resolver 3's MSRV-aware selection prefers
  a compatible version but is only a *preference* — `--ignore-rust-version`, or
  a consumer resolving this tree on a newer toolchain, walks straight past it.
  A manifest cap is a fact. `age-plugin-pq` must keep inheriting the workspace
  entry (`time = { workspace = true, … }`) rather than declaring `time = "0.3"`
  itself, which used to bypass the cap entirely.

  **The `age` 0.12 migration (issue #29), settled in `0.2.0-rc.2`.** The 1.70
  floor was what had blocked it; `age` 0.12.1 / `age-core` 0.12.0 /
  `age-plugin` 0.7.0 all declare `rust-version = "1.74"`, edition 2021, well
  under our floor.

  | Item | Was | Now |
  |------|-----|-----|
  | `age` (`age-pq-keys`, normal + `armor` dev-dep) | `0.11` | `0.12` |
  | `age-core` (`age-pq-keys`, `age-plugin-pq`) | `0.11` | `0.12` |
  | `age-plugin` (`age-plugin-pq`) | `0.6` | `0.7` |

  **No changes to any crate's `src/`.** The `Recipient` / `Identity` trait
  signatures are byte-identical across the jump, the `"postquantum"` label is
  unchanged, and the wire format does not move — 19/19 CCTV vectors and D1–D5
  verified per-vector before *and* after, not just as a summary line. (Test
  code did change: the migration added the two HRP-case guards listed in the
  plugin-discovery section above.)

  What it drags in, and this is the part that will surprise an auditor:
  **`age` 0.12 depends non-optionally on `ml-kem 0.2`, `p256 0.13`, `hpke 0.12`
  and `sha3 0.10`** — no feature gates. So RustCrypto `ml-kem` is now in this
  workspace's graph. It is **not** a second implementation of our KEM: it backs
  `age` 0.12's own `native::tagpq` recipient (`mlkem768p256tag`, HRP
  `age1tagpq`, label `MLKEM768-P256`), which is a different format from our
  `mlkem768x25519` and shares no code with it.

  Reach is asymmetric, and **the two resolution modes disagree — deliberately,
  so state which one you measured.** Per-package (`cargo tree -p <crate> …`,
  the crate's own dependency edges): `age-pq-keys` reaches `ml-kem` + `p256` +
  `hpke` + `aes-gcm`; `age-plugin-pq` reaches `hpke` + `aes-gcm` only, because
  `age-core` takes `hpke` with `default-features = false, features = ["alloc"]`
  and no `ml-kem`. Workspace-wide (`cargo tree --workspace …`, which is how CI
  and every bare `cargo build` / `cargo test` in this repo resolve), feature
  unification turns `hpke`'s `p256` feature on for *everyone* — `age` enables
  it, there is one `hpke` build, and the plugin binary therefore links `p256`,
  `elliptic-curve`, `crypto-bigint`, `sec1`, `der`, `const-oid`, `ff`, `group`
  and `primeorder` as dead code it never calls. The **ML-KEM half of the claim
  survives both modes**: `cargo tree -i ml-kem --workspace -e normal` shows
  `ml-kem 0.2.3 <- age 0.12.1 <- age-pq-keys` and nothing else, so `ml-kem` does
  not reach `age-plugin-pq` either way. **`age-pq-hpke` gets nothing new** in
  either mode — it has no `age` edge at all, so the verified-ML-KEM crate is the
  only ML-KEM in that crate's graph.

  Two consequences that are documentation, not code: the "formally verified
  ML-KEM" claim is now a claim about *our path*, not about the graph (see
  `docs/design/hpke-import-vs-own.md`), and a **pre-release** rides in
  transitively — `kem 0.3.0-pre.0`, pulled by **`ml-kem 0.2.3`** with an *exact*
  pin (`[dependencies.kem] version = "=0.3.0-pre.0"`), not by `hpke`, whose
  manifest declares no `kem` dependency at all. Because the puller is `ml-kem`,
  the pre-release rides only on `age-pq-keys` and the `=` pin means `cargo
  update` cannot move it even within the pre-release line. Either way it is not
  ours to cap; `Cargo.lock` is what holds it.

  **Not taken in that bump, deliberately:** `sha3` 0.10 → 0.12 and
  `x25519-dalek` 2.0 → 3.0. Neither is forced. `sha3` 0.12 needs `digest` 0.11
  while `sha2` / `hkdf` / `chacha20poly1305` / `aead` all remain on `digest`
  0.10, which would put two digest generations in one crypto tree, and it churns
  the X-Wing combiner and SHAKE KDF — the two modules that decide bytes on the
  wire. `x25519-dalek` 3.0's apparent dedup win is illusory: `crypto-common`
  (under `aead` 0.5) keeps `rand_core` 0.6 in the graph regardless, so taking it
  alone buys nothing while carrying `curve25519-dalek` 4→5 underneath the
  low-order-point rejection. Move the whole RustCrypto gen-2 cohort together
  (`sha2` 0.11 + `hkdf` 0.13 + `chacha20poly1305` 0.11 + `aead` 0.6 + `sha3`
  0.12 + `x25519-dalek` 3.0) in its own change, gated on the CCTV vectors and
  D1–D5, so exactly one commit can be blamed for a combiner-byte change.

  **The `age` 0.12 migration (issue #29, `0.2.0-rc.2`) added a hard blocker to
  that cohort.** Both crates `age` 0.12 pulls non-optionally pin the gen-1 side,
  read from their manifests rather than inferred: `hpke 0.12` declares `digest`
  0.10, `sha2` 0.10, `aead` 0.5, `hkdf` 0.12 and `hmac` 0.12; `ml-kem 0.2.3`
  declares `sha3` 0.10.8 (its full dependency list being `hybrid-array`
  0.2.0-rc.9, `kem` `=0.3.0-pre.0`, `rand_core` 0.6.4, `sha3` 0.10.8, and
  `zeroize` 1.8.1 optional). So the gen-2 move is no longer only ours to make:
  **it cannot happen before `age` itself moves**, or the split it was deferred
  to avoid appears anyway, now with the deciding side outside this workspace's
  control — and note `sha3` in particular, the crate the deferred bump is named
  for, is now pinned to 0.10 by `ml-kem` as well as by us. Measured after the
  migration, `digest` is still **single-generation at 0.10.7** across the whole
  workspace graph, as are `sha2` (0.10.9) and `sha3` (0.10.8) — the deferral is
  still holding, and this is the fact to re-check before anyone reopens it.

  **`cargo tree -d` will always show duplicate `rand` / `rand_core`, and that is
  correct.** Re-measured after the `age` 0.12 migration with
  `cargo tree -i rand@0.8.5 --workspace -e normal,dev`: `rand 0.8.5` still has
  **exactly three** consumers, `age 0.12.1`, `age-core 0.12.0` and
  `proptest 1.5.0` (a dev-dependency of `age-pq-keys`). `age` is the trait
  provider this workspace implements, so its generation is not ours to choose —
  **do not force-upgrade or `[patch]` `age` to collapse these.** `proptest` is
  the one consumer that *is* ours, but moving it does not dedup anything: the
  first release off `rand 0.8` is proptest 1.7, and it lands on `rand 0.9` — a
  different duplicate, not one fewer. That trade is out of scope for a
  dependency bump and is not taken.

  `rand_core 0.5.1` still comes from `x448 0.6`. **`rand_core 0.6.4` no longer
  "comes from `crypto-common`"** — that was true on `age` 0.11 and is now badly
  understated. `cargo tree -i rand_core@0.6.4 --workspace -e normal,dev` lists
  **twelve** direct consumers: `crypto-bigint`, `crypto-common`,
  `elliptic-curve`, `ff`, `group`, `hpke`, `kem`, `ml-kem`, `rand 0.8.5`,
  `rand_chacha 0.3.1`, `rand_xorshift` and `x25519-dalek 2.0.1`. This makes the
  paragraph above *stronger*, not weaker: moving `x25519-dalek` to 3.0 alone now
  removes one edge of twelve, so it cannot collapse the duplicate even in
  principle. Do not read the old single-consumer wording as a dedup opportunity.

  The criteria that *are* meaningful, all three re-measured on the migrated
  tree: exactly one `libcrux-ml-kem` (0.0.10); **exactly one RustCrypto
  `ml-kem` (0.2.3), which is `age` 0.12's own and is not on our KEM path** —
  `cargo tree -i ml-kem --workspace -e normal` must show `age` as its only
  consumer, never `age-pq-hpke`; and every direct declaration in the three
  crates on the `rand` 0.10 generation.

  **Duplicate-group count is not a regression signal by itself.** The `age` 0.12
  migration took it from 17 groups to 14 (`base64`, `bech32`, `rustc-hash` and
  `self_cell` resolved; `syn` 2/3 added, a proc-macro build-graph duplicate via
  `i18n-embed-fl`, not a runtime one). Separately, `Cargo.lock` holds `nom` 7.1.3
  beside `nom` 8.0.0, reachable only through the target-gated
  `crabgrind`/`bindgen` chain under `libcrux-secrets`; `cargo tree -d --target
  all` reports it, and it never compiles here. Same class of lockfile-only
  artifact as the retired wasip2 pins above — expected, not a thing to "fix".
- **Never set `panic = "abort"`.** `Drop` runs on unwind; `abort` skips
  destructors, which skips secure-gate zeroization, so a secret would survive in
  memory past a panic. It is a security property, not a size preference.

  **Convention** — nothing inspects the profiles.

  Stated precisely, because the previous wording ("in every profile", naming
  `[profile.bench]`) was wrong and unfollowable: `panic = "unwind"` is set
  explicitly in `[profile.dev]` and `[profile.release]`. Cargo **ignores**
  `panic` on the `test` and `bench` profiles — measured, it warns that the
  setting is ignored for the bench profile — so those take no entry and must
  not be given one.
- **No `cargo clean` casually** — `libcrux-ml-kem` and downstream verified
  crypto deps are slow to rebuild.
- **The two lockfile-only pins are gone.** `getrandom` at `0.3.1` and `uuid` at
  `1.11.0` were held back only because newer versions pull `wasip2` /
  `wit-bindgen` / `wit-bindgen-core`, which are edition 2024 and unparseable by
  **Cargo 1.70** — breaking all-target prefetch, and so vendoring and offline
  builds. Cargo 1.85 parses edition 2024 natively, so the reason is dead:
  `getrandom` 0.3.1 fell out of the graph with `rand_core` 0.9, and `uuid`
  floats again.

  The class of bug is worth remembering even though this instance is closed: it
  is **invisible to `check` / `build` / `test`**, because those crates are
  target-gated to WASI and never compile here. Only a fetch sees it. So if you
  ever change what resolves for WASI targets, verify with an actual all-target
  fetch rather than a green test run:

  ```sh
  cargo fetch --target x86_64-pc-windows-msvc \
              --target x86_64-unknown-linux-gnu \
              --target wasm32-wasip2
  ```

  That is how the pins' removal was confirmed, rather than by assuming.
- **No secrets in `static` or `lazy_static!`** — `Drop` does not run on statics.
  Const algorithm IDs, RFC version labels, and suite prefixes are fine
  (they aren't secrets); secret material never lives in a static.

---

## secure-gate Usage Rules

These rules apply uniformly across all three crates. Adapted from the
encrypted-file-vault project rules, retargeted for crypto-library work.

### Principle: wrap everything cryptographic

Salts, nonces, public keys, ciphertexts, IKM, KDF outputs, AAD, info strings,
suite contexts — wrap them in `secure-gate` newtype aliases even when the
bytes themselves are public. The wrapper provides:

- Type-level length enforcement
- `[REDACTED]` in `Debug`
- Self-documenting, greppable type names
- A consistent access surface (`with_secret` / `expose_secret`)
- Zeroization on drop for values that *are* secret

Wrapping public bytes is **not** free, and the previous wording ("zero-cost")
was wrong: `Drop for Fixed<T>` is unconditional, so a wrapped 1184-byte ML-KEM
public key is memset on every drop. The reason to wrap public bytes anyway is
auditability and the redacted `Debug` — that argument stands on its own without
a false cost claim.

Bare `[u8; N]`, `Vec<u8>`, or `&[u8]` holding cryptographic metadata is a code
smell. If a value participates in a cryptographic operation, give it a typed
alias in the owning crate's `src/aliases.rs`.

### The 3-Tier Access Hierarchy

**Tier 1 — `with_secret` / `with_secret_mut` (default).**
Scoped closure access; the borrow cannot escape. Use this unless a lower
tier is justified.

```rust
// Real Tier-1 site: age-pq-hpke/src/hpke.rs
let sealer = key.with_secret(|key_raw| aead.aead(key_raw))?;

// Derive multiple values inside one closure rather than re-opening.
plaintext.with_secret(|p| (blake3_hex(p), p.len()))
```

The example here used to be `ChaCha20Poly1305::new_from_slice` — which is the
one call site in this workspace that is a documented **Tier-2**, chosen
deliberately in `aead.rs` to avoid materialising a non-`Zeroize` key type. An
exemplar that contradicts the code teaches the wrong lesson twice.

**Tier 2 — `expose_secret` / `expose_secret_mut` (boundary escape hatch).**
Direct `&T` reference. Acceptable in two cases:

1. **External API requires `&[u8]` / `&T` and cannot accept a closure.** The
   list of legitimate Tier-2 sinks lives below in *Tier-2 boundary
   inventory*. Add a one-line `// Tier-2: <api>` comment at the call site.
2. **A `with_secret` rewrite would force ≥3 levels of closure nesting** and
   would obscure the operation. Single-statement lifetime; comment the
   rationale. This case is rare — if you reach for it routinely you're
   probably missing a refactor.

Every `expose_secret` should pass the sniff test: *could this be a
`with_secret` closure without making the code worse to read?* If yes,
use Tier 1.

**Tier 3 — `into_inner` (consumption).**
For moving a value into an API that takes `T` (or `[u8; N]`) by value when the
wrapper will not be needed again. It returns the **plain value**: the wrapper's
own storage is zeroized as the value leaves, but **protection ends at that call**
rather than following the value into the caller.

(There was a window on secure-gate `main` — `0.9.0-rc.8` only — where this
returned `InnerSecret<T>` instead, which merely derefs and cannot hand a
`Vec<u8>` or `String` back by value at all. `0.9.0-rc.9` restored the plain
value. If you are reading code that derefs an `into_inner()` result, it was
written against rc.8 and is stale.)

Read that as a boundary marker, not a downgrade. `into_inner` is the one call
that says "this secret is leaving wrapper protection now", and it is greppable.
Prefer it over `with_secret(|s| *s)` at FFI boundaries taking owned arrays: the
consumption is explicit, and you don't need a manual `clamped.zeroize()` after a
transformation. Where the receiving type is itself zeroize-aware
(`x25519_dalek::StaticSecret`, `x448::Secret`), coverage is continuous anyway.

Tier-3 examples in this workspace:

- `x25519_dalek::StaticSecret::from([u8; 32])` — takes the scalar by value
- `libcrux_ml_kem::*::encapsulate(&pk, [u8; 32])` — takes randomness by value
- `libcrux_ml_kem::*::generate_key_pair([u8; 64])` — takes the `d || z` seed by value
- `x448::Secret::from([u8; 56])` — takes the clamped scalar by value

**`into_inner` has no length ceiling.** The bound is
`Self::Inner: Sized + SentinelValue + Zeroize`, and the impl is
`impl<T: Default, const N: usize> SentinelValue for [T; N]` — the `Default`
bound sits on the *element* type, so every array length qualifies (verified
unchanged in `0.9.0-rc.9`). `into_inner` replaces the wrapper's contents with an inert sentinel,
zeroizes that storage, and hands the caller the plain value.

| Wrapper shape | Tier-3 (`into_inner`) | Tier-1 (`with_secret`) |
|--------------|----------------------|------------------------|
| `Fixed<[u8; N]>`, any `N` | ✅ available | ✅ available |
| `Dynamic<Vec<u8>>` / `Dynamic<String>` | ✅ available | ✅ available |

Any mutation (scalar clamping, for instance) must happen on the wrapper
*before* consumption — `into_inner` leaves no wrapper to mutate through. See
`kem/x25519.rs::static_secret_from_seed` for the pattern.

Audit Tier 3 separately — `into_inner` does not appear in an
`expose_secret` grep sweep. The Tier-2 boundary inventory below tags each
external API as Tier-2 (`&[u8]`) or Tier-3 (`[u8; N]` by value) so the
correct tier is grep-able per call site.

### NEVER do these

```rust
// WRONG: expose_secret().to_vec() copies the secret into an unzeroized Vec.
let copy = key.expose_secret().to_vec();

// WRONG: re-opening one wrapper to read several properties of it.
let a = secret.expose_secret()[0];
let n = secret.expose_secret().len();
// (Re-opening the same wrapper for genuinely separate derivations is fine —
//  see the three key-schedule expands in hpke.rs, each scoped to its own
//  block. The rule is about redundant opens, not about a running total.)

// WRONG: secret bytes stored as a struct field outside a wrapper.
struct DecapsulationKey { seed: [u8; 32] }   // use Seed32

// WRONG: capturing secret bytes into a closure as a bare Vec<u8>.
let raw = exporter_secret.expose_secret().to_vec();
move |ctx| use(&raw)   // raw is a long-lived unprotected secret

// WRONG: a wrapper in a *public* API signature. Public in/out types are
// native Rust types — see "Wire boundary" below. Wrap internally instead.
pub fn decap(&self, enc: &[u8]) -> Result<SharedSecret, Error>  // -> [u8; 32]
fn labeled_expand(...) -> Result<KdfBytes, Error>               // -> Vec<u8>

// WRONG: an internal buffer left unwrapped. Inside the crate, PRKs, OKMs,
// seeds, and shared secrets live in wrappers for their whole lifetime.
let prk: Vec<u8> = kdf.extract(...);          // use KdfBytes

// WRONG: `==` on secret wrapper contents.
secret_a.expose_secret() == secret_b.expose_secret()   // use ct_eq

// WRONG: secret bytes in error messages or Debug strings.
Err(format!("bad key: {:?}", key.expose_secret()))
```

### Construction — `new_with` over `new` for `Fixed` types

`Fixed::new(value)` moves a value into the wrapper; the compiler may leave a
plaintext copy on the caller's stack frame. `Fixed::new_with(f)` writes
directly into the wrapper's own storage — the secret never exists outside.

```rust
// PREFERRED — secret written straight into wrapper storage.
let seed = Seed32::new_with(|out| out.copy_from_slice(&derived));

// ACCEPTABLE — value already on caller's stack.
let seed = Seed32::from(seed_bytes);
```

`from_random()`, `from_rng()`, `try_from(&[u8])`, and the encoding decoders
route through `new_with` internally. Prefer these constructors where
applicable.

### Random generation

Always use `<Alias>::from_random()` / `from_rng(rng)` over a bare `SysRng` +
manual copy. (`OsRng` was the rand-0.9 spelling; rand 0.10 renamed it, and the
feature with it: `os_rng` became `sys_rng`.) The wrapper covers the CSPRNG → storage hop with no
intermediate plaintext.

```rust
let key   = AeadKey32::from_random();
let seed  = Seed32::from_rng(&mut rng).map_err(|_| Error::RandomnessError)?;
```

### Encoding and decoding

When a secret is encoded or decoded, route through secure-gate's built-ins
(`to_hex`, `try_from_hex`, `try_to_bech32m`, `try_from_bech32m`, etc.) rather
than calling the underlying `hex` / `base16ct` / `base64ct` / `bech32` crates
directly on raw secret bytes. Every encoder returns `EncodedSecret`, which
zeroizes its buffer on drop.

**On "constant-time backends", precisely:** true for hex, base32 and base64,
which go through RustCrypto's `base16ct` / `base32ct` / `base64ct`. **Not** true
for bech32 — which is the only encoding this workspace actually uses. There the
guarantee is no stack residue plus `EncodedSecret` zeroization, not constant
time. Do not cite this section as a timing-attack defence for key strings.

There are **no `*_zeroizing` encoder twins** — `to_hex_zeroizing` and friends do
not exist in secure-gate 0.9. The only `_zeroizing` symbol in the crate is
`EncodedSecret::into_zeroizing`, which downgrades to a `Zeroizing<String>` (it
keeps the wiping, drops the redacted `Debug`). This matches the note in the
*Tier-2 boundary inventory* below; if you meet a `*_zeroizing` encoder call in
an old branch, it is stale and will not compile.

```rust
// CORRECT — bech32 is what this workspace enables and uses.
let encoded = seed.try_to_bech32(IDENTITY_HRP, Case::Upper)?;  // EncodedSecret
let owned   = encoded.into_zeroizing();        // escape hatch: Zeroizing<String>
let seed    = Seed32::try_from_bech32(s, IDENTITY_HRP)?;

// WRONG
let hex = hex::encode(key.expose_secret());    // no zeroize, hand-rolled
```

The example was written in `to_hex` / `try_from_hex`, which do not compile here:
`encoding-hex` is enabled by no crate in this workspace. Only
`encoding-bech32` is.

This applies primarily to `age-plugin-pq` and `age-pq-keys`, which handle
human-facing key strings. `age-pq-hpke` currently performs no encoding.

### Type wrappers — nominal newtypes, not aliases

Each crate owns its `src/aliases.rs` (the filename is historical). Always define
and use a semantically named wrapper — never raw `Fixed<[u8; N]>` /
`Dynamic<Vec<u8>>` in function signatures or struct fields.

**These are `fixed_newtype!` / `dynamic_newtype!` — distinct types, not
aliases.** That distinction is the whole payoff and it is enforced by the
compiler: every 32-byte role here was once a `fixed_alias!`, which made them
mutually substitutable, so passing a decapsulation seed where an AEAD key
belonged compiled fine. It does not now.

```rust
// GOOD — a distinct type; transposing two 32-byte roles is a compile error.
fixed_newtype!(pub Seed32, 32, "Master seed / ML-KEM randomness / decapsulation key.");

// Add the derive if the type will ever be compared — see Equality above.
fixed_newtype!(pub(crate) X25519SharedSecret, 32, "…", derive: [ConstantTimeEq]);

// AVOID — leaks the implementation detail, and is substitutable.
fn from_seed(s: Fixed<[u8; 32]>) -> Self { ... }
```

**Enforced by** the type system: `combiner::combine_shared_secrets` takes four
distinct 32-byte newtypes precisely so its arguments cannot be transposed, and
`age-pq-hpke/src/aliases.rs` carries `compile_fail` doctests for it.

### Equality

- **Secret wrappers** compared via `secure_gate::ConstantTimeEq::ct_eq`.
  Never `==`.

  **Enforced by the type system, but only where the newtype opts in.**
  `ConstantTimeEq` is unconditional on raw `Fixed` / `Dynamic`, and **opt-in**
  on the generated newtypes this workspace actually uses: you get it by writing
  `derive: [ConstantTimeEq]` in the `fixed_newtype!` / `dynamic_newtype!`
  invocation. Without that the rule is unfollowable, and the tempting fallback
  is `assert_eq!(a.expose_secret(), b.expose_secret())` — which is `==` on
  secrets *and* renders both operands with `Debug` on failure.

  That is exactly what had happened: the four shared-secret newtypes had no
  opt-in, and two unit tests compared Diffie-Hellman secrets with `assert_eq!`.
  `SharedSecret`, `MlKemSharedSecret`, `X25519SharedSecret` and
  `X448SharedSecret` now derive it. **If you add a newtype that will be
  compared, add the derive in the same edit.**
- **Public bytes wrapped for auditability** (public keys, ciphertexts) may use
  `a.expose_secret() == b.expose_secret()`. `==` on `&[u8; N]` is the right
  semantic; `ct_eq` isn't required when the data isn't secret.

```rust
use age_pq_hpke::ConstantTimeEq;
assert!(original_ss.ct_eq(&recovered_ss));   // secret — ct_eq

assert!(pk_a.expose_secret() == pk_b.expose_secret());   // public — == is fine
```

### Length metadata — `SecretLen`, not `RevealSecret`

`len()` / `byte_len()` / `is_empty()` live on
a separate `SecretLen` trait rather than on `RevealSecret`, so `RevealSecret`
can be implemented for every inner type instead of only the length-bearing
shapes. `SecretLen` is implemented exactly where a length is meaningful:
`Fixed<[T; N]>`, `Dynamic<String>`, `Dynamic<Vec<T>>`.

Call sites that ask a wrapper its length need the trait in scope. `age-pq-hpke`
re-exports it next to the other two:

```rust
use age_pq_hpke::{ConstantTimeEq, RevealSecret, SecretLen};

let n = kdf_output.len();   // requires SecretLen
```

Length is metadata, not contents — but it is still a side channel for
variable-length secrets. Don't branch on it or log it where the value is
attacker-relevant.

### Tier-2 boundary inventory

External calls where wrapped bytes cross into another crate. **Convention** —
nothing checks that this table matches the code, or that it is complete. It was
wrong in eight rows at the 2026-09 sweep, so treat it as a map, not a contract.

Scope, stated because the old wording ("anything outside this list is suspect")
promised more than a hand-maintained table can deliver: this covers
**external-crate** boundaries in `age-pq-hpke`, plus the two upper crates' few.
It does not enumerate the ~44 `expose_secret` sites across the workspace, most
of which are internal trait plumbing. Tag each call site with the tier the table
gives it; a `// Tier-1` comment against a row saying 2 means one of the two is
wrong — that mismatch has been found twice.

**`age-pq-hpke`:**

| Call | Where | Tier | Reason |
|------|------|------|--------|
| `libcrux_ml_kem::*::encapsulate(&pk, [u8; 32])` | `kem/ml_kem/*.rs` | **3** | Randomness taken by value — consume via `into_inner` |
| `libcrux_ml_kem::*::generate_key_pair([u8; 64])` | `kem/ml_kem/*.rs` | **3** | `d \|\| z` seed taken by value — consume via `into_inner` |
| `libcrux_ml_kem::*Ciphertext::from([u8; N])` | `kem/ml_kem/*.rs` | 1 | Built inside a `with_secret` closure, then passed to `decapsulate`; no reference escapes |
| `libcrux_ml_kem::*PublicKey::from([u8; N])` | `kem/ml_kem/*.rs` | 1 | Same shape, for the public key |
| `libcrux_ml_kem::*::validate_public_key(&pk)` | `kem/ml_kem/*.rs` | 1 | FIPS 203 §7.2 check, inside the same closure |
| `x25519_dalek::StaticSecret::from([u8; 32])` | `kem/x25519.rs` | **3** | Scalar by value — `StaticSecret` is itself `ZeroizeOnDrop` |
| `x25519_dalek::SharedSecret::as_bytes()` | `kem/x25519.rs` | 2 | Returns `&[u8; 32]`; copied into the wrapper via `new_with` |
| `x448::Secret::from([u8; 56])` | `kem/x448.rs` | **3** | Scalar by value, after clamping on the wrapper |
| `x448::SharedSecret::as_bytes()` | `kem/x448.rs` | 2 | As above |
| `hkdf::Hkdf::{extract, expand}` | `kdf.rs` | 2 | Takes `&[u8]` |
| `chacha20poly1305::ChaCha20Poly1305::new_from_slice` | `aead.rs` | 2 | Takes `&[u8]`; chosen over Tier 1 to avoid materialising a non-`Zeroize` key type |
| `sha3::Digest::update` | `kem/combiner.rs` | 2 | Four wrapper reads into `Sha3_256` |

Rows deleted at the sweep and why, so they are not restored from memory:
`diffie_hellman` (receiver and argument are both plain types — no wrapper is
involved); `encrypt` / `decrypt` (they take the AEAD's own key, not wrapper
bytes); `combine_shared_secrets` (its signature became four distinct newtypes,
so the "4-arg call, closure nesting would obscure" rationale describes code that
no longer exists).

**`age-pq-keys`:**

| Call | Tier | Reason |
|------|------|--------|
| `age::Recipient::wrap_file_key` / `age::Identity::unwrap_stanza` | 2 | Trait expects `&FileKey` / returns `Vec<Stanza>` |
| `base64::Engine::{encode, decode}` (`BASE64_STANDARD_NO_PAD`) | — | **Used directly, deliberately.** Public stanza wire bytes only; no wrapper is involved, so there is nothing for secure-gate to protect |

`bech32` is no longer a direct dependency of either upper crate (#11); encoding
goes through secure-gate's `try_to_bech32*` / `try_from_bech32*`.

**`age-plugin-pq`:**

| Call | Tier | Reason |
|------|------|--------|
| `io::stdin().read_to_string(buf)` | 1 | Inside `with_secret_mut` — the plugin protocol's stdin read |
| `age_plugin::*` callbacks | 2 | Trait signatures defined upstream |
| `fs::write` for identity files | — | Paths and their contents are handled as public at this boundary |

When adding an external dependency, add its row in the PR that introduces it.

### Wire boundary — discipline inside, raw bytes out

**The "wrap everything cryptographic" rule applies inside library
implementations. At the public API boundary, return raw bytes.**

Forcing wrapped return types on callers — `Recipient::open -> Plaintext`,
`PrivateKey::bytes -> &Seed32`, etc. — propagates the wrapper type into
caller signatures, blocks direct use with `&[u8]` APIs, and demands an
`.expose_secret()` at every read site. The protection is illusory when
callers immediately copy the bytes out to feed downstream APIs anyway.
The Rust crypto ecosystem (chacha20poly1305, hkdf, x25519-dalek's
`SharedSecret::to_bytes`) overwhelmingly returns raw bytes for the same
reason: the library doesn't know the caller's threat model, and forcing
one shape is paternalism.

**Rule:**

- **Inputs** at the public API: accept `&[u8]` / `Vec<u8>`. Don't dictate
  caller's wrapper discipline for material they hand in.
- **Outputs** at the public API: return `Vec<u8>` / `[u8; N]`. Callers wrap
  themselves if their threat model warrants.
- **Internally**: PRKs, OKMs, seeds and shared secrets are wrapped on arrival
  and are never *stored* as bare `Vec<u8>`. The exporter secret captured by
  `Context::export` is a `KdfBytes`. Stack residue is minimised via `new_with`
  at construction and `into_inner` (or `with_secret`) at FFI hand-off.

  Not "every byte buffer, for its entire lifetime" — the internal `Kdf` trait
  returns bare `Vec<u8>` from `labeled_extract` / `labeled_expand` /
  `labeled_derive` by design, and callers wrap the result immediately. The rule
  is about where values *live*, not about a value never briefly existing
  unwrapped between a call and its wrap.

**Opt-in for callers who want it.** `age-pq-hpke`'s wrappers (`Plaintext`,
`KdfBytes`, `Seed32`, `MlKemSeed64`, etc.) are re-exported `pub` so callers
who want the redacted `Debug` and drop-zeroization can wrap their own
returns:

```rust
let pt = recipient.open(aad, &ct)?;             // -> Vec<u8>
let pt = age_pq_hpke::Plaintext::new(pt);       // explicit opt-in
let bytes = pt.with_secret(|b| b.to_vec());     // explicit reveal
```

The library exposes the building blocks; it doesn't lecture.

**`Vec<u8>` for serialization views of already-typed structs.** Wire-format
serializations (`PublicKey::bytes`, `kem::*::Ciphertext::to_bytes`, age
stanza bodies) return `Vec<u8>` / `[u8; N]`. The wrapper exists at the
struct level; the bytes are a projection of it.

**Inside the library, the rule still bites.** Every internal call chain
holds secrets in wrappers from construction through final consumption.
Audits can grep for `expose_secret` to enumerate the escape hatches — about 44
across the three `src` trees. Most are internal trait plumbing rather than FFI,
so a hit is a prompt to check the tier, not by itself a bug. The inventory
**above** covers external-crate boundaries only.

**Convention** — no test enforces the correspondence between call sites and the
inventory. A floor test over the grep count is the obvious verifier if this ever
matters enough to build.

### IO with `Dynamic<Vec<u8>>`

`Dynamic<Vec<u8>>` implements `std::io::Write`; use it for streaming sinks
where plaintext lands:

```rust
let mut plaintext = Plaintext::new(Vec::new());
std::io::copy(&mut reader, &mut plaintext)?;   // bytes flow into the wrapper
```

For source-side streaming, `Dynamic::as_reader()` yields a cursor over the
wrapped bytes. It avoids materialising the whole secret in an intermediate
buffer — but each `read` still copies into the caller's buffer, so "without
copying", as this said before, was wrong.

Two preconditions worth knowing before reaching for either:

- **Both are behind secure-gate's `std` feature.** `age-pq-hpke` does not
  enable it, so `Plaintext` gets these impls only via feature unification from
  the two upper crates. A change in what those crates enable could remove them
  from under `age-pq-hpke` without any edit to `age-pq-hpke` itself.
- **Neither is used anywhere in this workspace today.** This section documents
  an available capability, not an established pattern — so it is also
  unexercised by any test.

### Error message hygiene

Never include secret bytes, key material, or buffer contents in `Error`
payloads, `format!` strings, or `Debug` output. Wrappers redact in `Debug`,
but any `&[u8]` extracted from one will print plain bytes.

`age-pq-hpke::Error` is **entirely fieldless** — every variant is a bare
discriminant. Keep it that way: when adding a variant, do **not** give it a
`Vec<u8>` / `&[u8]` field unless the value is provably public.

The other two crates have no error enum of their own; they return `age`'s
`EncryptError` / `DecryptError`, and the messages they construct are the place
to watch there.

```rust
// WRONG
Err(format!("Key derivation failed for key {:?}", key_bytes))
// CORRECT
Err(Error::RandomnessError)
```

**Convention** — nothing checks that new variants stay fieldless. It would be
cheap to check: `age-pq-hpke/src/error.rs` is one file and a variant with a
field is greppable.

---

## What NOT to wrap

- Sequence numbers (`seq_num: u64`) and other counters
- KEM / KDF / AEAD algorithm identifiers (`u16` registry IDs)
- Output sizes, lengths, capacities
- The `&'static` `"HPKE-v1"` / `"KEM"` / `"DeriveKeyPair"` labels and suite-ID
  prefixes
- `Box<dyn Kem>` / `Box<dyn Aead>` / `Box<dyn Kdf>` trait objects themselves —
  the wrappers protect the bytes the algorithms consume, not the algorithm
  vtable pointers
- Public RFC 9180 wire-format scratch (`suite_id` byte array, `mode` byte,
  fixed-length prefixes)
- `age` stanza tag strings, type bytes, format version markers
- Filesystem paths in `age-plugin-pq` (paths to identity files are public;
  *contents* are not)
- Error variants and error messages (per *Error message hygiene*)

When in doubt: if removing the wrapper would let an attacker reconstruct
secret material from `Debug` output, logs, or process memory snapshots,
it should be wrapped.

---

## Cross-crate consistency

When `age-pq-hpke` changes a public signature (e.g. a method gains a parameter,
or an error type gains a variant), `age-pq-keys` and `age-plugin-pq` must follow
rather than work around the change. (The old example here — `PrivateKey::bytes`
returning a wrapper — is the shape the wire-boundary rule forbids, so it could
never have been a legitimate change to follow.) Workarounds tend to be the
exact `expose_secret().to_vec()` pattern this document forbids — fix the
consumer's call site, don't preserve the old shape.

(A sentence here used to require new public methods returning secret bytes to
*start* with a wrapper return type. It was the exact negation of the
wire-boundary rule above — "outputs at the public API: return `Vec<u8>` /
`[u8; N]`" — no code in the workspace obeyed it, and it was phrased as a
"must". Deleted at the 2026-09 sweep. If a future API genuinely wants a wrapped
return, that is a deliberate exception to argue for, not a standing rule.)

---

## Changelog protocol

Full rules and the portable checker:
[`.claude/skills/changelog-protocol/SKILL.md`](.claude/skills/changelog-protocol/SKILL.md).
Two invariants, enforced by CI on `main`:

1. **The top section matches the workspace version.** `[workspace.package]
   version` and the newest heading in the **root** `CHANGELOG.md` agree. The
   three crate files are frozen and exempt — the checker skips them, and says
   so on every run.
2. **A version heading is dated iff that tag exists.**
   `## [X.Y.Z] - unreleased` while in flight; the ISO date goes in when the tag
   is cut, and not before. (Written with a placeholder deliberately: a concrete
   version here goes stale at the next release, and did.)
3. **A dated top section sits at its own tag's commit.** Once a tag is cut, the
   next commit opens the next version — bump the manifest and add
   `## [<next>] - unreleased` in the same commit, or the check fails. Invariants
   1 and 2 both pass on a post-release tree whose changelog no longer describes
   it; this is the one that notices.

**One changelog, at the root.** The three crates share one version and ship as a
single git tag, so per-crate changelogs were telling one release's story four
times and giving invariant 1 four places to drift. Crate-specific changes get a
`### age-pq-hpke` / `### age-pq-keys` / `### age-plugin-pq` heading inside the
release section. The three crate `CHANGELOG.md` files are **frozen** — they keep
their history through `0.1.0-rc.1` and carry a
`<!-- changelog-protocol: frozen -->` marker that the checker skips (announcing
each skip, and failing if *every* file is frozen). If the crates ever publish
independently, versions and changelogs re-split together.

There is **no standing empty `## [Unreleased]` section** — the
versioned-but-undated section *is* the unreleased one, and keeping both leaves a
reader unable to tell which describes the code they have. This is not
hypothetical: `0.2.0-rc.1` sat dated `2026-09-10` while untagged, under an empty
`[Unreleased]`, claiming a release that had not happened.

**Do not date entries as bookkeeping** — git records that precisely and a typed
date drifts. **Do** date an entry when the date bounds an *observation*, because
git dates the commit, not the measurement:

```markdown
- Not reproduced on age v1.3.1 as of 2026-09-09.      <- keep, the date is the claim
- Moved encoding to secure-gate (2026-09-08).          <- drop, git knows
```

The `release/0.1` maintenance branch follows the same protocol but carries no CI
check; its `0.1.0-rc.1` heading is correctly dated because `v0.1.0-rc.1` exists.

---

## `conformance/` — the excluded package

`conformance/` holds in-process differential tests against rage. It is **not** a
workspace member and has its own `Cargo.lock`.

**The exclusion is mandatory, not stylistic.** rage's `age` crate and the
crates.io `age 0.12` this workspace ships against cannot resolve in one
dependency graph — measured, not assumed:

```text
crates.io age 0.12.1 -> ml-kem ^0.2 -> ml-kem 0.2.3 -> kem =0.3.0-pre.0
rage's    age 0.12.1 -> ml-kem ^0.3 -> ml-kem 0.3.0 -> kem ^0.3.0
```

`ml-kem 0.2.3` pins `kem` **exactly** at a pre-release (the same exact pin
documented under the `age` 0.12 migration above), and a pre-release shares its
version slot with its release, so the two are mutually exclusive under any
arrangement of features or dev-dependency placement. `conformance/Cargo.toml`
patches `age` itself to rage so exactly one `age` exists there.

Consequences to keep in mind before citing a green run from it:

- **`age-pq-keys` is compiled there against rage's `age`**, not the crates.io
  one it ships against. Those tests are evidence the two implementations agree
  *given a common `age` core* — not evidence about the shipped build. The
  shell-out oracle and the CCTV vectors are what cover that.
- **`cargo test --workspace` does not reach it.** Run it from `conformance/`;
  CI has a separate job.
- **Its `Cargo.lock` is committed and is the pin on rage.** CI uses `--locked`
  so drift fails rather than silently testing a different rage.
- **Its `[lints.rust]` table is a hand-maintained copy** of the root one — see
  the build-rules section above.

Full record: [`docs/design/conformance-workspace-isolation.md`](docs/design/conformance-workspace-isolation.md).

## Toolchain pin

`rust-toolchain.toml` pins the workspace toolchain. CI runs against that pin.
Local `cargo` commands inherit it. Do not invoke `cargo +nightly` or other
override toolchains for routine work — verified-crypto deps in this workspace
have been validated against the pinned compiler.
