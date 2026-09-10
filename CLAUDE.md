# Project Rules — age-pq-workspace

Workspace-wide rules for `age-pq-hpke`, `age-pq-keys`, and `age-plugin-pq`.
Every rule below applies to every crate in this workspace unless a section
explicitly scopes itself.

---

## Workspace overview

| Crate | Role |
|-------|------|
| `age-pq-hpke` | Post-quantum hybrid HPKE primitives — X-Wing KEM (ML-KEM-768 + X25519), HPKE Base-mode key schedule (RFC 9180 + draft-ietf-hpke-pq-03), ChaCha20-Poly1305 AEAD. Library only. |
| `age-pq-keys` | The key layer over `age-pq-hpke`: recipient **and** identity types, keypair generation, the bech32 key formats and their HRPs, and the `mlkem768x25519` stanza wire format (wrap/unwrap plus its validation). Implements `age::Recipient` / `age::Identity`. |
| `age-plugin-pq` | `age-plugin-*` binary that exposes the recipient layer over the age plugin protocol (stdio, newline-delimited base64). |

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

- **`#![forbid(unsafe_code)]`** at every crate root. No exceptions — and as of
  `0.2.0-rc.1` this is *enforced* rather than merely asserted. For most of this
  workspace's life only `age-pq-hpke` actually carried the attribute; the other
  two roots had nothing, so the rule was documentation. It is now backed by
  `[workspace.lints.rust] unsafe_code = "forbid"` in the root manifest, plus
  `[lints] workspace = true` in all three member manifests.

  **That member opt-in is the whole mechanism.** `[workspace.lints]` is inert
  without it — an earlier version of these tables existed with no member
  carrying `[lints]`, and governed nothing for its entire life. If you add a
  fourth crate, it needs that line or it is silently unlinted.

  The clippy cast lints (`cast_possible_truncation` and friends) are
  deliberately *not* in the table: they fire on ~19 `usize as u16` RFC 9180
  length prefixes in `age-pq-hpke`, which is real work on wire-format-adjacent
  code and belongs in its own change. Do not "enable and blanket-`#![allow]`" —
  that is exactly how the tables became decorative last time.
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

  Both halves of that coupling are now guarded rather than merely documented:

  - Change the **HRP** and `identity_hrp_matches_the_binary_name_age_will_look_for`
    (`age-plugin-pq/tests/integration.rs`) fails, naming the binary age would
    then look for. It derives the expected name from the HRP the plugin itself
    emits, so it needs no age binary.
  - Rename the **bin target** and the same test fails to compile, because
    `env!("CARGO_BIN_EXE_age-plugin-pq")` no longer resolves.

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

  `age-plugin-pq`'s own tests deliberately do the opposite — there, Cargo
  putting the fresh binary on `PATH` is what makes discovery testable, and it
  means age exercises the build from this run rather than a stale global
  install. Do not "fix" that by installing the plugin system-wide.
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

  **`cargo tree -d` will always show duplicate `rand` / `rand_core`, and that is
  correct.** Measured with `cargo tree -i rand@0.8.5 --workspace -e normal,dev`,
  `rand 0.8.5` has **three** consumers: `age 0.11`, `age-core 0.11`, and
  `proptest 1.5.0` (a dev-dependency of `age-pq-keys`). `rand_core 0.6.4` comes
  from `crypto-common`, `rand_core 0.5.1` from `x448 0.6`. `age 0.11` is the
  trait provider this workspace implements, so its generation is not ours to
  choose — **do not force-upgrade or `[patch]` `age` to collapse these.**
  `proptest` is the one consumer that *is* ours, but moving it does not dedup
  anything: the first release off `rand 0.8` is proptest 1.7, and it lands on
  `rand 0.9` — a different duplicate, not one fewer. That trade is out of scope
  for a dependency bump and is not taken. The criterion that *is* meaningful:
  exactly one `libcrux-ml-kem`, and every direct declaration in the three crates
  on the `rand` 0.10 generation.
- **`panic = "unwind"`** in every profile. `Drop` runs on unwind; `panic = "abort"`
  skips destructors, which skips secure-gate zeroization. The workspace
  `[profile.dev]` / `[profile.release]` / `[profile.bench]` must not set
  `panic = "abort"`.
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
- Free zeroization for values that *are* secret (and zero-cost wrapping for
  values that aren't)

Bare `[u8; N]`, `Vec<u8>`, or `&[u8]` holding cryptographic metadata is a code
smell. If a value participates in a cryptographic operation, give it a typed
alias in the owning crate's `src/aliases.rs`.

### The 3-Tier Access Hierarchy

**Tier 1 — `with_secret` / `with_secret_mut` (default).**
Scoped closure access; the borrow cannot escape. Use this unless a lower
tier is justified.

```rust
let cipher = key.with_secret(|k| ChaCha20Poly1305::new_from_slice(k))?;

// Derive multiple values inside one closure rather than re-opening.
plaintext.with_secret(|p| (blake3_hex(p), p.len()))
```

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

| Wrapper shape | Tier-3 (`into_inner`) | Tier-2 (`with_secret`) |
|--------------|----------------------|------------------------|
| `Fixed<[u8; N]>`, any `N` | ✅ available | ✅ available |
| `Dynamic<Vec<u8>>` / `Dynamic<String>` | ✅ available | ✅ available |

Historical note, kept because the marker still turns up in old branches:
secure-gate once bounded this on `Self::Inner: Default + Zeroize`, and the
stdlib's `Default for [T; N]` stopped at `N <= 32`, so wrappers above 32 bytes
(`MlKemSeed64` = 64, `X448Secret56` = 56, `ExpandedKeyMaterial96` = 96) were
pinned to Tier-2 with a `// Tier-2 (forced)` marker. That ceiling is long gone.
If you meet such a marker, it is stale — promote it rather than propagating it.

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

// WRONG: multiple sequential expose_secret calls — coalesce into with_secret.
let a = secret.expose_secret()[0];
let n = secret.expose_secret().len();

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

Always use `<Alias>::from_random()` / `from_rng(rng)` over bare `OsRng` +
manual copy. The wrapper covers the CSPRNG → storage hop with no
intermediate plaintext.

```rust
let key   = AeadKey32::from_random();
let seed  = Seed32::from_rng(&mut rng).map_err(|_| Error::RandomnessError)?;
```

### Encoding and decoding

When a secret is encoded or decoded, route through secure-gate's built-ins
(`to_hex`, `try_from_hex`, `try_to_bech32m`, `try_from_bech32m`, etc.) rather
than calling the underlying `hex` / `base16ct` / `base64ct` / `bech32` crates
directly on raw secret bytes. The built-ins use constant-time backends and every
encoder already returns `EncodedSecret`, which zeroizes its buffer on drop.

There are **no `*_zeroizing` encoder twins** — `to_hex_zeroizing` and friends do
not exist in secure-gate 0.9. The only `_zeroizing` symbol in the crate is
`EncodedSecret::into_zeroizing`, which downgrades to a `Zeroizing<String>` (it
keeps the wiping, drops the redacted `Debug`). This matches the note in the
*Tier-2 boundary inventory* below; if you meet a `*_zeroizing` encoder call in
an old branch, it is stale and will not compile.

```rust
// CORRECT
let hex = key.to_hex();                        // EncodedSecret (zeroizes on drop)
let owned = hex.into_zeroizing();              // escape hatch: Zeroizing<String>
let key = Seed32::try_from_hex(&hex_str)?;

// WRONG
let hex = hex::encode(key.expose_secret());    // timing leak, no zeroize
```

This applies primarily to `age-plugin-pq` and `age-pq-keys`, which handle
human-facing key strings. `age-pq-hpke` currently performs no encoding.

### Type aliases

Each crate owns its `src/aliases.rs`. Always define and use a semantically
named alias — never raw `Fixed<[u8; N]>` / `Dynamic<Vec<u8>>` in function
signatures or struct fields.

Add new aliases freely. The cost is one line; the payoff is self-documenting
code and greppable usage.

```rust
// GOOD — communicates intent.
fixed_alias!(pub Seed32, 32, "Master seed / ML-KEM randomness / decapsulation key.");

// AVOID — leaks the implementation detail.
fn from_seed(s: Fixed<[u8; 32]>) -> Self { ... }
```

### Equality

- **Secret wrappers** compared via `secure_gate::ConstantTimeEq::ct_eq`.
  Never `==`. (`==` isn't implemented on `Fixed` / `Dynamic` — this is enforced
  by the type system.)
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

External APIs that take raw bytes and are the *legitimate* Tier-2
escape points. Anything outside this list is suspect.

A few rows carry Tier **1**. They are inventoried anyway — every external
call that touches wrapped bytes belongs in this table, so that "considered and
classified" is distinguishable from "missed" — but the access itself is a
`with_secret` closure and nothing escapes it. Tag the call site with the tier
the table gives it; a `// Tier-1` comment against a row that says 2 is a
contradiction an audit will trip over, and one of the two is then wrong.

**`age-pq-hpke`:**

| Call | Where | Tier | Reason |
|------|------|------|--------|
| `libcrux_ml_kem::*::encapsulate(&pk, [u8; 32])` | `src/kem/ml_kem/*.rs` | **3** | Randomness taken by value — consume via `into_inner` |
| `libcrux_ml_kem::*::generate_key_pair([u8; 64])` | `src/kem/ml_kem/*.rs` | **3** | `d \|\| z` seed taken by value — consume via `into_inner` |
| `libcrux_ml_kem::*::decapsulate(&sk, &ct)` | `src/kem/ml_kem/*.rs` | 2 | Borrows; ct is public bytes via `with_secret` |
| `libcrux_ml_kem::*PublicKey::from([u8; N])` | `src/kem/ml_kem/*.rs` | 1 | Public-key bytes reached inside a `with_secret` closure; no reference escapes |
| `libcrux_ml_kem::*::validate_public_key(&pk)` | `src/kem/ml_kem/*.rs` | 1 | FIPS 203 §7.2 check on the key built by the row above, inside the same closure |
| `x25519_dalek::StaticSecret::from([u8; 32])` | `src/kem/x25519.rs` | **3** | Scalar taken by value — consume via `into_inner`; `StaticSecret` is itself `ZeroizeOnDrop` |
| `x25519_dalek::StaticSecret::diffie_hellman(&PublicKey)` | `src/kem/x25519.rs` | 2 | Borrowed peer key |
| `x448::Secret::from([u8; 56])` | `src/kem/x448.rs` | **3** | Scalar taken by value — consume via `into_inner` after clamping on the wrapper |
| `x448::Secret::as_diffie_hellman(&PublicKey)` | `src/kem/x448.rs` | 2 | Borrowed peer key |
| `hkdf::Hkdf::{extract, expand}` | `src/kdf.rs` | 2 | Takes `&[u8]` |
| `chacha20poly1305::{ChaCha20Poly1305::new_from_slice, encrypt, decrypt}` | `src/aead.rs` | 2 | Takes `&[u8]` / `&Nonce` |
| `sha3::Shake*::update` | `src/kdf.rs`, `src/kem/common.rs`, `src/kem/combiner.rs` | 2 | Takes `&[u8]` |
| `combiner::combine_shared_secrets(&[u8; 32], …)` | callers in `kem/mlkem768x25519.rs` | 2 | 4-arg call; closure nesting would obscure |

**`age-pq-keys`:**

| Call | Reason |
|------|--------|
| `age::Recipient::wrap_file_key` / `age::Identity::unwrap_stanza` | Trait expects `&FileKey` / returns `Vec<Stanza>` |
| ~~`bech32::encode` / `decode`~~ | **Removed in #11.** Neither crate depends on `bech32` directly any more; encoding goes through secure-gate's `try_to_bech32*` / `try_from_bech32*`, which take a `Case` and return `EncodedSecret`. There are no `*_zeroizing` twins — every encoder returns `EncodedSecret` already. |
| `base64::engine::*::encode_into_slice` / `decode` | If used directly; prefer secure-gate equivalents |

**`age-plugin-pq`:**

| Call | Reason |
|------|--------|
| `stdin().read_line` / `stdout().write_all` for the plugin protocol | Stdio is `&[u8]` / `&str` |
| `age_plugin::*` callbacks | Trait signatures defined upstream |

Anywhere else, prefer Tier 1. When adding a new external dependency, expand
this table in the PR that introduces it.

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
- **Internally**: every byte buffer is wrapped (`Seed32`, `KdfBytes`,
  `Plaintext`, etc.) for the entire intra-crate lifetime. PRK and OKM never
  live as bare `Vec<u8>`. The exporter secret captured by `Context::export`
  is a `KdfBytes`. Stack residue is minimized via `new_with` at construction
  and `into_inner` (or `with_secret`) at FFI hand-off.

**Opt-in for callers who want it.** The workspace aliases (`Plaintext`,
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
Audits should grep for `expose_secret` to find every escape hatch — if
you find one inside the implementation that doesn't sit at a Tier-2 / 3
FFI boundary documented in the inventory below, it's a bug.

### IO with `Dynamic<Vec<u8>>`

`Dynamic<Vec<u8>>` implements `std::io::Write`; use it for streaming sinks
where plaintext lands:

```rust
let mut plaintext = Plaintext::new(Vec::new());
std::io::copy(&mut reader, &mut plaintext)?;   // bytes flow into the wrapper
```

For source-side streaming, `Dynamic::as_reader()` yields a cursor over the
wrapped bytes without copying.

### Error message hygiene

Never include secret bytes, key material, or buffer contents in `Error`
payloads, `format!` strings, or `Debug` output. Wrappers redact in `Debug`,
but any `&[u8]` extracted from one will print plain bytes.

Crate `Error` enums in this workspace are payload-free for crypto values
(only carrying enum discriminants and `&'static str` reasons). Keep them
that way. When adding a new variant, do **not** add a `Vec<u8>` / `&[u8]`
field unless it is provably public.

```rust
// WRONG
Err(format!("Key derivation failed for key {:?}", key_bytes))
// CORRECT
Err(Error::KeyDerivationFailed)
```

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

When `age-pq-hpke` changes a public type (e.g. `PrivateKey::bytes` returns a
wrapped type instead of `Vec<u8>`), `age-pq-keys` and `age-plugin-pq`
must follow rather than work around the change. Workarounds tend to be the
exact `expose_secret().to_vec()` pattern this document forbids — fix the
consumer's call site, don't preserve the old shape.

A new public method that returns secret bytes in any crate must start with a
wrapper return type. Bumping a `pub fn` from `Vec<u8>` to a wrapper later is
a breaking change; doing it the right way the first time isn't.

---

## Toolchain pin

`rust-toolchain.toml` pins the workspace toolchain. CI runs against that pin.
Local `cargo` commands inherit it. Do not invoke `cargo +nightly` or other
override toolchains for routine work — verified-crypto deps in this workspace
have been validated against the pinned compiler.
