# Project Rules — age-pq-workspace

Workspace-wide rules for `age-hpke-pq`, `age-recipient-pq`, and `age-plugin-pq`.
Every rule below applies to every crate in this workspace unless a section
explicitly scopes itself.

---

## Workspace overview

| Crate | Role |
|-------|------|
| `age-hpke-pq` | Post-quantum hybrid HPKE primitives — X-Wing KEM (ML-KEM-768 + X25519), HPKE Base-mode key schedule (RFC 9180 + draft-ietf-hpke-pq-03), ChaCha20-Poly1305 AEAD. Library only. |
| `age-recipient-pq` | `age` recipient / identity wrapper around `age-hpke-pq`. Parses stanzas, performs file-key wrap/unwrap. |
| `age-plugin-pq` | `age-plugin-*` binary that exposes the recipient layer over the age plugin protocol (stdio, newline-delimited base64). |

All three depend on the workspace-pinned `secure-gate = "=0.8.0-rc.9"` with
features `rand`, `ct-eq`.

---

## Build rules — non-negotiable, workspace-wide

- **`#![forbid(unsafe_code)]`** at every crate root. No exceptions.
- **MSRV is `1.70`** (workspace `rust-toolchain.toml`). Never bump silently —
  many deps in this workspace are capped (`half < 2.5`, `unicode-ident < 1.0.23`)
  specifically to hold this pin. If a new feature would force an MSRV bump,
  raise it as a separate decision PR.
- **`panic = "unwind"`** in every profile. `Drop` runs on unwind; `panic = "abort"`
  skips destructors, which skips secure-gate zeroization. The workspace
  `[profile.dev]` / `[profile.release]` / `[profile.bench]` must not set
  `panic = "abort"`.
- **No `cargo clean` casually** — `libcrux-ml-kem` and downstream verified
  crypto deps are slow to rebuild.
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
For moving a value into an API that takes `T` (or `[u8; N]`) by value when
the wrapper will not be needed again. Returns `InnerSecret<T>`, which
derefs to `&T` and zeroizes on drop — so the secret remains zeroize-protected
through the hand-off. Prefer Tier 3 over `with_secret(|s| *s)` at FFI
boundaries that take owned arrays: the explicit consumption is clearer, the
zeroization is automatic, and you don't need a manual `clamped.zeroize()`
after a transformation.

Tier-3 examples in this workspace:

- `x25519_dalek::StaticSecret::from([u8; 32])` — takes the scalar by value
- `libcrux_ml_kem::*::encapsulate(&pk, [u8; 32])` — takes randomness by value

**MSRV 1.70 constraint on `into_inner`.** `into_inner` requires
`Self::Inner: Default + Zeroize`. The stdlib only provides
`impl<T: Default> Default for [T; N]` for `N <= 32` on Rust 1.70 (the const
generic impl for arbitrary `N` was stabilized later). Practical effect:

| Wrapper size | Tier-3 (`into_inner`) | Tier-2 (`with_secret`) |
|--------------|----------------------|------------------------|
| `Fixed<[u8; N]>` where `N <= 32` | ✅ available | ✅ available |
| `Fixed<[u8; N]>` where `N > 32`  | ❌ no `Default` impl | ✅ required |
| `Dynamic<Vec<u8>>` / `Dynamic<String>` | ✅ available (`Vec`/`String: Default`) | ✅ available |

For wrappers above 32 bytes (`MlKemSeed64` = 64, `X448Secret56` = 56,
`ExpandedKeyMaterial96` = 96, KEM public keys / ciphertexts ≥ 800 bytes), the
function still takes the wrapper *by value* — drop at end-of-function gives
the same zeroization end-state as Tier-3 — but the FFI hand-off uses
`with_secret(|bytes| *bytes)` to deref. Mark the call site as
`// Tier-2 (forced): [u8; N] lacks Default on MSRV 1.70.`

If the workspace MSRV ever bumps past the point where const-generic `Default`
for arrays is available, revisit these sites and promote to Tier-3.

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

// WRONG: returning raw Vec<u8> for plaintext, key material, or KDF output
// across a public API boundary.
pub fn open(...) -> Result<Vec<u8>, Error>    // use Plaintext
pub fn export(...) -> Result<Vec<u8>, Error>  // use KdfBytes
fn bytes(&self) -> Vec<u8>                    // use Seed32 / KdfBytes

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
(`to_hex`, `try_from_hex`, `to_bech32`, `try_from_bech32m`, etc.) rather than
calling the underlying `hex` / `base16ct` / `base64ct` / `bech32` crates
directly on raw secret bytes. The built-ins use constant-time backends and
offer `_zeroizing` variants that auto-zeroize the encoded form.

```rust
// CORRECT
let hex = key.to_hex_zeroizing();              // EncodedSecret (zeroizes on drop)
let key = Seed32::try_from_hex(&hex_str)?;

// WRONG
let hex = hex::encode(key.expose_secret());    // timing leak, no zeroize
```

This applies primarily to `age-plugin-pq` and `age-recipient-pq`, which handle
human-facing key strings. `age-hpke-pq` currently performs no encoding.

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
use age_hpke_pq::ConstantTimeEq;
assert!(original_ss.ct_eq(&recovered_ss));   // secret — ct_eq

assert!(pk_a.expose_secret() == pk_b.expose_secret());   // public — == is fine
```

### Tier-2 boundary inventory

External APIs that take raw bytes and are the *legitimate* Tier-2
escape points. Anything outside this list is suspect.

**`age-hpke-pq`:**

| Call | Where | Tier | Reason |
|------|------|------|--------|
| `libcrux_ml_kem::*::encapsulate(&pk, [u8; 32])` | `src/kem/ml_kem/*.rs` | **3** | Randomness taken by value — consume via `into_inner` |
| `libcrux_ml_kem::*::generate_key_pair([u8; 64])` | `src/kem/ml_kem/*.rs` | **3** | `d \|\| z` seed taken by value — consume via `into_inner` |
| `libcrux_ml_kem::*::decapsulate(&sk, &ct)` | `src/kem/ml_kem/*.rs` | 2 | Borrows; ct is public bytes via `with_secret` |
| `libcrux_ml_kem::*PublicKey::from([u8; N])` | `src/kem/ml_kem/*.rs` | 2 | Public-key bytes; `with_secret` deref |
| `x25519_dalek::StaticSecret::from([u8; 32])` | `src/kem/x25519.rs` | **3** | Scalar taken by value — consume via `into_inner`; `StaticSecret` is itself `ZeroizeOnDrop` |
| `x25519_dalek::StaticSecret::diffie_hellman(&PublicKey)` | `src/kem/x25519.rs` | 2 | Borrowed peer key |
| `x448::Secret::from(&[u8; 56])`, `as_diffie_hellman` | `src/kem/x448.rs` | 2/3 | Same shape as X25519 |
| `hkdf::Hkdf::{extract, expand}` | `src/kdf.rs` | 2 | Takes `&[u8]` |
| `chacha20poly1305::{ChaCha20Poly1305::new_from_slice, encrypt, decrypt}` | `src/aead.rs` | 2 | Takes `&[u8]` / `&Nonce` |
| `sha3::Shake*::update` | `src/kdf.rs`, `src/kem/common.rs`, `src/kem/combiner.rs` | 2 | Takes `&[u8]` |
| `combiner::combine_shared_secrets(&[u8; 32], …)` | callers in `kem/mlkem768x25519.rs` | 2 | 4-arg call; closure nesting would obscure |

**`age-recipient-pq`:**

| Call | Reason |
|------|--------|
| `age::Recipient::wrap_file_key` / `age::Identity::unwrap_stanza` | Trait expects `&FileKey` / returns `Vec<Stanza>` |
| `bech32::encode` / `decode` | If used directly; prefer secure-gate's `to_bech32m_zeroizing` instead |
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
let pt = age_hpke_pq::Plaintext::new(pt);       // explicit opt-in
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

When `age-hpke-pq` changes a public type (e.g. `PrivateKey::bytes` returns a
wrapped type instead of `Vec<u8>`), `age-recipient-pq` and `age-plugin-pq`
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
