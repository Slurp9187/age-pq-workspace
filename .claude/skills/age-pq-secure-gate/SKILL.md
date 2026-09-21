---
name: age-pq-secure-gate
description: Handling key material in age-pq-workspace with secure-gate wrappers — the newtype aliases in each crate's aliases.rs, the Tier-2/Tier-3 boundary inventory, and what stays plain at the public API. Use when touching seeds, shared secrets, scalars, AEAD keys or KDF output; adding a newtype; choosing an access tier; or bumping secure-gate. Not for stanza wire bytes or public parameters, which are deliberately plain.
---

# secure-gate in age-pq-workspace

**Sole authority for this topic.** `CLAUDE.md`'s *secure-gate Usage Rules* section is the
origin of these rules; this file is where they now live. The protocol, the access tiers and the
residue hazards are in the global `secure-gate` skill — **this file records only what is true
of this workspace.**

## Dependency

Workspace root `Cargo.toml`:

```toml
secure-gate = { version = "=0.9.0-rc.12", features = ["rand", "ct-eq"] }
```

Members opt in additively:

| crate | features on top | kind |
|---|---|---|
| `age-pq-hpke` | none — workspace as-is | library |
| `age-pq-keys` | `["encoding-bech32", "std"]` | library |
| `age-plugin-pq` | `["encoding-bech32", "std"]` | **binary** (`src/main.rs`) |

`encoding-bech32` only — not the full `encoding` set. Bech32 is the only encoding this
workspace uses, and per the global skill its guarantee is **no stack residue plus
zeroization, not constant time**. Do not cite it as a timing defense for key strings.

**Every rule in the global skill is read against rc.12.** See *Pending: rc.13* below — the
next bump is not routine.

## Boundary

All three crates are libraries in the sense that matters: **public in and out types are native
Rust types**. A wrapper in a public signature is a defect here.

```rust
pub fn decap(&self, enc: &[u8]) -> Result<SharedSecret, Error>  // -> [u8; 32]
fn labeled_expand(...) -> Result<KdfBytes, Error>               // -> Vec<u8>
```

Internally the opposite holds: PRKs, OKMs, seeds and shared secrets live in wrappers for their
whole lifetime. `let prk: Vec<u8> = kdf.extract(...)` is the defect shape.

## Newtypes, not aliases

**Unlike every sibling repo, this workspace uses `fixed_newtype!` / `dynamic_newtype!`
throughout** — distinct types, not `type` aliases. That distinction is the whole payoff and it
is compiler-enforced.

Every 32-byte role here was once a `fixed_alias!`, which made them mutually substitutable, so
passing a decapsulation seed where an AEAD key belonged compiled. It does not now.
`kem::combiner::combine_shared_secrets` takes four distinct 32-byte newtypes precisely so its
arguments cannot be transposed, and `age-pq-hpke/src/aliases.rs` carries `compile_fail`
doctests for it.

Declared in each crate's `src/aliases.rs`:

| crate | count | notable |
|---|---|---|
| `age-pq-hpke` | 30 | `Seed32`, `SharedSecret`, `AeadKey32`, `Nonce12`, `MlKemSeed64`, `X25519Scalar` (32), `X448Scalar` (56), `MlKem768PublicKey1184`, `Aad`, `ExporterContext` |
| `age-pq-keys` | 5 | 1 fixed, 4 dynamic |
| `age-plugin-pq` | 8 | 3 fixed, 5 dynamic |

Role-splitting is deliberate where a swap would be silent: `MlKemSharedSecret` /
`X25519SharedSecret` / `X448SharedSecret` are separate because the combiner takes them in a
fixed order, and `ct_t` / `ek_t` are separate 32-byte X25519 public keys that would otherwise
cross.

**`ConstantTimeEq` is opt-in on these arms at rc.12**, and four newtypes carry it —
`SharedSecret`, `MlKemSharedSecret`, `X25519SharedSecret`, `X448SharedSecret`
(`age-pq-hpke/src/aliases.rs`). Without the derive the ct_eq rule is unfollowable and the
tempting fallback is `assert_eq!`, which is `==` on secrets *and* renders both operands with
`Debug` on failure — which is exactly what had happened in two unit tests before these four
opted in.

## ⚠️ Pending: the rc.13 bump is a breaking migration

**rc.13 rejects `derive: [ConstantTimeEq]` on shaped arms** — `fixed_newtype!` with a size
literal is a shaped arm, and all four sites above are. They fail with
`E0119: conflicting implementations`, with no deprecation and no warning.

**Migration: delete the token at all four sites.** Nothing about the generated types changes —
`ct_eq` is emitted automatically on shaped arms from rc.11 onward, gated on `ct-eq`.

```
age-pq-hpke/src/aliases.rs:39   SharedSecret
age-pq-hpke/src/aliases.rs:59   MlKemSharedSecret
age-pq-hpke/src/aliases.rs:65   X25519SharedSecret
age-pq-hpke/src/aliases.rs:92   X448SharedSecret
```

Two things that make this worse than a normal break:

- **It stays required on `generic` arms**, so the rule is arm-scoped rather than global.
- **With `ct-eq` off the offending declaration still compiles** — both impls are discarded. This
  workspace has `ct-eq` **on**, so it will fail loudly here. A crate that had it off could bump,
  look green, and break later.

**This bump cannot be taken alone.** Four first-party crates pin `=0.9.0-rc.12` exactly, and two
different exact requirements in the same compatibility range cannot resolve — so
`encrypted-file-vault` stops resolving until every crate moves. Plan it as one coordinated
wave with this deletion inside it. See the global skill's *upgrade* reference.

## Access tiers — the inventory is the point

`CLAUDE.md` carries a **Tier-2 boundary inventory** tagging each external API as Tier-2
(`&[u8]`) or Tier-3 (`[u8; N]` by value). Keep it: it makes the correct tier greppable per call
site, and Tier 3 does not show up in an `expose_secret` sweep.

Measured usage in `*/src` (files, not occurrences):

```sh
for m in with_secret with_secret_mut expose_secret into_inner from_random from_rng ct_eq new_with; do
  printf '%-16s %s\n' "$m" "$(grep -rl "$m" --include=*.rs age-pq-hpke/src age-pq-keys/src age-plugin-pq/src | wc -l)"
done
```

| method | files |
|---|---|
| `with_secret` | 13 |
| `expose_secret` | 9 |
| `into_inner` | 8 |
| `new_with` | 6 |
| `with_secret_mut` | 5 |
| `ct_eq` | 3 |
| `from_rng` | 2 |
| `from_random` | 1 |

**Tier 3 is genuinely used here**, unlike in the sibling repos, because several dependencies
take owned arrays by value: `x25519_dalek::StaticSecret::from`, `x448::Secret::from`,
`libcrux_ml_kem` encapsulate and keypair generation. Where the receiving type is itself
zeroize-aware, coverage is continuous. **Mutate on the wrapper before consuming** — `into_inner`
leaves no wrapper to mutate through; see `kem/x25519.rs::static_secret_from_seed`.

One documented Tier-2 exception: `ChaCha20Poly1305::new_from_slice` in `aead.rs`, chosen
deliberately to avoid materializing a non-`Zeroize` key type.

## Deliberately not wrapped

- **Stanza wire bytes.** `base64::Engine::{encode, decode}` with `BASE64_STANDARD_NO_PAD` is
  used directly and deliberately — public stanza bytes only, no wrapper involved, so there is
  nothing for secure-gate to protect.
- Sequence numbers (`seq_num: u64`) and other counters.
- KEM / KDF / AEAD algorithm identifiers — `u16` registry IDs.
- Output sizes, lengths, capacities.
- The `&'static` `"HPKE-v1"` / `"KEM"` / `"DeriveKeyPair"` labels and suite-ID prefixes.
- `Box<dyn Kem>` / `Box<dyn Aead>` / `Box<dyn Kdf>` trait objects themselves — the wrappers
  protect the bytes the algorithms consume, not the vtable pointers.
- Public RFC 9180 wire-format scratch: the `suite_id` byte array, the `mode` byte,
  fixed-length prefixes.
- `age` stanza tag strings, type bytes, format version markers.
- Filesystem paths in `age-plugin-pq` — paths to identity files are public; *contents* are not.
- Error variants and error messages.

**When in doubt:** if removing the wrapper would let an attacker reconstruct secret material
from `Debug` output, logs, or a process memory snapshot, it should be wrapped.

## Cross-crate consistency

When `age-pq-hpke` changes a public signature, `age-pq-keys` and `age-plugin-pq` **follow
rather than work around it.** Workarounds tend to be exactly the `expose_secret().to_vec()`
shape this file forbids — fix the consumer's call site, do not preserve the old shape.

Two corrections recorded at the 2026-09 sweep, kept because they were both stated as rules and
both wrong:

- An example here had `PrivateKey::bytes` returning a wrapper. That is the shape the public
  boundary forbids, so it could never have been a legitimate change to follow.
- A sentence required new public methods returning secret bytes to *start* with a wrapper
  return type — the exact negation of the boundary rule, obeyed by no code in the workspace,
  and phrased as a "must". Deleted. A wrapped public return is a deliberate exception to argue
  for, never a standing rule.

Note the workspace's stated principle is to wrap public cryptographic bytes anyway (public
keys, ciphertexts) for auditability and redacted `Debug`. That is the policy fork the global
skill names, and it is **not free**: `Drop` is unconditional, so a wrapped 1184-byte ML-KEM
public key is memset on every drop. The earlier "zero-cost" wording was wrong and has been
corrected; the auditability argument stands on its own.

**Public bytes wrapped only for auditability may use `==`** on the revealed slices. Secrets
never may.

## Residue

The plugin protocol's stdin read fills a secret through secure-gate's `io::Write` impl, which
grows by hand and zeroizes each abandoned allocation — not through a closure holding a raw
`&mut Vec<u8>`.

**Upstream tracks the residual gap as secure-gate issue #133.** It cannot be closed from here.

`age-plugin-pq` is the **only binary in this workspace**, which makes it the only crate that
could install a zero-on-deallocate global allocator. The two libraries must not. See the
`heap-residue` skill before considering it.

## Enforcement

**None automated.** `ci.yml` mentions secure-gate only in a comment explaining a removed
`cargo update -p` step. Nothing checks tier usage, wrapper coverage or the `derive:` tokens —
it is caught in review only.

Saying so is the point. The compile-fail doctests in `age-pq-hpke/src/aliases.rs` are the one
mechanical guard that exists, and they cover transposition, not exposure.

## Verify

```sh
cargo metadata --locked --format-version 1 > /dev/null
cargo fmt -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked -- --nocapture --test-threads=1
cargo check --workspace --all-targets
```

## What did not transfer

- **The global skill's alias-vs-newtype hedging.** It presents `type` aliases as the common case
  and newtypes as the upgrade. Here the decision is already made in the other direction, and
  reverting any of these to an alias would undo a compile-time guarantee the combiner depends
  on.
- **The 3-tier "prefer Tier 1 almost always" emphasis**, softened for the same structural reason
  the sibling crates soften other rules: several dependencies take owned arrays, so Tier 3 is a
  documented boundary marker here rather than an exception.
- **Constant-time claims about encoding.** Only `encoding-bech32` is enabled, and bech32 is
  precisely the encoding that does *not* go through a constant-time backend.
