# Design — types at the public API boundary

Status: **Locked.** Implemented across `age-hpke-pq 0.0.7`,
`age-recipient-pq 0.0.6`, `age-plugin-pq 0.0.2`.

Supersedes the `DECIDE-2` / `DECIDE-5` / `DECIDE-6` entries in
[`../plans/age-hpke-pq-secure-gate-hardening.md`](../plans/age-hpke-pq-secure-gate-hardening.md),
which reached the same conclusion for return types only. This record extends it
to parameters and fields, and explains the one case where the opposite choice is
correct.

## Locked decisions

| ID | Decision |
|----|----------|
| **DECIDE-7** | **Public API *outputs* are native Rust types.** `[u8; 32]`, `Vec<u8>`, `String`. Implemented: the eight boundaries listed below. |
| **DECIDE-8** | **Public API *parameters and fields* are native Rust types too.** A wrapper in an input position dictates the caller's discipline for material they already hold; it buys nothing the callee cannot get by wrapping on arrival. |
| **DECIDE-9** | **Inside a crate, everything cryptographic stays wrapped** for its whole lifetime. The boundary is a boundary, not an excuse. |
| **DECIDE-10** | **A crate's aliases are `pub(crate)`.** Consequence of 7–9: if nothing crosses the boundary wrapped, nothing outside needs the alias. `age-hpke-pq` re-exports its aliases `pub` only so callers can opt in for their own values. |

### The eight boundaries this changed

`PublicKey::encap`, `PrivateKey::decap`, `Kdf::labeled_derive` /
`labeled_extract` / `labeled_expand`, `combiner::combine_shared_secrets`,
`EncapsulationKey::encapsulate` / `encapsulate_derand`,
`DecapsulationKey::decapsulate`, plus `HybridIdentity::to_string`
(`SecretString` → `String`).

### What DECIDE-9 looks like in practice

The boundary is where wrapping *starts*, not where it stops:

- `hpke::new_context` re-wraps every `Kdf` output in `KdfBytes` on arrival.
- `new_sender` / `new_recipient` re-wrap the shared secret in `SharedSecret`
  immediately after `encap` / `decap`.
- `age-plugin-pq::derive_key_and_nonce` re-wraps each PRK and OKM.

A native type at the boundary is not a native type in the body.

## The counter-example: `age`'s `FileKey`

`rage` / `age` made the opposite call. `FileKey` is `secrecy`-wrapped, it appears
in `Recipient::wrap_file_key(&self, file_key: &FileKey)` — an input position —
and reading it requires `ExposeSecret`.

**That is the right call there, and it does not contradict DECIDE-7/8.** The
variable that decides it is not *how secret is this value*. Every value in this
workspace is secret. It is **who implements the boundary, and how many of them
there are**:

| | Our boundaries | `FileKey` |
|---|---|---|
| Blast radius | one session's derived key | **the entire file**; everything else is derived from it or protects it |
| Lifetime | microseconds, then consumed | held across the whole `Encryptor` / `Decryptor` session, passed between stanzas |
| Who implements it | us, a handful of impls | **third parties** — X25519, scrypt, SSH, YubiKey, every plugin, us |
| Ergonomic cost of wrapping | an `.expose_secret()` at every read site; the type propagates into caller signatures | ~none: fixed 16 bytes, constructed once, read once, no `&[u8]` API needs it |

So the rule is narrower than "wrap secrets":

> Wrap at a public boundary when the boundary is a **trait implemented by parties
> you do not control** and the value's compromise is **total**. Otherwise return
> native and wrap on arrival.

`FileKey` satisfies both clauses. A shared secret returned from `decap` to the
caller one layer up satisfies neither. The wrapper on `FileKey` is doing work no
amount of documentation can do — it makes every third-party recipient
implementation *type* the words `expose_secret`, in a codebase upstream cannot
audit. That is a real mechanism, and it is cheap here.

### Where `age` did get it wrong: the leaked accessor

Not the wrapping — the **accessor**. `FileKey` is `age`'s own newtype, but reading
it requires `secrecy::ExposeSecret` in scope. So every downstream implementor
takes a `secrecy` dependency, or reaches through `age::secrecy`, purely to read
one of `age`'s types.

This workspace is the proof. After migrating all three crates to `secure-gate`,
`age-recipient-pq` has **zero** use for `secrecy` — and still carries
`use secrecy::ExposeSecret;`, solely for `FileKey`. Nothing else.

Had `FileKey` carried an inherent accessor:

```rust
impl FileKey {
    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8; 16]) -> R) -> R { ... }
}
```

it would keep every protection above while making `secrecy` a private
implementation detail that downstream never names. The lesson generalizes:

> A wrapper **type** in your public API is a decision about your users.
> A wrapper **trait** in your public API is a decision about your users'
> dependency graph.

If you wrap at a public boundary, own the accessor. This is why the aliases in
this workspace are `pub(crate)` (DECIDE-10) — we never put an accessor trait in
anyone's way.
