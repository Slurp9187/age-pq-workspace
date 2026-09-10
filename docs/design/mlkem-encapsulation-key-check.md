# The ML-KEM encapsulation key check: a validator that validated nothing

**Status:** fixed · **Date:** 2026-09-09 · **Severity:** conformance, not security

## What was wrong

`age-pq-hpke/src/kem/ml_kem/mlkem768.rs` carried this, and `mlkem512.rs` /
`mlkem1024.rs` carried it byte-for-byte:

```rust
/// Minimal parse/shape validation for ML-KEM public-key bytes.
pub(crate) fn validate_public_key(pk_m: &MlKem768PublicKey1184) {
    pk_m.with_secret(|bytes| {
        let _ = MlKem768PublicKey::from(*bytes).as_ref();
    });
}
```

`MlKem768PublicKey::from([u8; 1184])` is an infallible newtype wrap
(libcrux's `impl_generic_struct!`, `src/types.rs`) and `.as_ref()` only borrows.
The function returned `()`, so its one call site — inside
`impl TryFrom<&[u8]> for EncapsulationKey` — had nothing to check. Every one of
the 1184 attacker-supplied ML-KEM bytes went unvalidated.

**The dangerous part is the name.** An auditor greps for the encapsulation key
check, finds a function called `validate_public_key` sitting on the parse path,
and moves on. That is worse than having no function at all: a missing check is
visible, a fake one is not.

## The normative basis

X-Wing — draft-connolly-cfrg-xwing-kem-**10** §5.1, which is the construction this
crate implements (its `XWingLabel` `5c2e2f2f5e5c` is byte-identical to the
MLKEM768-X25519 label in [`hpke-pq.md`](../../age-pq-hpke/docs/hpke-pq.md)) —
states it as a MUST:

The revision matters, because this workspace's normative pins had drifted with
nothing watching them. -10 is the revision actually read for this change;
[`../plans/normative-source-refresh.md`](../plans/normative-source-refresh.md)
(issue #25) records the drift, quotes the same MUST, and is the place a later
reader should start. Earlier drafts of this note cited -07 §4, which nobody in
this pass opened — the section number moved between the two, so citing both was
citing one revision wrong.

> ML-KEM-768.Encaps(pk_M) MUST perform the encapsulation key check of
> [MLKEM] §7.2 and raise an error if it fails.

and, two lines later, deliberately waives the mirror-image check:

> ML-KEM-768.Decap(ct_M, sk_M) is NOT required to perform the decapsulation key
> check of [MLKEM] §7.3.

That waiver is load-bearing here — see *What not to do next* below.
draft-ietf-hpke-pq-**05** §3 says the same thing for pure ML-KEM ("an ML-KEM
encapsulation key check failure causes an HPKE EncapError"); §4 reaches it by
delegation. Both lineages, independently, and neither leaves it optional. `hpke-pq.md`'s own `Encaps` pseudocode shows no check, but that
document is a self-contained implementation reference that elides error paths —
its silence is not a waiver, and it should not be cited as one.

FIPS 203 §7.2 has two parts. Part 1 (the size check) was already discharged
twice, by the length gate in `EncapsulationKey::try_from` and by the fixed-size
wrapper type. Part 2 is the modulus check — every 12-bit coefficient below
q = 3329, equivalently `ByteEncode_12(ByteDecode_12(ek)) == ek` — and that is
the part that was missing.

## The measurement

age v1.3.1, locally, against recipient strings this crate produced:

| Recipient | age exit | age stderr |
|---|---|---|
| freshly generated | 0 | (encrypts) |
| ML-KEM half all `0xFF` | 1 | `malformed recipient "…": invalid MLKEM768-X25519 public key` |
| one coefficient pushed to 0xFFF, other 1214 bytes genuine | 1 | `malformed recipient "…": invalid MLKEM768-X25519 public key` |

age reaches that through `ParseHybridRecipient` → `newHybridRecipient` →
`hpke.MLKEM768X25519().NewPublicKey`, which routes the ML-KEM half into Go's
`crypto/mlkem.NewEncapsulationKey768`. rage rejects the same two inputs via
rust-hpke → x-wing → `ml-kem`, which implements §7.2 by the same round-trip.

We accepted both. **Adding the check removes a divergence rather than creating
one** — that is the whole reason it was safe to make the parser stricter days
before a permanent tag.

The single-coefficient case matters more than the all-`0xFF` one: it shows the
reference implementations enforce this limb by limb, so this is not a
degenerate-input corner.

## Severity: conformance and interoperability, plus a legible error

This is **not** a security fix, and should not be described as one. The words
"vulnerability" and "wrong-accept" are already spent on `hybrid_low_order` in
[`cctv-conformance.md`](cctv-conformance.md), which really was a wrong-accept;
reusing them here devalues that record.

What the check does **not** buy: any defence against recipient substitution. An
attacker who can rewrite a recipient string substitutes a *valid* key they own,
and no amount of validation helps. No shared secret becomes less predictable.
No CCTV vector changes its expected result.

What it does buy:

1. **We stop accepting recipients that no conformant implementation accepts.**
   Before this, a recipient age refuses outright encrypted fine here.
2. **Silent data loss is prevented.** ML-KEM `Encaps` derives `(K, r)` from
   `G(m ‖ H(ek))` over the *raw* `ek` bytes, so a non-canonical alias of a
   genuine key produces a ciphertext the rightful holder's canonical
   decapsulation key cannot reproduce. The file just fails to decrypt, for its
   intended recipient, with no diagnostic.
3. **A truthful error.** `Error::InvalidMlKemEncapsulationKey` is distinct from
   `Error::InvalidEncapsulationKeyLength`; reporting a length problem for a
   correctly-sized key is the same class of misleading diagnostic this change
   exists to remove.

## What changed

* All three `validate_public_key` helpers now return `CrateResult<()>` and
  delegate to `libcrux_ml_kem::mlkem{512,768,1024}::validate_public_key`
  (libcrux-ml-kem **0.0.8**, already in the lockfile — no new dependency, no
  feature flag, no MSRV movement). The 512/1024 twins are feature-gated and
  unreachable today, but `--all-features` compiles them, so leaving them would
  have left two live copies of the same lie.
* `Error::InvalidMlKemEncapsulationKey`, payload-free, added under
  `#[non_exhaustive]`.
* `EncapsulationKey::try_from` propagates it, and checks the ML-KEM half
  **before** the curve point, matching filippo.io/hpke's
  `hybridKEM.NewPublicKey` so a doubly-malformed key yields the same error in
  both implementations.
* `EncapsulationKey::from_components` was `pub` and validated nothing, which
  made the check advisory — any caller could route around it. It is
  `pub(crate)` now; its only caller is internal and derives its bytes from a
  seed. `Ciphertext::from_components` was demoted the same way and then had no
  caller at all, kept compiling by an `#[allow(dead_code)]`; it is **deleted**.
  `from_wrapped_components` and `TryFrom<&[u8]>` cover both construction paths,
  and a private constructor whose warning has to be silenced is the small
  version of the defect this note is about.
* `HybridRecipient::from_bytes` runs the full `EncapsulationKey::try_from` and
  **tolerates** `Error::InvalidX25519PublicKey`, so age-pq-keys rejects a bad
  ML-KEM half at **parse**, where age reports it, while a low-order curve point
  still surfaces at `wrap_file_key`, where age reports *that*.

  An earlier draft expressed the same staging with a public
  `validate_encapsulation_key_mlkem_half(&[u8])`. That function is gone. The two
  formulations are equivalent — the halves are checked in a fixed order, so
  reaching the curve error already proves the ML-KEM half passed — but only one
  of them leaves a half-checking function in a public API, where a later caller
  can validate a half and believe they validated the key. Removing it was free
  before the `v0.1.0` freeze and would have been a breaking change after.

### Why the X25519 half is *not* checked in `from_bytes`

Measured, not reasoned: age parses an all-zero recipient successfully and fails
only at wrap —

```
age: error: failed to wrap key for recipient #0: failed to set up HPKE sender:
crypto/ecdh: bad X25519 remote ECDH input: low order point
```

note "failed to wrap", not "malformed recipient". All-zero ML-KEM bytes are a
*canonical* §7.2 encoding, so they pass the modulus check by design. Our
existing low-order rejection inside `EncapsulationKey::try_from` already lands
at that same wrap-time moment, which is the right place for it. Moving it into
`from_bytes` would diverge from age.

**That measurement is now a test, not a note.** The staging is the whole reason
`from_bytes` tolerates one specific error rather than treating every rejection
alike, and prose in four places (this file, `HybridRecipient::from_bytes`, the
staging note on `EncapsulationKey::try_from`, and two CHANGELOGs) would all have
become false together and silently if a future age moved the curve check
earlier.
`differential_age_go.rs::go_stages_the_encapsulation_key_checks_where_we_do`
(D5) runs the real CLI against both crafted recipients and requires
`malformed recipient` for the bad ML-KEM half and `failed to wrap key` for the
low-order point — measured green against age v1.3.1, and confirmed in
filippo.io/hpke v0.4.0's source (`hybridKEM.NewPublicKey` validates the ML-KEM
half, then calls `crypto/ecdh`'s `NewPublicKey`, which only length-checks; the
low-order refusal comes from `ECDH` at wrap). D5 is the only test here that
reads age's stderr, which its doc comment justifies: the *stage* a check runs at
is invisible in an exit code.

The consequence on our side — `from_bytes(vec![0u8; 1216])` succeeding — has its
own named test,
`bech32_byte_identity.rs::from_bytes_accepts_an_all_zero_key_because_the_curve_check_belongs_to_wrap`.
It used to be a trailing line inside `from_bytes_rejects_a_wrong_length_recipient`,
whose name gives no hint that it also pinned the stage split.

## What not to do next

**Do not extend this to the decapsulation side.** X-Wing explicitly waives the
§7.3 check, and the CCTV vector `hybrid_currupted_enc_mlkem` expects **no
match** precisely because ML-KEM's implicit rejection returns a pseudorandom
shared secret and the AEAD open then fails quietly. Turning an ML-KEM decap
failure into a hard error flips that vector to a header failure. It is the one
way to break a CCTV vector with this change.

`validate_private_key` is inapplicable for a second, independent reason: this
crate's decapsulation key is a 32-byte seed re-expanded through
`KeyGen_internal` on every use, so a pair-consistency check on a key pair just
derived from its own seed can never fail.

`Ciphertext::try_from` staying length-only for `ct_m` is also correct, not a
repeat of this bug: FIPS 203 defines no ciphertext-validity check, and libcrux
exposes no ciphertext validator.

## Coverage, and why the corpus could not have caught this

**All 19 CCTV vectors are decryption-side** — every file carries `identity:` and
an age file, and `grep -c '^recipient:'` returns 0 for every one. Not one
supplies an encapsulation key, so no vector reaches
`EncapsulationKey::try_from` on attacker-supplied bytes. The corpus cannot
regress on this fix and could not have found the defect. Recipient-parse
conformance has **no vector coverage** and has to be tested locally.

New tests, in the shape that would have caught it:

* `mlkem768.rs` / `mlkem512.rs` / `mlkem1024.rs`, in-module: a derived key
  passes; one out-of-range coefficient fails.
* `mlkem768.rs`: an all-zero key **passes**, recorded so nobody "fixes" the
  validator into rejecting it.
* `mlkem768x25519_tests.rs`:
  `one_bad_ml_kem_coefficient_is_rejected_with_a_valid_x25519_half` and
  `all_ff_ml_kem_half_is_rejected_with_a_valid_x25519_half` keep a **genuine**
  curve point in the last 32 bytes, so the rejection is attributable to the
  ML-KEM half and cannot pass for the wrong reason;
  `all_zero_key_is_rejected_for_its_x25519_half_not_its_ml_kem_half` pins the
  other direction.
* `mlkem768x25519_tests.rs`:
  `a_key_malformed_in_both_halves_is_attributed_to_the_ml_kem_half` pins the
  check **order**. Every other test above deliberately keeps one half valid so
  attribution is unambiguous; this is the doubly-malformed case, and it is the
  only thing standing behind the comment in `try_from` that claims to match
  filippo.io/hpke's ordering. Reversing the two lines fails nothing else in the
  workspace — both orders reject, so the divergence is in which error is
  named, and age v1.3.1 names the ML-KEM one.
* `mlkem768.rs`: `a_corrupted_rho_still_passes_the_modulus_check_as_it_does_in_age`.
  The last 32 bytes of `ek` are `rho`, a seed, not coefficients — every 32-byte
  string is valid there. Flipping bytes 1152, 1170 and 1183 is accepted by us
  **and** by age v1.3.1. Pinned because it is the boundary a “stricter is safer”
  change would cross without noticing, in the direction opposite to the one this
  fix took.
* `hybrid_recipient_tests.rs`: the same rejection through `from_bytes` and
  through the bech32 string parser. The string-path test re-encodes mutated
  bytes with a local helper, so it first asserts that helper reproduces
  `HybridRecipient::to_string()` on *unmutated* bytes, and then asserts the
  rejection **names** the ML-KEM half. Without both, an HRP or checksum change
  would make `parse` reject for an unrelated reason and the test would stay
  green while proving nothing — the same can't-fail shape this pass exists to
  remove.
* `differential_age_go.rs`: D5, the staging oracle described above.

## A trap for anyone writing a negative recipient differential

rage 0.12.1 does **not** behave like age here. Given an `age1pq1…` string its
native parser rejects, rage falls back to spawning a plugin:

```
Error: Could not find 'age-plugin-pq' on the PATH. Have you installed the plugin?
```

With `age-plugin-pq` installed — or, on Windows, merely present in
`target/debug`, which Cargo puts on `PATH` for test processes — a test asserting
"rage rejects this" would be exercising our own plugin. Route any such test
through `age-pq-keys/tests/common.rs::age_command_without_plugins`. This is the
CLAUDE.md "never let an interop test reach our own plugin" rule in a new form.

Separately, rage **accepts** the all-zero recipient and encrypts (x-wing's
encapsulation side uses x25519-dalek, which does not error on a low-order peer
key; `XWingRejectNonContrib` only rejects on decapsulation), where age refuses
at wrap. That is a pre-existing age/rage divergence unrelated to this defect.
Our low-order check puts us on age's side; leave it there.
