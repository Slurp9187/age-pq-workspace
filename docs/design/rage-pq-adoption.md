# Decision: keep `age-pq-hpke`, use rage and age-go as conformance oracles

**Status:** decided · **Date:** 2026-09-08 · **Tracking:** issue #12

## Context

Both official age implementations now ship post-quantum support natively:

- **age-go v1.3.0+** — `pq.go` in the `age` package (`filippo.io/age`). Verified
  locally against the v1.3.2 clone.
- **rage** — `age::pq::{Identity, Recipient}` on the unmerged `pq` branch.

This crate set predates both. The question was whether to adopt one of them or
keep our own implementation.

**Decision: keep ours.** The strategic driver is extensibility to non-standard
variants (MLKEM1024-P384 next), which the plugin protocol is the only sanctioned
extension point for. We own all runtime code; rage and age-go become conformance
oracles rather than dependencies.

## Q1 — Is the wire format identical? Yes, byte-for-byte

This was the decisive question, and it is settled empirically, not by reading
drafts.

**A premise correction worth recording, because it cost a round of analysis.**
CFRG X-Wing (`draft-connolly-cfrg-xwing-kem`) and `draft-ietf-hpke-pq-03`'s
MLKEM768-X25519 are *the same construction by design*, sharing KEM id `0x647a`.
They are not two lineages that happen to use the same primitives. Anyone
revisiting this should not re-derive the "maybe they diverge" hypothesis — it is
false.

| Parameter | Value | Verified |
|---|---|---|
| KEM id | `0x647a` | here |
| Combiner | `SHA3-256(ss_pq \|\| ss_t \|\| ct_t \|\| ek_t \|\| label)`, label **appended last** | here |
| X-Wing label | `\.//^\` (`5c2e2f2f5e5c`) | here |
| Seed expansion | `SHAKE256(seed, 96)`, split three ways | here |
| Stanza tag | `mlkem768x25519` | here |
| HPKE info label | `age-encryption.org/mlkem768x25519` | here |
| KDF / AEAD | HKDF-SHA256 (`0x0001`) / ChaCha20-Poly1305 (`0x0003`) | here |
| HRPs | `age1pq`, `AGE-SECRET-KEY-PQ-`, plugin `AGE-PLUGIN-PQ-` | here |
| `Nenc` / body | 1120 / 32 (16-byte file key + 16-byte tag) | here |

Our normative source is [`age-pq-hpke/docs/hpke-pq.md`](../../age-pq-hpke/docs/hpke-pq.md),
a mirror of [filippo.io/hpke-pq](https://filippo.io/hpke-pq).

**Cross-implementation results** (run by the peer session, not re-run here):
3 fixed seeds through our crate produce bech32 identities that `age-keygen -y`
and `rage-keygen -y` both expand to byte-identical recipients (6/6). Ciphertext
written by us decrypts under rage-pq and under age-go. rage ↔ age-go passes in
both directions.

**Nothing to migrate.** The divergence was never format; it was input validation.

## Q2 — Is rage's PQ reusable? Yes, but the premise moved

`age::pq::{Identity, Recipient}` are `pub`, so adoption was technically
available. But the original rationale for `age-plugin-pq` — "the plugin is how
you get PQ interop with Go age" — **expired with age-go v1.3.0**. Go and rage
now interoperate natively with no plugin present.

Remaining plugin value:

1. age < 1.3 compatibility.
2. **Non-standard variants** (MLKEM1024-P384, `0x0051`), where the plugin
   protocol is the only sanctioned extension point. Per the peer session,
   `age/src/plugin.rs` forwards *every* header stanza to identity plugins, so a
   plugin identity can also unwrap native `mlkem768x25519` stanzas produced by
   official binaries.

Item 2 was originally cited as *the* reason to keep our own runtime.

> **Superseded 2026-09-09.** That reasoning no longer holds. `rust-hpke` already
> implements `MlKem1024P384` with KAT coverage, so the variant is not something
> only we can reach — adopting rage would make it "wire a stanza type around an
> existing KEM". The decision to keep our own runtime stands, but on a different
> basis: `libcrux-ml-kem` is **formally verified** where `rust-hpke`'s
> RustCrypto `ml-kem` is not, and we require `#![forbid(unsafe_code)]` where
> `rust-hpke` does not declare it.
>
> Cite the verified-backend argument, not the extensibility one. Full analysis
> and the port estimate: [`hpke-import-vs-own.md`](hpke-import-vs-own.md).

## Q3 — Draft tracking: pinned, not chasing head

rage pins via `[patch.crates-io]` (`str4d/rust-hpke`, `str4d/RustCrypto-KEMs`).
Wire constants for `0x647a` did not change from draft `-03` to `-05`.

`draft-ietf-hpke-pq-05` restructured: it now defines only the suite id
(`KEM\x64\x7a`) and delegates the combiner to the CFRG CONCRETE/GENERIC drafts.
Our mirrored `hpke-pq.md` predates that split. **The constants remain correct**;
the document organisation is what changed. (Reported by the peer session.)

## Q4 / Q5 — MSRV and secret handling: only couple if we adopt the code

rage's `pq` branch is `rust-version = "1.85"` and uses `age_core::secrecy`. We
are MSRV 1.70 for one more release (issue #2) and standardised on `secure-gate`.

Adopting rage's *code* would force the MSRV bump and put two secret libraries in
one tree. Using rage as an *oracle* in an isolated workspace does neither —
which is a large part of why the oracle approach wins.

## Q6 — Maintenance status

rage's `pq` branch is unmerged; `age::pq` is under `[Unreleased]`. No timeline.

Format-shift risk is not rage's to create: the format is specified at
[c2sp.org/age](https://c2sp.org/age) and shipped in age-go v1.3.0. rage
implements an existing spec rather than defining one.

## Q7 — Test vectors: 19, and they found real bugs

The C2SP CCTV age testkit has 19 `hybrid_*` / `armor_hybrid` vectors. These
caught two bugs in rage's own PQ implementation (rage commit `5391c78`, "Fix
`pq` bugs exposed by testkit test vectors"), and seven in ours.

See [`cctv-conformance.md`](cctv-conformance.md).

## Consequences

- We own all shipping code; libcrux stays inside.
- rage and age-go are oracles, pulled into an isolated conformance workspace so
  their MSRV, their `secrecy` dependency, and the `[patch.crates-io]` forks stay
  out of our shipping graph. `[patch.crates-io]` is workspace-global, so
  isolation is load-bearing, not tidiness. See
  [`../plans/conformance-workspace.md`](../plans/conformance-workspace.md).
- Cost of keeping ours: the seven CCTV fixes (done) plus ongoing conformance
  maintenance.

## Provenance

Facts marked "verified here" were checked against this repo and the local
age-go v1.3.2 / rage `pq` @ `5d33e3e` clones during this session. Facts
attributed to "the peer session" come from a parallel Claude session that ran
the cross-implementation decrypt matrix; they are consistent with everything
checked here but were not independently re-run.
