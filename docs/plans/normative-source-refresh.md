# Plan: refresh the normative source mirror

**Status:** proposed · **Date:** 2026-09-09 · **Tracking:** issue #25

`age-pq-hpke/docs/hpke-pq.md` is the document this workspace treats as
normative — it is a mirror of [filippo.io/hpke-pq](https://filippo.io/hpke-pq),
chosen because it is self-contained where the underlying specifications require
cross-referencing four drafts with inconsistent nomenclature.

**The mirror is pinned to revisions that have since moved.** Nothing in the
construction changed, but the pin is stale and nothing in the repository would
have noticed.

## The drift

| Document | Our mirror cites | Current |
|---|---|---|
| `draft-ietf-hpke-pq` | **03** | **05** (posted 2026-07-06, expires 2027-01-07, active) |
| `draft-irtf-cfrg-hybrid-kems` | **07** | **12** |
| `draft-irtf-cfrg-concrete-hybrid-kems` | **02** | **03** |
| `draft-ietf-hpke-hpke` | 02 | not re-checked |

Internal inconsistency to reconcile while doing this:
[`conformance-workspace.md`](conformance-workspace.md) cites "CFRG CONCRETE-04"
for the MLKEM1024-P384 parameters, while the mirror cites concrete-**02** and
hpke-pq-05 cites concrete-**03**. At most one of those is right.

## The X-Wing draft is expired — and that is not a problem

`draft-connolly-cfrg-xwing-kem-10` was posted 2026-03-02 and **expired
2026-09-03**. Datatracker shows IESG state "Expired", no responsible AD, and no
formal `Replaces` relationship.

This is not abandonment, and the distinction matters because it is the kind of
thing that gets misread later:

- It is an **individual** submission (`draft-connolly-`). Individual drafts
  expire 185 days after posting unless a new revision is posted; there is no
  separate "refresh filing" to forget — the refresh *is* posting `-11`.
- Its substance now lives in the **working group** line.
  `draft-ietf-hpke-pq-05` is active, defines MLKEM768-X25519 with the same
  parameters, and never mentions X-Wing by name — it takes the construction from
  `draft-irtf-cfrg-hybrid-kems` and `draft-irtf-cfrg-concrete-hybrid-kems`.
- Those CFRG drafts moved 07 → 12 and 02 → 03 while the individual draft sat
  still. Five revisions of movement in the WG line is the signature of content
  migrating, not of authors walking away.

Drafts 08, 09 and 10 of X-Wing added **no change-log entries at all** — the
newest entry is "Since draft-07". They are expiry-refresh republishes.

## What was verified unchanged

Checked directly against draft-connolly-cfrg-xwing-kem-10 and
draft-ietf-hpke-pq-05, because these are the things that would break interop:

| Invariant | Value | Matches |
|---|---|---|
| HPKE KEM id | `0x647a` (25722 = 25519 + 203) | our `MlKem768X25519` |
| `Nenc` / `Npk` | 1120 / 1216 | our constants |
| Combiner inputs | `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)` | `kem/combiner.rs` argument order |
| `XWingLabel` | hex `5c2e2f2f5e5c` | `X_WING_LABEL = br"\.//^\"` |

**Caveat, stated rather than glossed:** `draft-ietf-hpke-pq-05` carries no
change-log appendix, so the 03 → 05 delta was not enumerated. The invariants
above were confirmed directly; anything else that changed between those
revisions is currently unknown. That is the gap this plan exists to close.

The strongest evidence the construction is stable is empirical rather than
textual: we byte-match the Go age CLI at **both** v1.3.1 and v1.3.2 across 64
derivation cases and 22 payload cases in each direction
([`../design/age-go-differential-oracle.md`](../design/age-go-differential-oracle.md)),
and pass 19/19 C2SP CCTV vectors. A wire-format change in hpke-pq-05 would have
had to move age-go too, and the oracle would be red.

## The conformance gap this surfaced

Both normative lineages **mandate** the ML-KEM encapsulation key check, and this
workspace does not perform it:

> `ML-KEM-768.Encaps(pk_M)` MUST perform the encapsulation key check of
> [MLKEM] §7.2 and raise an error if it fails.
> — draft-connolly-cfrg-xwing-kem-10 §5.1

> The `Encap` function corresponds to the function `ML-KEM.Encaps` in
> [FIPS203], where an ML-KEM encapsulation key check failure causes an HPKE
> `EncapError`.
> — draft-ietf-hpke-pq-05 §3

`age-pq-hpke/src/kem/ml_kem/mlkem{512,768,1024}.rs::validate_public_key` was a
no-op that only re-wrapped the bytes, so an all-`0xFF` encapsulation key parsed
successfully. Tracked and fixed separately — this document records only that the
requirement is **normative in both lineages**, so the fix is conformance, not
gold-plating.

Note the deliberate asymmetry, which the fix must respect: the same drafts state
that `Decap` is **NOT** required to perform the §7.3 decapsulation key check.
Adding one would be over-implementation.

## `XWING_DRAFT_VERSION` should not survive this

`age-pq-hpke/src/lib.rs:57`:

```rust
pub const XWING_DRAFT_VERSION: &str = "09";
```

Three problems, in increasing order of seriousness:

1. **It is stale** — the draft is at 10.
2. **It is dead.** Defined once, read by nothing, asserted by no test. Nothing
   could ever have caught (1).
3. **It is a conformance claim with no verifier behind it.** Draft-09 mandates
   the encapsulation key check that the crate did not perform, so the constant
   asserted conformance the code did not have — the same failure shape as the
   no-op validator it sat above, and as the workflow that never ran (#13) and
   the tests that self-skipped (#14).

Bumping `"09"` to `"10"` fixes only the least important of the three, and
re-arms the rot: the number changes on expiry-refresh even when the
specification does not.

**Recommendation:** delete the constant. Put spec provenance in the module doc,
where it reads as documentation instead of masquerading as a checked value, and
keep in code only what is checkable — the KEM id `0x647a`, already covered by the
CCTV vectors. This is a breaking change to a public item, which is free before
the `v0.1.0` freeze (DECIDE-13) and awkward after.

## Work items

- [ ] Re-render or re-fetch `filippo.io/hpke-pq` and diff it against the
      in-tree mirror. Record the delta rather than silently replacing the file.
- [ ] Enumerate the `draft-ietf-hpke-pq` 03 → 05 changes from the datatracker
      diff tool, since the draft itself carries no change log.
- [ ] Reconcile the CONCRETE revision cited across the mirror,
      `conformance-workspace.md`, and hpke-pq-05.
- [ ] Delete `XWING_DRAFT_VERSION`; move provenance into the module doc with the
      revisions actually diffed.
- [ ] Confirm MLKEM768-P256 — the third variant in hpke-pq-05, and the one this
      workspace has never tracked — has no bearing on MLKEM768-X25519. It is a
      candidate sibling for #19 either way.
- [ ] Re-run the CCTV vectors and the age-go differential oracle after the
      refresh. They are the check that the refresh changed documentation only.

## Why this is a plan and not a defect

Nothing here is known to be wrong in the shipped code. The construction we
implement matches both the expired individual draft and the active WG draft on
every invariant checked, and matches two independent implementations
empirically. What is wrong is that the **pin drifted with nothing watching it** —
and this workspace's recurring failure mode is precisely a claim nobody
verifies. A stale normative pin is that shape, one level up from the code.
