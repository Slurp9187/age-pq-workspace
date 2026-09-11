# Plan: refresh the normative source mirror

**Status:** executed, two items open · **Date:** 2026-09-09 · **Tracking:** issue #25

`age-pq-hpke/docs/hpke-pq.md` is the document this workspace treats as
normative — it is a mirror of [filippo.io/hpke-pq](https://filippo.io/hpke-pq),
chosen because it is self-contained where the underlying specifications require
cross-referencing four drafts with inconsistent nomenclature.

**The mirror's citations name revisions the IETF has since moved past — but the
mirror is not stale.** That distinction is the correction this plan earned by
being executed: the in-tree file is byte-identical to the upstream source it was
taken from, and *upstream* still cites -03/-07/-02, so "re-fetch and diff" is a
no-op (work item 1 below). The drift is upstream-vs-IETF, not ours-vs-upstream,
and nothing in the construction changed across it.

## The drift

| Document | Mirror (and upstream) cites | IETF current, checked 2026-09-09 |
|---|---|---|
| `draft-ietf-hpke-pq` | **03** | **05** (posted 2026-07-06, expires 2027-01-07, active) |
| `draft-irtf-cfrg-hybrid-kems` | **07** | **12** |
| `draft-irtf-cfrg-concrete-hybrid-kems` | **02** | **04** (posted 2026-07-06, active) — **not** 03; an earlier revision of this table said 03, which is what set up the trap below |
| `draft-ietf-hpke-hpke` | 02 | not re-checked |

Apparent internal inconsistency, checked rather than reconciled:
[`conformance-workspace.md`](conformance-workspace.md) cites "CFRG CONCRETE-04"
for the MLKEM1024-P384 parameters, while the mirror cites concrete-**02** and
hpke-pq-05 cites concrete-**03**. **This plan originally said "at most one of
those is right" — that sentence was itself the error.** `concrete-hybrid-kems`
is an independently-versioned external draft; each of the three citing
documents correctly names whatever revision was current when *that document*
last checked it, not a claim about what is current today. `-04` is in fact the
currently active revision (posted 2026-07-06). All three citations are
correct about different moments, and none needs to change. Full writeup, plus
why this is a trap worth remembering: [`../design/normative-provenance.md`](../design/normative-provenance.md#4-concrete-04-is-correct--three-citations-three-different-moments).

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

**Update:** `draft-ietf-hpke-pq-05` carries no change-log appendix, so the
03 → 05 delta had to be enumerated by diffing the full texts directly rather
than reading a summary. That diff is now done — see
[`../design/normative-provenance.md`](../design/normative-provenance.md#2-the-draft-ietf-hpke-pq-03--05-delta)
for the section-by-section table. Result: §4 (Hybrid KEMs, the construction
itself) is byte-identical; the only substantive change touching this
workspace's citations is Appendix A's rename of `QSF-X25519-MLKEM768` to
`MLKEM768-X25519`, and §5 kept its section number across the revision.

The strongest evidence the construction is stable is empirical rather than
textual: we byte-match the Go age CLI at **both** v1.3.1 and v1.3.2 across 64
derivation cases and 22 payload cases in each direction
([`../design/age-go-differential-oracle.md`](../design/age-go-differential-oracle.md)),
and pass 19/19 C2SP CCTV vectors. A wire-format change in hpke-pq-05 would have
had to move age-go too, and the oracle would be red.

## The conformance gap this surfaced

Both normative lineages **mandate** the ML-KEM encapsulation key check, and this
workspace did not perform it (fixed on `fix/pre-freeze-test-hygiene`; see
[`../design/mlkem-encapsulation-key-check.md`](../design/mlkem-encapsulation-key-check.md)):

> `ML-KEM-768.Encaps(pk_M)` MUST perform the encapsulation key check of
> [MLKEM] §7.2 and raise an error if it fails.
> — draft-connolly-cfrg-xwing-kem-10 §5.1

> The `Encap` function corresponds to the function `ML-KEM.Encaps` in
> [FIPS203], where an ML-KEM encapsulation key check failure causes an HPKE
> `EncapError`.
> — draft-ietf-hpke-pq-05 §3

`age-pq-hpke/src/kem/ml_kem/mlkem{512,768,1024}.rs::validate_public_key` was a
no-op that only re-wrapped the bytes, so an all-`0xFF` encapsulation key parsed
successfully. Fixed separately — this document records only that the requirement
is **normative in both lineages**, so the fix is conformance, not gold-plating.
The two quotations above are the citations the fix now carries in
`Error::InvalidMlKemEncapsulationKey` and `mlkem768.rs::validate_public_key`;
they cited -07 §4 briefly, a revision nobody had opened, and were corrected to
match this page.

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

- [x] Re-render or re-fetch `filippo.io/hpke-pq` and diff it against the
      in-tree mirror. Record the delta rather than silently replacing the file.
      **Done.** Compared byte-for-byte against `FiloSottile/hpke @ 8aa8a04`
      (2025-12-08), the same commit the mirror was imported from at subtree
      `04516c2` — identical. `filippo.io/hpke-pq` still redirects there and
      still cites -03/-07/-02, so there is nothing newer to pull: this was a
      **no-op**, because the earlier premise ("stale pin implies stale
      content") did not hold — upstream has not moved its own pin either. See
      [`../design/normative-provenance.md`](../design/normative-provenance.md#3-why-refreshing-the-mirror-is-a-no-op).
- [x] Enumerate the `draft-ietf-hpke-pq` 03 → 05 changes from the datatracker
      diff tool, since the draft itself carries no change log. **Done** by
      diffing the full uploaded texts of -03 and -05 directly: §4 (Hybrid
      KEMs) is byte-identical, §5 keeps its section number with one reference
      swap, and Appendix A renames `QSF-X25519-MLKEM768` to
      `MLKEM768-X25519` with different vectors under the same appendix number.
      Table: [`../design/normative-provenance.md`](../design/normative-provenance.md#2-the-draft-ietf-hpke-pq-03--05-delta).
- [x] Reconcile the CONCRETE revision cited across the mirror,
      `conformance-workspace.md`, and hpke-pq-05. **No reconciliation needed —
      this was the trap.** All three citations (-02, -03, -04) are correct
      about the revision current when each document last checked it; CONCRETE
      -04 is in fact today's active revision. See
      [`../design/normative-provenance.md`](../design/normative-provenance.md#4-concrete-04-is-correct--three-citations-three-different-moments)
      and the correction above.
- [x] Delete `XWING_DRAFT_VERSION`; move provenance into the module doc with the
      revisions actually diffed. **Done** on `fix/pre-freeze-test-hygiene`: the
      constant is gone and `age-pq-hpke/src/lib.rs`'s module doc now carries a
      *Normative provenance* section. Taken in that pass because removing a
      `pub` item is free before the `v0.1.0` tag (DECIDE-13) and a breaking
      change after it. The module doc originally said the 03 → 05 delta had
      "not been enumerated"; now that the enumeration above is done, the
      module doc has been updated to link it instead of repeating the
      now-stale caveat.
- [ ] Confirm MLKEM768-P256 — the third variant in hpke-pq-05, and the one this
      workspace has never tracked — has no bearing on MLKEM768-X25519. It is a
      candidate sibling for #19 either way.
- [ ] Re-run the CCTV vectors and the age-go differential oracle after the
      refresh. They are the check that the refresh changed documentation only.

## Why this is a plan and not a defect

Nothing here is known to be wrong in the shipped code. The construction we
implement matches both the expired individual draft and the active WG draft on
every invariant checked, and matches two independent implementations
empirically. What was wrong is that **nothing was watching the pin** — not that
the pin was stale, which is what this plan assumed going in and what executing
it disproved. This workspace's recurring failure mode is a claim nobody
verifies, and an unwatched normative citation is that shape one level up from
the code. The finding it *did* surface is in "The conformance gap this
surfaced" above: a MUST both lineages state and the crate did not perform.
