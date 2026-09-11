# `age-pq-hpke/docs/`

## `hpke-pq.md` — the normative mirror

The document this workspace treats as normative. It is a mirror of
[filippo.io/hpke-pq](https://filippo.io/hpke-pq), chosen because it is
self-contained where the underlying specifications require cross-referencing
four drafts with inconsistent nomenclature.

**It is not stale.** It is byte-identical to `FiloSottile/hpke @ 8aa8a04`
(2025-12-08), the commit it was imported from at subtree `04516c2`, and
upstream still cites the same revisions it does. Re-fetching it is a no-op —
verified rather than assumed, because "the pin looks old, so the content must
be old" is exactly the inference that made issue #25 look like a defect.

Full provenance, and the 03 → 05 delta:
[`docs/design/normative-provenance.md`](../../docs/design/normative-provenance.md).

## The `.txt` drafts

Archived plain-text copies of the **three specifications the mirror normatively
references, at the revisions it cites**:

| File | Why it is here |
|---|---|
| `draft-ietf-hpke-pq-03.txt` | The revision the mirror cites; the cross-check used when transcribing `-05`'s Appendix A vectors |
| `draft-irtf-cfrg-hybrid-kems-07.txt` | The revision the mirror cites for the generic hybrid construction |
| `draft-ietf-hpke-hpke-02.txt` | The revision the mirror cites for the base HPKE text |

That is the whole rule for this directory: **a draft dump belongs here only if
the mirror cites that exact revision.** Two files that did not meet it —
`draft-ietf-lamps-pq-composite-kem-11.txt` (a X.509/CMS certificate format) and
`draft-ietf-tls-ecdhe-mlkem-03.txt` (TLS 1.3 key agreement) — were removed. No
constant, label, or wire-format decision in this crate derives from either, and
nothing outside a frozen changelog line referenced them; they are in git history
if that turns out to be wrong.

These are **archives, not oracles.** Current revisions live on the IETF
datatracker, which keeps every revision permanently. Where a citation does not
need to name a revision, it should not name one: a revision pinned in prose
rots on every expiry-refresh, and the deleted `XWING_DRAFT_VERSION` constant is
what that failure looks like in code.

## `untracked/`

Local research scratch — plain-text drafts fetched while verifying the corpora.
Deliberately **not** committed, and the only thing this directory's `.gitignore`
rule still covers.

They are not needed to build or test anything. What makes them disposable is
that the durable half is already in the repo: each vector corpus records the
`url` and **`sha256`** of the draft it was transcribed from, so any copy can be
re-fetched and checked against the recorded hash. Both recorded hashes were
re-verified against these local files when they were written down.

| Corpus | Draft it records |
|---|---|
| `tests/data/hpke-pq-draft05-vectors.json` | `draft-ietf-hpke-pq-05` |
| `tests/data/test-vectors.json` | `draft-connolly-cfrg-xwing-kem-10` |

`hybrid-kems-03`/`-12` and the second copy of `hpke-pq-03` are there as the
diff inputs for the 03 → 05 enumeration, which is itself written down in
[`normative-provenance.md`](../../docs/design/normative-provenance.md) — the
prose is the artifact, not the dumps.
