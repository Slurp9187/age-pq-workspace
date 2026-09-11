**Status:** in progress · **Date:** 2026-09-10 · **Tracking:** #25, #35, #36

# Plan — #25, records first

## Context

Issue #25 said the normative mirror was pinned to superseded drafts. Research
showed that is **not** the problem, and turned up several that are. All of it
currently lives only in a session thread, which this repo has a standing rule
against. **Capture it before implementing anything** — it is the perishable
part, and #25's implementation gets simpler once it is written down.

Nothing below changes `src/` behaviour except one comment.

## What was established

**The mirror is not stale.** Byte-identical to `FiloSottile/hpke @ 8aa8a04`
(2025-12-08), imported via subtree `04516c2` (2026-03-25), taken from the repo
file. filippo.io/hpke-pq redirects there and still cites -03/-07/-02, so
"re-fetch and diff" is a **no-op**. The drift is upstream-vs-IETF.

**The 03 → 05 delta, enumerated** (was recorded as unknown):

| Section | 03 → 05 |
|---|---|
| §3 ML-KEM | unchanged; adds "Section 4.4 of [HPKE]" |
| §4 Hybrid KEMs | **byte-identical** — the construction did not change |
| §5 Single-Stage KDFs | unchanged; kangarootwelve → RFC 9861 |
| Appendix A | **restructured**; `QSF-X25519-MLKEM768` → `MLKEM768-X25519` |

**Three of four test corpora are mislabelled.**

| Corpus | Label says | Actually |
|---|---|---|
| `test-vectors.json` | hpke-pq-03 App A.5 | **X-Wing Appendix C**, upstream `# TODO: replace`. ~~truncated to 20 bytes~~ — **struck: that was false, see the correction below.** Predates the workspace |
| `tests/data/testkit/` | C2SP CCTV | CCTV `e9274a7b` → **rage `26fe921`** → our `85fe5c0`; taken from rage `origin/pq @ 5d33e3e`. **Both** compressed vectors decompressed: `armor_hybrid` 1951→2554, `hybrid_multiple_recipients` 2739→3441 |
| `kat_tests.rs` header | RFC 9180 + hpke-pq-03 | those two **plus** the unnamed X-Wing file |

**Two claims I nearly shipped as fixes were wrong**, caught by a Plan agent and
a peer independently:

- `conformance-workspace.md`'s **CONCRETE-04 is correct** —
  `draft-irtf-cfrg-concrete-hybrid-kems-04` exists, 2026-07-06, active. The
  three citations (-02 mirror, -03 hpke-pq-05, -04 current) are each right about
  a different moment. The actual defect is
  `normative-source-refresh.md:24-26`'s "at most one of those is right".
- **DeriveKeyPair does have a published vector** — `ikmR → skRm` in the hpke-pq
  appendices *is* `DeriveKeyPair(ikmR)`.

**One claim of the peer's was wrong**, and the cause generalises: it reported
the five `docs/*.txt` as untracked and unenumerable by git. They **are**
tracked. `git log --diff-filter=A` does not show files added by **merge
commits** without `-m`, and these arrived via subtree `04516c2`. No junction, no
nested `.git`. That blind spot hides anything else from that merge — including
`test-vectors.json`.

**Oracle trap.** `O:\…\age-hpke-pq-go` (a stale fork of `hpkewg/hpke-pq`)
assigns `QsfX25519MlKem768 = 0x0051`. Current is **0x647a**; `0x0051` is
MLKEM1024-P384. Wrong in two places — `reference-implementation/src/kem.rs` and
`src/bin/json-to-markdown.rs:41` — while its own IANA table has it right. Its
`test-vectors.json` has no `0x647a` vector at all. Differential-testing against
it would "confirm" the wrong codepoint.

## Step 1 — record, and split #25 into issues

#25 has become a container for four unrelated concerns. Decompose it, because a
container issue is how the smaller pieces get lost:

**#35 — "Give the shipped suite a published-vector anchor".**
Adopt `-05` A.5 and A.12. This is the substantive win and it is *not* what #25
is titled; buried under "refresh the mirror" it would never be found. Detail in
step 2.

**#36 — "Test corpus provenance is wrong in three of four places".**
The relabelling and `source` envelopes. Distinct from citations. It originally
carried an open question — *why was the corpus truncated to 20 bytes?* — which
is **withdrawn**: nothing was truncated. See the correction below. `#36` was
filed with the false claim in it and has been corrected in a comment.

**Comments, not issues:**

- **#19 and #15** — the oracle trap, so it is seen before anyone reaches for
  that clone. It is guidance for that work, not work itself.
- **#25** — what is now answered: mirror refresh is a no-op, the 03→05 delta
  enumerated, CONCRETE-04 correct. Then **narrow #25 to the citation cleanup**
  (step 3), which is all that is genuinely left of its title.

**Documents:**

- **`docs/design/` note** — provenance of all four corpora with commits, plus
  the `--diff-filter=A` blind spot, which is a repo-wide research hazard and
  belongs in prose rather than an issue.
- **`docs/plans/normative-source-refresh.md`** — fix "at most one is right";
  close the completed items.
- **README among the reference clones** — the four repos, their remotes, and
  that `age-hpke-pq-go` is a stale fork whose README points upstream: read
  `.git/config`, not the README.
- **Update the saved memory entry** — it names three clones under the old
  `hpke-go` path; there are four, one renamed.

## Step 2 — the KAT (the only substantive work)

New `age-pq-hpke/tests/hpke_pq_draft_vectors.rs` + a vectors JSON carrying a
`source` block (`document`/`url`/`retrieved`/`sha256`) and `appendix`/`title`
**per vector**, since appendix numbering proved unstable. No "current" field —
that rots exactly like the deleted `XWING_DRAFT_VERSION`.

Vectors **-05 A.5** (`kdf 1`/`aead 3` — age's exact suite, the first published
anchor for what we actually ship) and **-05 A.12** (`kdf 17`/`aead 3`). Driver
selects by numeric ids, never by title. End-to-end through the existing public
API; `key`/`base_nonce`/`exporter_secret` asserted **indirectly** via
seal/export — **do not add a public accessor to make them assertable.**

Then retire the `-03` A.5 test in a **separate commit**: it hand-rebuilds
`secrets`/`ks_context`, so it would pass even if `hpke.rs`'s one-stage branch
broke, and its `aead_id 1` is not instantiable here.

## Step 3 — citations

Contradictory -03/-05 pairs in **three** files: `age-pq-hpke/README.md`,
root `README.md`, `docs/design/rage-pq-adoption.md`. Plus
`age-pq-hpke/Cargo.toml:5` (ships in package metadata),
`age-plugin-pq/README.md:67`, `CLAUDE.md:37`.

One real fix: **`mlkem768x25519.rs:41`** cites RFC 9180 §5.3 for the KEM
suite_id; §5.3 is the exporter. Correct is §4.1 / HPKE §4.4.

Leave alone: `README.md:169-170` ("mirror still pinned to -03") is **true**; the
frozen CHANGELOG entries; the mirror itself.

## Deferred

The five `docs/*.txt` — keep or delete is a judgement call worth making with the
record written, not before. `hpke-pq-03.txt` is the cross-check for the -05
transcription, so it stays at least until step 2 is green.

## Verification

- `cargo test --workspace --all-features -- --include-ignored` — 19/19 CCTV, D1–D5
- `cargo fmt --all -- --check`; `clippy --workspace --all-features --all-targets -D warnings`
- changelog-protocol check

Before any vector enters the repo, re-derive `DeriveKeyPair(ikmR)==skRm` and the
key-schedule outputs from the extracted bytes, so a transcription slip fails
where it looks like one. **Step 2 is the only step that can surprise** —
`derive_key_pair` and the 1216-byte `pkRm` have never been checked against
published bytes; if it reds after that pre-check passed, that is a conformance
finding, so stop and report. Mutation-check the new KAT.

`main` is on `0.2.0-rc.2 - unreleased`; no version bump or tag.

## Correction — the "20-byte truncation" did not happen

This plan was written with a false premise in it, and executing it is what
caught that. `age-pq-hpke/tests/data/test-vectors.json` was **not** truncated.
Every field of all three vectors was re-compared byte-for-byte against the
`draft-connolly-cfrg-xwing-kem-10` text:

| Field | Length in our file | Draft-10 |
|---|---|---|
| `seed` | 32 B | 32 B |
| `eseed` | 64 B | 64 B |
| `pk` | **1216 B** | 1216 B |
| `ct` | **1120 B** | 1120 B |
| `ss` | 32 B | 32 B |

All exact. The claim came from reading a *display* truncation back as a
property of the data: an inspection script printed `str(v)[:40]` per field, and
those 20-byte-looking values were then recorded as the file's contents. The
error propagated into issue #36, into a peer session, and into this document
before the verification pass caught it.

Worth keeping as a method note, not just a fact: **an inspection script's
formatting is not evidence about the data.** Where a length is the claim,
assert the length (`len(bytes.fromhex(v))`), do not eyeball a rendering of it.

With that withdrawn, the only remaining unknown about this corpus is benign:
it is X-Wing's placeholder appendix, carrying upstream's own
`# TODO: replace with test vectors that re-use ML-KEM, X25519 values`, and it
was mislabelled in `kat_tests.rs` as hpke-pq-03 Appendix A.5. Both are now
recorded in the file's `source` envelope. No clone of `Slurp9187/age-hpke-pq`
is needed.
