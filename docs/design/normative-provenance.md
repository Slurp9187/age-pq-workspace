# Normative provenance

**Status:** informational · **Date:** 2026-09-10 · **Tracking:** issue #25

This is the durable record of where this workspace's normative documents and
test corpora came from, and of a research trap that nearly produced a wrong
"fix" to a citation that was already correct. It exists because everything
below previously lived only in a session thread, and this repository has a
standing rule against that (see `MEMORY.md`: *durable records, not session
threads*).

## 1. Where each corpus came from

| Corpus | Provenance | Commit / pin |
|---|---|---|
| `age-pq-hpke/docs/hpke-pq.md` (the in-tree normative mirror) | Subtree import of `FiloSottile/hpke` | upstream `8aa8a04` (2025-12-08), imported via subtree `04516c2` (2026-03-25) |
| `age-pq-hpke/tests/data/test-vectors.json` | `draft-connolly-cfrg-xwing-kem` Appendix C, **complete and untruncated** — mislabelled in-tree as hpke-pq-03 App A.5 | see §1a |
| `age-pq-keys/tests/data/testkit/` (19 C2SP CCTV vectors) | C2SP/CCTV age testkit | `e9274a7b` → rage `26fe921` (2026-07-14) → this repo `85fe5c0` (2026-09-08), taken from rage `origin/pq @ 5d33e3e` |
| Reference clones on disk | see §6 | — |

### 1a. The X-Wing corpus — mislabelled, but complete

`age-pq-hpke/tests/data/test-vectors.json` holds three vectors from
`draft-connolly-cfrg-xwing-kem` **Appendix C**. Two things about it:

**The label was wrong.** `kat_tests.rs` named the file's sources as RFC 9180
Appendix A and draft-ietf-hpke-pq-03 Appendix A. It is neither — the field names
(`seed`/`eseed`/`ss`/`sk`/`pk`/`ct`) are X-Wing's, and the values are X-Wing's.

**It is NOT truncated.** An earlier note in this workstream — and, briefly, an
earlier draft of this very document — claimed each field was cut to its first 20
bytes. That was false, and the error is instructive enough to record: it came
from reading a *display* truncation (`str(v)[:40]` in an inspection script) back
as a property of the data. Re-verified field by field against the draft-10 text:

| field | length | matches draft |
|---|---|---|
| `seed`, `sk`, `ss` | 32 B each | ✅ |
| `eseed` | 64 B | ✅ |
| `pk` | **1216 B** (full ML-KEM-768 ‖ X25519) | ✅ |
| `ct` | **1120 B** (full ML-KEM-768 ‖ X25519) | ✅ |

Every field of all three vectors is a complete, exact match.

**What is genuinely provisional** is upstream's own status: that appendix is
titled "Test vectors # TODO: replace with test vectors that re-use ML-KEM,
X25519 values", in both -07 and -10. So the authors treat these as placeholder
bytes exercising the combiner's shape rather than vectors derived from published
ML-KEM/X25519 KATs. Expect them to be replaced upstream eventually.

### 1b. The testkit decompression

Both `armor_hybrid` and `hybrid_multiple_recipients` are stored in this
workspace **decompressed**, with upstream's `compressed: zlib` header line
removed:

| Vector | Compressed (upstream) | Decompressed (here) |
|---|---|---|
| `armor_hybrid` | 1951 B | 2554 B |
| `hybrid_multiple_recipients` | 2739 B | 3441 B |

This was done so the conformance harness needs no `flate2` dependency. The age
file bytes under test are unchanged — only the on-disk encoding differs.
Re-apply this deviation when refreshing vectors from upstream. See
[`cctv-conformance.md`](cctv-conformance.md) for the harness itself.

## 2. The draft-ietf-hpke-pq 03 → 05 delta

Diffed from the full texts of `-03` and `-05` (uploaded drafts, not summaries):

| Section | Result |
|---|---|
| §3 ML-KEM | Unchanged, except it now adds a cross-reference to "Section 4.4 of [HPKE]" for the `suite_id` construction. |
| §4 Hybrid KEMs | **Byte-identical.** The construction itself did not change between -03 and -05. |
| §5 Single-Stage KDFs | Unchanged apart from one reference swap: `kangarootwelve` → RFC 9861. **Still numbered §5 in -05**, so any existing "§5" citation in this workspace remains content-correct without edits. |
| Appendix A (test vectors) | **Restructured.** `QSF-X25519-MLKEM768` was renamed `MLKEM768-X25519`. -03 Appendix A.5 and -05 Appendix A.5 are **different vectors** — do not diff them expecting equality. |

Net effect: nothing in the construction moved. The rename in Appendix A is
cosmetic (a label change on the same algorithm, matching the CFRG
concrete-hybrid-kems naming), and every invariant this workspace's wire format
depends on — KEM id, `Nenc`/`Npk`, combiner input order, `XWingLabel` — was
independently confirmed unchanged (see `normative-source-refresh.md`).

## 3. Why refreshing the mirror is a no-op

`age-pq-hpke/docs/hpke-pq.md` was compared byte-for-byte against the current
`FiloSottile/hpke` upstream at commit `8aa8a04` (2025-12-08) — the same commit
the in-tree copy was imported from. They are **identical**. `filippo.io/hpke-pq`
still redirects to that repository and still cites `-03`/`-07`/`-02` (the same
revisions the mirror cites), so there is nothing newer to pull.

"Refresh the mirror" was the framing of `normative-source-refresh.md` when it
was opened, on the assumption that a stale pin implied stale content. That
assumption was checked and did not hold: **the pin and the content are both
exactly where upstream currently has them.** The distinct, real gap was the
unenumerated 03 → 05 *draft* delta (§2 above), which is a different question
from mirror staleness — the mirror mirrors upstream's own choice of pin, and
upstream has not moved its pin either.

## 4. CONCRETE-04 is correct — three citations, three different moments

`draft-irtf-cfrg-concrete-hybrid-kems-04` exists (posted 2026-07-06, active,
no errata). Three files in this tree cite three different revision numbers of
this draft, and **all three are correct** because each is a true statement
about the revision current *at the moment that document last checked it*, not
a claim about what is current today:

| File | Cites | Correct because |
|---|---|---|
| `age-pq-hpke/docs/hpke-pq.md` (mirror) | -02 | That is upstream `FiloSottile/hpke`'s own pin as of `8aa8a04` — the mirror is byte-identical to upstream, so it correctly reproduces upstream's citation. |
| `draft-ietf-hpke-pq-05` (external draft, not ours to edit) | -03 | That is the revision the hpke-pq editors had pinned when -05 was published. |
| `docs/plans/conformance-workspace.md` | -04 | That is the current revision, cited when that document was written closest to today. |

**This is the trap.** `normative-source-refresh.md` originally read this
spread as an inconsistency — "At most one of those is right" — and treated it
as a defect to reconcile by picking one number and rewriting the other two.
That framing is the error, not the citations. A citation to an external,
independently-versioned draft is a snapshot of *when it was written*, not a
live pointer; three documents written at three different times correctly cite
three different snapshots of a document that has itself moved. Rewriting
`conformance-workspace.md`'s -04 down to -03 to "match" the mirror would have
turned a correct citation into a stale one, for the sake of an alignment
that was never the target. **Do not "fix" CONCRETE-04 to CONCRETE-03, or
otherwise force these three citations to agree.**

## 5. The `git log --diff-filter=A` blind spot

`git log --diff-filter=A -- <path>` reports when a path was **added by a
regular commit**. It does **not** surface files that first appeared via a
merge commit, unless that merge is walked with `-m` (which shows the merge's
diff against each parent separately). Several files in this workspace —
including `age-pq-hpke/docs/hpke-pq.md` itself — arrived through the subtree
merge at `04516c2`, a merge commit. A plain `--diff-filter=A` search for
"when was this file added" reports **nothing** for such a file, which reads as
"this file has always been here" or "this file was never added" — both wrong,
and both misleading in the same direction (understating how the file got
here).

This is a repo-wide research hazard, not a one-off. Before concluding a file
predates some point in history, or was authored in-repo rather than imported,
check whether it might have arrived by merge:

```sh
git log --follow -- <path>              # full history including renames
git log --diff-filter=A -m -- <path>    # includes merge-introduced adds
```

## 6. Reference clones on disk

| Directory under `O:\projects-github-clones\age\` | Remote (from `.git/config`) | Notes |
|---|---|---|
| `age-go` | `FiloSottile/age` | |
| `age-hpke-go` | `FiloSottile/hpke` | Carries `hpke-pq.md` — this is our mirror's upstream (§1, §3). |
| `age-hpke-pq-go` | `FiloSottile/hpke-pq` | **Stale fork — see the trap below.** |
| `age-rs` | `str4d/rage` | Kept checked out on the `pq` branch. |

### The `age-hpke-pq-go` trap (previously recorded on #19/#15)

This clone's `README.md` describes it as the working area for
`draft-ietf-hpke-pq` and links `hpkewg/hpke-pq` — the current working-group
repository — as the editor's copy and datatracker page. **The README is
generic boilerplate carried over from the draft-repo template; it describes
where the draft's canonical home is, not where this particular clone's remote
points.** `age-hpke-pq-go/.git/config` shows:

```ini
[remote "origin"]
	url = https://github.com/FiloSottile/hpke-pq.git
```

That is a fork, and it is stale relative to `hpkewg/hpke-pq`. Its **reference
implementation** assigns the wrong KEM id:

```rust
// reference-implementation/src/kem.rs:523-524
pub type QsfX25519MlKem768 =
    KemWithId<concrete_hybrid_kem::QsfX25519MlKem768Shake256Sha3256, 0x0051>;
```

The current, correct id is **`0x647a`**; `0x0051` is MLKEM1024-P384. The same
wrong mapping appears in `src/bin/json-to-markdown.rs`.

The clone is **internally inconsistent**, which is what makes it dangerous:
its own IANA table has the id *right* —
`draft-ietf-hpke-pq.md:381` reads
`| 0x647a | QSF-X25519-MLKEM768-SHAKE256-SHA3256 | 32 | 1120 | 1216 | 32 |`.
So a reader who checks the draft text concludes the clone is fine, while the
code a differential test would actually execute is wrong. (An earlier draft of
this note cited line 381 itself as evidence of the bug. It is evidence of the
opposite; the bug is in the Rust, not the markdown.) The rule this trap establishes: for any reference clone, read
`.git/config` for what it actually tracks — a README can describe the
project's upstream home while the clone itself sits on a fork that has since
diverged. Do not use `age-hpke-pq-go` as a differential target for the KEM id
or anything else that has moved since its fork point; use `age-hpke-go`
(`FiloSottile/hpke`, confirmed current, §3) instead.

## See also

- [`cctv-conformance.md`](cctv-conformance.md) — the CCTV testkit chain and harness.
- [`../plans/normative-source-refresh.md`](../plans/normative-source-refresh.md) — the plan this note closes out the research portion of.
- [`age-go-differential-oracle.md`](age-go-differential-oracle.md) — the empirical cross-check that backs §2's "nothing moved" conclusion.
