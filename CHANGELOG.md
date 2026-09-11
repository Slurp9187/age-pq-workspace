# Changelog — age-pq-workspace

All notable changes to the workspace itself are documented here.
Individual crate changes live in each member's own `CHANGELOG.md`.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0-rc.2] - unreleased

**The `age` 0.12 migration (issue #29).** `age` 0.11 -> 0.12, `age-core` 0.11 ->
0.12, `age-plugin` 0.6 -> 0.7. The MSRV 1.70 floor was what had blocked this;
all three declare `rust-version = "1.74"`, well under the 1.85 line opened in
`0.2.0-rc.1`. Dependencies only — **the wire format does not change**, gated as
always by the 19 C2SP CCTV vectors and the five `age`-CLI differentials (D1-D5).

**The normative-source refresh (issue #25).** Ran as an investigation and came
back with the opposite of its premise: the in-tree mirror is *not* stale. What
it did surface is that the suite this workspace ships had no published-vector
anchor at all, and that three of four test corpora were mislabelled. Both are
fixed below, under *age-pq-hpke* and *Docs*.

### Workspace

#### Changed

- **`age` 0.11.2 -> 0.12.1, `age-core` 0.11.0 -> 0.12.0, `age-plugin` 0.6.1 ->
  0.7.0**, with **no changes to any crate's `src/`** — the only code added is
  in `age-plugin-pq/tests/integration.rs` (see *Added*). The `Recipient` /
  `Identity` trait signatures (`wrap_file_key`, `unwrap_stanza`,
  `unwrap_stanzas`) are identical across the jump, `Stanza` and `FileKey` are
  unchanged, and the `"postquantum"` label is still what `wrap_file_key`
  returns. Five version strings across two member manifests moved (three
  dependency names), including the `armor` dev-dependency on `age` — a stale
  dev-dep there would be the shape this mistake takes, so it now carries a
  comment saying to keep it in lockstep.

- **Wire format verified per-vector, not per-summary.** This is a 0.11.2 ->
  0.12.1 jump that silently carries 0.11.3/0.11.4/0.11.5, including a stricter
  armored reader (an empty final line is now `NotWrappedAt64Chars` rather than
  an accepted short line) — which `armor_hybrid` goes through. So the 19 CCTV
  vectors were run before *and* after and their per-vector `want`/`got` outcomes
  diffed: **identical, 19/19 both times**. The same was done for the whole
  suite as it stood before this release: **157 test outcomes, byte-identical
  before and after**. (The suite is larger now — the HRP-case guards added
  below are new tests, not changed outcomes.) D1-D5 ran
  against the real Go `age` v1.3.1 (D1 64 cases, D2 8, D3 22, D4 22, D5 2).
  "`test result: ok`" alone would not have distinguished this from a shortened
  vector list.

#### Added

- `age-plugin-pq`: `plugin_identity_hrp_is_uppercase_as_age_0_12_requires` and
  `plugin_recipient_hrp_is_lowercase_as_age_0_12_requires`, executable guards
  for a real semantic narrowing in this release pair. Both `age-plugin` 0.7 and
  `age` 0.12 flipped their plugin **identity** prefix constant from
  `"age-plugin-"` to `"AGE-PLUGIN-"`, and both test the identity prefix *and*
  the `"age1"` **recipient** prefix with a case-**sensitive**
  `hrp.as_str().starts_with(...)`, while `bech32` 0.9 -> 0.11 made `Hrp`
  case-preserving where 0.9's `decode` returned it pre-lowercased. (age-go does
  the same: `plugin/encode.go` prefix-tests the raw HRP, and only the bech32
  *data* part is case-folded.) A lowercase plugin identity that 0.6.1/0.11.2
  accepted is now rejected as an invalid HRP, and an uppercase recipient would
  be equally unparseable. We emit `Case::Upper` from both identity sites
  (`main.rs:439`, `:489`) and `Case::Lower` from the recipient site
  (`main.rs:426`), so nothing breaks — but the constraint had been invisible,
  since every fixture and keygen path in the workspace already produced the
  right case. The guards cover all three sites and were mutation-checked:
  flipping any one alone fails one of them, at the HRP assertion and with its
  diagnostic. (`age::x25519` is unaffected; it compares `Hrp == Hrp`, and that
  `PartialEq` is explicitly case-insensitive.)

  The `keygen` test helper had to stop selecting the identity line with a
  case-sensitive `starts_with("AGE-PLUGIN-")` for this to work: with it, the
  `--keygen` mutation died inside the helper's `expect` — reading as a broken
  keygen — rather than at the assertion written to explain it.

#### Dependencies

- **RustCrypto `ml-kem 0.2.3` is now in the graph, and it is not ours.** `age`
  0.12 depends non-optionally on `ml-kem 0.2`, `p256 0.13`, `hpke 0.12` and
  `sha3 0.10` — no feature gates — to back its own `native::tagpq` recipient
  (`mlkem768p256tag`, HRP `age1tagpq`, label `MLKEM768-P256`). That is a
  different wire format from our `mlkem768x25519` and shares no code with it.
  Reach is asymmetric, and the two resolution modes disagree — say which you
  measured. Through its own dependency edges (`cargo tree -p <crate> …`):
  `age-pq-keys` reaches `ml-kem` + `p256` + `hpke` + `aes-gcm`, and
  `age-plugin-pq` reaches `hpke` + `aes-gcm` only, since `age-core` takes
  `hpke` with `default-features = false, features = ["alloc"]` and no `ml-kem`.
  Workspace-wide (`cargo tree --workspace …`, which is how CI and every bare
  `cargo build`/`cargo test` here resolve) feature unification enables `hpke`'s
  `p256` feature for every member, so the plugin binary links the P-256 stack —
  `p256`, `elliptic-curve`, `crypto-bigint`, `sec1`, `der`, `const-oid`, `ff`,
  `group`, `primeorder` — as dead code. The `ml-kem` half holds in **both**
  modes: `cargo tree -i ml-kem --workspace -e normal` is `ml-kem 0.2.3 <- age
  0.12.1 <- age-pq-keys` and nothing else. **`age-pq-hpke` gets nothing new**
  either way — it has no `age` edge, so formally verified `libcrux-ml-kem`
  remains the only ML-KEM in that crate's graph. The claim wording in
  `README.md`, `CLAUDE.md`,
  `docs/design/hpke-import-vs-own.md` and `docs/design/rage-pq-adoption.md` was
  narrowed accordingly: the property defended is *which implementation our
  `mlkem768x25519` path executes*, not the contents of the dependency graph. The
  decision to keep our own runtime is unchanged.

- **Two long-standing duplicates resolved, one added.** `cargo tree -d
  --workspace -e normal,dev` goes from **17 duplicate groups to 14**. Gone:
  `base64` 0.21/0.22, `bech32` 0.9/0.11 (the one this workspace had carried
  since the hand-rolled-bech32 work — `age`, `age-core` and `age-plugin` now all
  declare `bech32 = "0.11"`, matching secure-gate), plus `rustc-hash` and
  `self_cell` via `i18n-embed` 0.15 -> 0.16. Added: `syn` 2.0.114/3.0.5, a
  proc-macro **build-graph** duplicate via `i18n-embed-fl` 0.10 ->
  `proc-macro-error3`, not a runtime one.

- **`digest` stays single-generation at 0.10.7**, as do `sha2` (0.10.9) and
  `sha3` (0.10.8). `hpke 0.12` and `ml-kem 0.2.3` both declare the 0.10
  generation, so for `digest` / `sha2` / `sha3` specifically the migration lands
  on this workspace's existing side of the RustCrypto split rather than
  straddling it. It is not a blanket claim: see the `base16ct` bullet below for
  one crate where it does not hold. It does however add a blocker to
  the deferred gen-2 cohort: that move can no longer happen before `age` itself
  moves. `x25519-dalek` stays 2.0.1, `chacha20poly1305` stays 0.10.

- **No MSRV pressure.** The maximum declared `rust-version` anywhere in the
  migrated graph is exactly **1.85** — `age` 0.12.1, `age-core` 0.12.0 and
  `age-plugin` 0.7.0 all declare 1.74. No new cap was added: in particular
  `hybrid-array` resolves to **0.2.3** (`rust-version` 1.81), because `ml-kem
  0.2.3` requires `hybrid-array` `0.2.0-rc.9`, a caret range that cannot select
  the edition-2024 0.4 line at all. That pin is structural, so a `time`-style
  manifest cap would guard nothing.

- **`rand` / `rand_core` duplicates are unchanged in kind.** `rand 0.8.5` still
  has exactly three consumers (`age` 0.12.1, `age-core` 0.12.0, `proptest`
  1.5.0). `rand_core 0.6.4`, previously reachable only through `crypto-common`,
  now has **twelve** direct consumers; this strengthens rather than weakens the
  standing conclusion that moving `x25519-dalek` to 3.0 alone would dedup
  nothing.

- **A pre-release enters the graph transitively:** `kem 0.3.0-pre.0`, pulled by
  **`ml-kem 0.2.3`** — not by `hpke`, whose 0.12.0 manifest declares no `kem`
  dependency at all. `ml-kem` pins it *exactly* (`[dependencies.kem] version =
  "=0.3.0-pre.0"`), so `cargo update` cannot move it even within the
  pre-release line and nothing needs `--precise`; `Cargo.lock` is what holds
  it. Two consequences of the parent being `ml-kem`: the pin is not ours to
  cap (it belongs to `age`'s dependency, not ours), and the pre-release reaches
  **`age-pq-keys` only** — `cargo tree -i kem@0.3.0-pre.0 --workspace -e
  normal` is `kem <- ml-kem 0.2.3 <- age 0.12.1 <- age-pq-keys`. Recorded here
  because a pre-release in a crypto-adjacent tree is the sort of thing an audit
  should find already written down, and an audit that followed a pointer to
  `hpke`'s manifest would find nothing. Separately, `hpke 0.12` takes `aes-gcm
  0.10` non-optionally, so `age-plugin-pq` now links AES-GCM, AES, CTR, GHASH
  and POLYVAL that it never calls.

- Lockfile grows from **239 to 258** packages. Cold build cost was not
  resolvable above run-to-run variance and no figure is claimed for it.

- **One RustCrypto crate *does* now straddle generations, and no instrument in
  this entry can see it.** `base16ct` 0.2.0 is newly compiled into
  `age-pq-keys` (`elliptic-curve 0.13.8` <- `p256 0.13.2` <- `age`/`hpke`),
  while `Cargo.lock` also carries `base16ct` 1.0.0 as `secure-gate`'s
  `encoding-hex` dependency. `cargo tree -d` cannot report this — 1.0.0 is
  feature-gated off here, so it is unreachable on the host target even under
  `--all-features` and the 17 -> 14 count above is correct while still missing
  it. Only a lockfile diff shows `base16ct: [1.0.0] -> [0.2.0, 1.0.0]`. Live
  consequence: the day anyone enables `secure-gate/encoding-hex`, two
  `base16ct` generations compile side by side — and `base16ct` is the
  constant-time hex backend the *Encoding and decoding* rules route secrets
  through, so it is crypto-adjacent rather than incidental.

- `Cargo.lock` keeps `nom` 7.1.3 beside the new `nom` 8.0.0. The 7.x copy is
  reachable only through the target-gated `crabgrind`/`bindgen` chain under
  `libcrux-secrets` and never compiles here — the same lockfile-only artifact
  class as the retired wasip2 pins. Expected; not a thing to fix.

#### Docs

- **`docs/design/normative-provenance.md` (new).** Durable record of where the
  four normative/test corpora came from (the `hpke-pq.md` mirror, the X-Wing
  Appendix C vectors, and the C2SP/CCTV testkit), the `draft-ietf-hpke-pq`
  03 → 05 delta (§4 Hybrid KEMs is byte-identical; Appendix A renames
  `QSF-X25519-MLKEM768` to `MLKEM768-X25519`), and why refreshing the in-tree
  mirror is a no-op — it is byte-identical to current upstream
  (`FiloSottile/hpke @ 8aa8a04`), which has not moved its own pin either.
- **Corrected `docs/plans/normative-source-refresh.md`'s "At most one of those
  is right."** That sentence was itself the error: the mirror, `hpke-pq-05`,
  and `conformance-workspace.md` cite CONCRETE-**02**/**03**/**04**
  respectively, and all three are correct about the revision current when each
  was last checked — `concrete-hybrid-kems` is an independently-versioned
  external draft, not a value with one live truth. `-04` is in fact the
  currently active revision. No citation was changed to "fix" this.
- Recorded a repo-wide research hazard: `git log --diff-filter=A` does not
  surface files introduced by a merge commit (several files here, including
  the `hpke-pq.md` mirror, arrived via the subtree merge at `04516c2`), and
  that `age-hpke-pq-go`'s README links the current `hpkewg/hpke-pq` while its
  actual remote (`.git/config`) is a stale fork still assigning
  `QsfX25519MlKem768 = 0x0051` — read the remote, not the README.
- `docs/design/cctv-conformance.md` now names the testkit's full chain of
  custody (C2SP/CCTV `e9274a7b` → rage `26fe921` → this repo `85fe5c0`) and
  both decompressed-vector sizes (`armor_hybrid` 1951→2554 B,
  `hybrid_multiple_recipients` 2739→3441 B), which it previously described
  without naming.
- `age-pq-hpke/src/lib.rs`'s `## Normative provenance` module doc no longer
  says the 03 → 05 delta "has not been enumerated" — it links the enumeration
  above instead.

### Notes

- `age` 0.12's `tagpq::Recipient` returns the same `"postquantum"` label we do,
  so `HybridRecipient` and `age::tagpq::Recipient` can now legally be combined
  in one file's header — the stanza tags (`mlkem768x25519` vs
  `mlkem768p256tag`) do not collide. Mixing with `x25519` / `tag` / `scrypt`
  still fails as before. This combination is legal but **untested here**.
- `age::EncryptError` and `age::DecryptError` are now `#[non_exhaustive]`.
  Nothing breaks today — `testkit.rs::classify` already ends in a catch-all —
  but any future `match` on them written without one will fail to compile.

### age-pq-hpke

#### Added

- **`tests/hpke_pq_draft_vectors.rs` and `tests/data/hpke-pq-draft05-vectors.json`
  (new) — the first published-vector anchor for the suite we actually ship.**
  `draft-ietf-hpke-pq-05` **Appendix A.5** (`kem 25722 / kdf 1 / aead 3` —
  MLKEM768-X25519, HKDF-SHA256, ChaCha20Poly1305, byte-for-byte age's suite) and
  **Appendix A.12** (`kdf 17`, the SHAKE256 one-stage variant of the same KEM).

  Until now `0x647a` / HKDF-SHA256 / ChaCha20Poly1305 was pinned only by
  agreement with the Go `age` CLI and by X-Wing's own appendix — a differential
  and a KEM-level check. Neither is a normative anchor for the *composed* suite:
  if age and this crate drifted the same way, both stay green. These vectors
  come from the draft instead of from another implementation.

  Shape decisions, so they are not undone by accident:

  - **Driven end-to-end through the public API** (`new_sender_with_testing_randomness`
    / `new_recipient`), not by reimplementing the key schedule in the test. The
    retired `-03` test is what that mistake looks like (see *Removed*).
  - **`key`, `base_nonce` and `exporter_secret` are asserted indirectly.** The
    draft prints all three; they are private to `Context`, and no public
    accessor was added to reach them. ChaCha20-Poly1305 is deterministic, so a
    wrong `key` or `base_nonce` cannot produce a matching tag for any of the ten
    sealed messages, and a wrong `exporter_secret` cannot produce a matching
    exported value. Exposing live key material on the crate's public surface to
    satisfy a test is the worse trade.
  - **Vectors are selected by numeric `kem_id`/`kdf_id`/`aead_id`, never by
    appendix title** — appendix numbering and suite names both moved between
    `-03` and `-05`, and `appendix` is therefore recorded per vector rather than
    once for the file. No "current draft" field: that is the shape of the
    deleted `XWING_DRAFT_VERSION`, and it rots the same way.
  - **The JSON carries only values the driver reads**, so no byte in it is
    unverified data a corruption could sit in unnoticed.

  Mutation-checked rather than assumed: **22 single-byte flips, 22 kills, no
  survivors** — every one of `info`, `ikmE`, `ikmR`, `pkRm`, `skRm`, `enc`,
  `shared_secret`, the first and last `ct`, an `aad`, and an `exported_value`, in
  both vectors. Before the vectors were committed,
  `DeriveKeyPair(ikmR) == skRm` and the key-schedule outputs were re-derived from
  the extracted bytes, so a transcription slip would have failed where it looked
  like one rather than as a conformance mystery.

#### Removed

- **`kat_tests.rs::shake256_draft_hpke_pq_key_schedule_vector_matches`**
  (`draft-ietf-hpke-pq-03` Appendix A.5) — superseded by
  `draft05_appendix_a12_shake256_chacha20poly1305`, which covers the same
  SHAKE256 one-stage key schedule. It is retired rather than updated because it
  was the wrong shape twice over: it hand-rebuilt `secrets` and `ks_context`
  inside the test, duplicating `hpke.rs`'s one-stage-KDF branch instead of
  exercising it — so it would have stayed green with that branch broken — and
  its suite's AEAD (AES-128-GCM, `aead_id 1`) is not instantiable in this crate
  (`new_aead(1)` -> `UnsupportedAead`), so it could never have driven a real
  seal/open. The replacement checks AEAD outputs, which cannot match on a wrong
  `key` or `base_nonce`, instead of a hand-copied intermediate `secret`.

#### Changed

- **`tests/data/test-vectors.json` now carries a `source` envelope**
  (`document` / `url` / `retrieved` / `sha256` / `note`), and
  `test_official_kat_vectors` asserts `source.document`, so swapping the corpus
  for a different document fails instead of silently changing what is proven.
  The file was labelled `draft-ietf-hpke-pq-03` Appendix A.5 in `kat_tests.rs`'s
  module header; it is in fact **`draft-connolly-cfrg-xwing-kem-10` Appendix
  C**, whose upstream title carries `# TODO: replace with test vectors that
  re-use ML-KEM, X25519 values`. The header now says so, and names the RFC 9180
  A.1 vectors sitting in the same file, which it also did not.

  **A claim this repo carried about that file was false and is retracted here:**
  it was described as truncated to the first 20 bytes of each field. It is not.
  Every field of all three vectors was re-compared byte-for-byte against the
  draft-10 text — `seed` 32 B, `eseed` 64 B, `pk` the full **1216** B, `ct` the
  full **1120** B, `ss` 32 B, all exact. The "truncation" was a *display*
  truncation in an inspection script (`str(v)[:40]`) read back as a property of
  the data.

- `kem/mlkem768x25519.rs`: the KEM `suite_id` prefix cited **RFC 9180 §5.3**,
  which is the exporter. Corrected to **§4.1** (`draft-ietf-hpke-pq-05` §3 cites
  the same text as "Section 4.4 of [HPKE]"). Comment only.

- `Cargo.toml`'s `description` said `draft-ietf-hpke-pq-03`. That string ships in
  package metadata and would have to be re-cut on every draft revision, so it now
  names the draft without a revision; the revision lives where it is checkable.

---

## [0.2.0-rc.1] - 2026-09-10

**The MSRV 1.85 cohort bump (issue #2).** The 1.70 line is frozen at
`v0.1.0-rc.1`; this release moves the whole workspace to **rustc 1.85**,
**edition 2024** and Cargo **resolver 3**, and takes the dependency upgrades
that 1.70 was holding back. Dependencies and toolchain only — **the wire format
does not change**, which the 19 C2SP CCTV vectors and the five `age`-CLI
differentials (D1-D5) gate.

### Workspace

#### Changed

- **MSRV 1.70 -> 1.85.** `rust-toolchain.toml` and `[workspace.package]
  rust-version` move together, as does CI. This was pre-decided; see the table
  in `CLAUDE.md` for what it unlocked.

- **Edition 2021 -> 2024**, landed as its own commit so a bisect can separate an
  edition drop-order change from a dependency behaviour change. It required
  **no source changes**. `cargo fix --edition` proposed three and all three were
  reverted as machine noise: two `if let / else` blocks rewritten into
  `match { Ok(x) => {} _ => {} }`, and `$id:expr` narrowed to `expr_2021` in a
  crate-internal macro called only with integer literals. A forced full rebuild
  with `-W if_let_rescope -W edition_2024_expr_fragment_specifier
  -W tail_expr_drop_order` reports zero warnings, so the reverts are verified
  rather than assumed. The edition's earlier temporary drop favours this
  workspace: the Drop-bearing types here are secure-gate wrappers and
  x25519-dalek secrets, so earlier drop means earlier zeroization.

- **Cargo `resolver` 2 -> 3**, as the in-file comment had prescribed for this
  bump. Its MSRV-aware selection is doing visible work: `cargo update` now
  reports "locking to latest Rust 1.85 compatible versions".

- **`secure-gate`: git `release/0.8` (0.8.0-rc.12) -> git `main`
  (0.9.0-rc.9).** The 0.8 line existed solely as the MSRV-1.70 backport and is
  retired. Features are unchanged (`rand`, `ct-eq`, plus `encoding-bech32` and
  `std` on the two upper crates).

  **rc.9, not rc.8, and the distinction is load-bearing.** 0.9.0-rc.8 was cut
  before the `Case` work landed: it has no `Case`, no `bech32_code_length` /
  `*_sized` encoders, and `into_inner` returning `InnerSecret<T>`. Since
  uppercase bech32 is what produces the `AGE-SECRET-KEY-PQ-` /
  `AGE-PLUGIN-PQ-` identity strings, adopting rc.8 would have been a
  wire-format regression, and the only in-crate workaround
  (`try_to_bech32(hrp)?.to_ascii_uppercase()`) leaves an unzeroized `String`
  copy of the private key on the heap. rc.9 forward-ported all of it, so the
  upper crates needed **no call-site churn at all**.

- **`rand` / `rand_core` 0.9 -> 0.10** and **`libcrux-ml-kem` 0.0.8 -> 0.0.10**.
  These are coupled to the secure-gate move rather than independent: 0.9's
  `from_rng` bound is `TryRng + TryCryptoRng`, so the rand rename cannot be
  sequenced separately without leaving the tree non-compiling. The renames:
  `os_rng` -> `sys_rng`, `OsRng` -> `SysRng`, `RngCore` -> `Rng`,
  `TryRngCore` -> `TryRng`, `rand::Rng` -> `rand::RngExt`.

- **MSRV caps removed, per pin rather than by reflex.** `half` and
  `unicode-ident` caps are gone (`half` left the graph entirely — it arrived via
  secure-gate 0.8). `clap` `=4.4.18` -> `"4"` was genuine scaffolding (4.5.0
  moved to 1.74). `proptest` `=1.5.0` -> `"1"` and `tempfile` `=3.10.1` -> `"3"`
  were **not** scaffolding: both declared MSRVs well under 1.70 across their
  whole range, so the exact pins were blanket style and never bought anything.

- **`time` stays capped**, at `>=0.3.40, <0.3.46`. This is the one pin that
  outlives the 1.70 line: `time` 0.3.46+ requires rustc 1.88, above the new
  floor. Resolver 3 is only a preference, so the cap remains a manifest fact.
  `age-plugin-pq` now inherits the workspace entry instead of declaring
  `time = "0.3"` itself, which had bypassed the cap entirely.

- **Both lockfile-only pins removed.** `getrandom` 0.3.1 fell out with
  `rand_core` 0.9; `uuid` floats to 1.26.1. Their reason (Cargo 1.70 cannot
  parse the edition-2024 WASI manifest chain) is dead at 1.85. Verified on the
  failure's own terms rather than by a green test run, since this class of
  breakage is invisible to `check` / `build` / `test`: `cargo fetch` across
  `wasm32-wasip2` + linux + windows succeeds.

- **One lockfile chain grew, and it is recorded here for the same reason.**
  `libcrux-ml-kem` 0.0.10 pulls `libcrux-secrets` 0.0.6, which added
  `[target."cfg(valgrind_ct_test)".dependencies.crabgrind]`. Cargo cannot
  evaluate a custom `cfg` during resolution, so `crabgrind` 0.2.6 and its build
  chain are now in `Cargo.lock` and reachable from `cargo tree --target all`.
  Measured against `main`'s lockfile, that is **14 new entries** — `crabgrind`,
  `bindgen` 0.72, `clang-sys`, `libloading`, `cexpr`, `prettyplease`, `glob`,
  `either`, `itertools`, `pkg-config`, `windows-link`, and `regex` /
  `regex-automata` / `aho-corasick` (the fifteenth new entry, `r-efi`, is
  unrelated: it rides in with `getrandom` 0.4). That cfg is
  never set, so none of it ever compiles — `cargo tree -e normal,build -i
  crabgrind` prints nothing — but it *is* vendored by `cargo vendor`, fetched by
  `cargo fetch --target all`, and would be scanned by a future `cargo audit` /
  `cargo deny` job (this workspace has none today: `ci.yml` has exactly the
  `msrv` and `conformance` jobs). Same invisible-to-`check`/`build`/`test` class
  as the WASI chain the removed pins guarded, so it gets the same treatment: a
  durable record rather than a surprise.

#### Added

- **`[workspace.lints]` restored — with the member opt-in that the pre-1.70
  version omitted.** All three members now carry `[lints] workspace = true`;
  without it the tables are inert, which is what the earlier tables were for
  their entire life.

- **`unsafe_code = "forbid"` is now enforced.** `CLAUDE.md` has always claimed
  `#![forbid(unsafe_code)]` at every crate root "no exceptions", but only
  `age-pq-hpke` carried the attribute. The lint table plus the attribute added
  to the other two roots makes the rule true for the first time. Cost was zero:
  the workspace contains exactly one `unsafe` token, and it is that attribute.

- Also added `unreachable_pub`, `unused_qualifications` and `unused_lifetimes`.
  The clippy cast lints are deliberately **excluded**: they fire on ~19
  `usize as u16` RFC 9180 length prefixes, which is real work on
  wire-format-adjacent code and belongs in its own change, not a blanket
  `#![allow]`.

#### Fixed

- Five unreachable-`pub` items in `age-pq-hpke` found by the new lints
  (`MLKEM768_CT_SIZE` now matches its already-`pub(crate)` neighbour
  `MLKEM768_PK_SIZE`, as do the feature-gated `MLKEM512_CT_SIZE` and
  `MLKEM1024_CT_SIZE`; plus the two scalar-clamp helpers), and one redundant
  path qualification in the `pq-keygen` example.

  The two feature-gated siblings were missed on the first pass because they only
  compile under `--all-features`, which the plain `cargo clippy --all-targets`
  used to verify the change does not enable — the lint table was already
  emitting noise on every CI run, which is how such a table drifts back to being
  decorative. The verification command below now carries `--all-features` for
  exactly that reason.

#### Not taken, deliberately

- **`sha3` 0.10 -> 0.12** and **`x25519-dalek` 2.0 -> 3.0.** Neither is forced
  by this bump and both are deferred to a single RustCrypto gen-2 cohort change.
  `sha3` 0.12 needs `digest` 0.11 while `sha2` / `hkdf` / `chacha20poly1305` /
  `aead` stay on `digest` 0.10, which would put two digest generations in one
  crypto tree, and it churns the X-Wing combiner and the SHAKE KDF — the two
  modules that decide bytes on the wire. For `x25519-dalek`, the apparent
  rand_core dedup win was **measured and found illusory**: `crypto-common`
  (under `aead` 0.5) keeps `rand_core` 0.6.4 in the graph regardless, so taking
  it alone dedups nothing while carrying `curve25519-dalek` 4->5 underneath the
  low-order-point rejection.

#### Verification

`cargo test --workspace --all-features -- --include-ignored`: **157 passed, 0
failed, 0 ignored**, including 19/19 C2SP CCTV hybrid vectors and D1-D5 against
the Go `age` CLI v1.3.1. `cargo clippy --workspace --all-features --all-targets
-- -D warnings` clean — with `--all-features`, which is the feature set the test
command above uses and the one the two feature-gated `unreachable_pub` fixes
needed. Exactly one `libcrux-ml-kem` in the graph.

Note on `cargo tree -d`: duplicate `rand` / `rand_core` remain and are
**expected**, not a regression. `rand 0.8.5` has three consumers —
`age 0.11`, `age-core 0.11`, and `proptest 1.5.0` (a dev-dependency of
`age-pq-keys`) — while `rand_core 0.6.4` comes from `crypto-common` and
`rand_core 0.5.1` from `x448 0.6`. `age 0.11` is the trait provider this
workspace implements, so its generation is not ours to choose. `proptest` is
ours, but the first release off `rand 0.8` is proptest 1.7, which takes
`rand 0.9` — a different duplicate, not one fewer — so moving it is not a dedup
and is not taken here.

### age-pq-hpke

#### Changed

- **BREAKING: the RNG trait bound on three public functions.**
  `EncapsulationKey::encapsulate`, `DecapsulationKey::generate` and the free
  `generate_keypair` move from `<R: TryRngCore + TryCryptoRng>` to
  `<R: TryRng + TryCryptoRng>`, following rand_core 0.10's rename of `RngCore`
  to `Rng` and `TryRngCore` to `TryRng`. This is a genuine signature change for
  downstream callers, not an internal rename.

- **`rand` 0.9 -> 0.10.** `rand::rngs::OsRng` is now `rand::rngs::SysRng`
  (the `os_rng` feature became `sys_rng`, and is on by default). Note that
  `SysRng` implements the fallible `TryRng` / `TryCryptoRng`, not the infallible
  `Rng` / `CryptoRng`.

- **`rand_core` moved to `[dev-dependencies]`.** Nothing in `src/` names it, and
  rand_core 0.10 has no features at all — the `os_rng` feature it used to carry
  went with `OsRng` itself, so the old
  `rand_core = { version = "0.9", features = ["os_rng"] }` line could not have
  been version-bumped in place.

- **`libcrux-ml-kem` 0.0.8 -> 0.0.10.** The four functions this crate calls keep
  their exact signatures, so the Tier-3 `into_inner()` hand-offs are unchanged.
  `default-features = false` is kept, and its comment corrected: it selects the
  ML-KEM variant explicitly (the default set also turns on mlkem512 and
  mlkem1024). The previous rationale blamed "older Cargo" and tls_codec default
  feature resolution, which was a Cargo-1.70 concern and stale at 1.85.

- **`sha3` stays at 0.10 and `x25519-dalek` at 2.0**, deliberately — see the
  root changelog.

- Dev-dependencies `rand` and `rand_chacha` move to 0.10. Seeded ChaCha output
  is bit-for-bit stable across this bump, and no fixed vector in this workspace
  derives from a seeded `rand` stream.

#### Fixed

- Five unreachable-`pub` items surfaced by the new workspace lint table:
  `MLKEM768_CT_SIZE` (now `pub(crate)`, matching its neighbour
  `MLKEM768_PK_SIZE`), the same constants in the feature-gated `mlkem512` /
  `mlkem1024` siblings, and `clamp_x25519_scalar` / `clamp_x448_scalar`.

  The two feature-gated ones were missed at first because they compile only
  under `--all-features`, so a plain `cargo clippy --all-targets` never sees
  them while `cargo test --workspace --all-features` — what CI runs — prints
  them on every run. Verification for this crate is now done with
  `--all-features --all-targets`.

### age-pq-keys

#### Changed

- **`secure-gate` moves from git `release/0.8` (0.8.0-rc.12) to git `main`
  (0.9.0-rc.9).** This crate needed **no call-site changes**: `Case`,
  `bech32_code_length` / `BECH32_CODE_LENGTH`, the `*_sized` encoders and the
  plain-value `into_inner` all exist on rc.9. Had this landed on 0.9.0-rc.8
  instead — which predates that work — the uppercase `AGE-SECRET-KEY-PQ-`
  identity encoding would have regressed to lowercase, so the exact rc matters.

- Dev-dependency exact pins (`proptest`, `tempfile`, `time`, `clap`) relax to
  the workspace entries; the `unicode-ident` MSRV cap is gone.

#### Added

- `#![forbid(unsafe_code)]` at the crate root. `CLAUDE.md` had always required
  it, but this crate never actually carried it; it is now also enforced by
  `[workspace.lints.rust] unsafe_code = "forbid"` plus `[lints] workspace = true`.

#### Fixed

- `go_recipients_for_all_cases` in the differential harness carries a targeted
  `#[allow(clippy::zombie_processes)]`. The lint fires on a `?` inside the
  writer thread's closure, reading it as an early return from the function; it
  is not one, and `child.wait_with_output()` is reached on every path. Verified
  rather than restructured.

#### Verification

19/19 C2SP CCTV hybrid vectors pass, and all five differentials against the Go
`age` CLI v1.3.1 (D1-D5) pass, under rustc 1.85 and edition 2024.

### age-plugin-pq

#### Changed

- **`rand` 0.9 -> 0.10.** `rand::rngs::OsRng` becomes `rand::rngs::SysRng` at
  the import and both use sites (recipient encapsulation and identity-seed
  generation). The crate relies on rand's **default** features for `sys_rng`;
  adding `default-features = false` later would silently remove `SysRng` and
  break key generation.

- **`secure-gate` moves to git `main` (0.9.0-rc.9)** with no call-site changes —
  `Case::Upper` still produces the `AGE-PLUGIN-PQ-` identity string.

- **`time` now inherits the workspace entry** rather than declaring
  `time = "0.3"` locally. The local declaration bypassed the workspace's MSRV
  cap, so nothing was actually holding `time` below the version that requires
  rustc 1.88.

#### Added

- `#![forbid(unsafe_code)]` at the crate root, plus `[lints] workspace = true`
  so the workspace's `unsafe_code = "forbid"` governs this crate.

#### Unchanged

- The binary name stays `age-plugin-pq`, and the identity HRP stays
  `AGE-PLUGIN-PQ-`. Plugin discovery depends on both, and
  `identity_hrp_matches_the_binary_name_age_will_look_for` still guards the
  coupling.

---

## [0.1.0-rc.1] - 2026-09-10

**Release candidate for the frozen MSRV-1.70 line.** All three crates move to a
single workspace version and are distributed by the git tag `v0.1.0-rc.1`.

> **Numbering note — read before comparing this to `[0.1.0]` below.**
> The `[0.1.0] - 2026-03-25` entry further down is *not* an earlier release of
> this version. It recorded the creation of the monorepo itself, under a
> repository-scaffolding scheme that was never a crate version: the crates were
> on `0.0.x` throughout that period and until this entry. From here the root
> changelog and all three crates share one number. So `0.1.0-rc.1` **follows** the
> March `0.1.0` in time, even though SemVer orders it lower. The scaffolding
> entry is left as written rather than renumbered, because rewriting a changelog
> to tidy a discontinuity hides that the discontinuity happened.

### Changed

- **Unified versioning (DECIDE-13).** `age-pq-hpke` (was 0.0.7), `age-pq-keys`
  (was 0.0.6) and `age-plugin-pq` (was 0.0.2) now inherit
  `version.workspace = true`. They are one release rather than three:
  `age-pq-keys` layers on `age-pq-hpke`, `age-plugin-pq` exposes `age-pq-keys`,
  distribution is a single git tag over the whole workspace, and a consumer
  pinning `tag = "v0.1.0-rc.1"` gets all three at once. Three separate numbers would
  give that one tag three answers to "which version is this?".

- **Why not stay on `0.0.x`.** Cargo treats every `0.0.z` as mutually
  incompatible: `^0.0.8` resolves to exactly `>=0.0.8, <0.0.9`. There is no
  patch channel, so a security fix shipped as `0.0.9` reaches nobody pinned to
  `0.0.8` without an explicit dependency edit. `^0.1` picks up `0.1.1`
  automatically. `0.1.0` does not claim stability — under SemVer `0.x` still
  means anything may break at a minor bump — it claims only that compatible and
  incompatible changes are now distinguishable, which is the minimum a
  maintenance line needs.

- The workspace `license` and `edition` fields no longer carry
  "adjust to your actual license" / "or whatever your crates already use"
  placeholder comments. Both were verified rather than assumed: every member
  inherits `edition.workspace = true`, and the dual MIT / Apache-2.0 claim is
  backed by the license files now present in the root and in all three crates.

### Added

- `LICENSE-MIT` and `LICENSE-APACHE` at the repository root, and the same pair
  in `age-plugin-pq`. Both were missing: the workspace declared
  `license = "MIT OR Apache-2.0"` and an `include` list containing `/LICENSE*`,
  so `age-plugin-pq` carried a licence declaration with no licence text, and the
  repository root showed no licence at all. Copied verbatim from `age-pq-keys`.

### Notes on this being an `-rc`

A pre-release tag, not the freeze itself. It exists so the MSRV-1.70 line can be
exercised as a release — pinned by tag, built from a clean clone — before the
final `v0.1.0` makes the number permanent. `release/0.1` is still branched
lazily from whichever tag turns out to be final; nothing is maintained until a
patch is actually needed.

### Added

- **Differential oracle against the Go `age` CLI** (issue #15).
  `age-pq-keys/tests/differential_age_go.rs` checks this crate against the real
  binary over many cases instead of the single checked-in fixture: 64
  deterministic key-derivation cases (`age-keygen -y`), 8 fresh Go keypairs fed
  back through our decoder (`age-keygen -pq`), and 22 payload cases in each
  direction (we encrypt → `age -d`, `age -e` → we decrypt) across age's 64 KiB
  STREAM chunk boundary.

  Cases are a pure function of their index — `seed(i) = SHA-256(domain ‖ i)` —
  because the input that reproduces a failure is a private key. A randomised
  oracle would force a choice between an unreproducible failure and printing key
  material into a CI log; deriving the cases removes the choice. Failure
  messages carry a case index, a differential name and lengths, and nothing
  else. **No new dependency: `Cargo.lock` is unchanged.**

  What it deliberately does not prove — plugin routing, ciphertext bytes,
  anything version-specific — and the rationale for each mechanism is in
  [`docs/design/age-go-differential-oracle.md`](docs/design/age-go-differential-oracle.md).

- **Anti-gutting guard for the oracle**, as two steps in the `msrv` CI job. A
  test target with zero `#[test]` functions prints `running 0 tests … ok` and
  **exits 0**, so a job that merely names the file catches its deletion and not
  its gutting. The first step asserts a floor on the *declared* count. The
  second asserts on **evidence a body must produce**: each differential prints a
  `D1:`…`D4:` banner only after it has successfully spawned the age binary, and
  all four are required, because counting is not enough — six `#[test]` fns with
  their names kept and every body replaced by `{}` still reports `6 passed`. It
  also re-runs the target *without* `--include-ignored` and requires a floor
  there, which is the only way to see a file whose tests have all been
  `#[ignore]`d away. Two binary-free tests cover what neither can see — a matrix
  shrunk below its floor, a generator weakened, or the crate's identity encoder
  drifting from the oracle's.

### Changed (BREAKING)

- **Crates renamed to a consistent `age-pq-*` prefix.**

  | Was | Now | Why |
  |---|---|---|
  | `age-hpke-pq` | `age-pq-hpke` | prefix consistency |
  | `age-recipient-pq` | `age-pq-keys` | "recipient" named one of five responsibilities, and the public half of a keypair at that — the crate also owns identities, key generation, the bech32 formats and the stanza wire format |
  | `age-plugin-pq` | **unchanged** | protocol-mandated, see below |

  `age-plugin-pq` keeps its name deliberately. age discovers plugins by
  constructing the binary path as `"age-plugin-" + name`, where `name` comes
  from the identity HRP (`AGE-PLUGIN-PQ-`). Renaming the binary would break
  plugin discovery, and the failure is silent — age reports plugin-not-found
  rather than failing to build.

  Library paths change accordingly: `age_hpke_pq::` → `age_pq_hpke::` and
  `age_recipient_pq::` → `age_pq_keys::`.

  **No wire-format change.** Stanza tag, HRPs, KEM/KDF/AEAD identifiers and key
  encodings are all untouched; existing keys and ciphertexts are unaffected.


### Fixed

- **The ML-KEM encapsulation key check is enforced; it previously did nothing**
  (conformance, not a security fix). `validate_public_key` in
  `age-pq-hpke/src/kem/ml_kem/mlkem{512,768,1024}.rs` wrapped its argument in
  libcrux's newtype and threw the result away — the wrap is infallible and the
  function returned `()`, so its caller had nothing to check and 1184 of a
  recipient's 1216 attacker-supplied bytes were unvalidated. All three now call
  `libcrux_ml_kem::mlkem*::validate_public_key` and return `Result`.

  Both normative lineages make it a MUST — draft-connolly-cfrg-xwing-kem-**10**
  §5.1 ("ML-KEM-768.Encaps(pk_M) MUST perform the encapsulation key check of
  [MLKEM] §7.2 and raise an error if it fails") and draft-ietf-hpke-pq-**05** §3
  ("an ML-KEM encapsulation key check failure causes an HPKE EncapError"). Those
  are the revisions actually read; which pins are stale, and why, is
  [`docs/plans/normative-source-refresh.md`](docs/plans/normative-source-refresh.md)
  (issue #25). Measured against age v1.3.1: it rejects
  both an all-`0xFF` ML-KEM half **and** a single 12-bit coefficient pushed
  above q − 1 with `malformed recipient …: invalid MLKEM768-X25519 public key`,
  at parse time. We accepted both — so this **removes** a divergence from age
  and rage rather than creating one.

  Severity is conformance and interoperability plus a legible error, not a
  vulnerability: validation is no defence against recipient substitution, and no
  CCTV vector changes. What it prevents is accepting keys no conformant
  implementation accepts, and silently producing files the intended recipient
  cannot decrypt (ML-KEM binds `H(ek)` over the *raw* bytes, so a non-canonical
  alias of a real key yields a ciphertext its canonical decapsulation key cannot
  reproduce). Full write-up, including what **not** to extend it to, in
  [`docs/design/mlkem-encapsulation-key-check.md`](docs/design/mlkem-encapsulation-key-check.md).

  `Cargo.lock` unchanged — libcrux-ml-kem 0.0.8 already exposes the check.

- **Three claims in comments that no test checked** — the same defect shape as
  the no-op validator above, one level up. Each was found by mutating the code
  the comment describes and observing that nothing went red:

  * **The parse-vs-wrap stage contract.** `HybridRecipient::from_bytes` checks
    the ML-KEM half and defers the curve point to `wrap_file_key` *because that
    is what age does*. Nothing verified it. Differential **D5** in
    `age-pq-keys/tests/differential_age_go.rs` now runs the CLI against a
    bad-ML-KEM recipient and a low-order-curve recipient and requires
    `malformed recipient` for the first, `failed to wrap key` for the second.
    Confirmed green against age v1.3.1, and against filippo.io/hpke v0.4.0's
    source. It is the one differential that reads age's stderr; a stage is not
    visible in an exit code.
  * **The check order** in `EncapsulationKey::try_from`. The comment claims
    ML-KEM is checked before the curve point to match filippo.io/hpke; reversing
    the two lines failed zero tests. A key malformed in *both* halves now pins
    the attribution (`a_key_malformed_in_both_halves_is_attributed_to_the_ml_kem_half`).
  * **`test_derand_eseed_halves_are_bound_to_their_roles`** said the swap it
    tests rules out "one half having been dropped on the floor". It does not —
    deriving the X25519 ephemeral from `eseed[0..32]` leaves it green. It now
    perturbs each half separately and requires the ciphertext to move.

  Also pinned: `a_corrupted_rho_still_passes_the_modulus_check_as_it_does_in_age`,
  because `rho` is a seed rather than coefficients and the §7.2 check must *not*
  reach it — a boundary a "stricter is safer" change would cross silently.

- **Four tests that could not fail** (last pass before the v0.1.0 freeze).
  `age-pq-hpke/tests/error_tests.rs::test_max_size_key_x25519` ended
  `let _ = result;`; its all-`0xFF` key is exactly what the repaired validator
  now rejects, so it asserts that, renamed
  `all_ff_encapsulation_key_is_rejected_by_the_ml_kem_modulus_check`.
  `mlkem768x25519_tests.rs::test_derand_invalid_eseed_length` had an **empty
  body** — the property it named is unrepresentable (`encapsulate_derand` takes
  `&[u8; 64]`), so it is replaced by
  `test_derand_eseed_halves_are_bound_to_their_roles`, the one `eseed` mistake
  the type system cannot catch.
  `age-pq-keys/tests/hybrid_recipient_tests.rs::hybrid_recipient_keypair_generation_and_file_encryption`
  had no assertions and wrote a freshly generated **private key** to a temp file
  nothing read; it now asserts the on-disk age header and round-trips through
  the file, and the private-key write is gone. `age_cli_interop_roundtrip_tests.rs`
  no longer writes a `temp_recipient` file nothing reads.

- **`cargo fetch` works again on MSRV 1.70.** It failed on every branch,
  including `main`: three transitive crates in the WASI dependency chain
  (`wit-bindgen`, `wit-bindgen-core`, `wasip2`) are edition 2024, which Cargo
  1.70 cannot parse, so any all-target prefetch aborted. Ordinary
  `cargo check` / `build` / `test` were unaffected because those crates are
  target-gated to WASI and never compile here — which is why this went unnoticed.

  Pinned in `Cargo.lock`: `getrandom` 0.3.4 → 0.3.1 (drops `wasi` 0.14 for 0.13,
  removing `wasip2`) and `uuid` 1.22.0 → 1.11.0 (drops `getrandom` 0.4, removing
  the `wit-bindgen-*` and `wit-component` chain). Both are lockfile-only; no
  manifest requirement changed, and the 1.85 bump can simply drop the pins.

- **Child-process helpers resolve `age` and `age-keygen` to an absolute path**
  before applying the plugin-free `PATH` (`age-pq-keys/tests/common.rs`).
  Program resolution and plugin blocking are two different jobs, and conflating
  them was a live hazard: the WinGet `age` package ships
  `age-plugin-batchpass.exe` in the same directory as `age.exe`, so the filter
  removed the only directory holding age itself. It worked anyway because Rust
  on Windows falls back to the parent's `PATH` — a fallback Unix does not make
  once the environment is overridden. The filtered `PATH` now governs only what
  the child sees when *it* looks for a plugin.

- **`common::safe_stderr` filters identity strings out of child stderr** before
  it can reach a panic message, and the existing CLI round-trip test was routed
  through it. `age-keygen -y` echoes the **entire** identity when it cannot
  parse one; `age -d -i FILE` does not, naming the file instead. Filtering at
  the single place bytes become a message beats reasoning about the asymmetry
  per call site. The `docs/design/pre-freeze-audit.md` entry that recorded this
  leak as "not reproduced" is corrected there — it had measured only the second
  path.

### Changed

- **`panic = "unwind"` is now stated explicitly** in `[profile.dev]` and
  `[profile.release]`. It was already the effective behaviour via Rust's
  default, but it is a security property rather than a preference: `panic =
  "abort"` skips destructors, which skips secure-gate's zeroization, leaving
  secrets in memory past a panic. Spelling it out means a later size-motivated
  switch has to be a deliberate edit.



- **`publish = false` on all three crates**, inherited from `[workspace.package]`.
  These are experimental and distributed by git tag; none has ever been on
  crates.io. Nothing previously said so in the manifests, so `cargo publish` was
  permitted — now it is a hard error rather than a convention.

- **`secure-gate` moved to a git dependency on `release/0.8` (`0.8.0-rc.12`).**
  rc.12 is not on crates.io, which costs nothing here given the line above.
  `Cargo.lock` pins the exact rev regardless of the branch.

  Two rc.12 changes reach this workspace:

  - **`into_inner` returns the plain value; `InnerSecret<T>` is deleted.** Six
    call sites drop their `let owned = …; f(*owned)` dance for a direct
    `f(x.into_inner())`. Protection now ends at that call rather than following
    the value into the caller — which is what those sites wanted anyway, since
    each hands off to an API taking the array by value, and the two curve sites
    hand off to `StaticSecret` / `x448::Secret`, both zeroize-on-drop. CLAUDE.md's
    Tier-3 section is rewritten accordingly: `into_inner` is now best read as a
    greppable boundary marker — "this secret is leaving wrapper protection here".
  - **Every encoder returns `EncodedSecret`; the `*_zeroizing` twins are gone.**
    No call sites here (this workspace uses the `bech32` crate directly), but it
    settles an open API question — see below.

  Not adopted yet, and worth its own change: rc.12 adds `try_to_bech32_sized::<N>`
  / `Bech32Sized`, a caller-chosen bech32 code length. Both `age-pq-keys` and
  `age-plugin-pq` hand-roll a `Checksum` impl at `CODE_LENGTH = 8192` for exactly
  this reason, and that duplication now has an upstream answer.

### Changed (BREAKING)

- **`age-pq-hpke`'s public API no longer exposes secure-gate types.** Eight
  boundaries changed — see that crate's changelog for the table and migration
  notes. Downstream effects inside this workspace: `age-plugin-pq`'s
  `hpke_pq::derive_key_and_nonce` now parks each `Kdf` output in
  `zeroize::Zeroizing` on arrival instead of reaching through `with_secret`,
  and `age-plugin-pq` no longer imports `RevealSecret` at all — it consumes
  `encap`, `decap`, and the `Kdf` trait without touching secure-gate's access
  API. `age-pq-keys` was unaffected; it never used these types.

### Changed

- **`secure-gate` bumped `=0.8.0-rc.10` → `=0.8.0-rc.11`.** The one breaking
  change that reaches this workspace is rc.11's #156, which moves `len()` /
  `byte_len()` / `is_empty()` off `RevealSecret` onto a new `SecretLen` trait so
  `RevealSecret` can be implemented for every inner type. Libraries, binaries,
  and doctests were unaffected; three `age-pq-hpke` test files needed the new
  trait in scope. rc.11's other two breaking changes are inert here — no
  secure-gate encoding method is called anywhere in the workspace, and no
  `EncodedSecret` is ever constructed.
- **`CLAUDE.md`: corrected the `into_inner` rules.** The MSRV-1.70 table claimed
  `Fixed<[u8; N]>` with `N > 32` could not use Tier-3 because `into_inner`
  required `Self::Inner: Default`. secure-gate rc.10 replaced that bound with
  `SentinelValue`, whose array impl bounds the *element* type, so the ceiling
  has been gone for a release. Replaced the table, recorded the history so a
  stale `// Tier-2 (forced)` marker on an old branch is recognisable, documented
  that `InnerSecret` has no `DerefMut`, refreshed the pinned-version line, and
  split the `x448` row of the Tier-2 inventory into its Tier-3 (`Secret::from`)
  and Tier-2 (`as_diffie_hellman`) halves.
- **`CLAUDE.md`: new *Length metadata — `SecretLen`, not `RevealSecret`*
  section** covering the rc.11 trait split and the import it requires.

### Security

- rc.11 carries two upstream fixes relevant to patterns this workspace
  documents, though neither has a live call site here: #152 (`io::Write` on
  `Dynamic<Vec<u8>>` left the plaintext in the old allocation when the buffer
  grew — the exact `Plaintext::new(Vec::new())` + `io::copy` shape the
  *IO with `Dynamic<Vec<u8>>`* rule recommends) and #146 (`InnerSecret::clone()`
  resolved through `Deref` to `T::clone` and silently produced an unzeroized
  bare value).

### Added

- `.gitattributes`: `* text=auto` baseline with `binary` overrides for
  `age-pq-keys/tests/data/**` and `age-pq-hpke/tests/data/**` so encrypted fixtures and
  plaintext references are never subject to line-ending conversion on any platform.
- `rust-toolchain.toml` pinning the workspace to channel `1.70` with `cargo`, `rustc`,
  `rust-std`, `clippy`, and `rustfmt` (minimal profile), so contributors get the MSRV toolchain
  automatically.

### Changed

- `secure-gate` workspace dependency bumped to `=0.8.0-rc.10` (supersedes `rc.9`; pinned
  across `age-pq-hpke`, `age-plugin-pq`, and tests).
- `Cargo.toml` `include` patterns rewritten as workspace-rooted absolute paths
  (`/CHANGELOG.md`, `/LICENSE*`, `/README.md`) so packaging picks up the workspace files
  unambiguously regardless of member-crate cwd.
- `age-pq-keys/Cargo.toml`: `age-pq-hpke` dependency switched from
  `{ git = "...", tag = "v0.0.5" }` to `{ path = "../age-pq-hpke" }` for in-workspace
  development; the workspace `[patch]` table keeps the published git reference valid for
  downstream consumers without requiring changes to member `Cargo.toml` files.

### Fixed

- `age-pq-keys/tests/data/lorem.txt` re-written as pure LF (was committed with CRLF on
  Windows), fixing `test_decrypt_lorem_encrypted_with_age_cli` which compared decrypted bytes
  against the on-disk reference (the encrypted fixture was created from the LF version).
- `age-plugin-pq`: `rand` dependency corrected from `0.8` to `0.9` to match the rest of the
  workspace (was the sole outlier still on the old series).
- `age-pq-hpke/tests/error_tests.rs`: explicit type annotations (`0usize..2000usize`,
  `rng.random::<u8>()`) resolve type-inference ambiguity introduced by the `rand 0.9` API.

### Security

- `age-plugin-pq`: wrap private-key and file-key intermediates in `Zeroizing<...>` across
  `wrap_file_keys` / `unwrap_file_keys`, `add_identity`, `keygen`, and
  `convert_native_identities` (ChaCha20-Poly1305 key setup, decrypted file keys, bech32
  strings, and stack seed copies).

---

## [0.1.0] - 2026-03-25

Initial creation of the unified `age-pq-workspace` monorepo, consolidating three previously
independent crates into a single Cargo workspace.

### Added

- Root `Cargo.toml` establishing the workspace with three members:
  `age-pq-hpke`, `age-pq-keys`, and `age-plugin-pq`.
- `resolver = "2"` (required for MSRV 1.70; upgrade to `"3"` when MSRV rises to 1.85+).
- `[workspace.package]` block: shared `rust-version`, `edition`, `license`,
  `repository`, `homepage`, `authors`, `description`, `keywords`, `categories`,
  and `include` inherited by all members, eliminating per-crate duplication.
- `[patch."https://github.com/Slurp9187/age-pq-hpke"]`: redirects any member's published-style
  git dependency on `age-pq-hpke` to the local sibling path, enabling cross-crate development
  without modifying member `Cargo.toml` files.
- `[profile.dev] opt-level = 2`: avoids unusably slow crypto-math in debug builds.
- `[profile.bench] debug = true`: retains symbols for flamegraph / profiling workflows.
- `[workspace.lints.rust]` and `[workspace.lints.clippy]`: shared lint governance modelled on
  the RustCrypto/KEMs style (`missing_docs`, `unsafe_code = "deny"`, cast lints, etc.).
- `[workspace.dependencies]`:
  - `secure-gate = "=0.8.0-rc.4"` with features `["rand", "ct-eq"]` — pinned across all members.
  - `clap = "=4.4.18"` with `["derive"]` — single pinned CLI parser version.
  - `half = ">=2.0, <2.5"` (phantom cap): `half 2.5.0+` requires rustc ≥ 1.81; the upper bound
    keeps the resolver within MSRV 1.70 automatically on every `cargo update`.
  - `unicode-ident = ">=1.0, <1.0.23"` (phantom cap): `unicode-ident 1.0.23+` bumped its
    `rust-version` to 1.71; the cap prevents silent MSRV drift.
  - `proptest`, `tempfile`, `time` — pinned dev-dependency versions shared across members.
- Root `Cargo.lock` checked in as the authoritative lockfile; per-crate `Cargo.lock` files are
  not used.
- `.gitignore` scoped for Rust workspace conventions (target/, IDE files, per-crate lock files).

### Members brought in (via `git subtree`)

| Crate | Source tag | Notes |
|---|---|---|
| `age-pq-hpke` | `98316d9` (squashed) | Post-quantum HPKE core (ML-KEM-768 + X25519) |
| `age-pq-keys` | `a9a51a0` (squashed) | age recipient/identity wrapper |
| `age-plugin-pq` | `7a99b0c` (squashed) | age plugin binary |

Each subtree history was squashed into a single merge commit; full per-crate history is
preserved in the individual crate `CHANGELOG.md` files.
