# Project Rules — age-pq-workspace

Workspace-wide rules for `age-pq-hpke`, `age-pq-keys`, and `age-plugin-pq`.
Every rule below applies to every crate in this workspace unless a section
explicitly scopes itself.

## How to read this file

Rules carry one of two markers, and the distinction is the point of the file:

> **Enforced by** *`<test / lint / CI step>`* — something fails if you break it.
>
> **Convention** — nothing checks this. Care is the only mechanism.

Both are real rules. Only one will catch you.

That distinction exists because this workspace has a documented history of the
opposite: a CI workflow at a path GitHub never read, tests that printed
`SKIPPED` into a stream libtest swallows and passed, a test target that exits 0
with zero tests, a `validate_public_key` that validated nothing, a
`XWING_DRAFT_VERSION` asserting conformance the code lacked, and — in this very
file — `#![forbid(unsafe_code)]` "at every crate root. No exceptions." while two
of three roots lacked it. Confident phrasing is not evidence. If a rule below is
marked **Convention**, treat its confident wording as an aspiration with a
person behind it, not a guarantee with a machine behind it.

A sweep in 2026-09 checked all 173 assertions in this file against the code and
found 42 false or stale. What survives has been re-verified; where a claim could
not be, it now says so.

### Verifying the question you were actually asked

The failures above are unchecked claims. This is the harder neighbour: a claim
that *was* checked, carefully, against the wrong question. Three instances, all
from one session, all by people specifically looking for the thing they missed.

**`git tag -l` is not the published tag list.** It lists local refs, its output
is indistinguishable from the published set, and nothing about it says so. What
a consumer can reach is:

```sh
git ls-remote --tags origin | grep -v '\^{}'
```

The two disagreed here by eight tags. Acting on the local list produced
"eight published tags carry both defects" — which reached a downstream
consumer's remediation plan as a security claim before anyone ran the remote
command. **Three parties reached it independently**, each having run `git tag -l`
and treated the result as authoritative. It is a trap that catches whoever
checks, not one person's slip.

What made it durable is that the *contents* of those tags were then verified
rigorously — `git grep -c was_contributory` returning zero at the tag,
`validate_public_key` read and confirmed as a no-op. All true, and all about
what the objects contained rather than whether anyone could reach them. Careful
verification of the adjacent question reads exactly like verification of the
real one, and carries the confidence earned by the careful part.

**The fix was already written down, in this repository, and that is the part
worth sitting with.** `.claude/skills/changelog-protocol/SKILL.md` carries a
snippet captioned *"tags you have locally that the remote does not"*, which
`comm`s `git tag -l` against `git ls-remote --tags origin` — exactly the
comparison that settles this. It had been read during the same session. It is
filed under *pushing* tags, so it never surfaced while reasoning about
*consuming* them. Knowledge indexed under the wrong problem is not available
when you need it, which is an argument for putting the check where the mistake
happens rather than where the topic lives.

**An audit grep is a lower bound, never a count.** A sweep for secrets copied
out of a `with_secret` borrow used a pattern requiring `*` adjacent to the
closure parameter. It reported one site. The real number was seven — the six it
missed spell the deref inside a call, `from(*bytes)`. A third form
(`.to_vec()`, `.map()`) has no operator to match at all. See the copy-out
section under *Tier-2 boundary inventory*.

**A relay can add falsehood in either direction.** A maintainer's "not
zeroizing as *assumed*" was passed on as "the changelog *understates* it",
adding a severity claim the source never made; the claim was then withdrawn
entirely on a one-word refinement. The authoritative changelog entry was in a
clone on disk throughout, unread. Both the strengthening and the withdrawal
were invisible to the source, and the file settled it in one command.

The rule these share: **name the question the claim rests on, then check that
one.** When a claim is about what someone else can reach, reachability is the
question — not contents, not provenance, not what a local tool prints.

---

## Workspace overview

| Crate | Role |
|-------|------|
| `age-pq-hpke` | Post-quantum hybrid HPKE primitives — X-Wing KEM (ML-KEM-768 + X25519), HPKE Base-mode key schedule (RFC 9180 + draft-ietf-hpke-pq), ChaCha20-Poly1305 AEAD. Library only. |
| `age-pq-keys` | The key layer over `age-pq-hpke`: recipient **and** identity types, keypair generation, the bech32 key formats and their HRPs, and the `mlkem768x25519` stanza wire format (wrap/unwrap plus its validation). Implements `age::Recipient` / `age::Identity`. |
| `age-plugin-pq` | `age-plugin-*` binary that exposes the recipient layer over the age plugin protocol (stdio, newline-delimited base64). |
| `conformance/` | **Not a workspace member.** In-process differential tests against rage, with its own `Cargo.lock`. `cargo test --workspace` does not reach it — see the section below. |

**All three crates use `secure-gate`, inherited from the workspace.** This was
previously split (`secrecy` + `zeroize` in the two upper crates) and is now
unified — the secure-gate sections below bind every crate in full.

| Crate | Secret handling |
|-------|-----------------|
| `age-pq-hpke` | `secure-gate = { workspace = true }` |
| `age-pq-keys` | `secure-gate = { workspace = true }` |
| `age-plugin-pq` | `secure-gate = { workspace = true }` |

The workspace pin is an **exact registry version**, not a git dependency:

```toml
secure-gate = { version = "=0.9.0-rc.12", features = ["rand", "ct-eq"] }
```

`0.9.0-rc.12` is edition 2024, `rust-version = 1.85` — exactly this workspace's
floor. The `release/0.8` backport existed solely to hold MSRV 1.70 and is
**retired** — do not send fixes there, and read the changelog when planning
anything.

**It was `{ git = "...", branch = "main" }` until `0.2.0-rc.3`, and the change is
load-bearing for a public repo that cuts tags.** A branch pin puts the whole
guarantee in `Cargo.lock`: the lock holds a rev until someone runs `cargo
update`, and then silently takes whatever landed upstream. For a *tagged
release* it is worse — the rev a tag's lockfile names has no version identity,
need never correspond to any published secure-gate, and stops existing if the
branch is rebased or force-pushed, so anyone building from the tag resolves an
in-flight commit. This workspace has already watched a downstream consumer be
burned by a pin that silently stopped tracking upstream (the rename trap, below).
A registry version is immutable, published and checksummed instead.

`=` rather than a range is also deliberate: the 0.9.0-rc line is pre-release and
still moving, and a range would let `cargo update` walk onto an rc that nobody
has run the CCTV vectors or D1-D5 against. Bumping is a deliberate edit.

**Pre-release requirement syntax is a trap on this line.** A caret matches a
pre-release only when the requirement itself carries one: `"0.9.0-rc"` tracks
the line, `"=0.9.0-rc.12"` pins it, and plain `"0.9"` resolves to **nothing**,
because there is no stable `0.9.x`.

**`conformance/` carries its own copy of this pin** and inherits nothing, being
excluded from the workspace. It sat on `{ git, branch = "main" }` at
`0.9.0-rc.9` while the root had moved on — the same hand-maintained-duplicate
hazard as its `[lints.rust]` table. If you bump secure-gate here, bump it there.

Note that the base workspace pin enables no encoding feature; `age-pq-keys` and
`age-plugin-pq` add `features = ["encoding-bech32", "std"]` on top, which is
what issue #11 moved the hand-rolled bech32 onto.

One trap worth knowing if you meet it in an old branch or a stale cargo cache:
`0.9.0-rc.8` was cut *before* the `Case` work landed, so it has no `Case`, no
`bech32_code_length` / `*_sized` encoders, and `into_inner` returning
`InnerSecret<T>`. `rc.9` forward-ported all of it. Since uppercase bech32 is
what produces the `AGE-SECRET-KEY-PQ-` / `AGE-PLUGIN-PQ-` identity strings,
rc.8 would be a wire-format regression. Anything below rc.9 on `main` is wrong
for this workspace.

`secrecy` still appears in `age-pq-keys`'s source, but only as `age`'s own
re-export: `FileKey` is `age`'s type and keeps `age`'s accessor. Neither
`secrecy` nor `zeroize` is a direct dependency of any crate here. `zeroize`
appears once as an `x25519-dalek` feature, not as an API this workspace calls.

---

## Build rules — non-negotiable, workspace-wide

- **`#![forbid(unsafe_code)]`** at every crate root. No exceptions.

  **Enforced by** `[workspace.lints.rust] unsafe_code = "forbid"` in the root
  manifest, plus `[lints] workspace = true` in all three member manifests —
  belt and braces with the attribute at each root. Every `unsafe` token in the
  workspace is itself one of those attributes; there are four, one per crate
  root plus one in a test target.

  It was documentation-only until `0.2.0-rc.1`: two of three roots lacked the
  attribute while this file said "no exceptions". That is why the marker
  convention above exists.

  **That member opt-in is the whole mechanism.** `[workspace.lints]` is inert
  without it — an earlier version of these tables existed with no member
  carrying `[lints]`, and governed nothing for its entire life. If you add a
  fourth crate, it needs that line or it is silently unlinted.

  **A fourth package now exists, and it needs the opposite treatment.**
  `conformance/` is `exclude`d from the workspace, so it cannot inherit
  `[workspace.lints]` at all and `[lints] workspace = true` there would fail to
  resolve. It carries its own `[lints.rust]` table, a hand-maintained copy of
  the root one. Verified load-bearing rather than decorative by deleting the
  crate's `#![forbid(unsafe_code)]` attribute and compiling an `unsafe` block:
  it still failed, with `requested on the command line with -F unsafe-code`,
  which only the Cargo table produces. **Nothing keeps the two tables in step** —
  if you change `[workspace.lints.rust]`, change `conformance/Cargo.toml` too.

  The clippy cast lints (`cast_possible_truncation` and friends) are
  deliberately *not* in the table: they fire on the `usize as u16` RFC 9180
  length prefixes in `age-pq-hpke`, which is real work on wire-format-adjacent
  code and belongs in its own change. Do not "enable and blanket-`#![allow]`" —
  that is exactly how the tables became decorative last time. (A hand-counted
  figure lived here and had drifted; counts in prose rot, so it is gone.)
- **`age-plugin-pq` must keep that exact binary name.** The other two crates use
  an `age-pq-*` prefix; this one deliberately does not, and it is not an
  oversight to tidy up. age locates a plugin by *constructing* the path:

  ```go
  path := "age-plugin-" + name   // age-go plugin/client.go
  ```

  where `name` comes from the identity HRP (`AGE-PLUGIN-PQ-` → `pq`). Rename the
  binary and plugin discovery breaks silently: age reports plugin-not-found
  rather than failing to build. The Cargo *package* could be renamed while
  `[[bin]] name` stays put, but package ≠ binary is a trap for the next person,
  so both stay as they are.

  All three halves of that coupling are now guarded rather than merely
  documented (the third arrived with the `age` 0.12 migration, below):

  - Change the **HRP** and `identity_hrp_matches_the_binary_name_age_will_look_for`
    (`age-plugin-pq/tests/integration.rs`) fails, naming the binary age would
    then look for. It derives the expected name from the HRP the plugin itself
    emits, so it needs no age binary.
  - Rename the **bin target** and the same test fails to compile, because
    `env!("CARGO_BIN_EXE_age-plugin-pq")` no longer resolves.
  - Change the **case** of either HRP and one of
    `plugin_identity_hrp_is_uppercase_as_age_0_12_requires` /
    `plugin_recipient_hrp_is_lowercase_as_age_0_12_requires` (same file) fails.
    This is the constraint the 0.12 migration discovered: `age-plugin` 0.7 and
    `age` 0.12 both match plugin HRPs with a case-**sensitive** `starts_with`
    (`AGE-PLUGIN-` for identities, `age1` for recipients), and `bech32` 0.9 →
    0.11 made `Hrp` case-preserving where 0.9's `decode` pre-lowercased it.
    age-go does the same (`plugin/encode.go`; only the bech32 *data* part is
    folded). So the identity emitters at `age-plugin-pq/src/main.rs:439` and
    `:489` must stay `Case::Upper`, and the recipient emitter at `:426` must
    stay `Case::Lower`. Flip any one and you still get valid bech32 that still
    round trips through our own parser, while every 0.12-generation client
    rejects it as an invalid HRP — silently, in the same plugin-not-found shape
    as a rename. All three sites are mutation-checked. (`age::x25519` is
    unaffected: it compares `Hrp == Hrp`, and that `PartialEq` is explicitly
    case-insensitive. The narrowing is to the *plugin* prefix tests only.)

- **Never let an interop test reach our own plugin.** If a test in
  `age-pq-keys` handed `age` an `AGE-PLUGIN-PQ-` identity, age would spawn *our*
  plugin and "interoperability with the Go age CLI" would silently become
  "interoperability with our own code" — still green, proving nothing. It is
  reachable whenever someone has `cargo install`ed the plugin, and on Windows
  additionally from the build directory (see the platform note below).

  `age-pq-keys/tests/common.rs::age_command_without_plugins` strips every
  directory containing an `age-plugin-*` binary from the child's `PATH`, and
  the interop test asserts its identity is the native `AGE-SECRET-KEY-PQ-`
  form. `plugin_free_path_removes_directories_holding_plugins` guards the
  guard against synthetic directories, so a filter that silently matched
  nothing would fail rather than pass.

  **`PATH` is the only lever needed** — verified against both implementations
  rather than assumed. age-go resolves plugins solely with
  `exec.Command("age-plugin-" + name)` (`plugin/client.go`) and rage with
  `which::which` (`age/src/plugin.rs`). Neither consults an environment
  variable, a plugin directory, or a config file; there is no search path to
  miss. On Go 1.19+ `exec` also stopped resolving silently from the working
  directory. The match is case-insensitive because Windows and macOS
  filesystems are, and prefix-based so it covers `PATHEXT` variants and the
  `.exe` form rage looks for under WSL.

  The other route to a plugin is `age -j <name>`, which names one explicitly.
  No test here uses it.

  **Platform note, learned the hard way.** Cargo adds the build output directory
  to the *dynamic library* search path for test processes. That is `PATH` on
  Windows but `LD_LIBRARY_PATH` on Unix, so `target/debug` is on `PATH` for
  Windows test runs and **not** for Linux ones. A test that relies on it passes
  locally on Windows and fails in CI. `age-plugin-pq`'s round trip therefore
  prepends the plugin's directory to `PATH` explicitly rather than depending on
  Cargo — which is also better, since it guarantees age spawns this run's build
  instead of a globally installed one.

  `age-plugin-pq`'s own round trip does **not** rely on Cargo for this either.
  It prepends the plugin's directory to `PATH` explicitly, so age spawns this
  run's build rather than a stale global install. Do not "fix" that by
  installing the plugin system-wide.

  (An earlier version of this paragraph said the plugin's tests deliberately
  relied on Cargo's `PATH` behaviour. That was the approach that *caused* the
  Linux CI failure described above, and it was replaced; the sentence outlived
  the code by several releases and contradicted the paragraph directly above
  it.)
- **MSRV is `1.85`** (workspace `rust-toolchain.toml`), edition **2024**, Cargo
  `resolver = "3"`. The 1.70 line is frozen at `v0.1.0-rc.1` and the cohort bump
  (issue #2) landed in `0.2.0-rc.1`; `docs/plans/msrv-1.85-cohort-bump.md`
  records what shipped. Boundary-type decisions that constrained it:
  [`docs/design/api-boundary-types.md`](docs/design/api-boundary-types.md).

  What that bump settled, so it is not re-litigated:

  | Item | Was (1.70) | Now |
  |------|-----------|-----|
  | `secure-gate` | git `release/0.8` (`0.8.0-rc.12`) backport | git `main` (`0.9.0-rc.9`) |
  | `rand` / `rand_core` | `0.9` | `0.10` |
  | `libcrux-ml-kem` | `0.0.8` | `0.0.10` |
  | `half`, `unicode-ident` | capped for MSRV | **caps gone**; `half` left the graph with secure-gate 0.8 |
  | `clap`, `proptest`, `tempfile` | exact `=` pins | carets |
  | `time` | `=0.3.40` | **still capped**, `>=0.3.40, <0.3.46` — see below |
  | Cargo `resolver` | `"2"` | `"3"` |
  | Edition | 2021 | 2024 |
  | Workspace lint tables | omitted | present, **with member opt-in** |

  **`time` is the one cap that survived the bump.** `time` 0.3.46+ requires
  rustc 1.88, which is above this workspace's floor, so the cap is load-bearing
  and is not scaffolding to clean up. Resolver 3's MSRV-aware selection prefers
  a compatible version but is only a *preference* — `--ignore-rust-version`, or
  a consumer resolving this tree on a newer toolchain, walks straight past it.
  A manifest cap is a fact. `age-plugin-pq` must keep inheriting the workspace
  entry (`time = { workspace = true, … }`) rather than declaring `time = "0.3"`
  itself, which used to bypass the cap entirely.

  **The `age` 0.12 migration (issue #29), settled in `0.2.0-rc.2`.** The 1.70
  floor was what had blocked it; `age` 0.12.1 / `age-core` 0.12.0 /
  `age-plugin` 0.7.0 all declare `rust-version = "1.74"`, edition 2021, well
  under our floor.

  | Item | Was | Now |
  |------|-----|-----|
  | `age` (`age-pq-keys`, normal + `armor` dev-dep) | `0.11` | `0.12` |
  | `age-core` (`age-pq-keys`, `age-plugin-pq`) | `0.11` | `0.12` |
  | `age-plugin` (`age-plugin-pq`) | `0.6` | `0.7` |

  **No changes to any crate's `src/`.** The `Recipient` / `Identity` trait
  signatures are byte-identical across the jump, the `"postquantum"` label is
  unchanged, and the wire format does not move — 19/19 CCTV vectors and D1–D5
  verified per-vector before *and* after, not just as a summary line. (Test
  code did change: the migration added the two HRP-case guards listed in the
  plugin-discovery section above.)

  What it drags in, and this is the part that will surprise an auditor:
  **`age` 0.12 depends non-optionally on `ml-kem 0.2`, `p256 0.13`, `hpke 0.12`
  and `sha3 0.10`** — no feature gates. So RustCrypto `ml-kem` is now in this
  workspace's graph. It is **not** a second implementation of our KEM: it backs
  `age` 0.12's own `native::tagpq` recipient (`mlkem768p256tag`, HRP
  `age1tagpq`, label `MLKEM768-P256`), which is a different format from our
  `mlkem768x25519` and shares no code with it.

  Reach is asymmetric, and **the two resolution modes disagree — deliberately,
  so state which one you measured.** Per-package (`cargo tree -p <crate> …`,
  the crate's own dependency edges): `age-pq-keys` reaches `ml-kem` + `p256` +
  `hpke` + `aes-gcm`; `age-plugin-pq` reaches `hpke` + `aes-gcm` only, because
  `age-core` takes `hpke` with `default-features = false, features = ["alloc"]`
  and no `ml-kem`. Workspace-wide (`cargo tree --workspace …`, which is how CI
  and every bare `cargo build` / `cargo test` in this repo resolve), feature
  unification turns `hpke`'s `p256` feature on for *everyone* — `age` enables
  it, there is one `hpke` build, and the plugin binary therefore links `p256`,
  `elliptic-curve`, `crypto-bigint`, `sec1`, `der`, `const-oid`, `ff`, `group`
  and `primeorder` as dead code it never calls. The **ML-KEM half of the claim
  survives both modes**: `cargo tree -i ml-kem --workspace -e normal` shows
  `ml-kem 0.2.3 <- age 0.12.1 <- age-pq-keys` and nothing else, so `ml-kem` does
  not reach `age-plugin-pq` either way. **`age-pq-hpke` gets nothing new** in
  either mode — it has no `age` edge at all, so the verified-ML-KEM crate is the
  only ML-KEM in that crate's graph.

  Two consequences that are documentation, not code: the "formally verified
  ML-KEM" claim is now a claim about *our path*, not about the graph (see
  `docs/design/hpke-import-vs-own.md`), and a **pre-release** rides in
  transitively — `kem 0.3.0-pre.0`, pulled by **`ml-kem 0.2.3`** with an *exact*
  pin (`[dependencies.kem] version = "=0.3.0-pre.0"`), not by `hpke`, whose
  manifest declares no `kem` dependency at all. Because the puller is `ml-kem`,
  the pre-release rides only on `age-pq-keys` and the `=` pin means `cargo
  update` cannot move it even within the pre-release line. Either way it is not
  ours to cap; `Cargo.lock` is what holds it.

  **Not taken in that bump, deliberately:** `sha3` 0.10 → 0.12 and
  `x25519-dalek` 2.0 → 3.0. Neither is forced. `sha3` 0.12 needs `digest` 0.11
  while `sha2` / `hkdf` / `chacha20poly1305` / `aead` all remain on `digest`
  0.10, which would put two digest generations in one crypto tree, and it churns
  the X-Wing combiner and SHAKE KDF — the two modules that decide bytes on the
  wire. `x25519-dalek` 3.0's apparent dedup win is illusory: `crypto-common`
  (under `aead` 0.5) keeps `rand_core` 0.6 in the graph regardless, so taking it
  alone buys nothing while carrying `curve25519-dalek` 4→5 underneath the
  low-order-point rejection. Move the whole RustCrypto gen-2 cohort together
  (`sha2` 0.11 + `hkdf` 0.13 + `chacha20poly1305` 0.11 + `aead` 0.6 + `sha3`
  0.12 + `x25519-dalek` 3.0) in its own change, gated on the CCTV vectors and
  D1–D5, so exactly one commit can be blamed for a combiner-byte change.

  **The `age` 0.12 migration (issue #29, `0.2.0-rc.2`) added a hard blocker to
  that cohort.** Both crates `age` 0.12 pulls non-optionally pin the gen-1 side,
  read from their manifests rather than inferred: `hpke 0.12` declares `digest`
  0.10, `sha2` 0.10, `aead` 0.5, `hkdf` 0.12 and `hmac` 0.12; `ml-kem 0.2.3`
  declares `sha3` 0.10.8 (its full dependency list being `hybrid-array`
  0.2.0-rc.9, `kem` `=0.3.0-pre.0`, `rand_core` 0.6.4, `sha3` 0.10.8, and
  `zeroize` 1.8.1 optional). So the gen-2 move is no longer only ours to make:
  **it cannot happen before `age` itself moves**, or the split it was deferred
  to avoid appears anyway, now with the deciding side outside this workspace's
  control — and note `sha3` in particular, the crate the deferred bump is named
  for, is now pinned to 0.10 by `ml-kem` as well as by us. Measured after the
  migration, `digest` is still **single-generation at 0.10.7** across the whole
  workspace graph, as are `sha2` (0.10.9) and `sha3` (0.10.8) — the deferral is
  still holding, and this is the fact to re-check before anyone reopens it.

  **`cargo tree -d` will always show duplicate `rand` / `rand_core`, and that is
  correct.** Re-measured after the `age` 0.12 migration with
  `cargo tree -i rand@0.8.5 --workspace -e normal,dev`: `rand 0.8.5` still has
  **exactly three** consumers, `age 0.12.1`, `age-core 0.12.0` and
  `proptest 1.5.0` (a dev-dependency of `age-pq-keys`). `age` is the trait
  provider this workspace implements, so its generation is not ours to choose —
  **do not force-upgrade or `[patch]` `age` to collapse these.** `proptest` is
  the one consumer that *is* ours, but moving it does not dedup anything: the
  first release off `rand 0.8` is proptest 1.7, and it lands on `rand 0.9` — a
  different duplicate, not one fewer. That trade is out of scope for a
  dependency bump and is not taken.

  `rand_core 0.5.1` still comes from `x448 0.6`. **`rand_core 0.6.4` no longer
  "comes from `crypto-common`"** — that was true on `age` 0.11 and is now badly
  understated. `cargo tree -i rand_core@0.6.4 --workspace -e normal,dev` lists
  **twelve** direct consumers: `crypto-bigint`, `crypto-common`,
  `elliptic-curve`, `ff`, `group`, `hpke`, `kem`, `ml-kem`, `rand 0.8.5`,
  `rand_chacha 0.3.1`, `rand_xorshift` and `x25519-dalek 2.0.1`. This makes the
  paragraph above *stronger*, not weaker: moving `x25519-dalek` to 3.0 alone now
  removes one edge of twelve, so it cannot collapse the duplicate even in
  principle. Do not read the old single-consumer wording as a dedup opportunity.

  The criteria that *are* meaningful, all three re-measured on the migrated
  tree: exactly one `libcrux-ml-kem` (0.0.10); **exactly one RustCrypto
  `ml-kem` (0.2.3), which is `age` 0.12's own and is not on our KEM path** —
  `cargo tree -i ml-kem --workspace -e normal` must show `age` as its only
  consumer, never `age-pq-hpke`; and every direct declaration in the three
  crates on the `rand` 0.10 generation.

  **Duplicate-group count is not a regression signal by itself.** The `age` 0.12
  migration took it from 17 groups to 14 (`base64`, `bech32`, `rustc-hash` and
  `self_cell` resolved; `syn` 2/3 added, a proc-macro build-graph duplicate via
  `i18n-embed-fl`, not a runtime one). Separately, `Cargo.lock` holds `nom` 7.1.3
  beside `nom` 8.0.0, reachable only through the target-gated
  `crabgrind`/`bindgen` chain under `libcrux-secrets`; `cargo tree -d --target
  all` reports it, and it never compiles here. Same class of lockfile-only
  artifact as the retired wasip2 pins above — expected, not a thing to "fix".
- **Never set `panic = "abort"`.** `Drop` runs on unwind; `abort` skips
  destructors, which skips secure-gate zeroization, so a secret would survive in
  memory past a panic. It is a security property, not a size preference.

  **Convention** — nothing inspects the profiles.

  Stated precisely, because the previous wording ("in every profile", naming
  `[profile.bench]`) was wrong and unfollowable: `panic = "unwind"` is set
  explicitly in `[profile.dev]` and `[profile.release]`. Cargo **ignores**
  `panic` on the `test` and `bench` profiles — measured, it warns that the
  setting is ignored for the bench profile — so those take no entry and must
  not be given one.
- **No `cargo clean` casually** — `libcrux-ml-kem` and downstream verified
  crypto deps are slow to rebuild.
- **The two lockfile-only pins are gone.** `getrandom` at `0.3.1` and `uuid` at
  `1.11.0` were held back only because newer versions pull `wasip2` /
  `wit-bindgen` / `wit-bindgen-core`, which are edition 2024 and unparseable by
  **Cargo 1.70** — breaking all-target prefetch, and so vendoring and offline
  builds. Cargo 1.85 parses edition 2024 natively, so the reason is dead:
  `getrandom` 0.3.1 fell out of the graph with `rand_core` 0.9, and `uuid`
  floats again.

  The class of bug is worth remembering even though this instance is closed: it
  is **invisible to `check` / `build` / `test`**, because those crates are
  target-gated to WASI and never compile here. Only a fetch sees it. So if you
  ever change what resolves for WASI targets, verify with an actual all-target
  fetch rather than a green test run:

  ```sh
  cargo fetch --target x86_64-pc-windows-msvc \
              --target x86_64-unknown-linux-gnu \
              --target wasm32-wasip2
  ```

  That is how the pins' removal was confirmed, rather than by assuming.
- **No secrets in `static` or `lazy_static!`** — `Drop` does not run on statics.
  Const algorithm IDs, RFC version labels, and suite prefixes are fine
  (they aren't secrets); secret material never lives in a static.

---

## secure-gate

**Moved.** The rules that were here now live in
[`.claude/skills/age-pq-secure-gate/`](.claude/skills/age-pq-secure-gate/SKILL.md), which is
the sole authority for secure-gate in this workspace: the newtype inventory, the
Tier-2/Tier-3 boundary rules, what is deliberately not wrapped, and the pending rc.13
migration.

The protocol itself — access tiers, the residue hazards, Fixed vs Dynamic, alias vs newtype —
is in the global `secure-gate` skill and is not repeated per repo.

---

## Changelog protocol

Full rules and the portable checker:
[`.claude/skills/changelog-protocol/SKILL.md`](.claude/skills/changelog-protocol/SKILL.md).
Two invariants, enforced by CI on `main`:

1. **The top section matches the workspace version.** `[workspace.package]
   version` and the newest heading in the **root** `CHANGELOG.md` agree. The
   three crate files are frozen and exempt — the checker skips them, and says
   so on every run.
2. **A version heading is dated iff that tag exists.**
   `## [X.Y.Z] - unreleased` while in flight; the ISO date goes in when the tag
   is cut, and not before. (Written with a placeholder deliberately: a concrete
   version here goes stale at the next release, and did.)
3. **A dated top section sits at its own tag's commit.** Once a tag is cut, the
   next commit opens the next version — bump the manifest and add
   `## [<next>] - unreleased` in the same commit, or the check fails. Invariants
   1 and 2 both pass on a post-release tree whose changelog no longer describes
   it; this is the one that notices.

**One changelog, at the root.** The three crates share one version and ship as a
single git tag, so per-crate changelogs were telling one release's story four
times and giving invariant 1 four places to drift. Crate-specific changes get a
`### age-pq-hpke` / `### age-pq-keys` / `### age-plugin-pq` heading inside the
release section. The three crate `CHANGELOG.md` files are **frozen** — they keep
their history through `0.1.0-rc.1` and carry a
`<!-- changelog-protocol: frozen -->` marker that the checker skips (announcing
each skip, and failing if *every* file is frozen). If the crates ever publish
independently, versions and changelogs re-split together.

There is **no standing empty `## [Unreleased]` section** — the
versioned-but-undated section *is* the unreleased one, and keeping both leaves a
reader unable to tell which describes the code they have. This is not
hypothetical: `0.2.0-rc.1` sat dated `2026-09-10` while untagged, under an empty
`[Unreleased]`, claiming a release that had not happened.

**Do not date entries as bookkeeping** — git records that precisely and a typed
date drifts. **Do** date an entry when the date bounds an *observation*, because
git dates the commit, not the measurement:

```markdown
- Not reproduced on age v1.3.1 as of 2026-09-09.      <- keep, the date is the claim
- Moved encoding to secure-gate (2026-09-08).          <- drop, git knows
```

The `release/0.1` maintenance branch follows the same protocol but carries no CI
check; its `0.1.0-rc.1` heading is correctly dated because `v0.1.0-rc.1` exists.

---

## `conformance/` — the excluded package

`conformance/` holds in-process differential tests against rage. It is **not** a
workspace member and has its own `Cargo.lock`.

**The exclusion is mandatory, not stylistic.** rage's `age` crate and the
crates.io `age 0.12` this workspace ships against cannot resolve in one
dependency graph — measured, not assumed:

```text
crates.io age 0.12.1 -> ml-kem ^0.2 -> ml-kem 0.2.3 -> kem =0.3.0-pre.0
rage's    age 0.12.1 -> ml-kem ^0.3 -> ml-kem 0.3.0 -> kem ^0.3.0
```

`ml-kem 0.2.3` pins `kem` **exactly** at a pre-release (the same exact pin
documented under the `age` 0.12 migration above), and a pre-release shares its
version slot with its release, so the two are mutually exclusive under any
arrangement of features or dev-dependency placement. `conformance/Cargo.toml`
patches `age` itself to rage so exactly one `age` exists there.

Consequences to keep in mind before citing a green run from it:

- **`age-pq-keys` is compiled there against rage's `age`**, not the crates.io
  one it ships against. Those tests are evidence the two implementations agree
  *given a common `age` core* — not evidence about the shipped build. The
  shell-out oracle and the CCTV vectors are what cover that.
- **`cargo test --workspace` does not reach it.** Run it from `conformance/`;
  CI has a separate job.
- **Its `Cargo.lock` is committed and is the pin on rage.** CI uses `--locked`
  so drift fails rather than silently testing a different rage.
- **Its `[lints.rust]` table is a hand-maintained copy** of the root one — see
  the build-rules section above.

**Do not move other tests here.** This is a quarantine for tests that must
*link* rage, not a category for conformance tests. A test that spawns a binary
or reads vectors from disk has nothing to isolate and belongs where it is.
Moving one here would silently weaken it while keeping it green:
`differential_age_go.rs` builds with `age::Encryptor` and reads with
`age::Decryptor`, which resolve to **rage's** implementations here — so it would
stop testing the STREAM implementation we ship and never say so. Today exactly
one file qualifies for this directory.

Full record: [`docs/design/conformance-workspace-isolation.md`](docs/design/conformance-workspace-isolation.md).

## Toolchain pin

`rust-toolchain.toml` pins the workspace toolchain. CI runs against that pin.
Local `cargo` commands inherit it. Do not invoke `cargo +nightly` or other
override toolchains for routine work — verified-crypto deps in this workspace
have been validated against the pinned compiler.
