# Plan — MSRV 1.85 and the secure-gate 0.9 cohort bump

**Tracking issue: [#2](https://github.com/Slurp9187/age-pq-workspace/issues/2)**
— "age-pq-hpke 0.0.7: the cohort bump — rand 0.10, libcrux-ml-kem 0.0.10,
secure-gate 0.9, MSRV 1.85"

Status: **LANDED in `0.2.0-rc.1`.** The 1.70 line is frozen and tagged
`v0.1.0-rc.1`; this workspace is now rustc 1.85, edition 2024, Cargo resolver 3,
secure-gate `main` (0.9.0-rc.9), rand 0.10 and libcrux-ml-kem 0.0.10.

The checklist below is kept as a record of what shipped, with the items that the
planning phase got **wrong** corrected in place rather than deleted — a plan
that quietly loses its bad predictions teaches nothing the next time.

This document is the workspace-side checklist. Issue #2 carries the downstream
motivation — this workspace is the remaining upstream blocker for
`encrypted-file-vault`'s S09 slice
([Slurp9187/encrypted-file-vault#205](https://github.com/Slurp9187/encrypted-file-vault/issues/205)).

## Locked decisions

| ID | Decision |
|----|----------|
| **DECIDE-11** | **MSRV moves 1.70 → 1.85 in the next release.** Decided; does not need re-litigating. The CLAUDE.md rule "raise an MSRV bump as a separate decision PR" is satisfied by this document plus issue #2. |
| **DECIDE-12** | **The bump and the `secure-gate` 0.9 upgrade are one piece of work,** not two. See below — they are the same constraint. |
| **DECIDE-14** | **`HybridRecipient::pub_key` becomes private and validated** before the freeze. The `expect` in `to_string()` is a reachable panic today and #11 makes it easier to reach. Breaking, deliberately taken in this window. See [`../design/pre-freeze-audit.md`](../design/pre-freeze-audit.md). |
| **DECIDE-13** | **The version lines split *at* the bump, not before.** 1.70 work continues on `0.0.x`; the final 1.70 state is tagged `v0.1.0`, and the 1.85 line opens at `0.2.0`. See below. |

## DECIDE-13 — the version-line split

`0.0.x` stays while the 1.70 line is still changing (#11 rewrites the bech32
path, #3 renamed public types). Graduating to `0.1.0` early would mean cutting
`0.1.1` immediately for work that belongs in `0.1.0`.

**Order matters.** The freeze tag has to be cut from the last 1.70 commit,
*before* the bump touches anything — bump first and version after, and there is
no clean point left to tag:

1. ~~Finish the remaining 1.70 work on `0.0.x`~~ **done** — #11 (PR #23), the
   age-go half of #15 (PR #24), and the FIPS 203 encapsulation key check with
   its test-hygiene sweep (PR #27).
2. ~~Set the crate versions to `0.1.0`~~ — **amended: the first tag is
   `v0.1.0-rc.1`, not `v0.1.0`.** The crates move to a single
   `version.workspace = true` at `0.1.0-rc.1` and are tagged as a release
   candidate, so the frozen line can be exercised as a release — pinned by tag,
   built from a clean clone — before the number becomes permanent. `v0.1.0`
   follows when the candidate has been exercised; further candidates are
   `-rc.2`, and so on.
3. Only then start #2. `main` becomes `0.2.0`.
4. Create `release/0.1` **lazily** — branch it from whichever tag proves final,
   if and when a patch is actually needed. Nothing to maintain until then, and
   the tag marks the boundary either way.

**Why an `-rc` rather than going straight to `v0.1.0`.** A tag is cheap to add
and awkward to move once anything pins it. The candidate costs one extra tag and
buys the chance to find a packaging-level problem — a missing licence file, an
`include` that omits something, a crate that does not build from a clean clone at
the pinned toolchain — while the number can still change without anyone having
depended on it. Two such problems were in fact found while cutting this one: the
repository root and `age-plugin-pq` both declared `MIT OR Apache-2.0` with no
licence text present.

### Why not keep `0.0.x` for the maintenance line

Cargo treats every `0.0.z` as mutually incompatible: `^0.0.8` resolves to exactly
`>=0.0.8, <0.0.9`. There is no patch channel — a security fix shipped as `0.0.9`
reaches nobody pinned to `0.0.8` without an explicit dependency edit. `^0.1`
picks up `0.1.1` automatically. Keeping `0.0.x` would defeat the reason for
having a maintenance line at all.

Note the caveat: these crates are `publish = false` and distributed by git, so a
consumer pinning `tag = "v0.1.0"` bypasses SemVer ranges entirely and the number
becomes documentation. The *branch* is then the patch channel — which is exactly
how this workspace consumes secure-gate (`branch = "release/0.8"`). The number
still earns its place as signalling: `0.1.0 → 0.1.1` says "compatible fix";
`0.0.8 → 0.0.9` says nothing.

`0.1.0` does not claim stability. Under SemVer `0.x` explicitly means anything
may break at a minor bump; it claims only that compatible and incompatible
changes are now distinguished, which is the minimum needed for a maintenance
line.

### Precedent

secure-gate does this already — `release/0.8` is the MSRV-1.70 backport line
while `main` is `0.9` (edition 2024, MSRV 1.85). Mirroring the structure of our
own dependency keeps the relationship legible.

**Not** modelled on libcrux, despite the surface similarity of its `0.0.x`
releases. libcrux's versioning tracks *its own* API and formal-verification
maturity — its README grades subcrates with `pre-verification` / `verified`
badges, and `libcrux-ml-kem` sits at `0.0.10` while the workspace is `0.0.5`. It
is not a statement about ML-KEM's standing: FIPS 203 was finalised in August
2024. Do not cite "ML-KEM is still experimental" as a reason for anything here.

### Crate versions unify at `0.1.0`

**Decided.** At step 2 the three crates move to `version.workspace = true` and a
single number, replacing today's `0.0.7` / `0.0.6` / `0.0.2`.

They are not independently releasable in practice:

- `age-pq-keys` and `age-plugin-pq` both depend on `age-pq-hpke` **by path**, so
  a change there ships in the same commit as its consumers — there is no
  version-resolution step that could pick a different combination.
- Distribution is a git tag over the whole workspace. `v0.1.0` has to mean one
  thing; three numbers make "which version is the 1.70 line?" ambiguous exactly
  when the answer matters most.
- With `publish = false`, per-crate precision buys nothing — no consumer is
  resolving `age-pq-keys 0.0.6` against `age-pq-hpke 0.0.7` from a registry.

The honest counter-argument is that unified versions publish releases for crates
that did not change, so the number stops being evidence about a specific crate.
Accepted: the changelogs carry that detail, and for a git-tagged workspace a
coherent tag is worth more than per-crate precision.

libcrux does the opposite — `libcrux-ml-kem` at `0.0.10` while its workspace is
`0.0.5` — but its subcrates have genuinely independent consumers pulling
individual algorithms from crates.io. That is not this workspace's shape.

**Related cleanup:** hardcoded version strings must go at the same time, or the
unified number gains another place to drift. `age-plugin-pq` already uses
`env!("CARGO_PKG_VERSION")`; `age-pq-keys/examples/pq-keygen.rs` had a literal
`"0.0.6"` and has been hand-realigned before (CHANGELOG 0.0.5). Fixed here.

## Why the MSRV bump and secure-gate 0.9 are the same task

The `secure-gate = "=0.8.0-rc.*"` line this workspace pins is **a backport of
secure-gate's `main`, created specifically to hold MSRV 1.70**. Mainline 0.9.x is
`edition = "2024"`, `rust-version = "1.85"`.

Two consequences, both of which the bump bore out:

1. Staying on 1.70 means staying on a backport branch — it receives `main`'s
   fixes late and adapted (rc.11, for instance, took `base32ct 0.2` instead of
   0.3 purely because 0.3 is edition 2024).
2. **Plan against `main`'s changelog, not the backport's.** The `0.8.0-rc.*`
   entries describe adaptations *away from* `main`, so reading them to plan a
   move *to* `main` inverts the sense of every note.

## Checklist — what actually landed

| Item | Was (1.70) | Now | |
|------|-----------|-----|--|
| `rust-toolchain.toml` | `1.70` | `1.85` | ✅ |
| `[workspace.package] rust-version` | `1.70` | `1.85` | ✅ |
| Workspace version | `0.1.0-rc.1` | `0.2.0-rc.1` | ✅ |
| Cargo `resolver` | `"2"` | `"3"` | ✅ |
| Edition | 2021 | 2024 | ✅ |
| `secure-gate` | git `release/0.8` (`0.8.0-rc.12`) | git `main` (`0.9.0-rc.9`) | ✅ |
| `rand` / `rand_core` | `0.9` | `0.10` | ✅ |
| `libcrux-ml-kem` | `0.0.8` | `0.0.10` | ✅ |
| `half` | capped `>=2.0, <2.5` | cap gone; **left the graph entirely** | ✅ |
| `unicode-ident` | capped `>=1.0, <1.0.23` | cap gone; floats to 1.0.24 | ✅ |
| `clap` | `=4.4.18` | `"4"` | ✅ |
| `proptest` | `=1.5.0` | `"1"` | ✅ |
| `tempfile` | `=3.10.1` | `"3"` | ✅ |
| `time` | `=0.3.40` | `>=0.3.40, <0.3.46` — **cap kept** | ⚠️ |
| Lockfile pins `getrandom` / `uuid` | pinned | removed | ✅ |
| Workspace lint tables | omitted | present **+ member opt-in** | ✅ |
| `sha3` | `0.10` | `0.10` — **declined** | ⏸ |
| `x25519-dalek` | `2.0` | `2.0` — **declined** | ⏸ |

## Corrections — what the planning phase got wrong

These were all recorded as expectations before the work and turned out to be
false. They are kept because each one would have caused a wrong move.

1. **"secure-gate 0.9 is a straightforward upgrade."** Not at the version the
   local cargo cache held. `0.9.0-rc.8` was cut *before* the `Case` /
   `bech32_code_length` / `*_sized` work landed on the 0.8 backport, and it had
   `into_inner` returning `InnerSecret<T>`. Adopting rc.8 would have dropped
   uppercase bech32 — i.e. changed the `AGE-SECRET-KEY-PQ-` and
   `AGE-PLUGIN-PQ-` identity formats — and the only in-crate workaround writes
   the private key to an unzeroized `String`. **`main` had already moved to
   `0.9.0-rc.9`, which forward-ported all of it**, and the workspace needed no
   call-site changes at all. Lesson: `git ls-remote` before reasoning from
   `~/.cargo/git/checkouts`, which can be arbitrarily stale.

2. **"`cargo tree -d` should show one `rand`, one `rand_core`."** Recorded on
   issue #2 as an acceptance criterion; it is **not achievable and should not
   be pursued**. Measured with `cargo tree -i rand@0.8.5 --workspace -e
   normal,dev`, `rand 0.8.5` has **three** consumers: `age 0.11`, `age-core
   0.11`, and `proptest 1.5.0` — a dev-dependency of `age-pq-keys`, i.e. the one
   that *is* ours. `rand_core 0.6.4` comes from `crypto-common` (under `aead`
   0.5 / `chacha20poly1305` 0.10), `rand_core 0.5.1` from `x448 0.6`. `age 0.11`
   is the trait provider this workspace implements, so its generation is not
   ours to choose. Moving `proptest` does not help either: the first release off
   `rand 0.8` is proptest 1.7, which takes `rand 0.9` — a *different* duplicate,
   not one fewer, since our own crates are on 0.10. So the criterion fails on
   three counts, not two, and no reachable move satisfies it. The meaningful
   criterion is **exactly one `libcrux-ml-kem`**, plus every direct declaration
   on the 0.10 generation — both of which hold.

3. **"All four exact pins are MSRV scaffolding."** Only two were. `clap`
   `=4.4.18` genuinely held 1.70 (4.5.0 moved to 1.74), and `time` `=0.3.40`
   genuinely did too. But `proptest` and `tempfile` declared MSRVs far below
   1.70 across their entire ranges — those pins were blanket style and never
   bought anything.

4. **"The `time` cap is removable at 1.85."** It is **not**. `time` 0.3.46+
   requires rustc **1.88**, above the new floor, so the cap outlives the bump.
   Worse, `age-plugin-pq` declared `time = "0.3"` locally instead of inheriting,
   so relaxing the workspace entry to a bare caret would have left *nothing*
   capping it. It now inherits.

5. **"libcrux-ml-kem 0.0.10 declares no `rust-version`, so resolver 3 will not
   refuse it."** True but not the question — no declared rust-version means
   cargo will not *check*, not that it compiles. The libcrux workspace root says
   1.89. **Settled by building:** `cargo build --workspace --all-targets` on
   1.85.1 succeeds, and the full suite passes.

   It did, however, grow the lockfile in a way no build or test can see.
   `libcrux-ml-kem` 0.0.10 pulls `libcrux-secrets` 0.0.6, which declares
   `[target."cfg(valgrind_ct_test)".dependencies.crabgrind]`. Cargo cannot
   evaluate a custom `cfg` at resolution time, so `crabgrind` 0.2.6 plus its
   build chain (`bindgen` 0.72, `clang-sys`, `libloading`, `regex` and friends —
   14 new lockfile entries, counted by diffing package names against `main`'s
   `Cargo.lock`) are in `Cargo.lock` and reachable from `cargo tree --target all`,
   even though the cfg is never set and none of it compiles
   (`cargo tree -e normal,build -i crabgrind` prints nothing). It will be
   vendored, fetched by `cargo fetch --target all`, and scanned by any future
   `cargo audit` / `cargo deny` job — this workspace has none today. Same
   invisible-to-`check`/`build`/`test` class as the WASI chain the removed
   lockfile pins guarded, which is why it is written down rather than left to be
   rediscovered.

6. **"`#![forbid(unsafe_code)]` at every crate root"** (CLAUDE.md, "no
   exceptions"). This was simply false — only `age-pq-hpke` carried it. Fixed
   in this bump, and now enforced by `[workspace.lints.rust]` rather than by
   documentation.

7. **"x25519-dalek 3.0 dedups `rand_core`."** Measured: it does not.
   `crypto-common` keeps `rand_core` 0.6.4 in the graph regardless, so taking
   x25519-dalek alone dedups nothing while carrying `curve25519-dalek` 4→5
   underneath the low-order-point rejection. Deferred to the RustCrypto gen-2
   cohort instead.

## Deferred out of this bump

- **RustCrypto generation 2 as one cohort:** `sha2` 0.11 + `hkdf` 0.13 +
  `chacha20poly1305` 0.11 + `aead` 0.6 + `sha3` 0.12 + `x25519-dalek` 3.0.
  Taking any one alone splits `digest` 0.10 / 0.11 across one crypto tree, and
  `sha3` 0.12 churns the X-Wing combiner and the SHAKE KDF — the two modules
  that decide bytes on the wire. Gate it on the CCTV vectors and D1-D5 so a
  single commit can be blamed for any combiner-byte change.
- **The clippy cast lints** (`cast_possible_truncation` and friends): ~19
  `usize as u16` RFC 9180 length prefixes in `age-pq-hpke`. Each needs a checked
  bound or an individually justified `#[allow]`; a blanket crate-level allow
  would make the lint tables decorative again.

## Known API deltas to expect

Not exhaustive — established while migrating rc.10 → rc.11:

- **`SecretLen`.** `len()` / `byte_len()` / `is_empty()` moved off `RevealSecret`
  onto `SecretLen`. Already handled here; unchanged in 0.9.0-rc.9.
- **Encoding methods are trait impls,** not inherent (`ToHex`, `ToBase64Url`,
  `ToBech32`, `ToBech32m`). Call sites need the trait import. **This note is now
  stale in its premise:** issue #11 moved the workspace off the `bech32` crate
  onto secure-gate's encoders, so these traits *are* imported and used in
  `age-pq-keys` and `age-plugin-pq`. They survive 0.9.0-rc.9 unchanged, taking a
  `Case` and returning `EncodedSecret`.
- **`EncodedSecret: Display` was removed.** Use `&*encoded`. Not used here.
- **`fixed_newtype!` / `dynamic_newtype!`** (new in rc.11) emit nominal `struct`s
  rather than `type` aliases, so two 32-byte roles stop being the same type.
  Worth evaluating for `Seed32` vs `AeadKey32` vs `SharedSecret32`, which are
  currently mutually substitutable in all three crates. Not a blocker, and not
  gated on this bump — tracked separately as
  [#3](https://github.com/Slurp9187/age-pq-workspace/issues/3).
