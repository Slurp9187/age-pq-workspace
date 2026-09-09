# Plan — MSRV 1.85 and the secure-gate 0.9 cohort bump

**Tracking issue: [#2](https://github.com/Slurp9187/age-pq-workspace/issues/2)**
— "age-pq-hpke 0.0.7: the cohort bump — rand 0.10, libcrux-ml-kem 0.0.10,
secure-gate 0.9, MSRV 1.85"

Status: **Not started.** The current release
(`age-pq-hpke 0.0.7` / `age-pq-keys 0.0.6` / `age-plugin-pq 0.0.2`) is the
**last one pinned to MSRV 1.70**. Nothing in it may depend on the bump.

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

**Order matters.** The `v0.1.0` tag has to be cut from the last 1.70 commit,
*before* the bump touches anything — bump first and version after, and there is
no clean point left to tag:

1. Finish the remaining 1.70 work on `0.0.x` (#11, and the age-go half of #15).
2. Set the crate versions to `0.1.0`, commit, **tag `v0.1.0`**. That tag is the
   frozen MSRV-1.70 line.
3. Only then start #2. `main` becomes `0.2.0`.
4. Create `release/0.1` **lazily** — branch it from the tag if and when a patch
   is actually needed. Nothing to maintain until then, and the tag marks the
   boundary either way.

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

Two consequences for whoever picks this up:

1. Staying on 1.70 means staying on a backport branch — it receives `main`'s
   fixes late and adapted (rc.11, for instance, took `base32ct 0.2` instead of
   0.3 purely because 0.3 is edition 2024).
2. **Plan against `main`'s changelog, not the backport's.** The `0.8.0-rc.*`
   entries describe adaptations *away from* `main`, so reading them to plan a
   move *to* `main` inverts the sense of every note.

## Checklist

| Item | Today (1.70) | After 1.85 |
|------|--------------|------------|
| `secure-gate` | `=0.8.0-rc.11` backport line | mainline `0.9.x` |
| `half` | capped `>=2.0, <2.5` | cap removable (2.5+ needs 1.81) |
| `unicode-ident` | capped `>=1.0, <1.0.23` | cap removable (1.0.23+ needs 1.71) |
| Cargo `resolver` | `"2"` | `"3"` |
| Edition | 2021 | 2024 available |
| Workspace lint tables | omitted (need Cargo 1.74+) | available |
| `rust-toolchain.toml` | `1.70` | `1.85` |

Each of the four pinned lines in the workspace `Cargo.toml` carries an inline
note pointing here, so the constraint is found at the line being edited rather
than only in this file.

Issue #2 additionally covers `rand 0.9 → 0.10` and
`libcrux-ml-kem 0.0.8 → 0.0.10`, and records that libcrux-ml-kem 0.0.10 declares
no `rust-version`, so resolver 3 will not refuse it.

## Known API deltas to expect

Not exhaustive — established while migrating rc.10 → rc.11:

- **`SecretLen`.** `len()` / `byte_len()` / `is_empty()` moved off `RevealSecret`
  onto `SecretLen` (rc.11 / 0.9.0-rc.8). Already handled here.
- **Encoding methods are trait impls,** not inherent (`ToHex`, `ToBase64Url`,
  `ToBech32`, `ToBech32m`). Call sites need the trait import. This workspace
  calls none of them today — it uses the `bech32` crate directly, deliberately
  (see the length-cap note in `age-plugin-pq/src/main.rs`) — so this is only a
  risk if that changes.
- **`EncodedSecret: Display` was removed.** Use `&*encoded`. Not used here.
- **`fixed_newtype!` / `dynamic_newtype!`** (new in rc.11) emit nominal `struct`s
  rather than `type` aliases, so two 32-byte roles stop being the same type.
  Worth evaluating for `Seed32` vs `AeadKey32` vs `SharedSecret32`, which are
  currently mutually substitutable in all three crates. Not a blocker, and not
  gated on this bump — tracked separately as
  [#3](https://github.com/Slurp9187/age-pq-workspace/issues/3).
