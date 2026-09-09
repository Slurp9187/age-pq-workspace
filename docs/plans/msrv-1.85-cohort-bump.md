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
