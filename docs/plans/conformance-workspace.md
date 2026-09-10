# Plan: isolated conformance workspace

**Status:** in progress · **Date:** 2026-09-08, updated 2026-09-09 · **Tracking:** issue #15

Follows from [`../design/rage-pq-adoption.md`](../design/rage-pq-adoption.md):
we keep our own runtime and use rage and age-go as conformance oracles. This
plan is how the oracles get in without contaminating what we ship.

## Why isolation is load-bearing

`[patch.crates-io]` is **workspace-global**. Pulling rage in as a dev-dependency
of a member crate would apply the `str4d/rust-hpke` and `str4d/RustCrypto-KEMs`
patches to the entire workspace graph, including what we publish. Isolation is
what keeps those forks — plus rage's MSRV 1.85 and its `secrecy` dependency —
quarantined.

## Shape

A `conformance/` directory that is **excluded from the main workspace's
`members`** and carries its own `Cargo.lock`:

```toml
# conformance/Cargo.toml
[dependencies]
age-pq-hpke       = { path = "../age-pq-hpke" }
age-pq-keys  = { path = "../age-pq-keys" }
age               = { git = "https://github.com/str4d/rage", rev = "5d33e3e" }

[patch.crates-io]
hpke   = { git = "https://github.com/str4d/rust-hpke",        rev = "1268205e" }
x-wing = { git = "https://github.com/str4d/RustCrypto-KEMs",  rev = "f5dd74e2" }
```

MSRV 1.85 applies inside `conformance/` only. The main workspace stays at 1.70
until issue #2 lands.

## Work items

- [x] **CCTV hybrid vectors in-tree.** 19 vectors + harness; 19/19 pass. Landed
      ahead of this plan because it needed no rage dependency — the vectors drive
      our own `HybridIdentity` through the `age` 0.11 crate we already depend on.
      See [`../design/cctv-conformance.md`](../design/cctv-conformance.md).
- [x] **CI actually runs.** Workflow moved to the repository root; CCTV vectors
      get their own job.
- [ ] **Scaffold `conformance/`** with the layout above; confirm it resolves
      without perturbing the main lockfile.
- [x] **Differential oracle against the Go `age` CLI** — 64 deterministic
      derivation cases plus 22 payload cases in each direction, replacing a
      sample size of one. `age-pq-keys/tests/differential_age_go.rs`; needed no
      `conformance/` workspace, no rage, and no MSRV bump, which is why it
      landed ahead of the two items below. Design, and what it does *not* prove:
      [`../design/age-go-differential-oracle.md`](../design/age-go-differential-oracle.md).
- [ ] **In-process differential tests** against `age::pq` over random seeds and
      plaintexts — still wanted. The shell-out oracle above covers the same
      *directions* but pays a process spawn per case and can only see public
      inputs and outputs; an in-process oracle can compare intermediate values
      and run orders of magnitude more cases. Needs `conformance/`, since
      `age::pq` means rage.
- [ ] **End-to-end shell-out** to real `age` and `rage` binaries. The `age` half
      is done (above); **`rage` is not**, and that is the remaining gap — it is
      a third implementation with its own bugs, not a restatement of age-go.
- [x] **Make binary-dependent tests fail rather than skip** when the binary is
      absent in CI (issue #14). `common::require_age_cli()` panics; the
      `SKIPPED` `eprintln!` is gone. The oracle's two CI guard steps close the
      remaining hole — a target with zero tests exits 0, so naming the file
      catches deletion but not gutting.
- [ ] **Refresh vectors verbatim from upstream** now that `cargo fetch` works,
      either by keeping the `flate2`-free deviation or adding `flate2`.
- [ ] **Add `rust-hpke` as a second differential oracle** (post-1.85). Its
      `MlKem1024P384` KATs are the acceptance criterion for our own port (#19).
      Same shape as the rage decision: own the runtime, borrow the oracle.

## Blocked / adjacent

~~`cargo fetch` fails workspace-wide on every branch including `main`~~ —
**fixed 2026-09-09.** The WASI chain (`wit-bindgen`, `wit-bindgen-core`,
`wasip2`) is edition 2024 and unparseable by Cargo 1.70, so any all-target
prefetch aborted; `check` / `build` / `test` / `clippy` never noticed because
those crates are target-gated to WASI. Resolved with two lockfile-only pins,
`getrandom` 0.3.1 and `uuid` 1.11.0, verified from a clean clone on rustc
1.70.0. Documented in the root `CHANGELOG.md`, the README MSRV policy, and as a
build rule in `CLAUDE.md` so a routine `cargo update` does not silently undo it.

The CCTV harness was nonetheless written to use only already-locked crates
(`sha2`, `hex`), and the two compressed vectors were pre-decompressed rather
than adding `flate2`. Worth keeping either way: the conformance harness carries
no dependency footprint of its own.

## Next variant: MLKEM1024-P384

Tracked as issue #19. Note this is **no longer** the argument that justifies
keeping our own runtime — `rust-hpke` already implements it. We keep our runtime
for verified ML-KEM; see [`../design/hpke-import-vs-own.md`](../design/hpke-import-vs-own.md).

Port estimate against our existing modules — **~650–750 lines**, nearly all
structural mirroring:

| Piece | Status |
|---|---|
| ML-KEM-1024 primitives | already exist (`ml_kem/mlkem1024.rs`, libcrux-verified); feature declared, not default |
| P-384 classical half | missing entirely; ~100 lines mirroring `x25519.rs` / `x448.rs` |
| `mlkem1024p384.rs` | ~560 lines mirroring `mlkem768x25519.rs` |
| Combiner | label must be parameterised (`MLKEM1024-P384`) |

**libcrux has no verified P-384**, so the classical half is RustCrypto `p384`
either way. The verified-backend advantage applies only to the PQ half.

Parameters per `hpke-pq.md` / CFRG CONCRETE-04:

| Parameter | Value |
|---|---|
| KEM id | `0x0051` |
| Label | `MLKEM1024-P384` |
| `Nenc` / `Npk` | 1665 / 1665 |
| `Nrandom` | 80 |
| `Group.Nseed` | 48 |

Note it is **P-384, not X448** — the existing `x448.rs` is not the classical
half for this variant.

Two reference implementations to diff against, both using RustCrypto `p384` for
the classical half (libcrux has no verified P-384):

- `rust-hpke` `src/kem/mlkem_nistp.rs` (`MlKem1024P384`)
- libcrux `main`, `crates/protocols/hpke/libcrux_provider/src/lib.rs`, `mod hybrid`
  — unreleased; the published `hpke-rs-libcrux` 0.7.0 does not have it.
