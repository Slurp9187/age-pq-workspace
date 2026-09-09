# Plan: isolated conformance workspace

**Status:** proposed · **Date:** 2026-09-08 · **Tracking:** issue #15

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
age-hpke-pq       = { path = "../age-hpke-pq" }
age-recipient-pq  = { path = "../age-recipient-pq" }
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
- [ ] **In-process differential tests** against `age::pq` over random seeds and
      plaintexts — the check that catches divergence the fixed vectors miss.
- [ ] **End-to-end shell-out** to real `age` and `rage` binaries.
- [ ] **Make binary-dependent tests fail rather than skip** when the binary is
      absent in CI (issue #14). Today's interop tests `eprintln!("SKIPPED")` and
      return, so they pass without testing anything — the same failure shape as
      the workflow that never ran.
- [ ] **Restore the `flate2`-free deviation** or add `flate2` once `cargo fetch`
      works again, so vectors can be refreshed verbatim from upstream.

## Blocked / adjacent

`cargo fetch` currently fails workspace-wide on every branch including `main`:
a transitive `wit-bindgen-core 0.51.0` is edition 2024, which Cargo 1.70 cannot
parse. `check` / `build` / `test` / `clippy` are unaffected because the
dependency is already vendored. This is why the CCTV harness was written to use
only already-locked crates (`sha2`, `hex`) and why the two compressed vectors
were pre-decompressed instead of adding `flate2`.

## Next variant: MLKEM1024-P384

The extensibility argument that justifies keeping our own runtime. Parameters
per `hpke-pq.md` / CFRG CONCRETE-04:

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
