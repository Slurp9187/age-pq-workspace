# Decision: keep our own HPKE, for verified ML-KEM — not for extensibility

**Status:** decided · **Date:** 2026-09-09 · **Tracking:** issue #12, issue #19

## The question

Now that `rust-hpke` (str4d's fork, the one rage uses) implements the same
MLKEM768-X25519 construction we do, should we import it instead of maintaining
`age-pq-hpke`?

**Decision: keep ours.** But the *reason* has changed, and the old reason should
stop being cited.

## On the 1.70 line there is no decision

`rust-hpke` is `edition = 2024`, `rust-version = "1.85"`. It cannot compile
against this workspace's MSRV at all. The question only becomes live after the
cohort bump (issue #2).

## What the trade actually is, after 1.85

| | `age-pq-hpke` (ours) | `rust-hpke` (str4d fork `1268205e`) |
|---|---|---|
| ML-KEM backend | `libcrux-ml-kem 0.0.8` — **formally verified** (hax/F*) | RustCrypto `ml-kem 0.3` — **not verified** |
| `#![forbid(unsafe_code)]` | every crate root, non-negotiable | not declared (`src/lib.rs` sets only `no_std`) |
| MLKEM768-X25519 | implemented, KAT + 19 CCTV vectors | implemented |
| MLKEM1024-P384 | not implemented | **already implemented, with KATs** |
| x25519-dalek | 2.0 | 3.0 |

Importing would trade formally-verified ML-KEM for unverified, and give up the
unsafe-forbid guarantee. Those two properties are what distinguish this
workspace: a PQ library whose post-quantum half is machine-checked is a
substantive claim, where "another HPKE wrapper" is not.

## The argument being retired

We previously justified keeping our own runtime on **extensibility** — that the
plugin protocol lets us ship non-standard variants that rage cannot. See
[`rage-pq-adoption.md`](rage-pq-adoption.md) Q2.

**That argument is now weak and should not be cited.** `MlKem1024P384` already
exists upstream, fully instantiated:

```rust
impl_mlkem_nistp!(
    mlkem1024p384, MlKem1024P384, MlKem1024, p384,
    b"MLKEM1024-P384", 0x0051, U1665, U1665, 48, 48
);
```

One macro invocation, with KAT coverage, in `rust-hpke/src/kem/mlkem_nistp.rs`.
Adopting rage would make the variant work "wire an age stanza type around an
existing KEM", not "implement a KEM".

Keep ours for **verified ML-KEM**. That is the whole of it.

## Cost of the variant if we keep ours

| Piece | Status | Approx. size |
|---|---|---|
| ML-KEM-1024 primitives | **already exist**, libcrux-verified; feature declared but not default | `ml_kem/mlkem1024.rs`, 58 lines |
| P-384 classical half | **missing entirely** — new module | ~100 lines, mirroring `x25519.rs` (101) / `x448.rs` (80) |
| Hybrid KEM module | new `mlkem1024p384.rs` | ~560 lines, mirroring `mlkem768x25519.rs` (564) |
| Combiner | label must be parameterised (`MLKEM1024-P384`, not the X-Wing squiggle) | 54 lines today |

**~650–750 lines**, nearly all structural mirroring of modules that already pass
vectors. `x448.rs` is already a wired-but-unused classical half, so the shape is
established.

## The asymmetry that settles it

**libcrux has no verified P-384.** The classical half of MLKEM1024-P384 must be
RustCrypto `p384` whichever path we take. So the verified-backend advantage
survives only on the post-quantum half — which is exactly the half that matters,
and exactly the half importing `rust-hpke` would make unverified.

## Consequence

- Keep `age-pq-hpke`; port MLKEM1024-P384 ourselves (issue #19).
- Add `rust-hpke` as a **second differential oracle** in the isolated conformance
  workspace, alongside rage and age-go — its `MlKem1024P384` KATs become our
  acceptance criterion for the port. See
  [`../plans/conformance-workspace.md`](../plans/conformance-workspace.md).
- This is the same shape as the rage decision (own the runtime, borrow the
  oracle), which is a consistency check rather than a coincidence.

## Provenance

All facts in the comparison table were read directly from the local cargo git
checkout of `str4d/rust-hpke` at rev `1268205e` and from this workspace's own
manifests on 2026-09-09.

The `MlKem1024P384` finding — the one that retires the extensibility argument —
was **independently confirmed** by a parallel session at
`src/kem/mlkem_nistp.rs:555-562` of the same rev, reached by its own grep rather
than from this document. Two readings of the same source is weaker evidence than
two independent implementations, but it does rule out a misread, which is the
failure mode that matters here: the whole reframing turns on that macro
invocation existing.
