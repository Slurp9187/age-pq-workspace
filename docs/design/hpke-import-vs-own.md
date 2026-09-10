# Decision: keep our own HPKE, for verified ML-KEM — not for extensibility

**Status:** decided · **Date:** 2026-09-09 · **Tracking:** issue #12, issue #19

## The question

Now that `rust-hpke` (str4d's fork, the one rage uses) implements the same
MLKEM768-X25519 construction we do, should we import it instead of maintaining
`age-pq-hpke`?

**Decision: keep ours.** But the *reason* has changed, and the old reason should
stop being cited.

## ~~On the 1.70 line there is no decision~~ — superseded, the question is live

~~`rust-hpke` is `edition = 2024`, `rust-version = "1.85"`. It cannot compile
against this workspace's MSRV at all. The question only becomes live after the
cohort bump (issue #2).~~

**Updated 2026-09-10.** The cohort bump landed in `0.2.0-rc.1`: this workspace
is on MSRV 1.85 and edition 2024, so the MSRV objection is gone and `rust-hpke`
would compile here. The decision is unchanged, but it now rests entirely on the
two properties in the table below — formally verified ML-KEM, and
`#![forbid(unsafe_code)]`. The second of those got *stronger* in the same bump:
the workspace lint table plus the missing crate-root attributes made the
unsafe-forbid rule true for all three crates rather than only `age-pq-hpke`.
See [`rage-pq-adoption.md`](rage-pq-adoption.md) Q4/Q5 for the same MSRV fact
from the adjacent question's side.

## What the trade actually is, after 1.85

| | `age-pq-hpke` (ours) | `rust-hpke` (str4d fork `1268205e`) |
|---|---|---|
| ML-KEM backend | `libcrux-ml-kem 0.0.10` — **formally verified** (hax/F*) | RustCrypto `ml-kem 0.3` — **not verified** [^mlkem] |
| `#![forbid(unsafe_code)]` | every crate root, non-negotiable [^unsafe] | not declared (`src/lib.rs` sets only `no_std`) |
| MLKEM768-X25519 | implemented, KAT + 19 CCTV vectors | implemented |
| MLKEM1024-P384 | not implemented | **already implemented, with KATs** |
| x25519-dalek | 2.0 | 3.0 |

[^mlkem]: Since the `age` 0.12 migration this is no longer a statement about
    which crates are *compiled*. RustCrypto `ml-kem 0.2.3` is in this
    workspace's graph either way — `age` 0.12 depends on it non-optionally for
    its own `mlkem768p256tag` recipient. It reaches `age-pq-keys` only;
    `age-pq-hpke` and `age-plugin-pq` never link it. Measured with
    `cargo tree -i ml-kem --workspace -e normal`.

[^unsafe]: The guarantee is "no `unsafe` in code we wrote", enforced by
    `[workspace.lints.rust] unsafe_code = "forbid"` plus `[lints] workspace =
    true` in each member. It has never been a property of the whole graph —
    `curve25519-dalek`, `cpufeatures` and `aes` have always carried `unsafe` —
    and `ml-kem 0.2.3` now adds its own (`src/util.rs`, 7 occurrences including
    an `unwrap_unchecked` and two `ptr::read`s).

**Updated 2026-09-10, after the `age` 0.12 migration.** The trade is no longer
"verified ML-KEM in the graph versus unverified in the graph". Importing
`rust-hpke` would move **our** ML-KEM-768 path from formally-verified libcrux to
unverified RustCrypto. It would not change which crates are compiled: `hpke`
0.12 and `ml-kem` 0.2.3 are already linked into `age-pq-keys` by `age` itself.
The property being defended is *which code our `mlkem768x25519` stanza runs*,
not the contents of the dependency graph. Note also that the `hpke` crate in the
table's right-hand column is the same crate as the `hpke 0.12.0` now compiled
into both `age-pq-keys` and `age-plugin-pq` via `age-core` 0.12 — unforked, and
carrying zero `unsafe` in its `src/`.

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

Keep ours so that the **`mlkem768x25519` path is verified end to end**. That is
the whole of it. (Before the `age` 0.12 migration this line read "keep ours for
verified ML-KEM", which was a graph-level claim; it is now a claim about our own
code path, which is the thing that was ever actually true.)

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
