# C2SP CCTV conformance: the seven defects, and why they survived

**Status:** fixed · **Date:** 2026-09-08 · **Tracking:** issue #13

## Why this document exists

Before 2026-09-08 this workspace had **never run a hostile-input test**. The
first run of the C2SP CCTV hybrid vectors found seven failures, one of which was
a wrong-accept. That ratio is the argument for the whole conformance strategy in
[`rage-pq-adoption.md`](rage-pq-adoption.md).

## How it survived: the workflow never ran

The only CI workflow was tracked at `age-pq-hpke/.github/workflows/ci.yml`.
**GitHub Actions only reads `.github/workflows/` at the repository root.** There
was no root `.github/`, no submodules, and no nested `.git`. `gh run list`
returned zero runs — the file had never executed once.

Fixed by moving it to [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)
and widening it to `--workspace`, with the CCTV vectors as their own job.

**Generalisable lesson:** a test suite that is green because it never ran is
indistinguishable, in every dashboard, from one that is green because it passed.
The same failure shape appears again in the interop tests (issue #14), which
`eprintln!("SKIPPED")` and return when the `age` binary is absent — so they pass
without testing anything.

## The vectors

19 files, vendored from rage's tree at `5d33e3e` (upstream: C2SP/CCTV age
testkit), living in
[`age-pq-keys/tests/data/testkit/`](../../age-pq-keys/tests/data/testkit/)
and driven by [`tests/testkit.rs`](../../age-pq-keys/tests/testkit.rs).

The harness runs each vector through `age::Decryptor` with our `HybridIdentity`
— the same path official age and rage exercise — and compares the outcome
against the vector's `expect` field (`success` / `no match` / `header failure`).

**Local deviation:** upstream stores `armor_hybrid` and
`hybrid_multiple_recipients` with their age file bytes zlib-compressed
(`compressed: zlib`). Both are stored decompressed here, with that header line
dropped, so the harness needs no `flate2` dependency (`cargo fetch` is currently
broken workspace-wide — see issue #14 notes). The age file bytes under test are
unchanged. **Re-apply this when refreshing vectors from upstream.**

## Baseline: 12 passed, 7 failed

### The severe one — a wrong-accept

`hybrid_low_order` **decrypted successfully** when it must be rejected.

An attacker-supplied low-order X25519 point drives the Diffie-Hellman output to
the all-zero non-contributory value, pinning the classical half of the hybrid to
a known constant. We accepted the file; age and rage reject it.

The asymmetry that made this easy to miss: **`x448.rs` already performed this
check** (`Error::X448DiffieHellmanFailed`, via `as_diffie_hellman` returning
`Option`), while `x25519.rs` — the path actually used — did not, because
`x25519_dalek`'s `diffie_hellman` returns the shared secret unconditionally and
surfaces the check separately as `SharedSecret::was_contributory()`.

`parse_public_key` was not sufficient: it rejected only the all-zero *encoded*
point, so order-8 points passed through.

### The other six — rejected, but misclassified

All six returned `None` ("not addressed to this identity, try the next") where
the spec requires a fatal header failure. The practical consequence is that a
tampered or malformed header is silently skipped instead of rejected.

| Vector | Defect |
|---|---|
| `hybrid_identity` | X25519 part of `enc` is the identity point |
| `hybrid_extra_argument` | stanza carried an unexpected extra argument |
| `hybrid_long_file_key` | body not length-checked to 32 before decrypting |
| `hybrid_long_share` | extra leading zero byte on the X25519 part of `enc` |
| `hybrid_short_share` | trailing zero missing from the X25519 part of `enc` |
| `hybrid_not_canonical_enc` | non-canonical base64 in `enc` |

`hybrid_long_file_key` is the partitioning-oracle mitigation: the body length
must be checked *before* any decryption is attempted.

## The fixes

Seven vectors, two code sites — they clustered, which is why keeping our own
implementation stayed affordable.

**1. `age-pq-hpke/src/kem/x25519.rs`** — added `Error::X25519DiffieHellmanFailed`
and a `was_contributory()` check to both `decapsulate_from_private_seed` and
`encapsulate_to_public_key` (the latter for symmetry with x448; the
attacker-controlled path is decapsulation). Both now return `CrateResult`.

**2. `age-pq-keys/src/lib.rs::unwrap_stanza`** — rewritten to match age-go's
`pq.go` semantics exactly:

| Condition | Result |
|---|---|
| tag is not `mlkem768x25519` | `None` — genuinely not ours |
| `args.len() != 1` | header failure |
| `enc` is not canonical base64 | header failure |
| `enc.len() != 1120` | header failure |
| `body.len() != 32` | header failure — **checked before decrypting** |
| decapsulation / setup fails | header failure |
| AEAD open fails | `None` — implicit rejection, not for this identity |

The last two rows are why `new_recipient` and `Recipient::open` are now called
as separate steps rather than via the combined `hpke::open` helper: collapsing
both failure modes into one error is what let `hybrid_low_order` through.

The **legacy two-argument stanza form was removed**. No age implementation emits
it. The crate docs previously advertised it as "Legacy Support"; that claim is
gone.

One existing test, `pq_stanza_unwrap_malformed_ciphertext`, asserted
`result.is_none()` — it had encoded the defect as expected behaviour. It now
asserts `InvalidHeader`, with companion tests for the foreign-tag skip and the
extra-argument rejection.

## Result

19/19 CCTV vectors pass; full workspace suite green.

## Re-running and refreshing

```sh
cargo test -p age-pq-keys --test testkit
```

To refresh vectors from upstream, re-copy the `hybrid_*` and `armor_hybrid`
files and re-apply the decompression deviation described above.
