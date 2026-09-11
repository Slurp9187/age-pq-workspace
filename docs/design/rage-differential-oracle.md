# The rage differential oracle

**Status:** landed · **Date:** 2026-09-11 · **Tracking:** issue #15

`age-pq-keys/tests/differential_rage.rs` checks this workspace against **rage**,
the Rust implementation of age, across the same case matrix the Go `age` CLI
oracle uses. This records what it proves, what it measured, and the two
decisions a future reader is most likely to want to re-litigate.

## Why a second oracle

Before it, every cross-implementation claim here rested on one implementation.
age-go is a strong oracle and that is still not enough on its own: a
specification ambiguity that age-go and this crate happened to resolve the same
way is invisible to a differential between them, and both stay green forever.

rage is a genuinely separate codebase — different language from age-go,
different bech32 and bignum stacks, and **RustCrypto `ml-kem`** where we use the
formally verified libcrux. A key-dependent bug has to survive all three to hide.

It is not, on its own, evidence that we are *right*. Where all three agree and
the draft disagrees, the draft wins; that direction is
`age-pq-hpke/tests/hpke_pq_draft_vectors.rs`, which checks published vectors
rather than another implementation's opinion.

## What runs

| # | Direction | Cases |
|---|---|---|
| R1 | our identity → `rage-keygen -y` | 64 |
| R2 | fresh `rage-keygen` → our parser | 8 |
| R3 | we encrypt → `rage -d` | 22 |
| R4 | `rage -e` → we decrypt | 22 |
| R5 | `rage -a -e` → we decrypt (armored) | 11 |

127 cases, both directions, all passing against rage `5d33e3e` (`pq` branch,
"Default to `pq` identities", 2026-08-20).

**R5 closes a loop the testkit left open.** `tests/data/testkit/armor_hybrid`
reached this repository *via* rage (C2SP/CCTV `e9274a7b` → rage `26fe921` → here
`85fe5c0`) and was **decompressed** in transit, 1951 → 2554 bytes, to avoid a
`flate2` dependency. The in-tree armored vector is therefore a modified copy of
rage's, and nothing checked our armored path against rage's live output. R5
does, at every plaintext length including the two on age's 64 KiB STREAM chunk
boundary.

## The one behavioural difference found, and why it is not a format bug

`rage -d -o OUT` **does not create `OUT`** when the decrypted plaintext is zero
bytes. Measured against the same ciphertext, three ways:

```
rage -d -i F -o OUT ct     exit 0, OUT not created
rage -d -i F    ct         exit 0, 0 bytes on stdout
age  -d -i F -o OUT ct     exit 0, OUT created, 0 bytes
```

rage creates the output file lazily on first write, so a payload with no bytes
never triggers creation. `rage -e -o` is unaffected — a ciphertext always has
header bytes.

**Nothing about the stanza or the payload framing differs.** R3 checks
`status.success()` before reading the file, and a zero exit already proves rage
unwrapped our stanza and ran the STREAM reader to completion — which, for an
empty payload, is the entire claim. So R3 treats a missing output file as an
empty one **only when the expected plaintext is empty**; a non-empty plaintext
with no output file stays a failure. The exception is written at the call site
with the measurements above beside it.

This is a CLI ergonomics difference, not an interoperability one. It is not
reported upstream as a bug here because nothing in this workspace depends on it,
and `-o` with an empty payload is a corner a user is unlikely to hit; recorded
so the next person meets a measurement instead of a mystery.

## Two decisions worth not re-litigating

### The matrix is shared, not duplicated

`seed_for_case`, `identity_for_case`, `plaintext_for_case` and the reporting
helpers moved out of `differential_age_go.rs` into `tests/common.rs`, and both
oracles now draw from them. Two copies would be two places for the matrices to
drift, at which point "rage agrees with us" and "age-go agrees with us" stop
being comparable statements — which is most of the value of having two.

The domain-separator **byte strings still read `differential-age-go`** and must
not be renamed. They are inputs to every derived seed and plaintext, so changing
them moves every case and invalidates `GENERATOR_DIGEST` — a digest pinned from
a run in which all 64 derivation cases passed against a real age-go binary. The
name is historical; the matrix is shared. Renaming the Rust constants is free,
renaming the bytes is not.

That the extraction changed no derived value is not an assurance, it is a
checked fact: `oracle_case_generation_is_pinned` passes unchanged across it.
That test exists for exactly this.

### A version check cannot gate this oracle

Released rage 0.12.1 and the `pq` branch answer `--version` identically, and
**only the branch implements `mlkem768x25519`** — the release carries
`mlkem768p256tag`, a different format with a different HRP. A version-only gate
would let a released rage turn all five differentials into no-ops that still
report `ok`: the same shape as every other defect this repository has had to dig
out.

So `common::require_rage_pq_support` makes the binary *produce* a keypair and
asserts the recipient starts with `age1pq`. Verified by pointing the harness at
`rage-keygen --pq=false`:

```
rage-keygen produced a `age1xukn` recipient, not `age1pq…`. This is the released
rage, which has no mlkem768x25519 — build the `pq` branch and point RAGE_BIN at it.
```

## Falsifiability

Not asserted — measured, by breaking things on purpose:

| Mutation | Result |
|---|---|
| rage without `mlkem768x25519` (`--pq=false` wrapper) | caught by `require_rage_pq_support`, message above |
| `rage-keygen -y` returns a short list (3 of 64) | `rage-keygen -y returned 3 recipient(s) for 64 identities` |
| `RAGE_BIN` / `RAGE_KEYGEN_BIN` pointing nowhere | caught, with the build-the-pq-branch instruction |
| matrix counts shrunk | `rage_oracle_matrix_floors_hold`, which is **not** `#[ignore]`d |

## CI

The `pq` branch has no tagged release, so CI builds rage from source, **pinned
to a commit rather than the branch**. `pq` is in flight; tracking the tip would
mean a green run today and a red one tomorrow for reasons outside this
repository, and "our oracle moved" is indistinguishable from "we regressed" in
that log. The build is cached on the pin, so only the first run after a
deliberate bump pays for it.

The binaries are **not** optional there. The suite step runs with
`--include-ignored` and the differentials fail loudly if rage is absent — the
same contract age has. A second oracle that silently stops running is worth less
than no second oracle, because it still reads as coverage. A separate guard step
requires the `R1:`…`R5:` banners in the output, each printed only after the
binary was spawned and proven pq-capable.

Locally, point `RAGE_BIN` and `RAGE_KEYGEN_BIN` at a `pq`-branch build:

```sh
RAGE_BIN=/path/rage RAGE_KEYGEN_BIN=/path/rage-keygen \
  cargo test -p age-pq-keys --all-features --test differential_rage -- --include-ignored --nocapture
```
