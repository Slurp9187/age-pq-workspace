# Why `conformance/` is a separate workspace

**Status:** landed · **Date:** 2026-09-11 · **Tracking:** issue #15

`conformance/` holds in-process differential tests against **rage**, linked as a
library. It is excluded from the root workspace and carries its own
`Cargo.lock`. This records *why* — because the reason in issue #15 was true but
was the milder of two problems, and the real one is worth not rediscovering.

## The stated reason, which is real

`[patch.crates-io]` is workspace-global. rage requires two patched forks:

```toml
hpke   = { git = "https://github.com/str4d/rust-hpke.git",        rev = "1268205e…" }
x-wing = { git = "https://github.com/str4d/RustCrypto-KEMs.git",  rev = "f5dd74e2…" }
```

Those are **load-bearing, not development pins** — measured, not assumed. rage
declares `hpke = "0.14"`, and crates.io *has* `hpke 0.14.1`, so the patch looks
skippable. It is not. Compiling a probe crate against crates.io `hpke 0.14.1`
with rage's exact feature set (`mlkem`, `nistp`, `x25519`, plus an AEAD):

```
error[E0425]: cannot find type `XWingRejectNonContrib` in module `hpke::kem`
```

That type is what rage's entire pq module is built on
(`type Kem = hpke::kem::XWingRejectNonContrib;`). Without the fork, rage does
not compile.

Note also that **Cargo ignores `[patch]` in dependencies** — it is honoured only
in the top-level manifest — so pulling rage in does not inherit its patches;
they have to be restated by whoever links it.

## The harder reason, which #15 did not know

**rage's `age` crate and crates.io `age 0.12` cannot coexist in one dependency
graph at all.** Not "they perturb the lockfile" — resolution *fails*. Measured
by adding rage as a dev-dependency of `age-pq-keys` in the main workspace:

```
error: failed to select a version for `kem`.
    ... required by package `ml-kem v0.3.0`
    ... which satisfies dependency `ml-kem = "^0.3"` of package `age v0.12.1 (git+…rage)`
versions that meet the requirements `^0.3` are: 0.3.0

all possible versions conflict with previously selected packages.

  previously selected package `kem v0.3.0-pre.0`
    ... which satisfies dependency `kem = "=0.3.0-pre.0"` of package `ml-kem v0.2.3`
    ... which satisfies dependency `ml-kem = "^0.2"` of package `age v0.12.1`
```

The chain:

| | `ml-kem` | `kem` |
|---|---|---|
| crates.io `age 0.12.1` | `^0.2` → 0.2.3 | **`=0.3.0-pre.0`** (exact) |
| rage's `age 0.12.1` | `^0.3` → 0.3.0 | `^0.3.0` |

`ml-kem 0.2.3` pins `kem` **exactly** at a pre-release — a fact CLAUDE.md
already records for a different reason — and a pre-release shares its version
slot with the release, so `kem 0.3.0` and `kem 0.3.0-pre.0` are mutually
exclusive. No feature flag, dev-dependency placement or `[patch]` arrangement
avoids it.

**So isolation is mandatory, not preferential.** The main workspace's
`Cargo.lock` is provably untouched by this directory: `exclude = ["conformance"]`
in the root manifest keeps `cargo test --workspace` out, and the lockfile is
byte-identical to `HEAD` after a full resolve here.

## How the scaffold resolves it

`conformance/Cargo.toml` patches `age` **itself** to rage:

```toml
[patch.crates-io]
age      = { git = "https://github.com/str4d/rage", rev = "5d33e3e…" }
age-core = { git = "https://github.com/str4d/rage", rev = "5d33e3e…" }
```

Inside this workspace there is then exactly **one** `age` crate, so
`age-pq-keys`'s `age ^0.12` requirement and rage's own are satisfied by the same
package and only one `ml-kem` is pulled. 229 packages, resolves clean.

That is also precisely the shape an in-process differential wants: our recipient
and rage's, driven through the same `age` trait objects in one process.

### The consequence that bounds what this proves

> `age-pq-keys` is compiled here against **rage's** `age`, not the crates.io
> `age 0.12` it ships against.

So these tests are evidence that the two stanza implementations agree *given a
common `age` core*. They are **not** evidence about the shipped build. That is
what `age-pq-keys/tests/differential_rage.rs` (shell-out, real binaries, crates.io
build) and the CCTV vectors cover. The two oracles are complements, and neither
subsumes the other — which is the honest reason to keep both rather than a
tidiness argument.

## What the in-process tests add

| | Shell-out (`differential_rage.rs`) | In-process (here) |
|---|---|---|
| Derivation cases | 64 | **512** |
| Sees the `FileKey` | no | **yes** |
| Tests the shipped build | **yes** | no |
| Needs a rage binary | yes | no |
| Runs in the main CI job | yes | separate job |

**P2 is the one a subprocess cannot make.** `rage -d` tells you the plaintext
survived; it cannot tell you the stanza carried the file key you put in, because
the file key never leaves either process. P2 unwraps each side's stanza with the
other's identity and compares the recovered 16 bytes directly, pinning the
stanza's meaning rather than its downstream effect.

## Falsifiability

Measured by breaking each one on purpose:

| Mutation | Result |
|---|---|
| P1: rage derives from case + 1 | killed |
| P2: file key corrupted before wrap | killed — `rage unwrapped OUR stanza to a different file key` |
| P3: recipient truncated before rage parses it | killed |
| counts shrunk below the floors | `in_process_matrix_floors_hold` |

The floor test also asserts `DERIVATION_CASES > 64` — if this file ever stops
exceeding the shell-out oracle, it is no longer earning the workspace it needs,
and the right move is to delete it rather than keep a second copy of the same
64 cases.

## Running it

```sh
cd conformance && cargo test -- --nocapture
```

Roughly 80 s; it is 512 ML-KEM keypairs plus 128 wrap/unwrap round trips on both
sides. CI runs it as its own job, cached on `conformance/Cargo.lock` and invoked
with `--locked` — that lockfile *is* the pin on rage, and a drift should fail the
job rather than silently test a different rage.
