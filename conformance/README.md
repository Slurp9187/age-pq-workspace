# `conformance`

In-process differential tests against **rage**, linked as a library.

**This is not a member of the workspace.** `cargo test --workspace` from the
repository root does not reach it, on purpose. Run it here:

```sh
cd conformance
cargo test -- --nocapture
```

Roughly 80 s — 512 ML-KEM keypairs plus 128 wrap/unwrap round trips on both
sides. Nothing is `#[ignore]`d and nothing needs a binary on `PATH`: rage is a
library dependency, so the tests either compile against it or the build fails.

## What it tests

| | |
|---|---|
| **P1** | rage and `age-pq-keys` derive the same recipient from the same seed — 512 cases |
| **P2** | each side unwraps the other's stanza to the same **`FileKey`** — 128 cases, both directions |
| **P3** | recipient strings round-trip through each implementation's parser — 512 cases |

Cases are derived with the same domain bytes as the two shell-out oracles
(`age-pq-keys/tests/differential_age_go.rs`, `differential_rage.rs`), so **case
41 is the same key in all three** and a disagreement found here is reproducible
there by index.

## Read this before trusting a green run

> `age-pq-keys` is compiled here against **rage's** `age` crate, not the
> crates.io `age 0.12` it ships against.

That is forced, not chosen: rage's `age` and crates.io `age 0.12` cannot resolve
in one dependency graph, because their `ml-kem` generations require incompatible
exact versions of the pre-release `kem` crate. This workspace patches `age` to
rage so exactly one exists.

So these tests are evidence that the two implementations **agree given a common
`age` core**. They are *not* evidence about the shipped build. That is what the
shell-out oracle (real binaries, crates.io build) and the C2SP CCTV vectors
cover. Neither oracle subsumes the other, which is why both exist.

Full measurements — including why rage's `hpke` fork is load-bearing rather than
a development pin — are in
[`docs/design/conformance-workspace-isolation.md`](../docs/design/conformance-workspace-isolation.md).

## What does **not** belong here

This directory is not "where conformance tests live". It is a quarantine for
tests that need a dependency graph the shipped crates cannot have. The name
invites the opposite reading, so the rule is written down:

| Does the test… | Then |
|---|---|
| spawn a binary (`age`, `rage`) | **stays** in `age-pq-keys/tests/` — a subprocess shares no dependency graph, so there is nothing to isolate |
| read vectors from disk (CCTV, KATs) | **stays** — nothing to isolate |
| **link** rage as a library | belongs here, and pays for it by not testing the shipped build |

Only the third row qualifies. Today that is exactly one file.

**Moving a shell-out test here would silently weaken it**, which is worth
spelling out because it would still pass. `differential_age_go.rs` builds
ciphertext with `age::Encryptor` and reads it back with `age::Decryptor`. Under
this workspace those resolve to **rage's** implementations, so the test would
stop proving *"our stanza, inside the STREAM implementation we ship, is readable
by Go age"* and start proving *"…inside rage's STREAM implementation…"* — while
keeping its name, its case count, and its green tick. That is precisely the
shape of defect this repository keeps having to dig out.

The same applies to `differential_rage.rs` (the shell-out one),
`age-pq-keys/tests/testkit.rs`, and both KAT targets in `age-pq-hpke`. They test
the shipped build with the shipped lockfile, and that is the entire source of
their value.

## Maintenance notes

- **`Cargo.lock` is committed and is the pin on rage.** CI runs with `--locked`
  so resolution drift fails the job instead of silently testing a different
  rage. Bumping rage means bumping the `rev` in three places in `Cargo.toml`
  (the dependency and both `[patch]` entries) and re-locking.
- **The `[lints.rust]` table here is a hand-maintained copy** of the root
  `[workspace.lints.rust]`. An excluded package cannot inherit workspace lints,
  and `[lints] workspace = true` would fail to resolve. Nothing will tell you if
  the two drift — keep them in step by hand.
