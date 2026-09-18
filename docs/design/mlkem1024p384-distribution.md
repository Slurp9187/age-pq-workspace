# How would anyone *get* an MLKEM1024-P384 plugin?

**Status:** open question, no decision · **Date:** 2026-09-18 · **Tracking:**
issue [#19](https://github.com/Slurp9187/age-pq-workspace/issues/19)

`docs/design/hpke-import-vs-own.md` costs the MLKEM1024-P384 variant in detail
— ~650–750 lines, ML-KEM-1024 primitives already present and libcrux-verified,
the P-384 classical half missing entirely, a new hybrid module and a
parameterised combiner label. That is the whole of what is written down, and it
is entirely about *building* it.

Nothing anywhere asks how a user would **obtain** it. For a variant whose stated
rationale is that the age plugin protocol is the only sanctioned extension
point, that is a load-bearing gap: a plugin nobody can install extends nothing.

This document records the question and the two routes. It does not decide
between them.

## Why it surfaced

A downstream consumer (encrypted-file-vault) was planning a long-horizon
preservation layer and asked which binary a future reader would need. The advice
given, and taken, was to cite upstream's `filippo.io/age/extra/age-plugin-pq`
and **not** this workspace's `age-plugin-pq`, on the grounds that a recovery
document pointing at a `publish = false` git-only binary defeats its own purpose.

That reasoning transfers to MLKEM1024-P384 with full force, and the consumer
noticed before we did. If the variant ships only here, its recovery story is
strictly worse than `mlkem768x25519`'s — which is upstream, spec'd, and needs no
plugin at all on age ≥ 1.3.0.

## Current state, verified 2026-09-18

| Fact | How checked |
|---|---|
| `.github/workflows/` contains only `ci.yml` | `ls .github/workflows/` |
| No release workflow, no binary artifacts, no `go install` / `cargo install` path | same; no other workflow exists to produce one |
| `publish = false` at `[workspace.package]`, deliberate | root `Cargo.toml`: *"Never published to crates.io, and `publish = false` makes that a hard error rather than a convention"* |
| Distribution is a git tag over the whole workspace | `docs/plans/msrv-1.85-cohort-bump.md` |

So the current answer to "can a stranger install it?" is **no**, and that is the
baseline any plan starts from.

## The framing this corrects

It is tempting — and it is what a reader would infer from the current docs — to
describe MLKEM1024-P384 as a non-standard variant that age will never carry.
That is wrong in the direction that matters.

`age-pq-hpke/docs/hpke-pq.md`, our in-tree mirror of `draft-ietf-hpke-pq`,
tabulates **three** hybrid KEMs, not one:

| | MLKEM768-X25519 | MLKEM768-P256 | MLKEM1024-P384 |
|---|---|---|---|
| Group | Curve25519 | P-256 | P-384 |
| KEM identifier | `0x647a` | `0x0050` | `0x0051` |
| Label | `"\.//^\"` | `"MLKEM768-P256"` | `"MLKEM1024-P384"` |

MLKEM1024-P384 is in the same draft, same table, as the KEM this workspace
already ships. What it lacks is an **age stanza binding**, not standardisation.

And there is precedent for that binding: `c2sp.org/age` specifies five stanza
types — `mlkem768x25519`, `X25519`, `scrypt`, `p256tag` and **`mlkem768p256tag`**
— the last being the `0x0050` sibling from this same draft. age has already
taken a NIST-curve hybrid from `draft-ietf-hpke-pq` into its spec once.

The accurate description is therefore **a standardised KEM awaiting an age
stanza binding**, not a bespoke variant. Anything written for a long-lived
audience should use the first phrasing; the second ages badly and forecloses a
route that is open.

## The two routes

**A. Solve distribution here.** A release workflow producing signed artifacts,
or a `cargo install`-able path. Note this does not fully close the gap for
recovery purposes: it would make our plugin *installable*, but it would still be
a binary from a repository the future reader has never heard of. It helps
operators; it helps a stranger less.

Also note `publish = false` is deliberate and load-bearing (it makes accidental
publication a hard error, not a convention). Route A means revisiting that
decision, not working around it.

**B. Pursue the upstream binding.** Get `mlkem1024p384` into `c2sp.org/age` and
implemented upstream — in age core, or in `extra/age-plugin-pq` alongside
`mlkem768x25519`. Strictly better for the recovery story, because it moves the
whole path off this workspace. Costs and likelihood are unknown and not
researched; the precedent above says only that it is not precluded.

These are not exclusive, and B does not require A to have happened first.

## What this changes today

Nothing in the code. `mlkem768x25519` is unaffected — a future variant arrives
as a **new stanza tag**, so files written today are untouched by any of this.

The one thing to carry forward: **decide the distribution route before, not
after, writing the plugin.** Route B in particular is cheaper to pursue with a
reference implementation in hand than to retrofit as an afterthought, and the
answer determines whether the variant is worth building for anyone outside this
workspace at all.

## Related

- [`hpke-import-vs-own.md`](hpke-import-vs-own.md) — the build-side cost and why
  we keep our own runtime.
- [`rage-pq-adoption.md`](rage-pq-adoption.md) — why the plugin protocol is the
  extension point (Q2).
- The age plugin protocol is spec'd at [c2sp.org/age-plugin](https://c2sp.org/age-plugin):
  `recipient-v1` / `identity-v1` state machines, normative `PATH` discovery,
  `postquantum` labels. It carries no explicit stable/draft status and has a
  `TODO: Errors` section, so "v1, stable in practice across multiple independent
  implementations, spec incomplete in its error handling" is the supportable
  description — not "frozen".
