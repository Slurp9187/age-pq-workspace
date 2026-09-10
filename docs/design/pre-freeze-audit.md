# Pre-freeze audit — findings, decisions, and dead ends

**Date:** 2026-09-09 · **Tracking:** #11, #15, #2

Before the MSRV-1.70 line is frozen and tagged `v0.1.0` (DECIDE-13 in
[`../plans/msrv-1.85-cohort-bump.md`](../plans/msrv-1.85-cohort-bump.md)), an
8-agent workflow scoped the remaining work and then tried to refute its own
plans. Every plan came back `SOUND_WITH_CORRECTIONS`; the corrections were the
valuable part.

This document exists so the conclusions — and especially the **dead ends** —
are not re-derived. Several plausible-sounding claims below were checked and
found false; re-deriving them costs a round of analysis each.

---

## DECIDE-14 — `HybridRecipient::pub_key` becomes private and validated

**Found independently by two agents.** `HybridRecipient::to_string()` calls
`.expect("encoding with valid data never fails")` while `pub_key` is a
`pub Vec<u8>` field with **no length validation anywhere** — `parse()` does
`let pub_key = checked.byte_iter().collect();` and stores whatever length it
got.

So the `expect` is reachable today: a caller who sets `pub_key` to something
long enough panics. At the current `CODE_LENGTH = 8192` that needs roughly
5100 bytes; **after #11 drops the code length to 1959 it needs only 1216**.

The invariant was never real — it was resting on nobody exercising a `pub`
field. Preserving the old code length would only hide that. Instead:

- `pub_key` becomes private, with a validating constructor and an accessor.
- Length is checked once, at construction, against
  `MLKEM768X25519_ENCAPSULATION_KEY_SIZE`.
- `to_string()` then genuinely cannot fail.

This is a **breaking API change**, deliberately taken before the freeze. It is
free now and expensive after `v0.1.0` — which is the argument for doing it in
this window rather than deferring it.

---

## Verified findings acted on

| Finding | Disposition |
|---|---|
| `age-plugin-pq/tests/data/` held four files referenced by nothing, two of them **private keys in files named `.recipient`** (`pq-native.recipient` → `AGE-SECRET-KEY-PQ-1…`, `pq-plugin.recipient` → `AGE-PLUGIN-PQ-1…`) | Deleted. Throwaway test keys, so not an exposure — but that naming is how a real key eventually gets published by someone trusting the extension. |
| The `Checksum` doc comment in `age-pq-keys` is wrong three ways: claims a 4096 maximum while setting 8192, claims error detection that does not hold past 1023 characters, and its byte estimate is off by ~2× | Replaced in #11 by a derived constant with an accurate note. |
| `CODE_LENGTH` is a **length gate, not a strength parameter** — it never enters the checksum computation, so output is byte-identical at any sufficient value | Recorded; settles the sizing question. Reducing 8192 → 1959 changes no bytes. |

---

## Dead ends — checked, false, do not re-derive

**"Reducing the code length weakens the checksum."** No. `N` never enters the
checksum computation. Separately, the BCH error-detection bound is 1023
characters and an `age1pq` recipient is 1959, so the guarantee is already gone
at *any* code length — that is inherent to bech32-encoding a 1216-byte key, not
a decision made here. secure-gate's own docs say it "degrades to an integrity
check with no proven detection bound".

**"`Cargo.lock` will not change when the encoding feature is enabled."** False,
and it matters: `bech32 0.11.1` joins the `dependencies` arrays of the
`age-pq-keys` and `age-plugin-pq` package entries. `cargo fetch --locked` fails
between the manifest edit and a lock refresh. Order: edit manifest → `cargo
check` to refresh the lock → inspect the diff.

**"Only the Go-CLI fixture would catch a `Case` slip; our own round-trip tests
would not."** False. A skeptic sabotaged each `Case` argument in a migrated tree
and re-ran the suite — our own tests caught it. Do not justify the fixture tests
on this basis; they earn their place as cross-implementation evidence instead.

**"`git grep HybridRecipientBech32` must return zero hits after #11."**
Unsatisfiable as a gate: two CHANGELOG entries mention the type permanently, and
the change itself adds more. A gate that can never pass gets waved through.

**"`cargo tree -p age-pq-keys -e normal -i bech32`" as a verification step.**
Never runs — two `bech32` versions are in the graph (0.9.1 via `age`, 0.11.1 via
secure-gate) and the spec is ambiguous. Needs `-i bech32@0.11.1`.

**"Go echoes the whole secret key on stderr when it fails to parse an
identity."** ~~Not reproduced.~~ **Reproduced, and this entry was wrong — the
answer depends on which binary you ask.** Measured on age v1.3.1 while
implementing #15, by feeding a lowercased throwaway identity to each path and
`grep -F`-ing the whole key against the captured stderr:

| Path | rc | Echoes the identity? |
|---|---|---|
| `age-keygen -y` (identity on stdin) | 1 | **Yes** — `unknown identity type: "age-secret-key-pq-<the entire 77-char key>"`, 245 bytes of stderr, full-key substring match confirmed |
| `age -d -i <file>` | 1 | No — the error names the *file* (`reading "lower.id": … unknown identity type`), 174 bytes, no substring match |

So the original entry measured only the second row and generalised from it. The
asymmetry is not a subtlety to reason about per call site: it is why
`age-pq-keys/tests/common.rs::safe_stderr` filters at the single place that
turns child stderr into a message, and why `age-keygen` stderr in the
differential oracle is `Stdio::null()` rather than captured at all.

The same habit is general, not PQ-specific: age echoes the offending token in
`unknown recipient type: "AGE1PQ1…"` too. That one is harmless because
recipients are public — but "age quotes what you fed it" is the rule, and
whether that is safe depends entirely on what you fed it.

**"The plugin's `full_encrypt_decrypt_cycle_through_the_age_cli` is
plugin↔plugin evidence, not cross-implementation evidence."** False. age
encrypts to an `age1pq1…` recipient **natively**, with no plugin on `PATH` — the
plugin is only spawned for the identity half. It is genuine cross-implementation
evidence in one direction.

---

## Corrections carried into #15's design

The age-go differential-oracle plan needs these before it is implemented:

- **Identities must be uppercased.** `bech32::encode::<Bech32>` emits lowercase,
  and Go refuses to parse a lowercase `age-secret-key-pq-…`. A generator that
  skips the uppercase step produces identities the oracle cannot even load.
- **`age-keygen -y` appends `\n`.** A literal byte-for-byte comparison against
  `to_public().to_string()` fails on every case; trim first.
- **`age-keygen -o` uses `O_EXCL`** and fails on a second run against the same
  path — one-shot commands in docs will not reproduce.
- **The local `age` is v1.3.1 while CI installs v1.3.2.** Measurements taken
  locally are against a binary CI will not use.
- **A test target containing zero tests exits 0.** `running 0 tests … ok`. So a
  dedicated CI job catches file *deletion* but not file *gutting*, and any
  in-test `assert!(cases >= MIN)` cannot fire when nothing runs. Same
  green-without-running shape as the rest of this repo's history.
