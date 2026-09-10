# Design: the age-go differential oracle

**Status:** landed · **Date:** 2026-09-09 · **Tracking:** issue #15

Implements the 1.70-doable half of [`../plans/conformance-workspace.md`](../plans/conformance-workspace.md):
`age-pq-keys/tests/differential_age_go.rs`, which checks this crate against the
real Go `age` CLI over many deterministic cases rather than the single
checked-in fixture. It needs no `conformance/` workspace, no rage dependency,
and no MSRV bump — which is exactly why it landed first.

Corrections that shaped it were measured before implementation and recorded in
[`pre-freeze-audit.md`](pre-freeze-audit.md); the stderr-echo row in that
document's *dead ends* section was **corrected** by this work.

---

## What the oracle proves

Four differentials, in both directions across the implementation boundary. All
four are `#[ignore]`d and shell out; `common::require_age_cli()` panics rather
than skips when the binary is absent, so "ignored" and "passed" never blur.

| # | Direction | What it establishes | Cases |
|---|---|---|---|
| **D1** | our identity → `age-keygen -y` | Go parses what our encoder emits, and Go's seed→recipient derivation agrees with `HybridIdentity::to_public()` byte-for-byte | 64 |
| **D2** | `age-keygen -pq` → our parser | our identity **and** recipient decoders accept *arbitrary fresh* Go output, re-encode it byte-identically, and derive the recipient Go printed | 8 |
| **D3** | we encrypt → `age -d` | our stanza, carried inside the `age` crate's STREAM payload, is readable by Go | 22 |
| **D4** | `age -e` → we decrypt | Go's stanza and payload are readable by us | 22 |

The length matrix in D3/D4 additionally pins the **`age` crate's** STREAM
framing against Go's across the 64 KiB chunk boundary. That is worth having for
a pinned dependency, but it is not evidence about this workspace: nothing here
varies with plaintext length. Our contribution to D3/D4 is one 16-byte file key
in one stanza, identical for a 0-byte and a 131 072-byte file — what the 22
cases add *for us* is 22 more distinct keys through `wrap_file_key` /
`unwrap_stanza`.

The step up from what existed before is a sample size. `bech32_byte_identity.rs`
and `age_cli_interop_decrypt_tests.rs` each check **one** checked-in artefact.
A defect that is a function of the key bytes — a carry, a leading-zero trim, an
off-by-one at a chunk edge — has roughly a one-in-N chance of appearing in a
single fixture. D1 gives it sixty-four chances, D3/D4 twenty-two each at
deliberately chosen sizes.

D2 is the only one pointed at our **decoders** with fresh input. Everything else
in the suite decodes either our own output or the same frozen string — which is
why D2 feeds Go's recipient back through `HybridRecipient::parse` as well as its
identity through `HybridIdentity::parse`. Without that, a decoder-side defect in
a direction our own encoder never emits would pass all four differentials.

## What it does *not* prove

- **Nothing about the plugin protocol.** Every identity is age's native
  `AGE-SECRET-KEY-PQ-` form, and every child process gets a `PATH` with
  plugin-bearing directories stripped. If any of this ever routed through
  `age-plugin-pq`, "interoperability with Go age" would silently become
  "interoperability with our own code" — green, and proving nothing.
- **Nothing about ciphertext bytes.** age encryption is randomised: two
  encryptions of identical plaintext to the same recipient match in length and
  differ in bytes. Cross-implementation agreement on a ciphertext is provable
  only by decrypting it, which is what D3 and D4 do. Ciphertext bytes are never
  compared anywhere.
- **Nothing about a specific age version.** Assertions are on exit codes and
  stdout bytes only — never on stderr text, error strings, or the `# created:`
  timestamp. Those differ between platforms (`The file exists.` vs `file
  exists`) and between the developer's CLI and whatever `scripts/install-age.sh`
  pins for CI. Local development here ran against **v1.3.1**; CI installs
  **v1.3.2**. No measurement taken locally is presented as CI's behaviour.

  Retired unknown, first CI run of PR #24: all four differentials passed against
  v1.3.2 with their banners in the log, so the one CLI feature this oracle newly
  depends on -- `age -d -i -`, reading the identity from stdin, measured only on
  v1.3.1 while D3 was written -- is confirmed on the version CI actually uses.
- **Nothing about the second KEM variant.** MLKEM1024-P384 (issue #19) does not
  exist yet, in this crate or in the age CLI.

## Why the seeds are deterministic

Every case is a pure function of its index:

```
seed(i)     = SHA-256("age-pq-workspace/differential-age-go/v1/seed" ‖ be32(i))
identity(i) = bech32(seed(i), hrp = "age-secret-key-pq-", Case::Upper)
```

Nothing is sampled at run time. The reason is not tidiness — it is that **the
input which reproduces a failure is a private key.** A randomised oracle forces
a choice between an unreproducible failure and printing key material into a CI
log. Deriving the cases removes the choice: a failure at case 41 says `case 41`
and nothing else, and any machine can reproduce it.

Two properties make that total rather than best-effort:

- **Every 32-byte value is a valid hybrid seed.** X-Wing expands the seed
  through SHAKE-256 and `new_private_key` fails only on a length mismatch, so
  there is no rejection sampling and no case is ever skipped. This was checked
  against the Go CLI too: all-zero, all-`0xFF` and hashed seeds are all accepted
  and all yield well-formed 1959-character recipients.
- **The identity is uppercase.** `Case::Upper` is applied by the encoder to the
  whole string, HRP included. A generator that emits lowercase produces
  identities Go refuses outright — every case would fail at once, but only for
  whoever ran the ignored tests.
  `identities_are_uppercase_and_match_the_crate_encoder` catches that with no
  binary present.

The HRP is **re-declared** in the test rather than imported. If the crate's HRP
ever changed, the oracle would keep emitting this one, `HybridIdentity::parse`
would reject it, and the change would fail loudly instead of silently
redefining what the tests compare.

That independence has a sharp edge, and it took a mutation run to find it: with
the oracle encoding its own identities, `HybridIdentity::to_string` — the
production encoder — was on no differential's happy path except D2's, which is
`#[ignore]`d and needs `age-keygen`. Flipping the crate encoder to `Case::Lower`
left D1, D3, D4 and the pinned digest all green (bech32 decoding is
case-insensitive, so the recipients, and therefore the digest, do not move),
while Go would have rejected every identity in the field. So
`identities_are_uppercase_and_match_the_crate_encoder` now also asserts, for
**every** case D1/D3/D4 use, that `HybridIdentity::parse(...).to_string()`
reproduces the oracle's bytes — wrapped in a `Dynamic<String>` and compared with
`ct_eq`, since both sides are private keys. That is two bech32 operations per
case and no process spawn, and it turns the slip red on a machine with no age
binary at all.

D2 is the deliberate exception: its keys come from Go's CSPRNG and cannot be
index-reproducible. Its failure messages carry the case index and the
**recipient** (public), and say plainly that the identity cannot be reprinted.
The temp directory is not kept — "keeping it for debugging" persists a private
key to disk.

### Plaintext sizes

`PLAINTEXT_LENGTHS = [0, 1, 15, 16, 17, 64, 1024, 65_535, 65_536, 65_537, 131_072]`,
cycled by case index, each filled by SHA-256 counter mode over the index.

65_536 is age's STREAM chunk size (`age-0.11.2/src/primitives/stream.rs:22`,
`CHUNK_SIZE = 64 * 1024`) and 131_072 is exactly two chunks. Those two are the
interesting sizes: an exact multiple forces the encryptor to flag a *full* chunk
as last rather than emit an empty one, and the reader rejects an empty final
chunk outright (`stream.rs:441`, `err-stream-last-chunk-empty`). The pinned
digest test asserts both are still present, because dropping them is the cheap
way to make D3/D4 look fine while testing nothing at the boundary.

## Secret hygiene

| Mechanism | What it stops |
|---|---|
| Derived identities held as `secure_gate::EncodedSecret` | Zeroizes on drop, redacts in `Debug`, and has **no `Display`** — a stray `{}` in a panic message is a compile error, not a key leak |
| Go-generated identities held as `Dynamic<String>` | D2's keys are the only genuinely secret ones here (every other case is `SHA-256(committed domain ‖ index)`). The whole keyfile lands in the wrapper on arrival, the identity line moves into a second one, and the re-encoding check compares them with `ct_eq` |
| `String::from_utf8_lossy`, never `from_utf8(..).expect(..)` | `expect` formats the error with `{:?}`, and `FromUtf8Error`'s `Debug` prints **every input byte** as a decimal. On D2's stdout — a whole keyfile — one non-UTF-8 byte would put a private key into a panic message that the CI guard echoes verbatim |
| `age-keygen` stderr is `Stdio::null()` | `age-keygen -y` echoes the **entire** identity on a parse failure; see the table below |
| `age` stderr goes through `common::safe_stderr` | Drops any whitespace token containing `AGE-SECRET-KEY`, at the one place bytes become a message |
| Failure messages carry index, lengths and digest handles | Recipients are compared with `assert!(a == b)`, not `assert_eq!`. D2 has no index to re-run from, so its messages carry `sha256:<12 hex>… (N chars)` of the public recipient rather than the recipient itself — eight failures once emitted ~16 KB of bech32 into a single panic and buried the legible part |
| No identity is written to disk at all | D3 pipes its key to `age -d -i -` (measured: the identity is read from stdin while the ciphertext stays a file argument). Its keys are index-derivable and so not really secret — but unlinking a temp file is not shredding it, and drop does not run at all if the runner is killed |

The stderr asymmetry, measured on v1.3.1 during this work:

| Path | Echoes the identity on failure? |
|---|---|
| `age-keygen -y` | **Yes** — `unknown identity type: "age-secret-key-pq-<full 77-char key>"` |
| `age -d -i FILE` | No — names the file instead |
| `age -d -i -` | No — names `-`, and reports a character *index* into the line (`malformed secret key: invalid character data part: s[0]=…`) |

That correction is carried back into [`pre-freeze-audit.md`](pre-freeze-audit.md),
whose *dead ends* section previously recorded the leak as "not reproduced" on
the strength of the second row alone.

## Process mechanics that are not optional

Two deadlocks were measured before the harness was written, both silent hangs
with no output at all:

1. **`age-keygen -y` blocks until stdin EOF.** Writing the identity line is not
   enough; the writer must be dropped.
2. **Batched output overruns the stdout pipe buffer.** 64 cases is ~125 KB of
   recipients, well past a 64 KiB pipe, so writing all of stdin before reading
   any stdout hangs the child mid-write.

D1 handles both by driving the two ends concurrently: a writer thread owns
`ChildStdin` (dropping it at the end of the closure) while the test thread sits
in `wait_with_output()`. The file-redirect alternative avoids the same
deadlocks, but writes 64 private keys to disk; the thread does not.

D3 and D4 use files rather than pipes for payloads, because 128 KiB in one
direction and more than a pipe buffer in the other is the same trap with the
roles swapped. Every `-o` destination is a path that does not yet exist:
`age-keygen -o` **and** `age-keygen -y -o` are `O_EXCL` and fail on a second run
against the same path. `age -o` overwrites, but a fresh path is used uniformly
rather than relying on remembering which binary does which.

### Program resolution vs plugin blocking

`common::plugin_free_path()` strips every directory containing an
`age-plugin-*` binary from the child's `PATH`. The WinGet `age` package ships
`age-plugin-batchpass.exe` in the **same directory** as `age.exe`, so on such a
machine that filter removes the only directory holding age itself.

It survived because Rust on Windows falls back to the parent's `PATH` when the
child's does not resolve the program. On Unix, Rust deliberately avoids
`posix_spawnp` once the environment is overridden, so the same layout would fail
to spawn with `ENOENT` — a bug that passes locally and fails in CI, for anyone
whose distribution ever co-locates a plugin with age.

`common.rs` now resolves the program to an absolute path against the
**unfiltered** `PATH` first, then applies the filtered `PATH` to the child. The
two jobs are separated: resolution finds the binary, the filtered `PATH` governs
what the child sees when *it* goes looking for `age-plugin-*`. CI is unaffected
either way — `scripts/install-age.sh` installs only `age` and `age-keygen` — but
the failure mode is now unreachable rather than accidentally avoided.

## The anti-gutting guard, and why it takes three legs

A test target with **zero** `#[test]` functions prints `running 0 tests … ok`
and exits **0**. So a CI job that merely names this file catches its deletion
and not its gutting — the same green-without-running shape as the workflow that
sat in a subdirectory and never ran once (see the note at the top of
`.github/workflows/ci.yml`).

Three checks, because no one of them sees all three degradations:

| Leg | Where | Catches | Blind to |
|---|---|---|---|
| **1. Declared count** | `msrv` job, before the age installer | file deleted (cargo exits 101, "no test target named"); tests removed (`--list` summary below the floor) | bodies voided, and tests all `#[ignore]`d — `--list` counts names, and counts ignored tests too |
| **2. Executed count + banners** | `msrv` job, after the workspace test run | bodies voided (no `D1:`…`D4:` banner is printed); tests re-`#[ignore]`d (no banner either, and the plain run drops to 0 passed); age missing or any failure (cargo exits 101) | a test whose *body* still runs but tests less |
| **3. Pinned digest + floors** | `oracle_case_generation_is_pinned` and `identities_are_uppercase_and_match_the_crate_encoder`, **not** `#[ignore]`d | any matrix shrunk below its floor — including `ORACLE_GO_KEYGEN_CASES`, which cannot go into the digest because Go's keys are random — `PLAINTEXT_LENGTHS` losing its chunk multiples, `seed_for_case` weakened to a constant, and the crate's identity encoder drifting from the oracle's | nothing above; it needs the file to still exist and run |

**Leg 2 is the one a mutation run rewrote**, and the earlier version of this
table overstated it. Measured on the pinned toolchain: six `#[test]` fns keeping
their exact names with every body replaced by `{}` reports `6 passed; 0 ignored`
in 0.00 s and *passes a count-shaped guard*. `passed` does **not** drop when a
body is voided — the test still runs, it just does nothing — and the `ignored`
counter is always 0 under `--include-ignored`, so an `ignored -ne 0` branch is
unreachable by construction. Both claims were written here and in `ci.yml`, and
both were false. Leg 3 cannot cover for either, because voiding deletes its body
along with the rest.

The repair is to assert on evidence a body must produce. Each differential
prints a banner (`D1: derivation differential against age …`) *after*
`common::require_age_cli()` has successfully spawned the binary, so a banner is
positive proof that the body ran real work against the real CLI. Leg 2 now runs
the target with `--nocapture --test-threads=1` and requires all four, matching on
the differential name only — never on the version substring, since CI is on
v1.3.2 and local development on v1.3.1. A voided body prints nothing; an
`#[ignore]`d one prints nothing either. A second, plain invocation (no
`--include-ignored`, nothing rebuilt) then asserts a floor of 2 passed, which is
the only check that can see an all-`#[ignore]`d file — the case where CI stays
green because every CI invocation passes `--include-ignored`, while a
developer's `cargo test` silently runs nothing.

Leg 3 is the one that had to live in Rust, and it is deliberately not
`#[ignore]`d so it runs on a machine with no age binary at all. Its digest
covers `(index ‖ recipient)` for all 64 derivation cases plus SHA-256 of every
payload case: public keys and public plaintexts only, so committing it leaks
nothing. The committed value was taken from a run in which D1 passed all 64
cases against Go age v1.3.1 — it pins recipients the Go CLI itself agreed with,
not merely whatever this crate produced that day.

Three implementation choices in the shell, each measured rather than assumed:

- **No `-q`.** `cargo test -q -- --list` suppresses the `N tests, M benchmarks`
  summary entirely, so a quiet guard reads an identical empty string from a
  healthy target and a gutted one — a vacuous pass.
- **`sed`, not `grep`.** `grep` exits 1 on zero matches, and the reflex repair
  `|| true` turns a libtest format change into a silent green build. `sed` exits
  0 with empty output, and an explicit `[ -z … ]` test makes an unparseable line
  a named, hard failure. There is no path through either step that passes
  without a number.
- **`--color never`**, because the job sets `CARGO_TERM_COLOR: always` and the
  regexes must never meet an escape sequence. No escapes leaked on the toolchain
  this was checked on, but that depends on libtest's tty detection and the flag
  is free.

### Why steps in `msrv`, not a fourth job

`ci.yml` has no build cache of any kind. The `msrv` job already installs age and
already runs this target via `cargo test --workspace --all-features --
--include-ignored`, so a dedicated job would pay a full cold `libcrux-ml-kem`
build for signal that job already produces. The only new signal is the guard
itself, which is why it is two steps rather than a job. If a cache is added
later, a separate job for legibility becomes cheap and this tradeoff is worth
revisiting.

**Both guards must use the same package and feature selection as the workspace
test step**, and originally they did not. `cargo test -p age-pq-keys` resolves
`libcrux-ml-kem` to `{mlkem768, rand}`, while `--workspace --all-features`
resolves `{mlkem512, mlkem768, mlkem1024, rand}` — age-pq-hpke's `mlkem512` and
`mlkem1024` forward to it. The two commands therefore link *different* test
binaries (verified by filename hash), and with no cache each compiles
`libcrux-ml-kem`, `age-pq-hpke` and `age-pq-keys` from cold. The guards were
paying exactly the full build the two-step design exists to avoid, inside the job
that was supposed to be sharing it. They now say `cargo test --workspace
--all-features --test differential_age_go`, which on cargo 1.70 still selects
exactly one target (one `Running` line, one `test result:` line, so the parse is
unchanged) and still exits 101 with "no test target named" when the file is
deleted. What remains duplicated is *execution*, measured in seconds, not
compilation.

## Cost, and raising the case count

The whole target runs in ~2.4 s locally (age v1.3.1, Windows, workspace dev
profile at `opt-level = 2` so ML-KEM keygen is not a factor). Cost is process
spawns, not crypto: D1 is a single batched spawn for all 64 cases, D2 is 8, and
D3/D4 are 22 each. Budget CI at 50–200 ms per spawn rather than quoting a local
number.

There is headroom to raise the counts substantially. If they are ever made
env-overridable, **the override must only be able to raise them** — an env var
that can lower the count lets one workflow edit set it to 1 and reintroduce
exactly the hole the guard exists to close.

## Dependencies

None added. `Cargo.lock` is unchanged by this work: `sha2` and `tempfile` were
already dev-dependencies, and `secure-gate`, `base64`, `age-core` and
`age-pq-hpke` are normal dependencies, which Cargo passes to test targets as
`--extern` (proven in-tree — `tests/pq_stanza_tests.rs` already uses
`age_core`). `encoding-hex` is **not** enabled on secure-gate here, so hex is
hand-rolled in the same shape `tests/testkit.rs` uses, and only ever applied to
public digests.

## Related

- [`../plans/conformance-workspace.md`](../plans/conformance-workspace.md) — the
  larger plan this is one work item of.
- [`pre-freeze-audit.md`](pre-freeze-audit.md) — the corrections this was built
  around, and the one entry it corrected.
- [`cctv-conformance.md`](cctv-conformance.md) — the fixed-vector harness. The
  oracle is complementary: CCTV pins *specified* behaviour including negative
  cases; the oracle checks agreement with a *second implementation* over inputs
  nobody chose in advance.
