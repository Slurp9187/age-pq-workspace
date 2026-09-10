//! Differential oracle against the real Go `age` CLI.
//!
//! `tests/bech32_byte_identity.rs` and `tests/age_cli_interop_decrypt_tests.rs`
//! check this crate against **one** checked-in keypair and **one** checked-in
//! ciphertext produced by Go age v1.3.1. That is cross-implementation evidence
//! with a sample size of one. A bug that is a function of the key bytes — a
//! carry, a leading-zero trim, a chunk boundary — has a one-in-N chance of
//! showing up in a single fixture and a much better chance of showing up in
//! sixty-four.
//!
//! Four differentials run here, in both directions across the boundary:
//!
//! | # | direction | what it proves |
//! |---|-----------|----------------|
//! | D1 | our identity → `age-keygen -y` | our encoder emits something Go parses, and Go's seed→recipient derivation agrees with [`HybridIdentity::to_public`] byte-for-byte |
//! | D2 | `age-keygen -pq` → our parser | our decoder accepts *arbitrary fresh* Go output, re-encodes it identically, and derives the same recipient Go printed |
//! | D3 | we encrypt → `age -d` | our stanza and STREAM payload are readable by Go, across the 64 KiB chunk boundary |
//! | D4 | `age -e` → we decrypt | Go's stanza and payload are readable by us, across the same boundary |
//!
//! ## Why the cases are derived, not random
//!
//! Every case is a pure function of its index: `seed(i) = SHA-256(domain ‖ i)`,
//! encoded to age's native uppercase identity form. Nothing is sampled at run
//! time, so a failure at case 41 is reproducible on any machine by running case
//! 41 — which matters enormously here, because **the input that reproduces the
//! failure is a private key and must never be printed.** Randomised cases would
//! force the harness to choose between an unreproducible failure and dumping key
//! material into CI logs. Deriving them removes the choice.
//!
//! Every 32-byte value is a valid hybrid seed (X-Wing expands the seed through
//! SHAKE-256; `new_private_key` fails only on a length mismatch), so the
//! index→key map is total and no case is ever skipped.
//!
//! D2 is the one differential that *cannot* be index-reproducible: its keys come
//! from Go's CSPRNG. It is here anyway, because it is the only direction that
//! exercises our **decoder** against fresh Go output rather than against one
//! frozen string. Its failures report the case index and the recipient (public);
//! the identity is deliberately unreportable and the temp directory is not kept.
//!
//! ## What this does *not* prove
//!
//! * Nothing about the **plugin** protocol. Every identity here is age's native
//!   `AGE-SECRET-KEY-PQ-` form, and every child gets a `PATH` with plugin
//!   directories stripped, so `age` is forced down its own code path. If these
//!   ever routed through `age-plugin-pq`, "interoperability with Go age" would
//!   silently become "interoperability with our own code".
//! * Nothing about **ciphertext bytes**. age encryption is randomised: two
//!   encryptions of the same plaintext to the same recipient differ in bytes
//!   while matching in length. Agreement is provable only by decrypting, which
//!   is what D3 and D4 do.
//! * Nothing about the **age version CI runs**. These assert on exit codes and
//!   stdout bytes only — never on stderr text, error strings, or the `# created:`
//!   timestamp, all of which differ between platforms and between the local CLI
//!   and whatever `scripts/install-age.sh` pins.
//!
//! ## Secret hygiene
//!
//! The per-case identity is held as a [`secure_gate::EncodedSecret`], which
//! zeroizes on drop, redacts in `Debug`, and has **no `Display`** — a stray `{}`
//! in a panic message is a compile error rather than a key leak. `age-keygen`'s
//! stderr is never surfaced (it echoes the whole identity on a parse failure);
//! `age`'s own stderr goes through `common::safe_stderr`. Failure messages carry
//! a case index, a differential name, and lengths. Nothing else.
//!
//! ## Anti-gutting
//!
//! [`oracle_case_generation_is_pinned`] is deliberately **not** `#[ignore]`d, so
//! it runs with no age binary present. A test target with zero tests prints
//! `running 0 tests … ok` and *exits 0*, so a CI step that merely names this file
//! would catch its deletion but not its gutting. The pinned digest covers the
//! case count, the seed derivation, the recipient derivation and the plaintext
//! generator, so shrinking the matrix or weakening the generator fails a
//! green-path test. The CI steps in `.github/workflows/ci.yml` close the
//! complementary hole — a file whose tests are all `#[ignore]`d away.
//!
//! Background and the measured CLI behaviours these tests are built around:
//! [`docs/design/age-go-differential-oracle.md`](../../docs/design/age-go-differential-oracle.md)
//! and [`docs/design/pre-freeze-audit.md`](../../docs/design/pre-freeze-audit.md).

#![forbid(unsafe_code)]

use age::Encryptor;
use age_pq_keys::{HybridIdentity, HybridRecipient};
use secure_gate::{fixed_newtype, Case, EncodedSecret, ToBech32};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs;
use std::io::{Read, Write};
use std::process::Stdio;

mod common;

fixed_newtype!(
    OracleSeed32,
    32,
    "Per-case oracle seed, derived from the case index. This is a private key."
);

/// Re-declared rather than imported: `age_pq_keys`'s copy is private, and that
/// is the point. If the crate's HRP ever changed, the oracle would keep emitting
/// this one, `HybridIdentity::parse` would reject it, and the change would fail
/// loudly here instead of silently redefining what the tests compare.
///
/// Lowercase, with `Case::Upper` — the encoder uppercases the whole string, HRP
/// included. Passing an already-uppercase HRP is a different (and wrong) thing.
const IDENTITY_HRP: &str = "age-secret-key-pq-";

const SEED_DOMAIN: &[u8] = b"age-pq-workspace/differential-age-go/v1/seed";
const PLAINTEXT_DOMAIN: &[u8] = b"age-pq-workspace/differential-age-go/v1/plaintext";

/// Cases in the derivation matrix (D1). Cheap: one batched `age-keygen -y`
/// converts all of them in a single process.
const ORACLE_CASES: usize = 64;

/// Floor for [`ORACLE_CASES`]. Lowering the count below this is a test failure,
/// not a tuning decision — see the module docs on gutting.
const ORACLE_MIN_CASES: usize = 32;

/// Cases in each payload differential (D3, D4). Smaller than [`ORACLE_CASES`]
/// because each one costs a process spawn plus up to 128 KiB of file I/O.
const ORACLE_STREAM_CASES: usize = 22;

/// Floor for [`ORACLE_STREAM_CASES`]: one full pass over [`PLAINTEXT_LENGTHS`].
const ORACLE_MIN_STREAM_CASES: usize = PLAINTEXT_LENGTHS.len();

/// Keypairs drawn from Go's own CSPRNG for the decoder differential (D2).
/// One spawn each, so kept small.
const ORACLE_GO_KEYGEN_CASES: usize = 8;

/// Plaintext sizes, cycled by case index.
///
/// 65_536 is age's STREAM chunk size (`age-0.11.2/src/primitives/stream.rs:22`,
/// `CHUNK_SIZE = 64 * 1024`); 131_072 is exactly two chunks. Those two are the
/// interesting ones: an exact multiple forces the encryptor to flag a *full*
/// chunk as last rather than emit an empty one, and the reader rejects an empty
/// final chunk outright (`stream.rs:441`, `err-stream-last-chunk-empty`). The
/// small sizes bracket the AEAD block boundary.
const PLAINTEXT_LENGTHS: &[usize] = &[0, 1, 15, 16, 17, 64, 1024, 65_535, 65_536, 65_537, 131_072];

/// SHA-256 over `(index ‖ recipient)` for every derivation case, then over the
/// SHA-256 of every payload case. Public keys and public plaintexts only, so
/// committing it leaks nothing.
///
/// The committed value was taken from a run in which D1 passed all 64 cases
/// against Go age v1.3.1, so it pins recipients the Go CLI itself agreed with —
/// not merely whatever this crate happened to produce.
///
/// Regenerate deliberately, never reflexively: this digest changing means the
/// oracle is now testing something other than what was reviewed.
const GENERATOR_DIGEST: &str = "0575ca97cb012afbb1b3a7d0ef00e496eb416aeef49681abe1f0f182d2b8b801";

/// How many individual failures a panic message lists before summarising.
const MAX_REPORTED_FAILURES: usize = 10;

// ---------------------------------------------------------------------------
// Deterministic case generation
// ---------------------------------------------------------------------------

fn seed_for_case(case: usize) -> OracleSeed32 {
    let mut h = Sha256::new();
    h.update(SEED_DOMAIN);
    h.update((case as u32).to_be_bytes());
    let digest = h.finalize();
    // `new_with` writes straight into the wrapper's storage; `new` would move a
    // value that briefly existed on this frame.
    OracleSeed32::new_with(|out| out.copy_from_slice(&digest))
}

/// The case's identity in age's native uppercase form.
///
/// `EncodedSecret` zeroizes on drop and cannot be `Display`ed, so this value
/// cannot reach a panic message by accident.
fn identity_for_case(case: usize) -> EncodedSecret {
    seed_for_case(case)
        .try_to_bech32(IDENTITY_HRP, Case::Upper)
        .expect("a 32-byte seed always encodes")
}

/// Public, deterministic plaintext for a case: SHA-256 counter mode, truncated.
///
/// Deliberately not `usize::div_ceil` anywhere — that is 1.73+ and this
/// workspace is pinned to 1.70.
fn plaintext_for_case(case: usize) -> Vec<u8> {
    let len = PLAINTEXT_LENGTHS[case % PLAINTEXT_LENGTHS.len()];
    let mut out = Vec::with_capacity(len);
    let mut block: u32 = 0;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(PLAINTEXT_DOMAIN);
        h.update((case as u32).to_be_bytes());
        h.update(block.to_be_bytes());
        let digest = h.finalize();
        let take = std::cmp::min(digest.len(), len - out.len());
        out.extend_from_slice(&digest[..take]);
        block += 1;
    }
    out
}

/// The public recipient our implementation derives for a case.
fn our_recipient_for_case(case: usize) -> HybridRecipient {
    let identity = identity_for_case(case);
    HybridIdentity::parse(&identity)
        .unwrap_or_else(|_| panic!("case {case}: our own identity encoding must re-parse"))
        .to_public()
        .unwrap_or_else(|_| panic!("case {case}: deriving the recipient must succeed"))
}

/// `encoding-hex` is not enabled on secure-gate in this workspace, so hex is
/// hand-rolled — the same shape `tests/testkit.rs` uses, and only ever applied
/// to public digests.
fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// Turns per-case failures into one panic, capped so a systemic break cannot
/// bury the log. Named so the message says which differential failed.
fn report(differential: &str, total: usize, failures: Vec<String>) {
    if failures.is_empty() {
        return;
    }
    let mut msg = format!(
        "{differential}: {} of {total} case(s) failed against the Go age CLI\n",
        failures.len()
    );
    for line in failures.iter().take(MAX_REPORTED_FAILURES) {
        msg.push_str("  - ");
        msg.push_str(line);
        msg.push('\n');
    }
    if failures.len() > MAX_REPORTED_FAILURES {
        let _ = writeln!(
            msg,
            "  … and {} more",
            failures.len() - MAX_REPORTED_FAILURES
        );
    }
    msg.push_str(
        "re-run a single case by index; the inputs are derived, so nothing secret needs printing",
    );
    panic!("{msg}");
}

// ---------------------------------------------------------------------------
// The anti-gutting guard — deliberately NOT #[ignore]d
// ---------------------------------------------------------------------------

/// Pins the whole case matrix to a committed digest, with no age binary needed.
///
/// This is the third leg of the anti-gutting guard, and the only one that can
/// see a *weakened* generator. `--list` counts declared tests and cannot tell a
/// real body from an empty one; the CI result line counts what ran. Neither
/// notices `ORACLE_CASES` dropping to 2, `PLAINTEXT_LENGTHS` losing its chunk
/// boundaries, or `seed_for_case` returning a constant. The digest notices all
/// three, and it covers only public keys and public plaintexts, so committing it
/// leaks nothing.
///
/// The floor assertions come first so a deliberately shrunk matrix reports *why*
/// it failed rather than only that a digest moved.
// `clippy::assertions_on_constants` says a constant assertion is folded away by
// the compiler and should be deleted. Its premise does not hold for a floor: the
// whole point is that these compare two constants, and that *editing one of them
// downwards* turns a green suite red. A tried-and-discarded alternative was
// `const _: () = assert!(…)`, which is stronger still (gutting then fails to
// compile) but which this clippy also flags — and, on 1.70, additionally reports
// the floor constants as dead code, since a `const _` item registers no use.
#[allow(clippy::assertions_on_constants)]
#[test]
fn oracle_case_generation_is_pinned() {
    assert!(
        ORACLE_CASES >= ORACLE_MIN_CASES,
        "the derivation matrix shrank to {ORACLE_CASES} cases, below its floor of {ORACLE_MIN_CASES}"
    );
    assert!(
        ORACLE_STREAM_CASES >= ORACLE_MIN_STREAM_CASES,
        "the payload matrix shrank to {ORACLE_STREAM_CASES} cases, below its floor of \
         {ORACLE_MIN_STREAM_CASES} (one full pass over PLAINTEXT_LENGTHS)"
    );
    assert!(
        PLAINTEXT_LENGTHS.contains(&65_536) && PLAINTEXT_LENGTHS.contains(&131_072),
        "the payload matrix must keep the exact STREAM chunk multiples; they are the sizes a \
         chunking bug actually shows up at"
    );

    let mut h = Sha256::new();
    for case in 0..ORACLE_CASES {
        h.update((case as u32).to_be_bytes());
        h.update(our_recipient_for_case(case).to_string().as_bytes());
    }
    for case in 0..ORACLE_STREAM_CASES {
        h.update(Sha256::digest(plaintext_for_case(case)));
    }
    let got = hex_encode(&h.finalize());

    assert!(
        got == GENERATOR_DIGEST,
        "the differential oracle's case generation changed.\n  expected {GENERATOR_DIGEST}\n  \
         got      {got}\nIf that was intentional, say so in the commit and update \
         GENERATOR_DIGEST; if it was not, the seed derivation, the recipient derivation, the \
         case count or PLAINTEXT_LENGTHS moved under you."
    );
}

/// A sanity check on the derived identities themselves, again with no binary.
///
/// Catches the mirror-image slip that would make D1 vacuous: emitting a
/// lowercase identity. Go refuses `age-secret-key-pq-…` outright, so every case
/// would fail at once — but only when someone actually ran the ignored tests.
#[test]
fn derived_identities_are_in_ages_native_uppercase_form() {
    for case in [0usize, 1, ORACLE_CASES - 1] {
        let identity = identity_for_case(case);
        // Length and prefix are public facts about the format, not key material:
        // a 32-byte seed under this HRP always encodes to 77 characters.
        assert!(
            identity.starts_with("AGE-SECRET-KEY-PQ-1"),
            "case {case}: identity is not in age's native uppercase form"
        );
        assert!(
            identity.len() == 77,
            "case {case}: identity is {} characters, expected 77",
            identity.len()
        );
    }
}

// ---------------------------------------------------------------------------
// D1 — our identity → age-keygen -y
// ---------------------------------------------------------------------------

/// Every case's recipient, as derived by the Go CLI, in case order.
///
/// One batched `age-keygen -y` rather than [`ORACLE_CASES`] spawns: `-y` reads
/// one identity per line and writes one recipient per line, in input order.
///
/// Both pipe ends are driven concurrently, which is not optional. `age-keygen -y`
/// blocks until stdin EOF, so the writer must be dropped; and the output is
/// ~2 KB per case, so at this matrix size it comfortably exceeds a 64 KiB pipe
/// buffer — writing all of stdin before reading any stdout deadlocks the child
/// mid-write, silently and with no output at all. A writer thread plus
/// `wait_with_output` on this thread avoids both, and keeps the private keys off
/// disk entirely, which the file-redirect alternative does not.
fn go_recipients_for_all_cases() -> Vec<String> {
    let mut child = common::age_keygen_command_without_plugins()
        .arg("-y")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Never captured, never surfaced: on a parse failure `age-keygen`
        // reports `unknown identity type: "<the entire input identity>"`.
        .stderr(Stdio::null())
        .spawn()
        .expect("age-keygen must be on PATH alongside age");

    let mut sink = child.stdin.take().expect("stdin was requested");
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        for case in 0..ORACLE_CASES {
            let identity = identity_for_case(case);
            // Tier-2: `ChildStdin::write_all` takes `&[u8]`. `EncodedSecret` has
            // no `AsRef<[u8]>` on purpose, so this is the explicit hand-off.
            sink.write_all(identity.as_bytes())?;
            sink.write_all(b"\n")?;
        }
        sink.flush()
        // `sink` drops here, closing stdin. Without that, the child never exits.
    });

    let output = child.wait_with_output().expect("age-keygen -y did not run");
    writer
        .join()
        .expect("the identity writer thread panicked")
        .expect("writing identities to age-keygen failed");

    assert!(
        output.status.success(),
        "age-keygen -y exited with {:?} (stderr withheld: it echoes the input identity)",
        output.status.code()
    );

    let stdout = String::from_utf8(output.stdout).expect("age-keygen -y emits ASCII recipients");
    let lines: Vec<String> = stdout
        .lines()
        .map(|l| l.trim_end().to_owned())
        .filter(|l| !l.is_empty())
        .collect();

    // Asserted before any comparison: a short read would otherwise silently
    // compare a prefix of the matrix and report success.
    assert!(
        lines.len() == ORACLE_CASES,
        "age-keygen -y returned {} recipient(s) for {ORACLE_CASES} identities",
        lines.len()
    );
    lines
}

/// D1: Go's seed→recipient derivation agrees with ours, byte for byte, over the
/// whole deterministic matrix.
///
/// This is the differential the single checked-in fixture cannot give: it holds
/// the seed distribution fixed and varies the seed, so a key-dependent bug in
/// either implementation's ML-KEM or X25519 half has sixty-four chances to show
/// rather than one.
#[test]
#[ignore = "requires age CLI >= 1.3 and age-keygen on PATH; run with --include-ignored"]
fn go_derives_the_same_recipient_from_our_identities() {
    let version = common::require_age_cli();
    eprintln!("D1: derivation differential against age {version}, {ORACLE_CASES} cases");

    let go = go_recipients_for_all_cases();
    let mut failures = vec![];

    for (case, go_recipient) in go.iter().enumerate() {
        let ours = our_recipient_for_case(case);
        let ours_string = ours.to_string();

        // Compared with `assert!`-style equality rather than `assert_eq!` so a
        // mismatch cannot dump two 1959-character strings into the log. These
        // are public keys, but the habit is what keeps the identity path safe.
        if &ours_string != go_recipient {
            // `from_bytes` cannot fail on a well-formed Go recipient; if the
            // parse itself is what broke, say that instead of guessing.
            let attribution = match HybridRecipient::parse(go_recipient) {
                Ok(parsed) if parsed.as_bytes() == ours.as_bytes() => {
                    "same key bytes, different encoding (encoder drift)"
                }
                Ok(_) => "different key bytes (derivation drift)",
                Err(_) => "Go's recipient does not parse at all",
            };
            failures.push(format!(
                "case {case}: recipient mismatch — {attribution} (ours {} chars, Go {} chars)",
                ours_string.len(),
                go_recipient.len()
            ));
        }
    }

    report("D1 derivation", ORACLE_CASES, failures);
}

// ---------------------------------------------------------------------------
// D2 — age-keygen -pq → our parser
// ---------------------------------------------------------------------------

/// D2: our decoder round-trips *freshly generated* Go keypairs.
///
/// The only differential here whose inputs are not reproducible by index — the
/// keys come from Go's CSPRNG. It earns its place because it is the only
/// direction that points our **decoder** at arbitrary Go output; today that is
/// checked against exactly one frozen string in `tests/data/`.
///
/// A failure therefore reports the case index and the recipient (public data)
/// and states plainly that the identity cannot be reprinted. The temp directory
/// is not kept: "keeping it for debugging" would persist a private key to disk.
#[test]
#[ignore = "requires age CLI >= 1.3 and age-keygen on PATH; run with --include-ignored"]
fn we_reparse_freshly_generated_go_keypairs() {
    let version = common::require_age_cli();
    eprintln!("D2: decoder differential against age {version}, {ORACLE_GO_KEYGEN_CASES} cases");

    let mut failures = vec![];

    for case in 0..ORACLE_GO_KEYGEN_CASES {
        let output = common::age_keygen_command_without_plugins()
            .arg("-pq")
            // `age-keygen -pq` duplicates the public key on stderr whenever
            // stdout is not a TTY, and adds a world-readable-file warning on
            // some platforms. Non-empty stderr is normal here; discard it.
            .stderr(Stdio::null())
            .output()
            .expect("age-keygen -pq did not run");

        assert!(
            output.status.success(),
            "case {case}: age-keygen -pq exited with {:?}",
            output.status.code()
        );

        // The keyfile is three lines: `# created:`, `# public key: `, identity.
        let text = String::from_utf8(output.stdout).expect("age-keygen emits ASCII");
        let go_recipient = match text
            .lines()
            .find_map(|l| l.strip_prefix("# public key: "))
            .map(str::trim)
        {
            Some(r) => r.to_owned(),
            None => {
                failures.push(format!(
                    "case {case}: no `# public key: ` line in the keyfile"
                ));
                continue;
            }
        };
        let go_identity = match text
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("AGE-SECRET-KEY-PQ-"))
        {
            Some(i) => i,
            None => {
                failures.push(format!(
                    "case {case}: no native identity line in the keyfile"
                ));
                continue;
            }
        };

        let identity = match HybridIdentity::parse(go_identity) {
            Ok(i) => i,
            Err(_) => {
                failures.push(format!(
                    "case {case}: our parser rejected a fresh Go identity (identity withheld; \
                     its recipient is {go_recipient})"
                ));
                continue;
            }
        };

        if identity.to_string() != go_identity {
            failures.push(format!(
                "case {case}: identity did not re-encode byte-identically (values withheld; its \
                 recipient is {go_recipient})"
            ));
        }

        match identity.to_public() {
            Ok(ours) if ours.to_string() == go_recipient => {}
            Ok(ours) => failures.push(format!(
                "case {case}: we derived {} from Go's identity, Go printed {go_recipient}",
                ours.to_string()
            )),
            Err(_) => failures.push(format!(
                "case {case}: deriving a recipient from Go's identity failed (its recipient is \
                 {go_recipient})"
            )),
        }
    }

    report("D2 decoder", ORACLE_GO_KEYGEN_CASES, failures);
}

// ---------------------------------------------------------------------------
// D3 / D4 — payload differentials
// ---------------------------------------------------------------------------

/// D3: the Go CLI decrypts what we encrypt, across the STREAM chunk boundary.
///
/// Keys are D1's, so a failure is re-runnable from the index alone. Files are
/// used on both ends rather than pipes: 128 KiB through a child's stdin while it
/// writes more than a pipe buffer to stdout deadlocks, and the deadlock is
/// silent.
#[test]
#[ignore = "requires age CLI >= 1.3 on PATH; run with --include-ignored"]
fn go_decrypts_what_we_encrypt() {
    let version = common::require_age_cli();
    eprintln!("D3: our encrypt → Go decrypt against age {version}, {ORACLE_STREAM_CASES} cases");

    let dir = tempfile::tempdir().expect("tempdir");
    let mut failures = vec![];

    for case in 0..ORACLE_STREAM_CASES {
        let plaintext = plaintext_for_case(case);
        let identity = identity_for_case(case);
        let recipient = our_recipient_for_case(case);

        let ciphertext_path = dir.path().join(format!("d3-{case}.age"));
        let identity_path = dir.path().join(format!("d3-{case}.key"));
        let recovered_path = dir.path().join(format!("d3-{case}.out"));

        let mut ciphertext = Vec::new();
        {
            let encryptor =
                Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                    .expect("a validated recipient always builds an encryptor");
            let mut writer = encryptor
                .wrap_output(&mut ciphertext)
                .expect("wrapping an in-memory sink cannot fail");
            writer.write_all(&plaintext).expect("write plaintext");
            writer.finish().expect("finish");
        }
        fs::write(&ciphertext_path, &ciphertext).expect("write ciphertext");
        // Tier-2: the file sink takes `&[u8]`; `age -d -i` needs a path, so the
        // key must land on disk. The temp directory is dropped at test end.
        fs::write(&identity_path, identity.as_bytes()).expect("write identity");

        let output = common::age_command_without_plugins()
            .args([
                "-d".as_ref(),
                "-i".as_ref(),
                identity_path.as_os_str(),
                "-o".as_ref(),
                recovered_path.as_os_str(),
                ciphertext_path.as_os_str(),
            ])
            .output()
            .expect("age -d did not run");

        if !output.status.success() {
            failures.push(format!(
                "case {case} ({} byte plaintext): age -d exited with {:?}: {}",
                plaintext.len(),
                output.status.code(),
                common::safe_stderr(&output.stderr)
            ));
            continue;
        }

        let recovered = fs::read(&recovered_path).expect("read the decrypted file");
        if recovered != plaintext {
            failures.push(format!(
                "case {case}: Go decrypted {} bytes, expected {}",
                recovered.len(),
                plaintext.len()
            ));
        }
    }

    report("D3 our encrypt → Go decrypt", ORACLE_STREAM_CASES, failures);
}

/// D4: we decrypt what the Go CLI encrypts, across the same boundary.
///
/// The recipient is passed on the command line, which is safe — it is public,
/// and age echoes it verbatim on a rejection. The identity never leaves the
/// process here; only D3 needs it on disk.
#[test]
#[ignore = "requires age CLI >= 1.3 on PATH; run with --include-ignored"]
fn we_decrypt_what_go_encrypts() {
    let version = common::require_age_cli();
    eprintln!("D4: Go encrypt → our decrypt against age {version}, {ORACLE_STREAM_CASES} cases");

    let dir = tempfile::tempdir().expect("tempdir");
    let mut failures = vec![];

    for case in 0..ORACLE_STREAM_CASES {
        let plaintext = plaintext_for_case(case);
        let encoded_identity = identity_for_case(case);
        let identity =
            HybridIdentity::parse(&encoded_identity).expect("our own encoding must re-parse");
        let recipient = our_recipient_for_case(case).to_string();

        let plaintext_path = dir.path().join(format!("d4-{case}.bin"));
        let ciphertext_path = dir.path().join(format!("d4-{case}.age"));
        fs::write(&plaintext_path, &plaintext).expect("write plaintext");

        let output = common::age_command_without_plugins()
            .args([
                "-e".as_ref(),
                "-r".as_ref(),
                recipient.as_ref(),
                "-o".as_ref(),
                ciphertext_path.as_os_str(),
                plaintext_path.as_os_str(),
            ])
            .output()
            .expect("age -e did not run");

        if !output.status.success() {
            failures.push(format!(
                "case {case} ({} byte plaintext): age -e exited with {:?}: {}",
                plaintext.len(),
                output.status.code(),
                common::safe_stderr(&output.stderr)
            ));
            continue;
        }

        let ciphertext = fs::read(&ciphertext_path).expect("read the ciphertext");
        let decryptor = match age::Decryptor::new(&ciphertext[..]) {
            Ok(d) => d,
            Err(e) => {
                failures.push(format!("case {case}: header from Go rejected ({e})"));
                continue;
            }
        };
        let mut reader = match decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity)) {
            Ok(r) => r,
            Err(e) => {
                failures.push(format!(
                    "case {case}: our identity did not unwrap Go's stanza ({e})"
                ));
                continue;
            }
        };
        let mut recovered = Vec::new();
        if let Err(e) = reader.read_to_end(&mut recovered) {
            failures.push(format!(
                "case {case} ({} byte plaintext): payload read failed ({e})",
                plaintext.len()
            ));
            continue;
        }
        if recovered != plaintext {
            failures.push(format!(
                "case {case}: we decrypted {} bytes, expected {}",
                recovered.len(),
                plaintext.len()
            ));
        }
    }

    report("D4 Go encrypt → our decrypt", ORACLE_STREAM_CASES, failures);
}
