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
//! Five differentials run here, in both directions across the boundary:
//!
//! | # | direction | what it proves |
//! |---|-----------|----------------|
//! | D1 | our identity → `age-keygen -y` | our encoder emits something Go parses, and Go's seed→recipient derivation agrees with [`HybridIdentity::to_public`] byte-for-byte |
//! | D2 | `age-keygen -pq` → our parser | our identity **and** recipient decoders accept *arbitrary fresh* Go output, re-encode it identically, and derive the same recipient Go printed |
//! | D3 | we encrypt → `age -d` | our stanza, carried inside the `age` crate's STREAM payload, is readable by Go |
//! | D4 | `age -e` → we decrypt | Go's stanza and payload are readable by us |
//! | D5 | two malformed recipients → `age -e` | age rejects a bad **ML-KEM** half at *parse* and a low-order **curve point** at *wrap*, which is the staging [`HybridRecipient::from_bytes`] is built around |
//!
//! D1-D4 are about wire format. D5 is about an **API decision**: it is the only
//! thing in the repository that would go red if a future age moved the curve
//! check earlier, at which point our `from_bytes` would start accepting
//! recipients age calls malformed. See its own doc comment for why it is the
//! one test here that reads age's stderr.
//!
//! The length matrix in D3/D4 additionally pins the **`age` crate's** STREAM
//! framing against Go's across the 64 KiB chunk boundary. That is real
//! regression value for a pinned dependency, but it is not evidence about this
//! workspace: no code here varies with plaintext length. Our contribution to
//! those two is one 16-byte file key in one stanza, identical for a 0-byte and a
//! 131 072-byte file — what the 22 cases add *for us* is 22 more distinct keys
//! through `wrap_file_key` / `unwrap_stanza`.
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
//! exercises our **decoders** against fresh Go output rather than against one
//! frozen string. Its failures report the case index and a short digest handle
//! for the recipient (public); the identity is deliberately unreportable, and
//! nothing it touches is written to disk.
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
//! * Nothing about the **age version CI runs**. D1-D4 assert on exit codes and
//!   stdout bytes only — never on stderr text, error strings, or the `# created:`
//!   timestamp, all of which differ between platforms and between the local CLI
//!   and whatever `scripts/install-age.sh` pins.
//!
//!   **D5 is the one exception, deliberately.** The *stage* at which a check
//!   runs is not visible in an exit code — both of its inputs exit 1 — so the
//!   message is the only signal there is. It matches two short substrings
//!   (`malformed recipient`, `failed to wrap key`), never a whole message, and
//!   never the version. The cost is real and accepted: a reworded age error
//!   fails D5 with no staging change behind it. Read the messages it prints
//!   before changing anything on our side.
//!
//! ## Secret hygiene
//!
//! Every identity here lives in a secure-gate wrapper for its whole life: the
//! derived ones as [`secure_gate::EncodedSecret`], the ones Go generates as
//! [`secure_gate::Dynamic`]`<String>`. Both zeroize on drop, redact in `Debug`,
//! and have **no `Display`** — a stray `{}` in a panic message is a compile
//! error rather than a key leak — and identity comparisons go through `ct_eq`.
//! No identity is written to disk: D3 pipes its key to `age -d -i -`.
//!
//! `String::from_utf8(..).expect(..)` is banned on any child's stdout here, and
//! this is not a style rule: `expect` formats the error with `{:?}`, and
//! `FromUtf8Error`'s `Debug` prints every input byte as a decimal. On D2's
//! stdout — a whole `age-keygen -pq` keyfile — one non-UTF-8 byte would put a
//! private key into a panic message that CI echoes verbatim.
//!
//! `age-keygen`'s stderr is never surfaced (it echoes the whole identity on a
//! parse failure); `age`'s own stderr goes through `common::safe_stderr`.
//! Failure messages carry a case index, a differential name, lengths, and — for
//! D2, whose cases have no index to re-run — a truncated SHA-256 handle of the
//! public recipient. Nothing else.
//!
//! ## Anti-gutting
//!
//! A test target with zero tests prints `running 0 tests … ok` and *exits 0*, so
//! a CI step that merely names this file would catch its deletion but not its
//! gutting. Worse, and measured: `#[test]` fns whose bodies are all replaced by
//! `{}` still report every one of them as passed, so a guard that counts names
//! or results is green on a completely voided oracle.
//!
//! Two mechanisms answer that, and they are aimed at different halves:
//!
//! * [`oracle_case_generation_is_pinned`] and
//!   [`identities_are_uppercase_and_match_the_crate_encoder`] are deliberately
//!   **not** `#[ignore]`d, so they run with no age binary present. The pinned
//!   digest covers the case counts, the seed derivation, the recipient
//!   derivation and the plaintext generator; the floor assertions catch a matrix
//!   shrunk to nothing; and the encoder check catches a crate-side encoding slip
//!   that leaves every other test in this file green.
//! * The `.github/workflows/ci.yml` guards require the **banners** each
//!   differential prints (`D1:` … `D5:`) to appear in the run's output. A banner
//!   is emitted only after `common::require_age_cli()` has successfully spawned
//!   the binary, so its presence is positive evidence that a body ran real work
//!   against the real CLI — which a voided body cannot fake and an `#[ignore]`d
//!   one cannot produce.
//!
//! Background and the measured CLI behaviours these tests are built around:
//! [`docs/design/age-go-differential-oracle.md`](../../docs/design/age-go-differential-oracle.md)
//! and [`docs/design/pre-freeze-audit.md`](../../docs/design/pre-freeze-audit.md).

#![forbid(unsafe_code)]

use age::Encryptor;
use age_pq_keys::{HybridIdentity, HybridRecipient};
use secure_gate::{
    fixed_newtype, Case, ConstantTimeEq, Dynamic, EncodedSecret, RevealSecret, ToBech32,
};
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

/// Floor for [`ORACLE_GO_KEYGEN_CASES`].
///
/// This one cannot be covered by [`GENERATOR_DIGEST`] — Go's keys are random, so
/// there is nothing deterministic to hash — which is exactly why it needs an
/// explicit floor. D2 is the only differential pointed at our **decoder** with
/// fresh input, and setting its count to 0 would make it pass vacuously with
/// every CI guard still green: `report()` returns early on an empty failure
/// list, and the test still counts as one that ran.
const ORACLE_MIN_GO_KEYGEN_CASES: usize = 4;

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
///
/// Encoded here rather than through [`HybridIdentity::to_string`] so the oracle
/// keeps its own, independent notion of the format — see [`IDENTITY_HRP`]. That
/// independence is only worth anything if the two are also *checked* against
/// each other, which is what
/// [`identities_are_uppercase_and_match_the_crate_encoder`] does, over every
/// case D1/D3/D4 use and with no binary present. Without that check, flipping
/// the crate's encoder to `Case::Lower` would leave every test in this file
/// green except D2.
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

/// A short, stable handle for a **public** string.
///
/// D2's cases come from Go's CSPRNG, so a failure cannot be re-run by index and
/// needs *some* correlator across its several messages. The recipient itself is
/// public and would do the job, but it is 1959 characters: eight failing cases
/// once emitted ~16 KB of bech32 into a single panic message and buried the part
/// a reader needs. A truncated digest plus the length is enough to correlate and
/// short enough to read.
fn public_handle(s: &str) -> String {
    let digest = hex_encode(&Sha256::digest(s.as_bytes()));
    format!("sha256:{}… ({} chars)", &digest[..12], s.len())
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
        ORACLE_GO_KEYGEN_CASES >= ORACLE_MIN_GO_KEYGEN_CASES,
        "the decoder matrix shrank to {ORACLE_GO_KEYGEN_CASES} case(s), below its floor of \
         {ORACLE_MIN_GO_KEYGEN_CASES}; at 0 it would pass vacuously, and it is the only \
         differential that points our decoder at fresh Go output"
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

/// A sanity check on the identities themselves, again with no binary — and the
/// only place the **crate's** identity encoder is checked without one.
///
/// Two jobs, and the second is the load-bearing one:
///
/// 1. The oracle's own identities are in age's native uppercase form. Go refuses
///    `age-secret-key-pq-…` outright, so a lowercase generator would fail every
///    case at once — but only for whoever ran the ignored tests.
/// 2. **[`HybridIdentity::to_string`] produces the very same bytes.** Without
///    this, the oracle's most-advertised claim — "our encoder emits something Go
///    parses" — would be carried by D2 alone, which is `#[ignore]`d and needs
///    `age-keygen`. Measured: flipping the crate encoder to `Case::Lower` left
///    D1, D3, D4 and the pinned-digest test all green, because bech32 decoding
///    is case-insensitive, so the recipients (and therefore the digest) do not
///    move. This assertion is what turns that slip red, on any machine, with no
///    age binary at all.
///
/// Every case D1/D3/D4 use is covered, not a sample: the check is two bech32
/// operations per case and costs no process spawn.
#[test]
fn identities_are_uppercase_and_match_the_crate_encoder() {
    for case in 0..ORACLE_CASES {
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

        // The crate's own encoder, round-tripped through its own parser. Held in
        // a `Dynamic<String>` — `to_string` returns the private key as a plain
        // `String` by design (wire-boundary rule), and this is the wrapper its
        // own docs tell callers to reach for — and compared with `ct_eq`, since
        // both sides are secret material.
        let via_crate = Dynamic::<String>::new(
            HybridIdentity::parse(&identity)
                .unwrap_or_else(|_| panic!("case {case}: our own identity encoding must re-parse"))
                .to_string(),
        );
        assert!(
            via_crate.with_secret(|s| s.as_bytes().ct_eq(identity.as_bytes())),
            "case {case}: HybridIdentity::to_string disagrees with the oracle's encoder \
             (values withheld — they are private keys). Case, HRP or checksum drift in \
             age-pq-keys would otherwise leave D1/D3/D4 green while Go rejected every identity."
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

    // Order matters, and it is the reverse of the obvious one. If `age-keygen`
    // rejects an identity it exits after the first bad line, the writer thread
    // is still mid-write and gets `BrokenPipe` (Rust ignores SIGPIPE, so this is
    // an `Err`, not a signal). Unwrapping the writer first would therefore
    // report a spawn-plumbing error in exactly the scenario the status
    // assertion below was written for: a real encoder regression.
    let writer_result = writer.join().expect("the identity writer thread panicked");
    assert!(
        output.status.success(),
        "age-keygen -y exited with {:?} (stderr withheld: it echoes the input identity)",
        output.status.code()
    );
    writer_result.expect("writing identities to age-keygen failed");

    // `from_utf8_lossy`, never `String::from_utf8(..).expect(..)`: `expect`
    // formats the error with `{:?}`, and `FromUtf8Error`'s `Debug` prints every
    // input byte as a decimal. Here that is only public recipients, but the
    // same call on D2's stdout would print a private key, so the two paths
    // deliberately do not differ in habit.
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
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
    let keygen_version = common::require_age_keygen_cli();
    eprintln!(
        "D1: derivation differential against age {version} / age-keygen {keygen_version}, \
         {ORACLE_CASES} cases"
    );

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
/// A failure therefore reports the case index and a short digest **handle** for
/// the recipient (public data) and states plainly that the identity cannot be
/// reprinted. Nothing is written to disk: `age-keygen -pq` prints the keyfile on
/// stdout, and it stays in a [`Dynamic<String>`] for its whole life here.
///
/// These are the only genuinely secret keys in this file — every other case is
/// `SHA-256(committed domain ‖ index)` and reconstructible by anyone holding the
/// repository — so this is where the wrapper discipline actually earns its keep.
#[test]
#[ignore = "requires age CLI >= 1.3 and age-keygen on PATH; run with --include-ignored"]
fn we_reparse_freshly_generated_go_keypairs() {
    let version = common::require_age_cli();
    let keygen_version = common::require_age_keygen_cli();
    eprintln!(
        "D2: decoder differential against age {version} / age-keygen {keygen_version}, \
         {ORACLE_GO_KEYGEN_CASES} cases"
    );

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

        // The keyfile is three lines: `# created:`, `# public key: `, identity —
        // and one of them is a live private key, so the whole buffer goes
        // straight into a wrapper that zeroizes on drop and redacts in `Debug`.
        //
        // `from_utf8_lossy`, never `String::from_utf8(..).expect(..)`: `expect`
        // formats the error with `{:?}`, `FromUtf8Error`'s `Debug` prints every
        // input byte as a decimal, and this stdout is the whole keyfile. A
        // single non-UTF-8 byte would put the private key in the panic message,
        // which CI echoes verbatim.
        let keyfile = Dynamic::<String>::new(String::from_utf8_lossy(&output.stdout).into_owned());

        // The recipient is public and may leave the wrapper. The identity line
        // may not: it moves into a wrapper of its own inside the same closure.
        let (go_recipient, go_identity) = keyfile.with_secret(|text| {
            (
                text.lines()
                    .find_map(|l| l.strip_prefix("# public key: "))
                    .map(|r| r.trim().to_owned()),
                text.lines()
                    .map(str::trim)
                    .find(|l| l.starts_with("AGE-SECRET-KEY-PQ-"))
                    .map(|i| Dynamic::<String>::new(i.to_owned())),
            )
        });

        let go_recipient = match go_recipient {
            Some(r) => r,
            None => {
                failures.push(format!(
                    "case {case}: no `# public key: ` line in the keyfile"
                ));
                continue;
            }
        };
        // A short digest of the (public) recipient correlates this case's
        // messages without dumping 1959 characters of bech32 per failure.
        let handle = public_handle(&go_recipient);
        let go_identity = match go_identity {
            Some(i) => i,
            None => {
                failures.push(format!(
                    "case {case}: no native identity line in the keyfile ({handle})"
                ));
                continue;
            }
        };

        let identity = match go_identity.with_secret(|s| HybridIdentity::parse(s)) {
            Ok(i) => i,
            Err(_) => {
                failures.push(format!(
                    "case {case}: our parser rejected a fresh Go identity (identity withheld; \
                     its recipient is {handle})"
                ));
                continue;
            }
        };

        // Both sides are private keys: wrapped, and compared with `ct_eq`.
        let ours_encoded = Dynamic::<String>::new(identity.to_string());
        if !ours_encoded.ct_eq(&go_identity) {
            failures.push(format!(
                "case {case}: identity did not re-encode byte-identically (values withheld; its \
                 recipient is {handle})"
            ));
        }

        let ours_recipient = match identity.to_public() {
            Ok(r) => r,
            Err(_) => {
                failures.push(format!(
                    "case {case}: deriving a recipient from Go's identity failed ({handle})"
                ));
                continue;
            }
        };
        if ours_recipient.to_string() != go_recipient {
            failures.push(format!(
                "case {case}: the recipient we derived from Go's identity differs from the one \
                 Go printed ({handle}; ours {} chars, Go's {} chars)",
                ours_recipient.to_string().len(),
                go_recipient.len()
            ));
        }

        // The recipient *decoder*, against fresh Go output. Without this, no
        // Go-produced recipient string is ever fed through `HybridRecipient::parse`
        // on a passing run: D1 only reaches it in its failure-attribution branch,
        // and D4 hands `age -e` a recipient we produced ourselves. A decoder-side
        // defect in a direction our own encoder never emits would otherwise pass
        // all four differentials.
        match HybridRecipient::parse(&go_recipient) {
            Ok(parsed) if parsed.as_bytes() == ours_recipient.as_bytes() => {}
            Ok(_) => failures.push(format!(
                "case {case}: our recipient decoder accepted Go's recipient but produced \
                 different key bytes ({handle})"
            )),
            Err(_) => failures.push(format!(
                "case {case}: our recipient decoder rejected a fresh Go recipient ({handle})"
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
/// used for the *payload* on both ends rather than pipes: 128 KiB through a
/// child's stdin while it writes more than a pipe buffer to stdout deadlocks,
/// and the deadlock is silent.
///
/// The **identity** is the exception and goes down stdin (`-i -`), so no key
/// ever lands on disk. These particular keys are `SHA-256(committed domain ‖
/// index)` and so publicly reconstructible — but "the temp file is unlinked on
/// drop" is not the same as "nothing was persisted": unlinking does not shred,
/// and drop does not run at all if the runner is killed mid-test. 77 bytes fits
/// any pipe buffer, so the writer-thread dance D1 needs is unnecessary here;
/// dropping the handle before `wait_with_output` is enough.
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

        // `-i -` reads the identity from stdin while the ciphertext stays a file
        // argument (measured against the local CLI; `-` for an identity path is
        // documented age behaviour, not a version-specific accident).
        let mut child = common::age_command_without_plugins()
            .args([
                "-d".as_ref(),
                "-i".as_ref(),
                "-".as_ref(),
                "-o".as_ref(),
                recovered_path.as_os_str(),
                ciphertext_path.as_os_str(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("age -d did not run");
        let written = {
            let mut sink = child.stdin.take().expect("stdin was requested");
            // Tier-2: `ChildStdin::write_all` takes `&[u8]`. `EncodedSecret` has
            // no `AsRef<[u8]>` on purpose, so this is the explicit hand-off.
            sink.write_all(identity.as_bytes())
                .and_then(|()| sink.write_all(b"\n"))
            // `sink` drops here, closing stdin; age reads identities to EOF.
        };
        let output = child
            .wait_with_output()
            .expect("age -d did not run to completion");
        // Checked *after* the child's status, for D1's reason: a child that
        // exits early turns this write into `BrokenPipe`, and the exit code is
        // the more informative half.
        if output.status.success() {
            written.expect("writing the identity to age's stdin failed");
        }

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

/// Encodes raw 1216-byte recipient bytes the way the crate does, bypassing
/// `HybridRecipient` so D5 can build recipients the constructor refuses.
///
/// The HRP is re-declared for [`IDENTITY_HRP`]'s reason, and checked against the
/// real encoder inside D5 before any mutated key is built — an encoder that had
/// drifted would make age reject every case for a bech32 reason and turn the
/// whole differential green and vacuous.
fn encode_recipient_bytes(bytes: &[u8]) -> String {
    const RECIPIENT_HRP: &str = "age1pq";
    const CODE_LENGTH: usize = secure_gate::bech32_code_length(RECIPIENT_HRP.len(), 1216);
    bytes
        .try_to_bech32_sized::<CODE_LENGTH>(RECIPIENT_HRP, Case::Lower)
        .expect("1216 bytes always encode")
        .into_inner()
}

/// Replaces any whitespace-delimited token longer than 64 characters with its
/// length, so a message that quotes a whole recipient stays readable.
///
/// Length only, and no digest: the caller already prints a [`public_handle`] of
/// the input it built. This runs *after* [`common::safe_stderr`], never instead
/// of it — eliding by length is not a redaction rule.
fn elide_long_tokens(s: &str) -> String {
    s.split_whitespace()
        .map(|token| {
            if token.chars().count() > 64 {
                format!("[{}-char token elided]", token.chars().count())
            } else {
                token.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// D5: age stages the two encapsulation-key checks where we stage them.
///
/// This is the differential that holds up an API decision rather than a wire
/// format. `HybridRecipient::from_bytes` validates the **ML-KEM** half and
/// deliberately does not validate the curve point; the low-order rejection
/// happens later, in `wrap_file_key`. That split exists for exactly one reason:
/// it is what age does. `hpke.MLKEM768X25519().NewPublicKey` checks the ML-KEM
/// half and then calls `crypto/ecdh`'s `NewPublicKey`, which only length-checks
/// — the low-order point is not refused until `ECDH` runs at wrap time.
///
/// Nothing else in the repository would notice if that changed. A future age
/// that hardened `ParseHybridRecipient` into rejecting the curve point would
/// leave our `from_bytes` accepting a recipient age calls malformed, and every
/// prose statement of the contract (this crate's `from_bytes` doc, the staging
/// note on `age-pq-hpke`'s `EncapsulationKey::try_from`, the design note and
/// three CHANGELOGs) would become false together, silently.
///
/// **This test asserts on age's stderr text, which the other four deliberately
/// never do.** The stage a check runs at is not observable in an exit code —
/// both inputs exit non-zero — so the message is the only signal there is. The
/// cost is accepted knowingly: a reworded age error fails this test without any
/// staging having changed. If that happens, read the messages printed below
/// before touching anything on our side.
#[test]
#[ignore = "requires age CLI >= 1.3 on PATH; run with --include-ignored"]
fn go_stages_the_encapsulation_key_checks_where_we_do() {
    let version = common::require_age_cli();
    eprintln!("D5: parse-vs-wrap staging against age {version}, 2 cases");

    let genuine = our_recipient_for_case(0);
    // The local encoder must agree with the crate's before it is used to build
    // recipients the crate would refuse to build.
    assert_eq!(
        encode_recipient_bytes(genuine.as_bytes()),
        genuine.to_string(),
        "encode_recipient_bytes no longer matches the crate's encoder"
    );

    // Case A — bad ML-KEM half, genuine curve point. Rejected at PARSE.
    let mut bad_ml_kem = genuine.as_bytes().to_vec();
    bad_ml_kem[0] = 0xFF;
    bad_ml_kem[1] |= 0x0F;

    // Case B — genuine ML-KEM half, all-zero (low-order) curve point. An
    // all-zero ML-KEM half would also be canonical, so the ML-KEM half is left
    // genuine to keep the attribution unambiguous. Rejected at WRAP.
    let mut low_order_curve = genuine.as_bytes().to_vec();
    let curve_offset = low_order_curve.len() - 32;
    low_order_curve[curve_offset..].fill(0);

    let dir = tempfile::tempdir().expect("tempdir");
    let plaintext_path = dir.path().join("d5.bin");
    fs::write(&plaintext_path, b"d5").expect("write plaintext");

    let mut failures = vec![];

    for (label, bytes, expected, forbidden) in [
        (
            "A (bad ML-KEM half)",
            &bad_ml_kem,
            "malformed recipient",
            "failed to wrap key",
        ),
        (
            "B (low-order curve point)",
            &low_order_curve,
            "failed to wrap key",
            "malformed recipient",
        ),
    ] {
        let recipient = encode_recipient_bytes(bytes);
        let output = common::age_command_without_plugins()
            .args([
                "-e".as_ref(),
                "-r".as_ref(),
                recipient.as_ref(),
                "-o".as_ref(),
                dir.path().join("d5.age").as_os_str(),
                plaintext_path.as_os_str(),
            ])
            .output()
            .expect("age -e did not run");

        // age echoes the whole recipient back in `malformed recipient %q`.
        // That is public data, but 1959 characters of bech32 in a panic message
        // buries the part a reader needs — measured, by writing this test with
        // the expectations deliberately swapped. `public_handle` correlates the
        // case; `elide_long_tokens` keeps the sentence.
        let stderr = elide_long_tokens(&common::safe_stderr(&output.stderr));
        let handle = public_handle(&recipient);

        if output.status.success() {
            failures.push(format!(
                "case {label} [{handle}]: age accepted a recipient it must reject"
            ));
            continue;
        }
        if !stderr.contains(expected) {
            failures.push(format!(
                "case {label} [{handle}]: expected {expected:?} in age's stderr, got: {stderr}"
            ));
        }
        if stderr.contains(forbidden) {
            failures.push(format!(
                "case {label} [{handle}]: age reported {forbidden:?}, so it now stages this \
                 check differently from us: {stderr}"
            ));
        }
    }

    // Our side of the same two cases, asserted here so the contract and its
    // oracle cannot drift apart in separate files.
    assert!(
        HybridRecipient::from_bytes(bad_ml_kem).is_err(),
        "we must reject a bad ML-KEM half at parse, as age does"
    );
    let deferred = HybridRecipient::from_bytes(low_order_curve)
        .expect("we must accept a low-order curve point at parse, as age does");
    // `Encryptor::with_recipients` already calls `wrap_file_key` (it needs the
    // labels), so the rejection surfaces there rather than at `wrap_output`.
    // Either is "at wrap"; chaining them keeps the assertion about the stage
    // and not about which age-rs call happens to reach it.
    let wrapped = Encryptor::with_recipients(std::iter::once(&deferred as &dyn age::Recipient))
        .map_err(|_| ())
        .and_then(|encryptor| encryptor.wrap_output(Vec::new()).map_err(|_| ()));
    assert!(
        wrapped.is_err(),
        "we must reject a low-order curve point at wrap, as age does"
    );

    report("D5 parse-vs-wrap staging", 2, failures);
}
