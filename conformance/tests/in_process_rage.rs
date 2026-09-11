//! In-process differentials against rage, linked as a library.
//!
//! The companion to `age-pq-keys/tests/differential_rage.rs`, which shells out
//! to a `rage` binary. That one is the portable oracle and runs in CI on every
//! push; this one exists for the two things a subprocess cannot give:
//!
//! * **Volume.** No process spawn per case, so the derivation differential runs
//!   hundreds of cases instead of 64 in about the same wall-clock time.
//! * **Intermediate values.** The shell-out oracle observes only "the plaintext
//!   came back". Here, P2 compares the recovered **`FileKey`** — the 16 bytes
//!   the stanza actually carries — so a stanza that round-trips for the wrong
//!   reason is visible.
//!
//! # Why this is a separate workspace
//!
//! Measured, not assumed. rage's `age` crate and crates.io `age 0.12` **cannot
//! coexist in one dependency graph**:
//!
//! ```text
//! crates.io age 0.12.1 -> ml-kem ^0.2 -> ml-kem 0.2.3 -> kem =0.3.0-pre.0
//! rage's    age 0.12.1 -> ml-kem ^0.3 -> ml-kem 0.3.0 -> kem ^0.3.0
//!
//! error: failed to select a version for `kem`.
//!   all possible versions conflict with previously selected packages.
//!   previously selected package `kem v0.3.0-pre.0`
//! ```
//!
//! `ml-kem 0.2.3` pins `kem` **exactly** at a pre-release, and a pre-release
//! shares its version slot with the release, so there is no arrangement of
//! features or dev-dependency placement that resolves. Issue #15 assumed the
//! blocker was `[patch.crates-io]` being workspace-global — true, but the
//! milder of the two problems.
//!
//! `conformance/Cargo.toml` resolves it by patching `age` itself to rage, so
//! this workspace contains exactly **one** `age` crate. That has a consequence
//! worth stating plainly, because it bounds what P2 below proves:
//!
//! > `age-pq-keys` is compiled here against **rage's** `age`, not the crates.io
//! > `age 0.12` it ships against.
//!
//! So P2 is evidence that the two stanza implementations agree *given a common
//! `age` core*. It is not evidence about the crates.io build — that is what the
//! shell-out oracle and the CCTV vectors cover, and why this file supplements
//! them rather than replacing them.
//!
//! # Case derivation
//!
//! Identical to the shell-out oracles: `seed(i) = SHA-256(domain ‖ be32(i))`
//! with the same domain bytes, so case 41 is the same key here, in
//! `differential_rage.rs`, and in `differential_age_go.rs`. A disagreement
//! found here is reproducible there by index.

#![forbid(unsafe_code)]

use std::str::FromStr;

use age::secrecy::ExposeSecret as _;
use age::{Identity as _, Recipient as _};
use age_core::format::FileKey;
use age_pq_keys::{HybridIdentity, HybridRecipient};
use secure_gate::{Case, ToBech32, fixed_newtype};
use sha2::{Digest, Sha256};

fixed_newtype!(
    OracleSeed32,
    32,
    "Per-case oracle seed, derived from the case index. This is a private key."
);

/// The same bytes the shell-out oracles use. Renaming the literal would move
/// every case and break the correspondence this file's value depends on; see
/// `age-pq-keys/tests/common.rs` for the full note.
const SEED_DOMAIN: &[u8] = b"age-pq-workspace/differential-age-go/v1/seed";
const IDENTITY_HRP: &str = "age-secret-key-pq-";

/// Derivation cases (P1). No process spawn, so this is an order of magnitude
/// past what the shell-out oracle can afford.
const DERIVATION_CASES: usize = 512;

/// Floor for [`DERIVATION_CASES`]. The point of an in-process oracle is volume;
/// shrinking it to the shell-out oracle's 64 would leave this file running but
/// no longer earning the workspace it needs.
const MIN_DERIVATION_CASES: usize = 256;

/// Stanza cases (P2). Each is a full wrap + unwrap on both sides.
const STANZA_CASES: usize = 128;

/// Floor for [`STANZA_CASES`].
const MIN_STANZA_CASES: usize = 64;

const MAX_REPORTED_FAILURES: usize = 10;

fn seed_for_case(case: usize) -> OracleSeed32 {
    let mut h = Sha256::new();
    h.update(SEED_DOMAIN);
    h.update((case as u32).to_be_bytes());
    let digest = h.finalize();
    OracleSeed32::new_with(|out| out.copy_from_slice(&digest))
}

/// The case's identity in age's native uppercase form.
///
/// Returned as an owned `String` because both parsers here want `&str` and the
/// value has to outlive the `EncodedSecret` that produced it. That is a real
/// (if brief) unwrapping of a private key — acceptable in a test whose inputs
/// are all `SHA-256(committed domain ‖ index)` and reconstructible by anyone
/// with the repository, and it is never printed: every failure below reports a
/// case index and a length, never the string.
fn identity_string_for_case(case: usize) -> String {
    let encoded = seed_for_case(case)
        .try_to_bech32(IDENTITY_HRP, Case::Upper)
        .expect("a 32-byte seed always encodes");
    std::str::from_utf8(encoded.as_bytes())
        .expect("bech32 is ASCII")
        .to_owned()
}

/// A deterministic, public 16-byte file key for a case.
///
/// Public on purpose: it is compared on failure, and a real file key would then
/// reach a panic message. Derived from a separate domain so it can never
/// collide with a seed.
fn file_key_for_case(case: usize) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(b"age-pq-workspace/conformance/v1/file-key");
    h.update((case as u32).to_be_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn report(differential: &str, total: usize, failures: Vec<String>) {
    if failures.is_empty() {
        return;
    }
    let mut msg = format!(
        "{differential}: {} of {total} case(s) failed against rage (in-process)\n",
        failures.len()
    );
    for line in failures.iter().take(MAX_REPORTED_FAILURES) {
        msg.push_str("  - ");
        msg.push_str(line);
        msg.push('\n');
    }
    if failures.len() > MAX_REPORTED_FAILURES {
        msg.push_str(&format!(
            "  … and {} more\n",
            failures.len() - MAX_REPORTED_FAILURES
        ));
    }
    msg.push_str("cases are derived; re-run one by index, nothing secret needs printing");
    panic!("{msg}");
}

// ---------------------------------------------------------------------------
// Anti-gutting guard — needs no rage call
// ---------------------------------------------------------------------------

/// Floors, so this file cannot be quietly reduced to the shell-out oracle's
/// coverage while still reporting `ok`.
#[allow(clippy::assertions_on_constants)]
#[test]
fn in_process_matrix_floors_hold() {
    assert!(
        DERIVATION_CASES >= MIN_DERIVATION_CASES,
        "derivation matrix shrunk to {DERIVATION_CASES}; floor is {MIN_DERIVATION_CASES}"
    );
    assert!(
        STANZA_CASES >= MIN_STANZA_CASES,
        "stanza matrix shrunk to {STANZA_CASES}; floor is {MIN_STANZA_CASES}"
    );
    // The whole justification for this workspace is doing more than the
    // shell-out oracle can. If that stops being true, delete the workspace
    // rather than keeping a second copy of the same 64 cases.
    assert!(
        DERIVATION_CASES > 64,
        "the shell-out oracle already runs 64 derivation cases; this file must exceed it"
    );
}

// ---------------------------------------------------------------------------
// P1 — derivation, at volume
// ---------------------------------------------------------------------------

/// P1: rage and this crate derive the same recipient from the same seed, over
/// `DERIVATION_CASES` keys.
///
/// The same comparison `R1` makes, run deep enough to catch a key-dependent
/// fault that 64 cases would miss.
#[test]
fn rage_derives_the_same_recipient_in_process() {
    eprintln!("P1: in-process derivation differential, {DERIVATION_CASES} cases");
    let mut failures = vec![];

    for case in 0..DERIVATION_CASES {
        let identity_string = identity_string_for_case(case);

        let ours = HybridIdentity::parse(&identity_string)
            .expect("our own encoding must re-parse")
            .to_public()
            .expect("deriving our recipient must succeed")
            .to_string();

        let theirs = match age::pq::Identity::from_str(&identity_string) {
            Ok(id) => id.to_public().to_string(),
            Err(e) => {
                failures.push(format!("case {case}: rage rejected our identity ({e})"));
                continue;
            }
        };

        if ours != theirs {
            failures.push(format!(
                "case {case}: recipient mismatch (ours {} chars, rage {} chars)",
                ours.len(),
                theirs.len()
            ));
        }
    }

    report("P1 derivation", DERIVATION_CASES, failures);
}

// ---------------------------------------------------------------------------
// P2 — the stanza, compared at the FileKey
// ---------------------------------------------------------------------------

/// P2: each implementation unwraps the other's stanza to the **same file key**.
///
/// This is the differential a subprocess cannot make. `rage -d` tells you the
/// plaintext survived; it cannot tell you the stanza carried the file key you
/// put in, because the file key never leaves either process. Comparing the
/// recovered 16 bytes directly pins the stanza's meaning rather than its
/// downstream effect.
#[test]
fn each_side_unwraps_the_other_stanza_to_the_same_file_key() {
    eprintln!("P2: in-process stanza differential (both directions), {STANZA_CASES} cases");
    let mut failures = vec![];

    for case in 0..STANZA_CASES {
        let identity_string = identity_string_for_case(case);
        let expected = file_key_for_case(case);

        let our_identity =
            HybridIdentity::parse(&identity_string).expect("our own encoding must re-parse");
        let our_recipient = our_identity
            .to_public()
            .expect("deriving our recipient must succeed");
        let their_identity = match age::pq::Identity::from_str(&identity_string) {
            Ok(id) => id,
            Err(e) => {
                failures.push(format!("case {case}: rage rejected our identity ({e})"));
                continue;
            }
        };
        let their_recipient = their_identity.to_public();

        // --- ours -> rage -------------------------------------------------
        let (our_stanzas, _) = match our_recipient.wrap_file_key(&FileKey::new(Box::new(expected)))
        {
            Ok(v) => v,
            Err(e) => {
                failures.push(format!("case {case}: our wrap_file_key failed ({e})"));
                continue;
            }
        };
        match their_identity.unwrap_stanzas(&our_stanzas) {
            Some(Ok(fk)) => {
                let got = fk.expose_secret();
                if got[..] != expected[..] {
                    failures.push(format!(
                        "case {case}: rage unwrapped OUR stanza to a different file key"
                    ));
                }
            }
            Some(Err(e)) => failures.push(format!(
                "case {case}: rage failed to unwrap our stanza ({e})"
            )),
            None => failures.push(format!(
                "case {case}: rage did not recognise our stanza at all"
            )),
        }

        // --- rage -> ours -------------------------------------------------
        let (their_stanzas, _) =
            match their_recipient.wrap_file_key(&FileKey::new(Box::new(expected))) {
                Ok(v) => v,
                Err(e) => {
                    failures.push(format!("case {case}: rage's wrap_file_key failed ({e})"));
                    continue;
                }
            };
        match our_identity.unwrap_stanzas(&their_stanzas) {
            Some(Ok(fk)) => {
                let got = fk.expose_secret();
                if got[..] != expected[..] {
                    failures.push(format!(
                        "case {case}: we unwrapped RAGE's stanza to a different file key"
                    ));
                }
            }
            Some(Err(e)) => failures.push(format!(
                "case {case}: we failed to unwrap rage's stanza ({e})"
            )),
            None => failures.push(format!(
                "case {case}: we did not recognise rage's stanza at all"
            )),
        }
    }

    report("P2 stanza", STANZA_CASES, failures);
}

// ---------------------------------------------------------------------------
// P3 — recipient strings parse across the boundary
// ---------------------------------------------------------------------------

/// P3: each side parses the other's recipient string and re-emits it unchanged.
///
/// Cheap, and it isolates encoder drift from derivation drift: P1 compares two
/// strings that were each derived *and* encoded locally, so a shared encoding
/// bug would cancel out. Round-tripping through the other implementation's
/// parser cannot cancel.
#[test]
fn recipient_strings_round_trip_through_each_parser() {
    eprintln!("P3: in-process recipient round-trip, {DERIVATION_CASES} cases");
    let mut failures = vec![];

    for case in 0..DERIVATION_CASES {
        let identity_string = identity_string_for_case(case);
        let ours = HybridIdentity::parse(&identity_string)
            .expect("our own encoding must re-parse")
            .to_public()
            .expect("deriving our recipient must succeed")
            .to_string();

        // ours -> rage's parser -> back to a string
        match age::pq::Recipient::from_str(&ours) {
            Ok(r) if r.to_string() == ours => {}
            Ok(r) => failures.push(format!(
                "case {case}: rage re-emitted our recipient differently ({} vs {} chars)",
                r.to_string().len(),
                ours.len()
            )),
            Err(e) => failures.push(format!("case {case}: rage rejected our recipient ({e})")),
        }

        // rage's own -> our parser -> back to a string
        let theirs = match age::pq::Identity::from_str(&identity_string) {
            Ok(id) => id.to_public().to_string(),
            Err(e) => {
                failures.push(format!("case {case}: rage rejected our identity ({e})"));
                continue;
            }
        };
        match HybridRecipient::parse(&theirs) {
            Ok(r) if r.to_string() == theirs => {}
            Ok(r) => failures.push(format!(
                "case {case}: we re-emitted rage's recipient differently ({} vs {} chars)",
                r.to_string().len(),
                theirs.len()
            )),
            Err(e) => failures.push(format!("case {case}: we rejected rage's recipient ({e:?})")),
        }
    }

    report("P3 recipient round-trip", DERIVATION_CASES, failures);
}
