//! Published known-answer tests for the suite this workspace actually ships.
//!
//! Source: `draft-ietf-hpke-pq-05`, Appendix A.5 (`kem 25722 / kdf 1 / aead 3`
//! — MLKEM768-X25519, HKDF-SHA256, ChaCha20Poly1305, the exact suite age uses)
//! and Appendix A.12 (`kem 25722 / kdf 17 / aead 3`, the SHAKE256 one-stage
//! variant of the same KEM). The transcription lives in
//! `tests/data/hpke-pq-draft05-vectors.json`; see that file's `source` block
//! for the document hash and what was and was not carried over.
//!
//! # Why this file exists
//!
//! Before it, `0x647a` / HKDF-SHA256 / ChaCha20Poly1305 had **no
//! published-vector anchor** in this tree. `tests/kat_tests.rs` pins the KEM
//! against X-Wing's own appendix and one SHAKE key-schedule value; the rest of
//! the evidence was agreement with the Go age CLI, which is a differential, not
//! a normative one — if age and this crate drifted the same way, both would
//! stay green. These vectors are the missing anchor: they come from the draft
//! rather than from another implementation.
//!
//! # Why `key`, `base_nonce` and `exporter_secret` are not asserted directly
//!
//! The draft prints all three. They are private fields of
//! [`age_pq_hpke::hpke::Context`] and this file deliberately does **not** add a
//! public accessor to reach them: putting live key material on the crate's
//! public surface to satisfy a test is a worse trade than checking it
//! indirectly. It *is* checked indirectly, and tightly. ChaCha20-Poly1305 is
//! deterministic, so a wrong `key` or `base_nonce` cannot produce a matching
//! tag for any of the ten sealed messages, and a wrong `exporter_secret`
//! cannot produce a matching exported value. If you are here to "improve" this
//! by exposing the context internals — don't; the ciphertexts already pin them.
//!
//! The vector JSON therefore carries only values this driver reads, so no byte
//! in it is unverified data that a corruption could sit in unnoticed.

use age_pq_hpke::kem::Kem;
use age_pq_hpke::{
    Error, MlKem768X25519, new_aead, new_kdf, new_recipient, new_sender_with_testing_randomness,
};
use serde::Deserialize;
use std::fs;

const VECTORS_PATH: &str = "tests/data/hpke-pq-draft05-vectors.json";
const EXPECTED_DOCUMENT: &str = "draft-ietf-hpke-pq-05";

// ---------------------------------------------------------------------------
// Corpus shape
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Corpus {
    source: Source,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Source {
    document: String,
}

/// One appendix section.
///
/// `appendix` and `title` are stored per vector because appendix numbering is
/// not stable across draft revisions — -03's A.5 and -05's A.5 are different
/// vectors for different suites. Selection below is by numeric id regardless;
/// the title is only ever used in failure messages.
#[derive(Deserialize)]
struct Vector {
    appendix: String,
    title: String,
    mode: u8,
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    info: String,
    #[serde(rename = "ikmE")]
    ikm_e: String,
    #[serde(rename = "ikmR")]
    ikm_r: String,
    #[serde(rename = "pkRm")]
    pk_rm: String,
    #[serde(rename = "skRm")]
    sk_rm: String,
    enc: String,
    shared_secret: String,
    encryptions: Vec<Encryption>,
    exports: Vec<Export>,
}

#[derive(Deserialize)]
struct Encryption {
    sequence_number: u64,
    pt: String,
    aad: String,
    ct: String,
}

#[derive(Deserialize)]
struct Export {
    exporter_context: String,
    #[serde(rename = "L")]
    length: usize,
    exported_value: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("non-hex digit in vector"))
        .collect()
}

fn load_corpus() -> Corpus {
    let json = fs::read_to_string(VECTORS_PATH)
        .unwrap_or_else(|e| panic!("failed to read {VECTORS_PATH}: {e}"));
    serde_json::from_str(&json).expect("failed to parse the draft-05 vector corpus")
}

// ---------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------

/// Runs one appendix section end-to-end through the crate's public API.
fn run_vector(v: &Vector) -> Result<(), Error> {
    let kem = MlKem768X25519;
    let at = &v.appendix;

    // --- Suite guard ------------------------------------------------------
    //
    // Selection is by numeric id, never by title: a renamed suite (-03's
    // `QSF-X25519-MLKEM768` is -05's `MLKEM768-X25519`) must not change which
    // code path a vector exercises. These asserts also stop the driver from
    // being pointed at a section it does not implement and quietly passing.
    assert_eq!(v.mode, 0, "{at} ({}): not Base mode", v.title);
    assert_eq!(
        v.kem_id,
        kem.id(),
        "{at} ({}): kem_id is not the KEM under test",
        v.title
    );
    let kdf = new_kdf(v.kdf_id)?;
    assert_eq!(kdf.id(), v.kdf_id, "{at}: new_kdf returned another KDF");
    let aead = new_aead(v.aead_id)?;
    assert_eq!(aead.id(), v.aead_id, "{at}: new_aead returned another AEAD");

    let info = hex_decode(&v.info);
    let ikm_e = hex_decode(&v.ikm_e);
    let ikm_r = hex_decode(&v.ikm_r);
    let pk_rm = hex_decode(&v.pk_rm);
    let sk_rm = hex_decode(&v.sk_rm);
    let expected_enc = hex_decode(&v.enc);
    let expected_ss = hex_decode(&v.shared_secret);

    // --- 1. DeriveKeyPair(ikmR) -> skRm -----------------------------------
    let derived = kem.derive_key_pair(&ikm_r)?;
    assert_eq!(
        derived.bytes()?,
        sk_rm,
        "{at}: DeriveKeyPair(ikmR) does not reproduce skRm"
    );

    // --- 2. skRm -> pkRm --------------------------------------------------
    let sk = kem.new_private_key(&sk_rm)?;
    assert_eq!(
        sk.public_key().bytes(),
        pk_rm,
        "{at}: public key derived from skRm does not reproduce pkRm"
    );

    // --- 3. Deterministic encapsulation -> enc ----------------------------
    let pk = kem.new_public_key(&pk_rm)?;
    let (enc, mut sender) = new_sender_with_testing_randomness(pk, Some(&ikm_e), kdf, aead, &info)?;
    assert_eq!(enc, expected_enc, "{at}: enc mismatch");

    // --- 4. Recipient side: decap(enc) -> shared_secret -------------------
    assert_eq!(
        sk.decap(&enc)?.as_slice(),
        expected_ss.as_slice(),
        "{at}: decapsulated shared secret mismatch"
    );

    let mut recipient = new_recipient(
        kem.new_private_key(&sk_rm)?,
        &enc,
        new_kdf(v.kdf_id)?,
        new_aead(v.aead_id)?,
        &info,
    )?;

    // --- 5. Seal / open each message --------------------------------------
    //
    // `seal` and `open` advance their own counters, so the vector's sequence
    // numbers must be the contiguous run 0..n for these calls to be testing
    // the nonces the draft printed.
    for (i, e) in v.encryptions.iter().enumerate() {
        assert_eq!(
            e.sequence_number, i as u64,
            "{at}: sequence numbers are not contiguous from 0"
        );
        let pt = hex_decode(&e.pt);
        let aad = hex_decode(&e.aad);
        let expected_ct = hex_decode(&e.ct);

        let ct = sender.seal(&aad, &pt)?;
        assert_eq!(ct, expected_ct, "{at}: ct mismatch at seq {i}");

        let opened = recipient.open(&aad, &expected_ct)?;
        assert_eq!(opened, pt, "{at}: open did not recover pt at seq {i}");
    }

    // --- 6. Exported values -----------------------------------------------
    for (j, x) in v.exports.iter().enumerate() {
        let ctx = hex_decode(&x.exporter_context);
        let expected = hex_decode(&x.exported_value);
        assert_eq!(
            expected.len(),
            x.length,
            "{at}: exported_value length disagrees with L at export {j}"
        );
        assert_eq!(
            sender.export(&ctx, x.length)?,
            expected,
            "{at}: sender export mismatch at export {j}"
        );
        assert_eq!(
            recipient.export(&ctx, x.length)?,
            expected,
            "{at}: recipient export mismatch at export {j}"
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn draft05_appendix_a5_hkdf_sha256_chacha20poly1305() -> Result<(), Error> {
    let corpus = load_corpus();
    assert_eq!(
        corpus.source.document, EXPECTED_DOCUMENT,
        "vector corpus is not the draft revision this driver was written against"
    );
    // kem 25722 / kdf 1 / aead 3 — the suite age ships.
    run_vector(select(&corpus, 25722, 1, 3))
}

#[test]
fn draft05_appendix_a12_shake256_chacha20poly1305() -> Result<(), Error> {
    let corpus = load_corpus();
    assert_eq!(
        corpus.source.document, EXPECTED_DOCUMENT,
        "vector corpus is not the draft revision this driver was written against"
    );
    // kem 25722 / kdf 17 / aead 3 — same KEM, one-stage SHAKE256 key schedule.
    run_vector(select(&corpus, 25722, 17, 3))
}

/// Picks the one vector with these ids, failing loudly if the corpus does not
/// hold exactly one. Suites are addressed numerically so a title change
/// upstream cannot silently repoint a test.
fn select(corpus: &Corpus, kem_id: u16, kdf_id: u16, aead_id: u16) -> &Vector {
    let mut found = corpus
        .vectors
        .iter()
        .filter(|v| v.kem_id == kem_id && v.kdf_id == kdf_id && v.aead_id == aead_id);
    let v = found
        .next()
        .unwrap_or_else(|| panic!("no vector for kem {kem_id} / kdf {kdf_id} / aead {aead_id}"));
    assert!(
        found.next().is_none(),
        "more than one vector for kem {kem_id} / kdf {kdf_id} / aead {aead_id}"
    );
    v
}
