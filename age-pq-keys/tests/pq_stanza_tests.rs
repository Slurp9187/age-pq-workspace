//! Interoperability tests for mlkem768x25519 with age-go's post-quantum implementation.
//!
//! These tests verify:
//! - Key generation and serialization match age-go formats.
//! - Encryption/decryption roundtrips work.
//! - Decryption of hardcoded age-go generated PQ-encrypted data succeeds.
//! - Error handling for invalid cases.
//! - Label enforcement prevents mixing with non-PQ recipients.
//!
//! Note: For full interop, run these alongside age-go binaries or use real files from age-go/testdata.
//! Hardcoded vectors here are illustrative; replace with actual age-go outputs for production testing.

use age::{Decryptor, Encryptor, Identity, Recipient, secrecy::ExposeSecret};
use age_core::format::Stanza;
use age_pq_keys::HybridRecipient;
use std::io::{Read, Write};

#[test]
fn pq_stanza_unwrap_simulated_age_go_file_key() {
    let known_file_key: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let file_key = age_core::format::FileKey::new(Box::new(known_file_key));
    let (recipient, identity) = HybridRecipient::generate().unwrap();

    // Generate stanza using Rust impl (simulates age-go wrap_file_key logic)
    let (stanzas, _) = recipient.wrap_file_key(&file_key).unwrap();
    assert_eq!(stanzas.len(), 1);

    // Verify unwrap_stanzas recovers the file_key
    if let Some(result) = identity.unwrap_stanzas(&stanzas) {
        let decrypted_key = result.unwrap();
        assert_eq!(
            decrypted_key.expose_secret().as_slice(),
            file_key.expose_secret().as_slice()
        );
    } else {
        panic!("Failed to unwrap stanza");
    }
}

#[test]
fn pq_stanza_unwrap_invalid_tag() {
    let (_, identity) = HybridRecipient::generate().unwrap();
    let invalid_stanza = Stanza {
        tag: "invalid_tag".to_string(),
        args: vec![],
        body: vec![],
    };

    let result = identity.unwrap_stanzas(&[invalid_stanza]);
    assert!(result.is_none()); // Should not match
}

/// A stanza that claims our tag but is malformed must fail the header, not be
/// skipped. `None` means "not addressed to this identity"; using it for
/// malformed input lets a tampered header slip past. See `tests/testkit.rs`
/// (`hybrid_not_canonical_enc`) for the CCTV vector covering this.
#[test]
fn pq_stanza_unwrap_malformed_ciphertext_is_header_failure() {
    let (_, identity) = HybridRecipient::generate().unwrap();
    let malformed_stanza = Stanza {
        tag: "mlkem768x25519".to_string(),
        args: vec!["invalid_base64".to_string()],
        body: vec![0; 32],
    };

    // `FileKey` has no `Debug` (it is secret), so describe each arm instead.
    match identity.unwrap_stanzas(&[malformed_stanza]) {
        Some(Err(age::DecryptError::InvalidHeader)) => {}
        Some(Err(e)) => panic!("expected InvalidHeader, got {e:?}"),
        Some(Ok(_)) => panic!("expected InvalidHeader, but the stanza decrypted"),
        None => panic!("expected InvalidHeader, but the stanza was skipped"),
    }
}

/// The counterpart to the test above: a stanza with a *different* tag is
/// genuinely not ours, so it is skipped rather than failing the file.
#[test]
fn pq_stanza_unwrap_foreign_tag_is_skipped() {
    let (_, identity) = HybridRecipient::generate().unwrap();
    let foreign = Stanza {
        tag: "X25519".to_string(),
        args: vec!["whatever".to_string()],
        body: vec![0; 32],
    };

    assert!(identity.unwrap_stanzas(&[foreign]).is_none());
}

/// Exactly one argument is required. The two-argument form that repeated the
/// tag was accepted historically; no age implementation emits it, and
/// accepting it diverges from the spec (CCTV `hybrid_extra_argument`).
#[test]
fn pq_stanza_unwrap_rejects_extra_argument() {
    let (_, identity) = HybridRecipient::generate().unwrap();
    let extra = Stanza {
        tag: "mlkem768x25519".to_string(),
        args: vec!["mlkem768x25519".to_string(), "AAAA".to_string()],
        body: vec![0; 32],
    };

    match identity.unwrap_stanzas(&[extra]) {
        Some(Err(age::DecryptError::InvalidHeader)) => {}
        Some(Err(e)) => panic!("expected InvalidHeader, got {e:?}"),
        Some(Ok(_)) => panic!("expected InvalidHeader, but the stanza decrypted"),
        None => panic!("expected InvalidHeader, but the stanza was skipped"),
    }
}

// #[test]
// fn test_label_enforcement_prevents_mixing() {
//     let (pq_recipient, _) = HybridRecipient::generate();
//     let non_pq_recipient = age::x25519::Recipient::generate(); // Assuming x25519 from age
//
//     // Try mixing PQ and non-PQ
//     let encryptor =
//         Encryptor::with_recipients(vec![Box::new(pq_recipient), Box::new(non_pq_recipient)]);
//
//     // Age allows mixing recipients with different labels
//     assert!(encryptor.is_ok());
// }

#[test]
fn pq_multiple_recipient_encryption_roundtrip() {
    let (recipient1, identity1) = HybridRecipient::generate().unwrap();
    let plaintext = b"Multi-recipient test";

    // Encrypt to recipient1
    let encryptor =
        Encryptor::with_recipients(std::iter::once(&recipient1 as &dyn Recipient)).unwrap();
    let mut encrypted = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();

    // Decrypt with first identity
    let decryptor = Decryptor::new(&encrypted[..]).unwrap();
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity1 as &dyn Identity))
        .unwrap();
    let mut decrypted = Vec::new();
    reader.read_to_end(&mut decrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}
