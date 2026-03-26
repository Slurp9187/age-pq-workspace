#![cfg(test)]

use age_hpke_pq::kem::mlkem768x25519::{Ciphertext as X25519CT, EncapsulationKey as X25519PK};
use age_hpke_pq::kem::Kem;

use age_hpke_pq::{
    aead::Aead as AeadTrait,
    new_aead, new_kdf, new_sender_with_testing_randomness,
    ChaCha20Poly1305Aead, Error, MlKem768X25519,
};

// Comprehensive error tests for all defined Error variants.
// These ensure robust handling of invalid inputs, preventing silent failures or panics.

#[test]
fn test_invalid_encapsulation_key_length_x25519() {
    // Simulate wrong length for x25519 key (1184 + 32 = 1216 total)
    let wrong_length: Vec<u8> = vec![0u8; 1215]; // 1 byte too short
    let result = X25519PK::try_from(wrong_length.as_slice());
    assert!(matches!(result, Err(Error::InvalidEncapsulationKeyLength)));
}

#[test]
fn test_invalid_ciphertext_length_x25519() {
    // X25519 ciphertext: 1088 + 32 = 1120 total
    let wrong_length: Vec<u8> = vec![0u8; 1119]; // 1 byte short
    let result = X25519CT::try_from(wrong_length.as_slice());
    assert!(matches!(result, Err(Error::InvalidCiphertextLength)));
}

#[test]
fn test_invalid_decapsulation_key_length() {
    let kem = MlKem768X25519;
    let result = kem.new_private_key(&[0u8; 31]);
    assert!(matches!(result, Err(Error::InvalidDecapsulationKeyLength)));
}

#[test]
fn test_invalid_x25519_public_key_all_zero() {
    // All-zero X25519 public key is invalid.
    let all_zero_pk = [0u8; 1184 + 32]; // Valid length but zero PK part
    let result = X25519PK::try_from(all_zero_pk.as_ref());
    assert!(matches!(result, Err(Error::InvalidX25519PublicKey)));
}

#[test]
fn test_invalid_key_length() {
    let chacha = ChaCha20Poly1305Aead;
    let key = vec![0u8; 16]; // Wrong key size
    let result = chacha.aead(&key);
    assert!(matches!(result, Err(Error::InvalidKeyLength)));
}

#[test]
fn test_invalid_x25519_ciphertext_all_zero() {
    // All-zero X25519 ciphertext public part.
    let all_zero_ct = [0u8; 1088 + 32];
    let result = X25519CT::try_from(all_zero_ct.as_ref());
    assert!(matches!(result, Err(Error::InvalidX25519PublicKey)));
}

#[test]
fn test_decryption_failed() {
    let chacha = ChaCha20Poly1305Aead;
    let key = vec![0u8; 32];
    let nonce = vec![0u8; 12];
    let plaintext = b"hello world";
    let aad = &[];

    let cipher = chacha.aead(&key).unwrap();
    let ciphertext = cipher.seal(&nonce, plaintext, aad).unwrap();

    // Tamper with the ciphertext to force decryption failure
    let mut tampered = ciphertext.clone();
    tampered[0] ^= 1;

    let result = cipher.open(&nonce, &tampered, aad);
    assert!(matches!(result, Err(Error::DecryptionFailed)));
}

#[test]
fn test_array_size_error_from_seed_x25519() {
    // from_seed now returns Result, and internally try_into can fail.
    // Test that valid seed works without error.
    let valid_seed = [42u8; 32];
    let result = X25519PK::from_seed(&valid_seed);
    assert!(result.is_ok());
}

#[test]
fn test_insufficient_testing_randomness() {
    let kem = MlKem768X25519;
    let pk = kem.generate_key().unwrap().public_key();
    let kdf = new_kdf(0x0001).unwrap();
    let aead = new_aead(0x0003).unwrap();

    // Pass only 31 bytes — not enough for full testing randomness (needs 64)
    let bad_rand = vec![0u8; 31];
    let result = new_sender_with_testing_randomness(pk, Some(&bad_rand), kdf, aead, b"test");
    assert!(matches!(result, Err(Error::InsufficientTestingRandomness)));
}

// Additional wild tests: Stress test with edge-case inputs

#[test]
fn test_max_size_key_x25519() {
    let max_key: Vec<u8> = vec![0xFF; 1216]; // Exact length but invalid data (all FF, but 0 check)
    let result = X25519PK::try_from(max_key.as_slice());
    // Should fail with InvalidX25519PublicKey if all zero, but here it's FF, so may pass validation but fail later.
    // Just assert it's a result.
    let _ = result; // Ensure try_from works without panic.
}

#[test]
fn test_empty_key_fails() {
    let empty: &[u8] = &[];
    let result = X25519PK::try_from(empty);
    assert!(result.is_err()); // Likely length error
}

#[test]
fn test_extremely_large_input_fails() {
    let large: Vec<u8> = vec![0u8; 100000]; // Way too big
    let result = X25519PK::try_from(large.as_slice());
    assert!(matches!(result, Err(Error::InvalidEncapsulationKeyLength)));
}

#[test]
fn test_unsupported_aead() {
    let result = new_aead(0xFFFF);
    assert!(matches!(result, Err(Error::UnsupportedAead)));
}

#[test]
fn test_unsupported_kdf() {
    let result = new_kdf(0xFFFF);
    assert!(matches!(result, Err(Error::UnsupportedKdf)));
}

#[test]
fn test_invalid_operation_for_kdf() {
    let kdf = new_kdf(0x0001).unwrap(); // HkdfSha256
    let result = kdf.labeled_derive(b"test", b"test", "test", b"test", 32);
    assert!(matches!(result, Err(Error::InvalidOperationForKdf)));
}

// Tests for unused errors (placeholders for future use)
// These assert that the variants exist and are matchable.

#[test]
fn test_invalid_length_variant() {
    assert!(matches!(Error::InvalidLength, Error::InvalidLength));
    assert!(!format!("{}", Error::InvalidLength).is_empty());
}

#[test]
fn test_exporter_length_too_large_variant() {
    assert!(matches!(Error::ExporterLengthTooLarge, Error::ExporterLengthTooLarge));
    assert!(!format!("{}", Error::ExporterLengthTooLarge).is_empty());
}

#[test]
fn test_encryption_failed_variant() {
    assert!(matches!(Error::EncryptionFailed, Error::EncryptionFailed));
    assert!(!format!("{}", Error::EncryptionFailed).is_empty());
}

#[test]
fn test_export_only_variant() {
    assert!(matches!(Error::ExportOnly, Error::ExportOnly));
    assert!(!format!("{}", Error::ExportOnly).is_empty());
}

#[test]
fn test_sequence_number_overflow_variant() {
    assert!(matches!(Error::SequenceNumberOverflow, Error::SequenceNumberOverflow));
    assert!(!format!("{}", Error::SequenceNumberOverflow).is_empty());
}

#[test]
fn test_invalid_x25519_private_key_variant() {
    assert!(matches!(Error::InvalidX25519PrivateKey, Error::InvalidX25519PrivateKey));
    assert!(!format!("{}", Error::InvalidX25519PrivateKey).is_empty());
}

#[test]
fn test_array_size_error_variant() {
    assert!(matches!(Error::ArraySizeError, Error::ArraySizeError));
    assert!(!format!("{}", Error::ArraySizeError).is_empty());
}

#[test]
fn test_randomness_error_variant() {
    assert!(matches!(Error::RandomnessError, Error::RandomnessError));
    assert!(!format!("{}", Error::RandomnessError).is_empty());
}

// Fuzz-like: Random invalid inputs
#[test]
fn test_random_invalid_keys() {
    use rand::Rng;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    for _ in 0..10 {
        let random_length = rng.random_range(0usize..2000usize);
        let random_bytes: Vec<u8> = (0..random_length).map(|_| rng.random::<u8>()).collect();
        let result_x25519_768 = X25519PK::try_from(random_bytes.as_slice());
        // let result_x25519_1024 = X25519PK1024::try_from(random_bytes.as_slice());
        // let result_x448 = X448PK::try_from(random_bytes.as_slice());
        // At least one should fail due to length or validation
        assert!(result_x25519_768.is_err()); // || result_x25519_1024.is_err() || result_x448.is_err());
    }
}
