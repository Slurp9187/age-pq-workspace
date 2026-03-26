//! Unit tests for mlkem768x25519.

use age_hpke_pq::kem::mlkem768x25519::{
    generate_keypair, Ciphertext, DecapsulationKey, EncapsulationKey,
    MLKEM768X25519_CIPHERTEXT_SIZE, MLKEM768X25519_ENCAPSULATION_KEY_SIZE,
};

use age_hpke_pq::Error;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

#[test]
fn test_generate_keypair() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_sk, pk) = generate_keypair(&mut rng).unwrap();

    assert_eq!(pk.to_bytes().len(), MLKEM768X25519_ENCAPSULATION_KEY_SIZE);
}

#[test]
fn test_encapsulation_decapsulation_roundtrip() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (sk, pk) = generate_keypair(&mut rng).unwrap();

    let (ct, ss_encap) = pk.encapsulate(&mut rng).unwrap();
    let ss_decap = sk.decapsulate(&ct).unwrap();

    assert_eq!(ss_encap, ss_decap);
    assert_eq!(ct.to_bytes().len(), MLKEM768X25519_CIPHERTEXT_SIZE);
}

#[test]
fn test_encapsulation_key_serialization() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_sk, pk) = generate_keypair(&mut rng).unwrap();

    let pk_bytes = pk.to_bytes();
    let pk_restored = EncapsulationKey::try_from(&pk_bytes).unwrap();

    assert_eq!(pk, pk_restored);
}

#[test]
fn test_ciphertext_serialization() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_sk, pk) = generate_keypair(&mut rng).unwrap();

    let (ct, _) = pk.encapsulate(&mut rng).unwrap();
    let ct_bytes = ct.to_bytes();
    let ct_restored = Ciphertext::try_from(&ct_bytes).unwrap();

    assert_eq!(ct, ct_restored);
}

#[test]
fn test_different_keys_produce_different_secrets() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_sk1, pk1) = generate_keypair(&mut rng).unwrap();
    let mut rng2 = ChaCha20Rng::seed_from_u64(43);
    let (_sk2, pk2) = generate_keypair(&mut rng2).unwrap();

    let (ct1, ss1) = pk1.encapsulate(&mut rng).unwrap();
    let (ct2, ss2) = pk2.encapsulate(&mut rng).unwrap();

    assert_ne!(ss1, ss2);
    assert_ne!(ct1, ct2);
}

#[test]
fn test_wrong_key_decapsulate_fails() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_sk1, pk1) = generate_keypair(&mut rng).unwrap();
    let mut rng2 = ChaCha20Rng::seed_from_u64(43);
    let (sk2, _pk2) = generate_keypair(&mut rng2).unwrap();

    let (ct, ss_encap) = pk1.encapsulate(&mut rng).unwrap();
    let ss_decap = sk2.decapsulate(&ct).unwrap();

    // Since it's hybrid, and ML-KEM decapsulates to random if wrong key,
    // but X25519 will give different ss_x, so overall different secret.
    assert_ne!(ss_encap, ss_decap);
}

#[test]
fn test_encapsulation_non_zero_ciphertext() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_, pk) = generate_keypair(&mut rng).unwrap();
    let (ct, _) = pk.encapsulate(&mut rng).unwrap();
    // Ensure CT is not all zeros
    assert!(!ct.to_bytes().iter().all(|&b| b == 0));
}

#[test]
fn test_decapsulation_modified_ciphertext_fails() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (sk, pk) = generate_keypair(&mut rng).unwrap();
    let (ct, ss_encap) = pk.encapsulate(&mut rng).unwrap();
    // Modify the CT
    let mut modified_bytes = ct.to_bytes();
    modified_bytes[0] ^= 1; // Flip a bit
    let modified_ct = Ciphertext::try_from(&modified_bytes).unwrap();
    let ss_decap = sk.decapsulate(&modified_ct).unwrap();
    // Should produce different secret
    assert_ne!(ss_encap, ss_decap);
}

#[test]
fn test_ciphertext_size() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_, pk) = generate_keypair(&mut rng).unwrap();
    let (ct, _) = pk.encapsulate(&mut rng).unwrap();
    assert_eq!(ct.to_bytes().len(), MLKEM768X25519_CIPHERTEXT_SIZE);
}

#[test]
fn test_invalid_x25519_public_key_validation() {
    // Test that all-zero X25519 public key is rejected
    let mut invalid_pk_bytes = [0u8; MLKEM768X25519_ENCAPSULATION_KEY_SIZE];
    // First 1184 bytes are ML-KEM key (leave as zeros for this test)
    // Last 32 bytes are X25519 public key - set to all zeros (invalid)
    invalid_pk_bytes[MLKEM768X25519_ENCAPSULATION_KEY_SIZE - 32..].fill(0);

    let result = EncapsulationKey::try_from(&invalid_pk_bytes);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), Error::InvalidX25519PublicKey));
}

#[test]
fn test_derand_encapsulation_decapsulation_roundtrip() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_sk, pk) = generate_keypair(&mut rng).unwrap();

    // Fixed 64-byte encapsulation seed (for derand, as per spec)
    let mut eseed = [0u8; 64];
    rng.fill_bytes(&mut eseed);

    let (ct, ss_encap) = pk.encapsulate_derand(&eseed).unwrap();
    let ss_decap = _sk.decapsulate(&ct).unwrap();

    assert_eq!(ss_encap, ss_decap);
    assert_eq!(ct.to_bytes().len(), MLKEM768X25519_CIPHERTEXT_SIZE);
}

#[test]
fn test_derand_with_all_zero_eseed() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_sk, pk) = generate_keypair(&mut rng).unwrap();

    // All-zero eseed (spec allows, but clamping ensures valid scalar)
    let eseed = [0u8; 64];

    let result = pk.encapsulate_derand(&eseed);
    assert!(result.is_ok()); // Should succeed after clamping

    let (ct, ss_encap) = result.unwrap();
    let ss_decap = _sk.decapsulate(&ct).unwrap();
    assert_eq!(ss_encap, ss_decap);
}

#[test]
fn test_derand_invalid_eseed_length() {
    // This test is conceptual; since function takes [u8;64], it can't be wrong length,
    // but if API changes, add runtime check.
    // For now, skip or mock if needed.
}

#[test]
fn test_from_seed_consistency() {
    let seed = [42u8; 32]; // Fixed seed for deterministic test
    let pk1 = EncapsulationKey::from_seed(&seed).unwrap();
    let pk2 = EncapsulationKey::from_seed(&seed).unwrap();
    assert_eq!(pk1, pk2);

    let sk = DecapsulationKey::from_seed(&seed);
    let pk_from_sk = sk.encapsulation_key().unwrap();
    assert_eq!(pk1, pk_from_sk);
}

#[test]
fn test_expand_key_determinism() {
    // This tests internal expand_key, but since it's crate-private, test via from_seed.
    let seed = [0u8; 32];
    let pk = EncapsulationKey::from_seed(&seed).unwrap();
    // Add assertions on expected sizes/output if KATs available
    assert_eq!(pk.pk_m().len(), 1184);
    assert_eq!(pk.pk_x().to_bytes().len(), 32);
}
