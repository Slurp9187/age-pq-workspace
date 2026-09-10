//! Unit tests for mlkem768x25519.

use age_pq_hpke::kem::mlkem768x25519::{
    generate_keypair, Ciphertext, DecapsulationKey, EncapsulationKey,
    MLKEM768X25519_CIPHERTEXT_SIZE, MLKEM768X25519_ENCAPSULATION_KEY_SIZE,
};

use age_pq_hpke::{ConstantTimeEq, Error};
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

    assert!(ss_encap.ct_eq(&ss_decap));
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

    assert!(!ss1.ct_eq(&ss2));
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
    assert!(!ss_encap.ct_eq(&ss_decap));
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
    assert!(!ss_encap.ct_eq(&ss_decap));
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

    assert!(ss_encap.ct_eq(&ss_decap));
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
    assert!(ss_encap.ct_eq(&ss_decap));
}

/// The two halves of `eseed` are bound to their roles: `eseed[0..32]` is
/// ML-KEM randomness and `eseed[32..64]` the X25519 ephemeral scalar.
///
/// This replaces a `test_derand_invalid_eseed_length` whose body was empty. A
/// wrong `eseed` length is unrepresentable — `encapsulate_derand` takes
/// `&[u8; 64]`, so the compiler already proves that property and no runtime
/// test can. Swapping the halves is the property the empty test was reaching
/// for: it is the one `eseed` mistake the type system cannot catch.
///
/// Two properties, asserted separately because the swap alone does not imply
/// the second: (1) the halves are not interchangeable, and (2) **neither half
/// is ignored** — perturbing one half at a time must move the ciphertext. A
/// swap test on its own passes even if the implementation reads only
/// `eseed[0..32]`, which is exactly the "dropped on the floor" failure. Which
/// half feeds which role is pinned by `test_official_kat_vectors`, not here.
#[test]
fn test_derand_eseed_halves_are_bound_to_their_roles() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (sk, pk) = generate_keypair(&mut rng).unwrap();

    let mut eseed = [0u8; 64];
    rng.fill_bytes(&mut eseed);

    let mut swapped = [0u8; 64];
    swapped[0..32].copy_from_slice(&eseed[32..64]);
    swapped[32..64].copy_from_slice(&eseed[0..32]);

    let (ct, ss) = pk.encapsulate_derand(&eseed).unwrap();
    let (ct_swapped, ss_swapped) = pk.encapsulate_derand(&swapped).unwrap();

    assert_ne!(
        ct, ct_swapped,
        "swapping the ML-KEM and X25519 halves of eseed must change the ciphertext"
    );
    assert!(
        !ss.ct_eq(&ss_swapped),
        "swapping the halves must change the shared secret"
    );

    // Both are still self-consistent: the swap changed the output without
    // producing a ciphertext its own shared secret cannot reproduce.
    assert!(ss.ct_eq(&sk.decapsulate(&ct).unwrap()));
    assert!(ss_swapped.ct_eq(&sk.decapsulate(&ct_swapped).unwrap()));

    // Neither half is dropped on the floor. Perturb one half at a time and
    // require the ciphertext to move; the swap above cannot show this, because
    // swapping still changes the input to a function that reads only one half.
    for byte in [0usize, 32] {
        let mut perturbed = eseed;
        perturbed[byte] ^= 0xFF;
        let (ct_perturbed, _) = pk.encapsulate_derand(&perturbed).unwrap();
        assert_ne!(
            ct, ct_perturbed,
            "eseed[{byte}] is ignored: its half of the seed reaches no derivation"
        );
    }
}

/// A genuinely derived encapsulation key still parses — the FIPS 203 section
/// 7.2 check must not reject honest keys.
#[test]
fn valid_encapsulation_key_passes_the_ml_kem_check() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_sk, pk) = generate_keypair(&mut rng).unwrap();
    let bytes = pk.to_bytes();

    assert!(EncapsulationKey::try_from(&bytes).is_ok());
}

/// The rejection is attributable to the **ML-KEM** half specifically: the
/// X25519 half here is a genuine, non-low-order point copied from a real key,
/// so `x25519::parse_public_key` accepts it and only the modulus check can
/// fail. Mutating byte 0 and the low nibble of byte 1 pushes the first 12-bit
/// coefficient to 0xFFF = 4095, above q - 1 = 3328; the other 1182 ML-KEM
/// bytes are untouched.
#[test]
fn one_bad_ml_kem_coefficient_is_rejected_with_a_valid_x25519_half() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_sk, pk) = generate_keypair(&mut rng).unwrap();

    let mut bytes = pk.to_bytes();
    let x25519_half_before = bytes[MLKEM768X25519_ENCAPSULATION_KEY_SIZE - 32..].to_vec();
    bytes[0] = 0xFF;
    bytes[1] |= 0x0F;

    // The curve point is untouched and parses on its own.
    assert_eq!(
        &bytes[MLKEM768X25519_ENCAPSULATION_KEY_SIZE - 32..],
        x25519_half_before.as_slice()
    );

    assert!(matches!(
        EncapsulationKey::try_from(&bytes).unwrap_err(),
        Error::InvalidMlKemEncapsulationKey
    ));
}

/// Same shape, blunter mutation: the whole ML-KEM half replaced with 0xFF
/// while the X25519 half stays a real point. Without a valid curve half this
/// case could pass for the wrong reason.
#[test]
fn all_ff_ml_kem_half_is_rejected_with_a_valid_x25519_half() {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let (_sk, pk) = generate_keypair(&mut rng).unwrap();

    let mut bytes = pk.to_bytes();
    bytes[..MLKEM768X25519_ENCAPSULATION_KEY_SIZE - 32].fill(0xFF);

    assert!(matches!(
        EncapsulationKey::try_from(&bytes).unwrap_err(),
        Error::InvalidMlKemEncapsulationKey
    ));
}

/// An all-zero ML-KEM half is *valid* under section 7.2 — zero coefficients
/// are canonical — so a key that is zero in both halves must still be rejected
/// for its curve point, not for its ML-KEM half. This pins the error
/// attribution that `test_invalid_x25519_public_key_validation` depends on.
#[test]
fn all_zero_key_is_rejected_for_its_x25519_half_not_its_ml_kem_half() {
    let all_zero = [0u8; MLKEM768X25519_ENCAPSULATION_KEY_SIZE];

    // Reaching the *curve* error is itself the proof that the ML-KEM half was
    // accepted: `try_from` checks the ML-KEM half first and returns on failure,
    // so `InvalidX25519PublicKey` is only reachable past a passing section 7.2
    // check. Asserting the halves separately would need a partially-validating
    // entry point in the public API, which is precisely what this crate does
    // not offer -- see the staging note on `EncapsulationKey::try_from`.
    assert!(matches!(
        EncapsulationKey::try_from(&all_zero).unwrap_err(),
        Error::InvalidX25519PublicKey
    ));
}

/// A key that is malformed in **both** halves is attributed to the ML-KEM half,
/// because `EncapsulationKey::try_from` checks that half first.
///
/// This is the only case in this file that leaves both halves invalid, and it
/// exists to pin the check *order*: filippo.io/hpke's `hybridKEM.NewPublicKey`
/// (pq.go, `NewPublicKey`) validates the ML-KEM half before handing the tail to
/// `curve.NewPublicKey`, so age v1.3.1 reports `invalid MLKEM768-X25519 public
/// key` for this input rather than a curve error. Reversing the two lines in
/// `try_from` keeps rejecting the key but changes which error it names, and
/// nothing else in the workspace would notice.
#[test]
fn a_key_malformed_in_both_halves_is_attributed_to_the_ml_kem_half() {
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let (_sk, pk) = generate_keypair(&mut rng).unwrap();

    let mut bytes = pk.to_bytes();
    // Bad ML-KEM: first 12-bit coefficient pushed to 0xFFF = 4095 > q - 1.
    bytes[0] = 0xFF;
    bytes[1] |= 0x0F;
    // Bad curve point: all-zero is the canonical low-order point.
    bytes[MLKEM768X25519_ENCAPSULATION_KEY_SIZE - 32..].fill(0);

    // Each half really is invalid on its own, so the assertion below is about
    // ordering and not about only one of them being broken. Both control cases
    // go through `try_from`, since no half-only entry point exists.
    let mut bad_mlkem_only = pk.to_bytes();
    bad_mlkem_only[0] = 0xFF;
    bad_mlkem_only[1] |= 0x0F;
    assert!(matches!(
        EncapsulationKey::try_from(&bad_mlkem_only).unwrap_err(),
        Error::InvalidMlKemEncapsulationKey
    ));
    let mut zero_curve_only = pk.to_bytes();
    zero_curve_only[MLKEM768X25519_ENCAPSULATION_KEY_SIZE - 32..].fill(0);
    assert!(matches!(
        EncapsulationKey::try_from(&zero_curve_only).unwrap_err(),
        Error::InvalidX25519PublicKey
    ));

    assert!(matches!(
        EncapsulationKey::try_from(&bytes).unwrap_err(),
        Error::InvalidMlKemEncapsulationKey
    ));
}

/// Length is checked before contents, so a short key never reaches either
/// half's validator and cannot be misattributed to one of them.
#[test]
fn try_from_rejects_a_wrong_length_key_before_checking_either_half() {
    assert!(matches!(
        EncapsulationKey::try_from(&[0u8; 1215][..]).unwrap_err(),
        Error::InvalidEncapsulationKeyLength
    ));
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
