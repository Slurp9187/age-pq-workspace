// tests/determinism_tests.rs
use age_hpke_pq::kem::mlkem768x25519::{DecapsulationKey, EncapsulationKey};

const FIXED_SEED: [u8; 32] = [42u8; 32];
const FIXED_ESEED: [u8; 64] = [0u8; 64];

const EXPECTED_CT_FIRST_32: [u8; 32] = [
    147, 139, 23, 174, 226, 157, 69, 121, 246, 158, 250, 55, 24, 204, 77, 105, 14, 26, 86, 43, 151,
    3, 24, 119, 49, 219, 134, 49, 173, 124, 97, 182,
];
const EXPECTED_SS: [u8; 32] = [
    173, 32, 151, 51, 107, 23, 145, 2, 150, 189, 164, 109, 62, 224, 67, 37, 221, 94, 97, 4, 141,
    236, 95, 110, 127, 122, 36, 57, 140, 108, 84, 36,
];
#[test]
fn test_deterministic_key_generation() {
    let seed = [0x42u8; 32];
    let pk1 = EncapsulationKey::from_seed(&seed).expect("Failed to generate key from seed");
    let pk2 = EncapsulationKey::from_seed(&seed).expect("Failed to generate key from seed");

    // Basic consistency check
    assert_eq!(pk1, pk2);
}

#[test]
fn test_full_deterministic_flow() {
    let pk = EncapsulationKey::from_seed(&FIXED_SEED).expect("Failed to generate key from seed");
    let sk = DecapsulationKey::from_seed(&FIXED_SEED);

    let (ct1, ss1) = pk
        .encapsulate_derand(&FIXED_ESEED)
        .expect("Failed to encapsulate derand");
    let (ct2, ss2) = pk
        .encapsulate_derand(&FIXED_ESEED)
        .expect("Failed to encapsulate derand");

    assert_eq!(ct1.to_bytes().as_slice(), ct2.to_bytes().as_slice());
    assert_eq!(ss1, ss2);

    assert_eq!(&ct1.to_bytes()[..32], EXPECTED_CT_FIRST_32);
    assert_eq!(ss1.as_ref(), &EXPECTED_SS);

    let ss_decap = sk.decapsulate(&ct1).unwrap();
    assert_eq!(ss1, ss_decap);
}
