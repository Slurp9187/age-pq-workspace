// tests/derand_tests.rs

use age_hpke_pq::kem::mlkem768x25519::{DecapsulationKey, EncapsulationKey};

const EXPECTED_CT_FIRST_32: [u8; 32] = [
    54, 105, 219, 179, 32, 45, 144, 182, 129, 59, 255, 3, 160, 229, 52, 47, 115, 181, 184, 250,
    140, 153, 171, 238, 31, 5, 154, 246, 58, 239, 88, 190,
];
const EXPECTED_SS: [u8; 32] = [
    87, 163, 123, 43, 122, 136, 22, 114, 19, 190, 75, 53, 147, 171, 207, 198, 188, 82, 119, 45,
    210, 218, 113, 98, 107, 157, 76, 142, 0, 103, 116, 186,
];

#[test]
fn test_derandomized_encapsulation() {
    let seed = [0u8; 32]; // or any fixed seed
    let pk = EncapsulationKey::from_seed(&seed).expect("Failed to generate key from seed");

    let eseed = [1u8; 64]; // fixed encapsulation seed
    let (ct, ss) = pk
        .encapsulate_derand(&eseed)
        .expect("Failed to encapsulate derand");
    // Assert against known values for strong regression checks
    assert_eq!(&ct.to_bytes()[..32], EXPECTED_CT_FIRST_32);
    assert_eq!(ss.as_ref(), &EXPECTED_SS);

    // Verify round-trip
    let sk = DecapsulationKey::from_seed(&seed);
    let ss_decap = sk.decapsulate(&ct).unwrap();
    assert_eq!(ss, ss_decap);
}
