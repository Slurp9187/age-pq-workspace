// tests/kat_tests.rs

use age_hpke_pq::kem::mlkem768x25519::{DecapsulationKey, EncapsulationKey};
use age_hpke_pq::RevealSecret;
use serde::Deserialize;

use std::fs;

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const TEST_VECTORS_PATH: &str = "tests/data/test-vectors.json";

#[derive(Deserialize)]
struct TestVector {
    seed: String,
    pk: String,
    eseed: String,
    ct: String,
    ss: String,
}

#[test]
fn test_official_kat_vectors() {
    let json = fs::read_to_string(TEST_VECTORS_PATH).expect("Failed to read test-vectors.json");
    let vectors: Vec<TestVector> =
        serde_json::from_str(&json).expect("Failed to parse test vectors");

    for (i, vec) in vectors.iter().enumerate() {
        println!("Testing vector {}", i);

        // 1. Generate key pair from seed
        let seed_vec = hex_decode(&vec.seed);
        let seed: [u8; 32] = seed_vec.as_slice().try_into().expect("Invalid seed length");
        let pk = EncapsulationKey::from_seed(&seed).expect("Failed to generate key from seed");
        let sk = DecapsulationKey::from_seed(&seed);

        // 2. Check public key matches
        assert_eq!(
            pk.to_bytes().as_slice(),
            hex_decode(&vec.pk).as_slice(),
            "Public key mismatch in vector {}",
            i
        );

        // 3. Deterministic encapsulation
        let eseed_vec = hex_decode(&vec.eseed);
        let eseed: [u8; 64] = eseed_vec
            .as_slice()
            .try_into()
            .expect("Invalid eseed length");
        let (ct, ss_sender) = pk
            .encapsulate_derand(&eseed)
            .expect("Failed to encapsulate derand");

        // 4. Check ciphertext and shared secret
        assert_eq!(
            ct.to_bytes().as_slice(),
            hex_decode(&vec.ct).as_slice(),
            "Ciphertext mismatch in vector {}",
            i
        );
        let ss_expected: [u8; 32] = hex_decode(&vec.ss)
            .as_slice()
            .try_into()
            .expect("Invalid ss length");
        assert_eq!(
            ss_sender.expose_secret(),
            &ss_expected,
            "Shared secret mismatch (sender) in vector {}",
            i
        );

        // 5. Decapsulation round-trip
        let ss_receiver = sk.decapsulate(&ct).unwrap();
        assert_eq!(
            ss_receiver.expose_secret(),
            &ss_expected,
            "Shared secret mismatch (receiver) in vector {}",
            i
        );
    }
}
