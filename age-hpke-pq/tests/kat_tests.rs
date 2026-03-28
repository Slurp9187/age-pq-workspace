//! Published known-answer tests (KATs) for KEM and KDF behavior.
//!
//! Sources:
//! - RFC 9180 Appendix A test vectors
//! - draft-ietf-hpke-pq-03 Appendix A test vectors

use age_hpke_pq::kem::mlkem768x25519::{DecapsulationKey, EncapsulationKey};
use age_hpke_pq::{kdf::Kdf, Error, HkdfSha256, RevealSecret, Shake256Kdf};
use serde::Deserialize;

use std::fs;

fn hex_decode(s: &str) -> Vec<u8> {
    let compact: String = s.split_whitespace().collect();
    (0..compact.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).unwrap())
        .collect()
}

fn hpke_suite_id(kem_id: u16, kdf_id: u16, aead_id: u16) -> [u8; 10] {
    let mut suite_id = [0u8; 10];
    suite_id[..4].copy_from_slice(b"HPKE");
    suite_id[4..6].copy_from_slice(&kem_id.to_be_bytes());
    suite_id[6..8].copy_from_slice(&kdf_id.to_be_bytes());
    suite_id[8..10].copy_from_slice(&aead_id.to_be_bytes());
    suite_id
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

#[test]
fn hkdf_sha256_rfc9180_key_schedule_vectors_match() -> Result<(), Error> {
    // RFC 9180 Appendix A.1:
    // DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM
    let kdf = HkdfSha256;
    let suite_id = hpke_suite_id(32, 1, 1);
    let shared_secret =
        hex_decode("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");
    let key_schedule_context = hex_decode(
        "00725611c9d98c07c03f60095cd32d400d8347d45ed670
         97bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f3052352
         6106f637abb05449",
    );
    let expected_secret =
        hex_decode("12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397");
    let expected_key = hex_decode("4531685d41d65f03dc48f6b8302c05b0");
    let expected_base_nonce = hex_decode("56d890e5accaaf011cff4b7d");
    let expected_exporter_secret =
        hex_decode("45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8");

    let secret = kdf.labeled_extract(&suite_id, Some(shared_secret.as_slice()), "secret", &[])?;
    assert_eq!(secret.expose_secret().as_slice(), expected_secret.as_slice());

    let key = kdf.labeled_expand(
        &suite_id,
        secret.expose_secret().as_slice(),
        "key",
        &key_schedule_context,
        16,
    )?;
    assert_eq!(key.expose_secret().as_slice(), expected_key.as_slice());

    let base_nonce = kdf.labeled_expand(
        &suite_id,
        secret.expose_secret().as_slice(),
        "base_nonce",
        &key_schedule_context,
        12,
    )?;
    assert_eq!(
        base_nonce.expose_secret().as_slice(),
        expected_base_nonce.as_slice()
    );

    let exporter_secret = kdf.labeled_expand(
        &suite_id,
        secret.expose_secret().as_slice(),
        "exp",
        &key_schedule_context,
        32,
    )?;
    assert_eq!(
        exporter_secret.expose_secret().as_slice(),
        expected_exporter_secret.as_slice()
    );

    Ok(())
}

#[test]
fn shake256_draft_hpke_pq_key_schedule_vector_matches() -> Result<(), Error> {
    // draft-ietf-hpke-pq-03 Appendix A.5:
    // QSF-X25519-MLKEM768, SHAKE256, AES-128-GCM
    let kdf = Shake256Kdf;
    let suite_id = hpke_suite_id(25722, 17, 1);
    let info = hex_decode(
        "3466363436353230366636653230363132303437373236353633363936313665
         3230353537323665",
    );
    let shared_secret = hex_decode(
        "47953ab0754bb180269445f55a488ca272b41ffe24507a6264f1d8d
         1e2826098",
    );
    let expected_secret = hex_decode(
        "44168255b16df6a4dd369364bad0215e
         275ece3cb4f1208402598fa9
         d3f07b6b8ce4d770ec483ec697ec0533510112c02b76f51d93fcd
         4a4296ae52d0b28baf2ec03882395dea009aa03d303c71201f931
         c03af325faa049e7de30cd",
    );

    let mut secrets = Vec::with_capacity(2 + 2 + shared_secret.len());
    secrets.extend_from_slice(&0u16.to_be_bytes());
    secrets.extend_from_slice(&(shared_secret.len() as u16).to_be_bytes());
    secrets.extend_from_slice(&shared_secret);

    let mut key_schedule_context = Vec::with_capacity(1 + 2 + 2 + info.len());
    key_schedule_context.push(0);
    key_schedule_context.extend_from_slice(&0u16.to_be_bytes());
    key_schedule_context.extend_from_slice(&(info.len() as u16).to_be_bytes());
    key_schedule_context.extend_from_slice(&info);

    let secret = kdf.labeled_derive(
        &suite_id,
        &secrets,
        "secret",
        &key_schedule_context,
        expected_secret.len() as u16,
    )?;
    assert_eq!(secret.expose_secret().as_slice(), expected_secret.as_slice());

    Ok(())
}
