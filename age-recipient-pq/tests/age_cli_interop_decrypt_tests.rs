use age::{Decryptor, Identity};
use age_recipient_pq::HybridIdentity;
use std::fs;
use std::io::Read;

const ENCRYPTED_FILE: &str = "tests/data/lorem.txt.age";
const PLAINTEXT_FILE: &str = "tests/data/lorem.txt";
const IDENTITY_FILE: &str = "tests/data/age_cli_pq_identity.key";

mod common;

#[test]
fn test_decrypt_lorem_encrypted_with_age_cli() {
    if !common::check_age_cli_version() {
        eprintln!("SKIPPED: age CLI not available");
        return;
    }

    // Read the encrypted file (lorem.txt.age from age-cli)
    let encrypted_data =
        fs::read(ENCRYPTED_FILE).unwrap_or_else(|_| panic!("Failed to read {}", ENCRYPTED_FILE));

    // Read the original plaintext for comparison
    let original_plaintext =
        fs::read(PLAINTEXT_FILE).unwrap_or_else(|_| panic!("Failed to read {}", PLAINTEXT_FILE));

    // Read the secret key from age-cli (corresponds to age_cli_pq_recipient.key public key)
    let mut identity_str = fs::read_to_string(IDENTITY_FILE)
        .unwrap_or_else(|_| panic!("Failed to read {}", IDENTITY_FILE));
    identity_str = identity_str.trim().to_string();

    // Parse the identity
    let identity = HybridIdentity::parse(&identity_str).expect("Failed to parse identity");

    // Decrypt using age-recipient-pq
    let decryptor = Decryptor::new(&encrypted_data[..]).expect("Failed to create decryptor");
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn Identity))
        .expect("Failed to start decryption");

    let mut decrypted = Vec::new();
    reader
        .read_to_end(&mut decrypted)
        .expect("Failed to read decrypted data");

    // Assert it matches the original
    assert_eq!(decrypted, original_plaintext);
}
