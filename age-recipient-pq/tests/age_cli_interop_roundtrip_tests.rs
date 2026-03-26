use age::secrecy::ExposeSecret;
use age::Encryptor;
use age_recipient_pq::HybridRecipient;
use std::fs;
use std::io::Write;
use std::iter::once;
use std::process::Command;
use tempfile::NamedTempFile;

mod common;

const LOREM_FILE: &str = "tests/data/lorem.txt";

#[test]
fn test_create_and_verify_pq_encryption_with_cli() {
    if !common::check_age_cli_version() {
        eprintln!("SKIPPED: age CLI not available");
        return;
    }

    // Generate PQ keys (same as binary)
    let (recipient, identity) = HybridRecipient::generate().unwrap();
    let recipient_str = recipient.to_string();
    let secret_str = identity.to_string();
    let identity_str = secret_str.expose_secret();

    // Write to temp files (auto-cleaned up)
    let mut temp_recipient = NamedTempFile::new().unwrap();
    temp_recipient.write_all(recipient_str.as_bytes()).unwrap();
    let mut temp_identity = NamedTempFile::new().unwrap();
    temp_identity.write_all(identity_str.as_bytes()).unwrap();

    // Encrypt plaintext from lorem.txt
    let plaintext = fs::read(LOREM_FILE).unwrap();
    let mut encrypted = Vec::new();
    {
        let encryptor =
            Encryptor::with_recipients(once(&recipient as &dyn age::Recipient)).unwrap();
        let mut e = encryptor.wrap_output(&mut encrypted).unwrap();
        e.write_all(&plaintext).unwrap();
        e.finish().unwrap();
    }

    // Save encrypted to temp file
    let mut temp_encrypted = NamedTempFile::new().unwrap();
    temp_encrypted.write_all(&encrypted).unwrap();

    // Save decrypted to temp file
    let temp_decrypted = NamedTempFile::new().unwrap();

    // Run age CLI to decrypt to file (assert success)
    let output = Command::new("age")
        .args([
            "-d",
            "-i",
            temp_identity.path().to_str().unwrap(),
            "-o",
            temp_decrypted.path().to_str().unwrap(),
            temp_encrypted.path().to_str().unwrap(),
        ])
        .output()
        .expect("age CLI failed");

    assert!(
        output.status.success(),
        "age CLI decryption failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify decrypted file matches lorem.txt exactly byte-for-byte
    assert_eq!(fs::read(temp_decrypted.path()).unwrap(), plaintext);
}
