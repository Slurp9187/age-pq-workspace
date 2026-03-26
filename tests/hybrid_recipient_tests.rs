use age::{secrecy::ExposeSecret, Encryptor, Recipient};
use age_recipient_pq::{HybridIdentity, HybridRecipient};
use std::io::{Read, Seek, Write};
use tempfile::NamedTempFile;

#[test]
fn hybrid_recipient_keypair_generation_and_file_encryption() {
    let (recipient, identity) = HybridRecipient::generate().unwrap();

    // Save recipient to a temporary file
    let mut temp_recipient =
        NamedTempFile::new().expect("Failed to create temp file for recipient");
    temp_recipient
        .write_all(recipient.to_string().as_bytes())
        .expect("Failed to write recipient");

    // Save identity to a temporary file
    let mut temp_identity = NamedTempFile::new().expect("Failed to create temp file for identity");
    temp_identity
        .write_all(identity.to_string().expose_secret().as_bytes())
        .expect("Failed to write identity");

    // Encrypt some plaintext to a temporary file
    let plaintext = b"This is a test message for mlkem768x25519 encryption.";
    let encryptor =
        Encryptor::with_recipients(std::iter::once(&recipient as &dyn Recipient)).unwrap();
    let mut temp_encrypted =
        NamedTempFile::new().expect("Failed to create temp file for encrypted data");
    let mut writer = encryptor.wrap_output(&mut temp_encrypted).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
}

#[test]
fn hybrid_recipient_encrypt_decrypt_roundtrip() {
    let (recipient, identity) = HybridRecipient::generate().unwrap();

    let plaintext = b"This is a test message for mlkem768x25519 encryption.";

    // Encrypt
    let encryptor =
        Encryptor::with_recipients(std::iter::once(&recipient as &dyn Recipient)).unwrap();
    let mut encrypted = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();

    // Decrypt
    let decryptor = age::Decryptor::new(&encrypted[..]).unwrap();
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .unwrap();
    let mut decrypted = Vec::new();
    reader.read_to_end(&mut decrypted).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn hybrid_recipient_file_encrypt_decrypt_roundtrip() {
    let (recipient, identity) = HybridRecipient::generate().unwrap();

    let plaintext = b"This is a test message for mlkem768x25519 encryption.";

    // Encrypt to a temporary file
    let mut temp_encrypted =
        NamedTempFile::new().expect("Failed to create temp file for encrypted data");
    let encryptor =
        Encryptor::with_recipients(std::iter::once(&recipient as &dyn Recipient)).unwrap();
    let mut writer = encryptor.wrap_output(&mut temp_encrypted).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();

    // Read the encrypted data back from the file
    let mut encrypted_data = Vec::new();
    temp_encrypted.rewind().unwrap();
    temp_encrypted.read_to_end(&mut encrypted_data).unwrap();

    // Decrypt
    let decryptor = age::Decryptor::new(&encrypted_data[..]).unwrap();
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .unwrap();
    let mut decrypted = Vec::new();
    reader.read_to_end(&mut decrypted).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn hybrid_recipient_key_generation_and_serialization() {
    let (recipient, identity) = HybridRecipient::generate().unwrap();

    let pub_str = recipient.to_string();
    assert!(pub_str.starts_with("age1pq1"));
    assert!(pub_str.len() > 100); // Long PQ keys

    let priv_str = identity.to_string();
    assert!(priv_str.expose_secret().starts_with("AGE-SECRET-KEY-PQ-1"));
    assert!(priv_str.expose_secret().len() > 50);

    // Parse back
    let parsed_recipient = HybridRecipient::parse(&pub_str).unwrap();
    assert_eq!(recipient.to_string(), parsed_recipient.to_string());

    let parsed_identity = HybridIdentity::parse(priv_str.expose_secret()).unwrap();
    assert_eq!(
        identity.to_string().expose_secret(),
        parsed_identity.to_string().expose_secret()
    );
}
