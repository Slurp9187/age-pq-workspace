use age::{Encryptor, Recipient};
use age_pq_keys::{HybridIdentity, HybridRecipient};
use std::io::{Read, Seek, Write};
use tempfile::NamedTempFile;

/// A generated recipient encrypts to a file that is a real age file, and the
/// matching identity reads it back.
///
/// Previously this test had no assertions at all — it could not fail — and it
/// wrote a freshly generated **private key** to a temp file that nothing read.
/// That write is gone: a test should not put secret material on disk for no
/// reason.
#[test]
fn hybrid_recipient_keypair_generation_and_file_encryption() {
    let (recipient, identity) = HybridRecipient::generate().unwrap();

    let plaintext = b"This is a test message for mlkem768x25519 encryption.";
    let encryptor =
        Encryptor::with_recipients(std::iter::once(&recipient as &dyn Recipient)).unwrap();
    let mut temp_encrypted =
        NamedTempFile::new().expect("Failed to create temp file for encrypted data");
    let mut writer = encryptor.wrap_output(&mut temp_encrypted).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();

    let mut encrypted = Vec::new();
    temp_encrypted.rewind().unwrap();
    temp_encrypted.read_to_end(&mut encrypted).unwrap();

    // It is an age file carrying our stanza, not just some bytes.
    assert!(
        encrypted.starts_with(b"age-encryption.org/v1\n"),
        "expected an age v1 header on disk"
    );
    assert!(
        encrypted.windows(14).any(|w| w == b"mlkem768x25519"),
        "expected the hybrid stanza tag in the header"
    );
    assert!(
        encrypted.len() > plaintext.len(),
        "ciphertext must carry a header and a tag"
    );

    // And it round-trips through the file, not just through memory.
    let decryptor = age::Decryptor::new(&encrypted[..]).unwrap();
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .unwrap();
    let mut decrypted = Vec::new();
    reader.read_to_end(&mut decrypted).unwrap();
    assert_eq!(decrypted, plaintext);
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

/// `from_bytes` rejects a key whose ML-KEM half is not a canonical
/// ByteEncode_12 output, at parse time — which is where age reports it
/// ("malformed recipient ...: invalid MLKEM768-X25519 public key"), before any
/// encryption begins.
///
/// The X25519 half here is a genuine point from a real key, so the rejection
/// cannot be coming from the curve half.
#[test]
fn from_bytes_rejects_a_malformed_ml_kem_half() {
    let (recipient, _identity) = HybridRecipient::generate().unwrap();
    let mut bytes = recipient.as_bytes().to_vec();
    assert!(HybridRecipient::from_bytes(bytes.clone()).is_ok());

    // Push the first 12-bit coefficient to 0xFFF = 4095 > q - 1 = 3328.
    bytes[0] = 0xFF;
    bytes[1] |= 0x0F;
    assert!(
        HybridRecipient::from_bytes(bytes).is_err(),
        "a single out-of-range ML-KEM coefficient must be rejected at parse"
    );
}

/// The same rejection reached through the string parser, so a bech32-encoded
/// recipient with a bad ML-KEM half fails before `wrap_file_key` is ever
/// called.
#[test]
fn parse_rejects_a_recipient_string_with_a_malformed_ml_kem_half() {
    let (recipient, _identity) = HybridRecipient::generate().unwrap();
    let good = recipient.to_string();
    assert!(HybridRecipient::parse(&good).is_ok());

    let mut bytes = recipient.as_bytes().to_vec();
    bytes[0] = 0xFF;
    bytes[1] |= 0x0F;
    // Re-encode through the crate's own encoder by way of a recipient we build
    // the only way that skips the check: there is none, so encode the mutated
    // bytes with the same bech32 machinery the good string came from.
    let bad = re_encode(&bytes);
    assert!(
        HybridRecipient::parse(&bad).is_err(),
        "parse must reject a recipient age calls malformed"
    );
}

/// Encodes raw recipient bytes with the same HRP and checksum the crate uses,
/// bypassing `HybridRecipient` so the test can build a string the constructor
/// would refuse.
fn re_encode(bytes: &[u8]) -> String {
    use secure_gate::{bech32_code_length, Case, ToBech32};
    const HRP: &str = "age1pq";
    const CODE_LENGTH: usize = bech32_code_length(HRP.len(), 1216);
    bytes
        .try_to_bech32_sized::<CODE_LENGTH>(HRP, Case::Lower)
        .expect("1216 bytes always encode")
        .into_inner()
}

#[test]
fn hybrid_recipient_key_generation_and_serialization() {
    let (recipient, identity) = HybridRecipient::generate().unwrap();

    let pub_str = recipient.to_string();
    assert!(pub_str.starts_with("age1pq1"));
    assert!(pub_str.len() > 100); // Long PQ keys

    let priv_str = identity.to_string();
    assert!(priv_str.starts_with("AGE-SECRET-KEY-PQ-1"));
    assert!(priv_str.len() > 50);

    // Parse back
    let parsed_recipient = HybridRecipient::parse(&pub_str).unwrap();
    assert_eq!(recipient.to_string(), parsed_recipient.to_string());

    let parsed_identity = HybridIdentity::parse(&priv_str).unwrap();
    assert_eq!(identity.to_string(), parsed_identity.to_string());
}
