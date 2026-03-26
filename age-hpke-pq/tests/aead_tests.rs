#[cfg(test)]
use age_hpke_pq::{aead::Aead, new_aead, ChaCha20Poly1305Aead};

#[test]
fn test_new_aead_valid() {
    let aead = new_aead(0x0003).unwrap();
    assert_eq!(aead.id(), 0x0003);
}

#[test]
fn test_new_aead_invalid() {
    assert!(new_aead(0x9999).is_err());
}

#[test]
fn test_chacha_properties() {
    let chacha = ChaCha20Poly1305Aead;
    assert_eq!(chacha.id(), 0x0003);
    assert_eq!(chacha.key_size(), 32);
    assert_eq!(chacha.nonce_size(), 12);
    assert_eq!(chacha.tag_size(), 16);
}

#[test]
fn test_aead_valid_key() {
    let chacha = ChaCha20Poly1305Aead;
    let key = vec![0u8; 32];
    let _cipher = chacha.aead(&key).unwrap();
    // Successfully created
}

#[test]
fn test_aead_invalid_key() {
    let chacha = ChaCha20Poly1305Aead;
    let key = vec![0u8; 16]; // Invalid length
    assert!(chacha.aead(&key).is_err());
}

#[test]
fn test_seal_open_no_aad() {
    let chacha = ChaCha20Poly1305Aead;
    let key = vec![0u8; 32];
    let nonce = vec![0u8; 12];
    let plaintext = b"hello world";
    let aad = &[];
    let cipher = chacha.aead(&key).unwrap();
    let ciphertext = cipher.seal(&nonce, plaintext, aad).unwrap();
    let decrypted = cipher.open(&nonce, &ciphertext, aad).unwrap();
    assert_eq!(&decrypted, plaintext);
}

#[test]
fn test_seal_open_with_aad() {
    let chacha = ChaCha20Poly1305Aead;
    let key = vec![0u8; 32];
    let nonce = vec![0u8; 12];
    let plaintext = b"hello world";
    let aad = b"additional data";
    let cipher = chacha.aead(&key).unwrap();
    let ciphertext = cipher.seal(&nonce, plaintext, aad).unwrap();
    let decrypted = cipher.open(&nonce, &ciphertext, aad).unwrap();
    assert_eq!(&decrypted, plaintext);
}

#[test]
fn test_open_wrong_nonce() {
    let chacha = ChaCha20Poly1305Aead;
    let key = vec![0u8; 32];
    let nonce = vec![0u8; 12];
    let wrong_nonce = vec![1u8; 12];
    let plaintext = b"hello world";
    let aad = &[];
    let cipher = chacha.aead(&key).unwrap();
    let ciphertext = cipher.seal(&nonce, plaintext, aad).unwrap();
    assert!(cipher.open(&wrong_nonce, &ciphertext, aad).is_err());
}

#[test]
fn test_open_tampered_ciphertext() {
    let chacha = ChaCha20Poly1305Aead;
    let key = vec![0u8; 32];
    let nonce = vec![0u8; 12];
    let plaintext = b"hello world";
    let aad = &[];
    let cipher = chacha.aead(&key).unwrap();
    let mut ciphertext = cipher.seal(&nonce, plaintext, aad).unwrap();
    ciphertext[0] ^= 1; // Tamper with ciphertext
    assert!(cipher.open(&nonce, &ciphertext, aad).is_err());
}
