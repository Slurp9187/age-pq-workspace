use crate::aliases::{AeadKey32, Nonce12};
use crate::Error;
use aead::{Aead as CryptoAead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaKey, Nonce as ChaNonce};
use secure_gate::RevealSecret;
use std::result::Result;

/// HPKE AEAD algorithm ID for ChaCha20-Poly1305 (RFC 9180 Table 5).
pub(crate) const CHACHA20_POLY1305_ID: u16 = 0x0003;
const CHACHA20_POLY1305_KEY_SIZE: usize = 32;
const CHACHA20_POLY1305_NONCE_SIZE: usize = 12;
const CHACHA20_POLY1305_TAG_SIZE: usize = 16;

// Trait for CipherAead, matching Go's cipher.AEAD
pub trait CipherAead {
    fn nonce_size(&self) -> usize;
    fn seal(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>;
    fn open(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>;
}

// Trait for AEAD, matching Go's AEAD interface
pub trait Aead {
    fn id(&self) -> u16;
    fn aead(&self, key: &[u8]) -> Result<Box<dyn CipherAead>, Error>;
    fn key_size(&self) -> usize;
    fn nonce_size(&self) -> usize;
    fn tag_size(&self) -> usize;
}

// Factory function matching NewAEAD
pub fn new_aead(id: u16) -> Result<Box<dyn Aead>, Error> {
    match id {
        CHACHA20_POLY1305_ID => Ok(Box::new(ChaCha20Poly1305Aead)),
        _ => Err(Error::UnsupportedAead),
    }
}

// ChaCha20Poly1305
pub struct ChaCha20Poly1305Aead;

impl Aead for ChaCha20Poly1305Aead {
    fn id(&self) -> u16 {
        CHACHA20_POLY1305_ID
    }

    fn aead(&self, key: &[u8]) -> Result<Box<dyn CipherAead>, Error> {
        let key = AeadKey32::try_from(key).map_err(|_| Error::InvalidKeyLength)?;
        let key: ChaKey = key.with_secret(|key_bytes| *ChaKey::from_slice(key_bytes));
        let cipher = ChaCha20Poly1305::new(&key);
        Ok(Box::new(ChaChaCipher { cipher }))
    }

    fn key_size(&self) -> usize {
        CHACHA20_POLY1305_KEY_SIZE
    }

    fn nonce_size(&self) -> usize {
        CHACHA20_POLY1305_NONCE_SIZE
    }

    fn tag_size(&self) -> usize {
        CHACHA20_POLY1305_TAG_SIZE
    }
}

// Implementation for ChaCha20Poly1305
struct ChaChaCipher {
    cipher: ChaCha20Poly1305,
}

impl CipherAead for ChaChaCipher {
    fn nonce_size(&self) -> usize {
        CHACHA20_POLY1305_NONCE_SIZE
    }

    fn seal(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = Nonce12::try_from(nonce).map_err(|_| Error::InvalidLength)?;
        let nonce_bytes = nonce.with_secret(|bytes| *bytes);
        let nonce = ChaNonce::from_slice(&nonce_bytes);
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        self.cipher
            .encrypt(nonce, payload)
            .map_err(|_| Error::EncryptionFailed)
    }

    fn open(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = Nonce12::try_from(nonce).map_err(|_| Error::InvalidLength)?;
        let nonce_bytes = nonce.with_secret(|bytes| *bytes);
        let nonce = ChaNonce::from_slice(&nonce_bytes);
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        self.cipher
            .decrypt(nonce, payload)
            .map_err(|_| Error::DecryptionFailed)
    }
}
