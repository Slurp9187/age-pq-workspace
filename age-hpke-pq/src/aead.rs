//! HPKE AEAD abstraction layer.
//!
//! Provides a trait-object interface over authenticated encryption algorithms
//! so that the HPKE key schedule in [`crate::hpke`] stays algorithm-agnostic.
//! Currently the only registered algorithm is ChaCha20-Poly1305 (RFC 9180
//! Table 5, `AEAD_ID = 0x0003`).

use crate::aliases::{AeadKey32, Nonce12};
use crate::Error;
use aead::{Aead as CryptoAead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaKey, Nonce as ChaNonce};
use secure_gate::RevealSecret;
use std::result::Result;

// ---------------------------------------------------------------------------
// Algorithm constants (RFC 9180 Table 5)
// ---------------------------------------------------------------------------

/// AEAD algorithm ID for ChaCha20-Poly1305.
pub(crate) const CHACHA20_POLY1305_ID: u16 = 0x0003;
const CHACHA20_POLY1305_KEY_SIZE: usize = 32;
const CHACHA20_POLY1305_NONCE_SIZE: usize = 12;
const CHACHA20_POLY1305_TAG_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// An instantiated AEAD cipher bound to a specific key.
///
/// Mirrors the Go `cipher.AEAD` interface: nonce-based seal/open with
/// associated data.
pub trait CipherAead {
    /// Returns the expected nonce length in bytes.
    fn nonce_size(&self) -> usize;
    /// Encrypts `plaintext` and authenticates `aad`, returning `ciphertext || tag`.
    fn seal(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>;
    /// Decrypts and verifies `ciphertext || tag` against `aad`.
    fn open(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>;
}

/// AEAD algorithm descriptor used by the HPKE key schedule.
///
/// Each implementation advertises its `id`, sizes, and provides a factory
/// method ([`Aead::aead`]) that keys a [`CipherAead`].
pub trait Aead {
    /// RFC 9180 AEAD identifier.
    fn id(&self) -> u16;
    /// Instantiates a keyed cipher from raw key bytes.
    fn aead(&self, key: &[u8]) -> Result<Box<dyn CipherAead>, Error>;
    /// Key length in bytes.
    fn key_size(&self) -> usize;
    /// Nonce length in bytes.
    fn nonce_size(&self) -> usize;
    /// Authentication tag length in bytes.
    fn tag_size(&self) -> usize;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Resolves an AEAD algorithm by its RFC 9180 identifier.
pub fn new_aead(id: u16) -> Result<Box<dyn Aead>, Error> {
    match id {
        CHACHA20_POLY1305_ID => Ok(Box::new(ChaCha20Poly1305Aead)),
        _ => Err(Error::UnsupportedAead),
    }
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 implementation
// ---------------------------------------------------------------------------

/// Algorithm descriptor for ChaCha20-Poly1305 (`AEAD_ID = 0x0003`).
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

/// Keyed ChaCha20-Poly1305 cipher.
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
