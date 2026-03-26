//! # xwing
//!
//! X-Wing hybrid post-quantum KEM (ML-KEM-512/768/1024 + X25519/X448)
//! using libcrux and x25519-dalek.
//!
//! Implements the hybrid KEM construction used by draft-ietf-hpke-pq-03.
//!
//! ## Security Properties
//!
// This implementation provides the following security properties:
// - **Constant-time operations**: All cryptographic operations execute in constant time to prevent
//   timing side-channel attacks. The underlying libraries (libcrux ML-KEM and x25519-dalek/x448) provide
//   verified constant-time implementations.
// - **Memory safety**: Sensitive data is automatically zeroized when it goes out of scope using
//   `ZeroizeOnDrop`.
// - **Input validation**: All public inputs are validated to prevent malformed data attacks.
// - **Cryptographic validation**: ML-KEM keys and X25519/X448 public keys are validated for proper format
//   and cryptographic validity.
//
// Currently provides:
// - `mlkem768x25519`: X-Wing Level 2 (ML-KEM-768 + X25519)
// - `xwing1024x25519`: X-Wing Level 3 variant (ML-KEM-1024 + X25519)
// - `xwing1024x448`: X-Wing Level 3 (ML-KEM-1024 + X448)
// - `xwing512`: ML-KEM-512 + X25519 variant (not yet implemented)
// #![no_std]
// #![deny(missing_docs)]
// #![deny(unsafe_code)]
extern crate alloc;

pub mod error;
// pub mod xwing1024x25519;
// pub mod xwing1024x448;
pub mod kem;
pub mod aliases;

// New modules for HPKE components
pub mod aead;
pub mod hpke;
pub mod kdf;

pub const XWING_DRAFT_VERSION: &str = "09";

pub const MASTER_SEED_SIZE: usize = 32;
pub const SHARED_SECRET_SIZE: usize = 32;

pub use error::{Error, Result};
pub use aliases::*;

// Re-export key HPKE components for easy access
pub use crate::aead::{new_aead, Aead, ChaCha20Poly1305Aead};
pub use hpke::{new_recipient, new_sender, new_sender_with_testing_randomness, open, seal};
pub use kdf::{new_kdf, HkdfSha256, HkdfSha384, HkdfSha512, Kdf, Shake128Kdf, Shake256Kdf};
pub use kem::{Kem, PrivateKey, PublicKey};

pub use kem::MlKem768X25519;
pub use secure_gate::ConstantTimeEq;

/// The shared secret produced by X-Wing KEM encapsulation or decapsulation.
///
/// This is a 32-byte array representing the hybrid post-quantum/classical symmetric key
/// derived from ML-KEM and X25519 components. It ensures type safety for the final output
/// of the scheme's cryptographic operations.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SharedSecret([u8; SHARED_SECRET_SIZE]);

impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SharedSecret")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0)
    }
}

impl Eq for SharedSecret {}

impl From<[u8; SHARED_SECRET_SIZE]> for SharedSecret {
    fn from(arr: [u8; SHARED_SECRET_SIZE]) -> Self {
        Self(arr)
    }
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::ops::Deref for SharedSecret {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub use hpke::compute_nonce;
