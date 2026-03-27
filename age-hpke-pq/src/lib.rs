//! # age-hpke-pq
//!
//! Post-quantum hybrid X-Wing KEM (ML-KEM-768 + X25519) with full HPKE support.
//!
//! This crate implements the hybrid post-quantum KEM construction from
//! [draft-ietf-hpke-pq-03](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-03)
//! using formally verified primitives from `libcrux` and `x25519-dalek`.
//!
//! ## Security Properties
//!
//! - **Constant-time operations**: All cryptographic primitives are constant-time to
//!   prevent timing side-channel attacks.
//! - **Memory safety**: Sensitive values are wrapped in `secure-gate::Fixed` and
//!   automatically zeroized on drop via `ZeroizeOnDrop`.
//! - **Explicit secret access**: All access to secret bytes requires an explicit
//!   `with_secret()` or `expose_secret()` call (no `Deref` or `AsRef`).
//! - **Constant-time equality**: Use `ConstantTimeEq` (re-exported) instead of `==`
//!   for secret values.
//!
//! ## Main Types
//!
//! - [`MlKem768X25519`]: The primary hybrid KEM (Level 2).
//! - [`SharedSecret`]: The final 32-byte hybrid shared secret (public API).
//! - [`Kem`]: Trait for generic KEM usage.
//! - [`new_sender`], [`new_recipient`]: High-level HPKE construction functions.
//!
//! ## Usage
//!
//! ```rust
//! use age_hpke_pq::{MlKem768X25519, kem::Kem, RevealSecret, ConstantTimeEq};
//!
//! let kem = MlKem768X25519;
//! let sk = kem.generate_key().unwrap();
//! let pk = sk.public_key();
//!
//! let (enc, ss) = pk.encap(None).unwrap();
//! let ss2 = sk.decap(&enc).unwrap();
//!
//! assert!(ss.ct_eq(&ss2));
//! ```

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
pub use secure_gate::{ConstantTimeEq, RevealSecret};

pub use hpke::compute_nonce;
