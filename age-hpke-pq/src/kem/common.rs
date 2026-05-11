//! Common traits, constants, and helper functions for the X-Wing KEM.

use crate::aliases::{ExpandedKeyMaterial96, KdfBytes, MlKemSeed64, Seed32, X25519Secret32};
use crate::error::{Error, Result as CrateResult};
use crate::kdf::HPKE_VERSION_LABEL;
use byteorder::{BigEndian, ByteOrder};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use secure_gate::RevealSecret;
use std::any::Any;
use zeroize::Zeroizing;

/// HPKE KEM identifier for MLKEM768-X25519.
pub const KEM_ID: u16 = 0x647a;
/// Size in bytes of raw X25519 scalar seed material.
pub const CURVE_SEED_SIZE: usize = 32;
/// Size in bytes of an X25519 public key / group element encoding.
pub const CURVE_POINT_SIZE: usize = 32;
/// Size in bytes of the root seed used to derive the hybrid private key.
pub const MASTER_SEED_SIZE: usize = 32;
/// Serialized private-key size exposed by this crate.
pub const PRIVATE_KEY_SIZE: usize = MASTER_SEED_SIZE;
/// Size in bytes of ML-KEM seed material (`d || z`).
pub const ML_KEM_SEED_SIZE: usize = 64;

/// Core KEM trait implemented by X-Wing variants.
pub trait Kem {
    /// Returns the HPKE KEM identifier for this algorithm.
    fn id(&self) -> u16;

    /// Generates a fresh private key using system randomness.
    fn generate_key(&self) -> CrateResult<Box<dyn PrivateKey>>;

    /// Parses a serialized public key.
    fn new_public_key(&self, data: &[u8]) -> CrateResult<Box<dyn PublicKey>>;

    /// Parses a serialized private key.
    fn new_private_key(&self, data: &[u8]) -> CrateResult<Box<dyn PrivateKey>>;

    /// Deterministically derives a private key from input keying material.
    fn derive_key_pair(&self, ikm: &[u8]) -> CrateResult<Box<dyn PrivateKey>>;

    /// Returns the ciphertext size in bytes for this KEM.
    fn enc_size(&self) -> usize;

    /// Returns the serialized public-key size in bytes for this KEM.
    fn public_key_size(&self) -> usize;
}

/// Trait implemented by X-Wing public keys.
pub trait PublicKey: Send + Sync + Any {
    /// Returns the KEM algorithm associated with this key.
    fn kem(&self) -> Box<dyn Kem>;

    /// Serializes the public key to its wire format.
    fn bytes(&self) -> Vec<u8>;

    /// Encapsulates to this public key and returns `(ciphertext, shared_secret)`.
    ///
    /// `testing_randomness`, when provided, is used only for deterministic tests.
    fn encap(
        &self,
        testing_randomness: Option<&[u8]>,
    ) -> CrateResult<(Vec<u8>, crate::SharedSecret)>;
}

/// Trait implemented by X-Wing private keys.
pub trait PrivateKey: Send + Sync + Any {
    /// Returns the KEM algorithm associated with this key.
    fn kem(&self) -> Box<dyn Kem>;

    /// Serializes the private key to its seed-based wire format.
    fn bytes(&self) -> CrateResult<Vec<u8>>;

    /// Derives the matching public key.
    fn public_key(&self) -> Box<dyn PublicKey>;

    /// Decapsulates `enc` and returns the resulting hybrid shared secret.
    fn decap(&self, enc: &[u8]) -> CrateResult<crate::SharedSecret>;
}

/// HPKE-style SHAKE256 labeled derive helper.
///
/// This matches the local `hpke-pq.md` / hpke-go `shakeKDF.labeledDerive`
/// construction:
///
/// `input_key || HPKE_VERSION_LABEL || suite_id || len(label) || label || len(L) || context`
///
/// and then expands the result with `SHAKE256(..., L)`.
///
/// `input_key` is the secret IKM and is fed once into the SHAKE absorb;
/// the helper does not retain it past the absorb call. Callers should
/// hold IKM in a wrapper (`KdfBytes`, `Seed32`, etc.) upstream and pass
/// its `expose_secret()` here.
pub(crate) fn shake256_labeled_derive(
    suite_id: &[u8],
    input_key: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> CrateResult<KdfBytes> {
    if length > u16::MAX as usize || label.len() > u16::MAX as usize {
        return Err(Error::InvalidLength);
    }
    let mut h = Shake256::default();
    h.update(input_key);
    h.update(HPKE_VERSION_LABEL);
    h.update(suite_id);
    let mut buf = [0u8; 2];
    BigEndian::write_u16(&mut buf, label.len() as u16);
    h.update(&buf);
    h.update(label);
    BigEndian::write_u16(&mut buf, length as u16);
    h.update(&buf);
    h.update(context);
    let mut out = Zeroizing::new(vec![0u8; length]);
    h.finalize_xof().read(&mut out);
    Ok(KdfBytes::new(core::mem::take(&mut *out)))
}

/// Expands a 32-byte hybrid seed into ML-KEM and X25519 key material.
///
/// This mirrors `expandKey` in `hpke-pq.md`: `SHAKE256(seed, 96)` split into
/// 64 bytes for ML-KEM (`d || z`) and 32 bytes for X25519 private-key material.
///
/// Returns wrapped seeds — both halves are written directly into wrapper
/// storage via `new_with`, eliminating the intermediate `[u8; 64]` and
/// `[u8; 32]` stack arrays the previous shape produced. The returned X25519
/// bytes are unclamped; clamping is performed by
/// `kem::x25519::static_secret_from_seed`.
///
/// `hpke-go` retries if the raw 32-byte X25519 seed is all-zero; this
/// implementation does not need a retry loop because RFC 7748 clamping
/// always sets bit 6 of the last byte, so the clamped scalar is never
/// all-zero.
pub(crate) fn expand_seed(seed: &Seed32) -> (MlKemSeed64, X25519Secret32) {
    seed.with_secret(|seed_bytes| {
        let mut hasher = Shake256::default();
        hasher.update(seed_bytes);
        let mut reader = hasher.finalize_xof();

        // Expand to 96 bytes (64 ML-KEM `d || z` + 32 X25519 scalar).
        let expanded = ExpandedKeyMaterial96::new_with(|bytes| reader.read(bytes));

        // Slice into the two wrapper halves without ever naming the raw
        // bytes in an outer binding — `new_with` writes directly into the
        // destination wrapper's storage.
        let ml = expanded.with_secret(|e| {
            MlKemSeed64::new_with(|out| out.copy_from_slice(&e[0..ML_KEM_SEED_SIZE]))
        });
        let x = expanded.with_secret(|e| {
            X25519Secret32::new_with(|out| out.copy_from_slice(&e[ML_KEM_SEED_SIZE..]))
        });
        (ml, x)
    })
}
