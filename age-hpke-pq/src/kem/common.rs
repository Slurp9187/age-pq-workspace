//! Common traits, constants, and helper functions for the X-Wing KEM.

use crate::aliases::{ExpandedKeyMaterial96, X25519Secret32};
use crate::error::{Error, Result as CrateResult};
use crate::kdf::HPKE_VERSION_LABEL;
use byteorder::{BigEndian, ByteOrder};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use secure_gate::{RevealSecret, RevealSecretMut};
use std::any::Any;

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
pub fn shake256_labeled_derive(
    suite_id: &[u8],
    input_key: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> CrateResult<Vec<u8>> {
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
    let mut out = vec![0; length];
    h.finalize_xof().read(&mut out);
    Ok(out)
}

/// Expands a 32-byte hybrid seed into ML-KEM and X25519 key material.
///
/// This mirrors `expandKey` in `hpke-pq.md`: `SHAKE256(seed, 96)` split into
/// 64 bytes for ML-KEM (`d || z`) and 32 bytes for X25519 private-key material.
///
/// The returned X25519 bytes are the raw expanded seed bytes. Clamping is
/// performed later by `kem::x25519::static_secret_from_seed`.
pub(crate) fn expand_seed(
    seed: &[u8; MASTER_SEED_SIZE],
) -> ([u8; ML_KEM_SEED_SIZE], [u8; CURVE_SEED_SIZE]) {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();

    // Expand to 64 bytes for ML-KEM (d || z) plus 32 bytes for X25519.
    let mut expanded = ExpandedKeyMaterial96::new([0u8; 96]);
    expanded.with_secret_mut(|bytes| reader.read(bytes));

    // First 64 bytes: `d || z` for libcrux ML-KEM key derivation.
    // This conversion is infallible because `expanded` is exactly 96 bytes.
    let ml_seed: [u8; ML_KEM_SEED_SIZE] =
        expanded.with_secret(|bytes| bytes[0..ML_KEM_SEED_SIZE].try_into().unwrap());

    // Next 32 bytes: raw X25519 scalar material (left unclamped here).
    //
    // hpke-go retries if the raw 32-byte seed is all-zero. This implementation
    // does not need a retry loop: RFC 7748 clamping always sets bit 6 of the
    // last byte, so the clamped scalar cannot be all-zero.
    // Same here: `[64..96]` is always exactly 32 bytes.
    let x_bytes: [u8; CURVE_SEED_SIZE] =
        expanded.with_secret(|bytes| bytes[ML_KEM_SEED_SIZE..96].try_into().unwrap());
    let x_secret = X25519Secret32::from(x_bytes);
    let x_bytes = x_secret.with_secret(|bytes| *bytes);
    (ml_seed, x_bytes)
}
