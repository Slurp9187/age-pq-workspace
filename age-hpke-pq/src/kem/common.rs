//! Common traits and helper functions shared across X-Wing KEM variants.

use crate::aliases::{ExpandedKeyMaterial96, X25519Secret32};
use crate::error::{Error, Result as CrateResult};
use crate::kdf::HPKE_VERSION_LABEL;
use byteorder::{BigEndian, ByteOrder};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use secure_gate::{RevealSecret, RevealSecretMut};
use std::any::Any;
use x25519_dalek::StaticSecret;

// Shared constants across variants
pub const KEM_ID: u16 = 0x647a;
pub const CURVE_SEED_SIZE: usize = 32;
pub const CURVE_POINT_SIZE: usize = 32;
pub const MASTER_SEED_SIZE: usize = 32;
pub const PRIVATE_KEY_SIZE: usize = MASTER_SEED_SIZE;
pub const ML_KEM_SEED_SIZE: usize = 64;

// Traits matching Go's interfaces

/// Core KEM trait for X-Wing variants
pub trait Kem {
    fn id(&self) -> u16;
    fn generate_key(&self) -> CrateResult<Box<dyn PrivateKey>>;
    fn new_public_key(&self, data: &[u8]) -> CrateResult<Box<dyn PublicKey>>;
    fn new_private_key(&self, data: &[u8]) -> CrateResult<Box<dyn PrivateKey>>;
    fn derive_key_pair(&self, ikm: &[u8]) -> CrateResult<Box<dyn PrivateKey>>;
    fn enc_size(&self) -> usize;
    fn public_key_size(&self) -> usize;
}

/// Public key trait for X-Wing variants
pub trait PublicKey: Send + Sync + Any {
    fn kem(&self) -> Box<dyn Kem>;
    fn bytes(&self) -> Vec<u8>;
    fn encap(
        &self,
        testing_randomness: Option<&[u8]>,
    ) -> CrateResult<(Vec<u8>, crate::SharedSecret)>;
}

/// Private key trait for X-Wing variants
pub trait PrivateKey: Send + Sync + Any {
    fn kem(&self) -> Box<dyn Kem>;
    fn bytes(&self) -> CrateResult<Vec<u8>>;
    fn public_key(&self) -> Box<dyn PublicKey>;
    fn decap(&self, enc: &[u8]) -> CrateResult<crate::SharedSecret>;
}

/// SHAKE256 labeled derive matching Go's shakeKDF.labeledDerive
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

// X25519 helper functions matching Go's ecdh.X25519().NewPrivateKey
pub fn x25519_new_private_key(seed: &[u8; CURVE_SEED_SIZE]) -> CrateResult<StaticSecret> {
    let mut s = X25519Secret32::from(*seed);
    s.with_secret_mut(clamp_x25519_scalar);
    if s.with_secret(|scalar| *scalar == [0u8; CURVE_SEED_SIZE]) {
        return Err(Error::InvalidX25519PrivateKey);
    }
    Ok(StaticSecret::from(s.with_secret(|scalar| *scalar)))
}

/// Clamp an X25519 scalar per RFC 7748 (matches hpke-go clamping).
pub fn clamp_x25519_scalar(scalar: &mut [u8; CURVE_SEED_SIZE]) {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
}

/// Seed expansion for ML-KEM + X25519 key generation.
///
/// This mirrors `expandKey` in `hpke-pq.md`: SHAKE256(seed, 96) split into
/// 64 bytes for ML-KEM (`d || z`) and 32 bytes for X25519 private key material.
pub(crate) fn expand_seed(
    seed: &[u8; MASTER_SEED_SIZE],
) -> ([u8; ML_KEM_SEED_SIZE], [u8; CURVE_SEED_SIZE]) {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();

    // Expand to 64 bytes for ML-KEM (d || z) + 32 bytes for X25519 = 96 bytes total
    let mut expanded = ExpandedKeyMaterial96::new([0u8; 96]);
    expanded.with_secret_mut(|bytes| reader.read(bytes));

    // First 64 bytes: d || z for libcrux (implicit mode)
    // This conversion is infallible because `expanded` is exactly 96 bytes.
    let ml_seed: [u8; ML_KEM_SEED_SIZE] =
        expanded.with_secret(|bytes| bytes[0..ML_KEM_SEED_SIZE].try_into().unwrap());

    // Next 32 bytes: X25519 scalar material (unclamped here; clamped in DH).
    //
    // Go retries if the raw 32-byte seed is all-zero. We don't need a retry
    // loop: RFC 7748 clamping always sets bit 6 of the last byte, so the
    // clamped scalar cannot be all-zero.
    // Same here: `[64..96]` is always exactly 32 bytes.
    let x_bytes: [u8; CURVE_SEED_SIZE] =
        expanded.with_secret(|bytes| bytes[ML_KEM_SEED_SIZE..96].try_into().unwrap());
    let x_secret = X25519Secret32::from(x_bytes);
    let x_bytes = x_secret.with_secret(|bytes| *bytes);
    (ml_seed, x_bytes)
}
