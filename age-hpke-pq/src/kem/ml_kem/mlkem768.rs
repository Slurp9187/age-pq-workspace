//! ML-KEM-768 primitive helpers used by the hybrid X-Wing KEM.

use crate::aliases::{MlKem768Ciphertext1088, MlKem768PublicKey1184};
use crate::error::{Error, Result as CrateResult};
use crate::kem::common::ML_KEM_SEED_SIZE;
use libcrux_ml_kem::mlkem768::{
    decapsulate, encapsulate, generate_key_pair as mlkem768_generate_key_pair, MlKem768Ciphertext,
    MlKem768KeyPair, MlKem768PublicKey,
};
use secure_gate::RevealSecret;

/// ML-KEM-768 public-key size in bytes.
pub(crate) const MLKEM768_PK_SIZE: usize = 1184;
/// ML-KEM-768 ciphertext size in bytes.
pub const MLKEM768_CT_SIZE: usize = 1088;

/// Derives an ML-KEM-768 key pair from a 64-byte (`d || z`) seed.
pub(crate) fn keypair_from_seed(seed: [u8; ML_KEM_SEED_SIZE]) -> MlKem768KeyPair {
    mlkem768_generate_key_pair(seed)
}

/// Encapsulates to an ML-KEM-768 public key using caller-supplied randomness.
///
/// Returns raw ciphertext bytes to match the current hybrid wire-layout helpers;
/// wrapping into `Fixed` aliases is deferred to parse/composition layers.
pub(crate) fn encapsulate_with_seed(
    pk_m: &MlKem768PublicKey1184,
    randomness: [u8; 32],
) -> CrateResult<([u8; MLKEM768_CT_SIZE], [u8; 32])> {
    let pk_m = pk_m.with_secret(|bytes| MlKem768PublicKey::from(*bytes));
    let (ct_m, ss_m) = encapsulate(&pk_m, randomness);
    let ct_m_bytes: [u8; MLKEM768_CT_SIZE] =
        ct_m.as_ref().try_into().map_err(|_| Error::ArraySizeError)?;
    Ok((ct_m_bytes, ss_m))
}

/// Decapsulates an ML-KEM-768 ciphertext using a previously derived key pair.
pub(crate) fn decapsulate_with_keypair(
    kp: &MlKem768KeyPair,
    ct_m: &MlKem768Ciphertext1088,
) -> [u8; 32] {
    let sk_m = kp.private_key();
    let ct_m = ct_m.with_secret(|bytes| MlKem768Ciphertext::from(*bytes));
    decapsulate(sk_m, &ct_m)
}

/// Minimal parse/shape validation for ML-KEM public-key bytes.
pub(crate) fn validate_public_key(pk_m: &MlKem768PublicKey1184) {
    pk_m.with_secret(|bytes| {
        let _ = MlKem768PublicKey::from(*bytes).as_ref();
    });
}
