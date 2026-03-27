//! ML-KEM-1024 primitive helpers used by the hybrid X-Wing KEM.
//!
//! Not yet wired into a hybrid orchestration module; suppress `dead_code` until callers exist.

#![allow(dead_code)]

use crate::aliases::{MlKem1024Ciphertext1568, MlKem1024PublicKey1568};
use crate::error::{Error, Result as CrateResult};
use crate::kem::common::ML_KEM_SEED_SIZE;
use libcrux_ml_kem::mlkem1024::{
    decapsulate, encapsulate, generate_key_pair as mlkem1024_generate_key_pair,
    MlKem1024Ciphertext, MlKem1024KeyPair, MlKem1024PublicKey,
};
use secure_gate::RevealSecret;

/// ML-KEM-1024 public-key size in bytes.
pub(crate) const MLKEM1024_PK_SIZE: usize = 1568;
/// ML-KEM-1024 ciphertext size in bytes.
pub const MLKEM1024_CT_SIZE: usize = 1568;

/// Derives an ML-KEM-1024 key pair from a 64-byte (`d || z`) seed.
pub(crate) fn keypair_from_seed(seed: [u8; ML_KEM_SEED_SIZE]) -> MlKem1024KeyPair {
    mlkem1024_generate_key_pair(seed)
}

/// Encapsulates to an ML-KEM-1024 public key using caller-supplied randomness.
///
/// Returns raw ciphertext bytes to match the current hybrid wire-layout helpers;
/// wrapping into `Fixed` aliases is deferred to parse/composition layers.
pub(crate) fn encapsulate_with_seed(
    pk_m: &MlKem1024PublicKey1568,
    randomness: [u8; 32],
) -> CrateResult<([u8; MLKEM1024_CT_SIZE], [u8; 32])> {
    let pk_m = pk_m.with_secret(|bytes| MlKem1024PublicKey::from(*bytes));
    let (ct_m, ss_m) = encapsulate(&pk_m, randomness);
    let ct_m_bytes: [u8; MLKEM1024_CT_SIZE] =
        ct_m.as_ref().try_into().map_err(|_| Error::ArraySizeError)?;
    Ok((ct_m_bytes, ss_m))
}

/// Decapsulates an ML-KEM-1024 ciphertext using a previously derived key pair.
pub(crate) fn decapsulate_with_keypair(
    kp: &MlKem1024KeyPair,
    ct_m: &MlKem1024Ciphertext1568,
) -> [u8; 32] {
    let sk_m = kp.private_key();
    let ct_m = ct_m.with_secret(|bytes| MlKem1024Ciphertext::from(*bytes));
    decapsulate(sk_m, &ct_m)
}

/// Minimal parse/shape validation for ML-KEM public-key bytes.
pub(crate) fn validate_public_key(pk_m: &MlKem1024PublicKey1568) {
    pk_m.with_secret(|bytes| {
        let _ = MlKem1024PublicKey::from(*bytes).as_ref();
    });
}
