//! ML-KEM-512 primitive helpers used by the hybrid X-Wing KEM.
//!
//! Not yet wired into a hybrid orchestration module; suppress `dead_code` until callers exist.

#![allow(dead_code)]

use crate::aliases::{MlKem512Ciphertext768, MlKem512PublicKey800, MlKemSeed64, Seed32, SharedSecret32};
use crate::error::{Error, Result as CrateResult};
use libcrux_ml_kem::mlkem512::{
    decapsulate, encapsulate, generate_key_pair as mlkem512_generate_key_pair, MlKem512Ciphertext,
    MlKem512KeyPair, MlKem512PublicKey,
};
use secure_gate::RevealSecret;

/// ML-KEM-512 public-key size in bytes.
pub(crate) const MLKEM512_PK_SIZE: usize = 800;
/// ML-KEM-512 ciphertext size in bytes.
pub const MLKEM512_CT_SIZE: usize = 768;

/// Derives an ML-KEM-512 key pair from a wrapped 64-byte (`d || z`) seed.
pub(crate) fn keypair_from_seed(seed: MlKemSeed64) -> MlKem512KeyPair {
    // Tier-2 (forced): [u8; 64] lacks Default on MSRV 1.70 — see mlkem768.rs.
    seed.with_secret(|bytes| mlkem512_generate_key_pair(*bytes))
}

/// Encapsulates to an ML-KEM-512 public key using caller-supplied randomness.
pub(crate) fn encapsulate_with_seed(
    pk_m: &MlKem512PublicKey800,
    randomness: Seed32,
) -> CrateResult<([u8; MLKEM512_CT_SIZE], SharedSecret32)> {
    let pk_m = pk_m.with_secret(|bytes| MlKem512PublicKey::from(*bytes));
    // Tier-3: libcrux encapsulate takes [u8; 32] randomness by value.
    let r = randomness.into_inner();
    let (ct_m, ss_m) = encapsulate(&pk_m, *r);
    let ct_m_bytes: [u8; MLKEM512_CT_SIZE] =
        ct_m.as_ref().try_into().map_err(|_| Error::ArraySizeError)?;
    Ok((ct_m_bytes, SharedSecret32::from(ss_m)))
}

/// Decapsulates an ML-KEM-512 ciphertext using a previously derived key pair.
pub(crate) fn decapsulate_with_keypair(
    kp: &MlKem512KeyPair,
    ct_m: &MlKem512Ciphertext768,
) -> SharedSecret32 {
    let sk_m = kp.private_key();
    let ct_m = ct_m.with_secret(|bytes| MlKem512Ciphertext::from(*bytes));
    SharedSecret32::from(decapsulate(sk_m, &ct_m))
}

/// Minimal parse/shape validation for ML-KEM public-key bytes.
pub(crate) fn validate_public_key(pk_m: &MlKem512PublicKey800) {
    pk_m.with_secret(|bytes| {
        let _ = MlKem512PublicKey::from(*bytes).as_ref();
    });
}
