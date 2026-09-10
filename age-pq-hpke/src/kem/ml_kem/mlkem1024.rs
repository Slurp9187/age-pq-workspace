//! ML-KEM-1024 primitive helpers used by the hybrid X-Wing KEM.
//!
//! Not yet wired into a hybrid orchestration module; suppress `dead_code` until callers exist.

#![allow(dead_code)]

use crate::aliases::{
    MlKem1024Ciphertext1568, MlKem1024PublicKey1568, MlKemSeed64, MlKemSharedSecret, Seed32,
};
use crate::error::{Error, Result as CrateResult};
use libcrux_ml_kem::mlkem1024::{
    decapsulate, encapsulate, generate_key_pair as mlkem1024_generate_key_pair,
    validate_public_key as mlkem1024_validate_public_key, MlKem1024Ciphertext, MlKem1024KeyPair,
    MlKem1024PublicKey,
};
use secure_gate::RevealSecret;

/// ML-KEM-1024 public-key size in bytes.
pub(crate) const MLKEM1024_PK_SIZE: usize = 1568;
/// ML-KEM-1024 ciphertext size in bytes.
pub const MLKEM1024_CT_SIZE: usize = 1568;

/// Derives an ML-KEM-1024 key pair from a wrapped 64-byte (`d || z`) seed.
pub(crate) fn keypair_from_seed(seed: MlKemSeed64) -> MlKem1024KeyPair {
    // Tier-3: seed taken by value — see mlkem768.rs.
    mlkem1024_generate_key_pair(seed.into_inner())
}

/// Encapsulates to an ML-KEM-1024 public key using caller-supplied randomness.
pub(crate) fn encapsulate_with_seed(
    pk_m: &MlKem1024PublicKey1568,
    randomness: Seed32,
) -> CrateResult<([u8; MLKEM1024_CT_SIZE], MlKemSharedSecret)> {
    let pk_m = pk_m.with_secret(|bytes| MlKem1024PublicKey::from(*bytes));
    // Tier-3: libcrux encapsulate takes [u8; 32] randomness by value.
    let (ct_m, ss_m) = encapsulate(&pk_m, randomness.into_inner());
    let ct_m_bytes: [u8; MLKEM1024_CT_SIZE] = ct_m
        .as_ref()
        .try_into()
        .map_err(|_| Error::ArraySizeError)?;
    Ok((ct_m_bytes, MlKemSharedSecret::from(ss_m)))
}

/// Decapsulates an ML-KEM-1024 ciphertext using a previously derived key pair.
pub(crate) fn decapsulate_with_keypair(
    kp: &MlKem1024KeyPair,
    ct_m: &MlKem1024Ciphertext1568,
) -> MlKemSharedSecret {
    let sk_m = kp.private_key();
    let ct_m = ct_m.with_secret(|bytes| MlKem1024Ciphertext::from(*bytes));
    MlKemSharedSecret::from(decapsulate(sk_m, &ct_m))
}

/// FIPS 203 section 7.2 encapsulation-key check — see `mlkem768.rs` for the
/// full rationale.
pub(crate) fn validate_public_key(pk_m: &MlKem1024PublicKey1568) -> CrateResult<()> {
    // Tier-1: public wire data, kept wrapped for redacted Debug and length.
    pk_m.with_secret(|bytes| {
        if mlkem1024_validate_public_key(&MlKem1024PublicKey::from(*bytes)) {
            Ok(())
        } else {
            Err(Error::InvalidMlKemEncapsulationKey)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_public_key_passes_and_a_bad_coefficient_fails() {
        let kp = keypair_from_seed(MlKemSeed64::from([7u8; 64]));
        let mut pk_bytes: [u8; MLKEM1024_PK_SIZE] = kp
            .public_key()
            .as_ref()
            .try_into()
            .expect("libcrux public key is MLKEM1024_PK_SIZE bytes");
        assert!(validate_public_key(&MlKem1024PublicKey1568::from(pk_bytes)).is_ok());

        pk_bytes[0] = 0xFF;
        pk_bytes[1] |= 0x0F;
        assert!(matches!(
            validate_public_key(&MlKem1024PublicKey1568::from(pk_bytes)),
            Err(Error::InvalidMlKemEncapsulationKey)
        ));
    }
}
