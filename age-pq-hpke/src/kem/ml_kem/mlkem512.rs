//! ML-KEM-512 primitive helpers used by the hybrid X-Wing KEM.
//!
//! Not yet wired into a hybrid orchestration module; suppress `dead_code` until callers exist.

#![allow(dead_code)]

use crate::aliases::{
    MlKem512Ciphertext768, MlKem512PublicKey800, MlKemSeed64, MlKemSharedSecret, Seed32,
};
use crate::error::{Error, Result as CrateResult};
use libcrux_ml_kem::mlkem512::{
    MlKem512Ciphertext, MlKem512PublicKey, decapsulate, encapsulate,
    generate_key_pair as mlkem512_generate_key_pair,
    validate_public_key as mlkem512_validate_public_key,
};
use secure_gate::RevealSecret;

use super::WipingKeyPair;

/// ML-KEM-512 public-key size in bytes.
pub(crate) const MLKEM512_PK_SIZE: usize = 800;
/// ML-KEM-512 ciphertext size in bytes.
pub(crate) const MLKEM512_CT_SIZE: usize = 768;
/// ML-KEM-512 private (decapsulation) key size in bytes.
pub(crate) const MLKEM512_SK_SIZE: usize = 1632;

/// ML-KEM-512 key pair whose private key is wiped on drop.
pub(crate) type MlKem512Keys = WipingKeyPair<MLKEM512_SK_SIZE, MLKEM512_PK_SIZE>;

/// Derives an ML-KEM-512 key pair from a wrapped 64-byte (`d || z`) seed.
pub(crate) fn keypair_from_seed(seed: &MlKemSeed64) -> MlKem512Keys {
    // Tier-3 boundary, borrowed rather than consumed: libcrux's
    // `generate_key_pair` takes the [u8; 64] `d || z` seed by value, so one
    // plain copy exists as the call argument. The wrapper keeps ownership of
    // its own storage and wipes it on drop; `into_inner` would instead have
    // moved the seed out through a return slot first.
    WipingKeyPair::new(seed.with_secret(|s| mlkem512_generate_key_pair(*s)))
}

/// Encapsulates to an ML-KEM-512 public key using caller-supplied randomness.
pub(crate) fn encapsulate_with_seed(
    pk_m: &MlKem512PublicKey800,
    randomness: &Seed32,
) -> CrateResult<([u8; MLKEM512_CT_SIZE], MlKemSharedSecret)> {
    let pk_m = pk_m.with_secret(|bytes| MlKem512PublicKey::from(*bytes));
    // Tier-3: libcrux encapsulate takes [u8; 32] randomness by value.
    // The wrapper is borrowed, not consumed, and wipes its storage on drop.
    let (ct_m, ss_m) = randomness.with_secret(|r| encapsulate(&pk_m, *r));
    let ct_m_bytes: [u8; MLKEM512_CT_SIZE] = ct_m
        .as_ref()
        .try_into()
        .map_err(|_| Error::ArraySizeError)?;
    Ok((ct_m_bytes, MlKemSharedSecret::from(ss_m)))
}

/// Decapsulates an ML-KEM-512 ciphertext using a previously derived key pair.
pub(crate) fn decapsulate_with_keypair(
    kp: &MlKem512Keys,
    ct_m: &MlKem512Ciphertext768,
) -> MlKemSharedSecret {
    let sk_m = kp.private_key();
    let ct_m = ct_m.with_secret(|bytes| MlKem512Ciphertext::from(*bytes));
    MlKemSharedSecret::from(decapsulate(sk_m, &ct_m))
}

/// FIPS 203 section 7.2 encapsulation-key check — see `mlkem768.rs` for the
/// full rationale.
pub(crate) fn validate_public_key(pk_m: &MlKem512PublicKey800) -> CrateResult<()> {
    // Tier-1: public wire data, kept wrapped for redacted Debug and length.
    pk_m.with_secret(|bytes| {
        if mlkem512_validate_public_key(&MlKem512PublicKey::from(*bytes)) {
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
        let kp = keypair_from_seed(&MlKemSeed64::from([7u8; 64]));
        let mut pk_bytes: [u8; MLKEM512_PK_SIZE] = kp
            .public_key()
            .as_ref()
            .try_into()
            .expect("libcrux public key is MLKEM512_PK_SIZE bytes");
        assert!(validate_public_key(&MlKem512PublicKey800::from(pk_bytes)).is_ok());

        pk_bytes[0] = 0xFF;
        pk_bytes[1] |= 0x0F;
        assert!(matches!(
            validate_public_key(&MlKem512PublicKey800::from(pk_bytes)),
            Err(Error::InvalidMlKemEncapsulationKey)
        ));
    }
}
