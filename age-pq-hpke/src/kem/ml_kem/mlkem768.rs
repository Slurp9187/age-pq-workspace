//! ML-KEM-768 primitive helpers used by the hybrid X-Wing KEM.

use crate::aliases::{
    MlKem768Ciphertext1088, MlKem768PublicKey1184, MlKemSeed64, MlKemSharedSecret, Seed32,
};
use crate::error::{Error, Result as CrateResult};
use libcrux_ml_kem::mlkem768::{
    decapsulate, encapsulate, generate_key_pair as mlkem768_generate_key_pair,
    validate_public_key as mlkem768_validate_public_key, MlKem768Ciphertext, MlKem768KeyPair,
    MlKem768PublicKey,
};
use secure_gate::RevealSecret;

/// ML-KEM-768 public-key size in bytes.
pub(crate) const MLKEM768_PK_SIZE: usize = 1184;
/// ML-KEM-768 ciphertext size in bytes.
pub const MLKEM768_CT_SIZE: usize = 1088;

/// Derives an ML-KEM-768 key pair from a wrapped 64-byte (`d || z`) seed.
///
/// Consumes the seed wrapper — libcrux's `generate_key_pair` takes
/// `[u8; 64]` by value.
pub(crate) fn keypair_from_seed(seed: MlKemSeed64) -> MlKem768KeyPair {
    // Tier-3: libcrux generate_key_pair takes the [u8; 64] `d || z` seed by
    // value. `into_inner` works at any length (SentinelValue, not Default).
    mlkem768_generate_key_pair(seed.into_inner())
}

/// Encapsulates to an ML-KEM-768 public key using caller-supplied randomness.
///
/// Consumes the randomness wrapper (Tier-3) — libcrux's `encapsulate` takes
/// `[u8; 32]` by value. Returns the wrapped shared secret; ciphertext bytes
/// are public (passed to the wire) and stay as a plain array.
pub(crate) fn encapsulate_with_seed(
    pk_m: &MlKem768PublicKey1184,
    randomness: Seed32,
) -> CrateResult<([u8; MLKEM768_CT_SIZE], MlKemSharedSecret)> {
    let pk_m = pk_m.with_secret(|bytes| MlKem768PublicKey::from(*bytes));
    // Tier-3: libcrux encapsulate takes [u8; 32] randomness by value.
    let (ct_m, ss_m) = encapsulate(&pk_m, randomness.into_inner());
    let ct_m_bytes: [u8; MLKEM768_CT_SIZE] = ct_m
        .as_ref()
        .try_into()
        .map_err(|_| Error::ArraySizeError)?;
    Ok((ct_m_bytes, MlKemSharedSecret::from(ss_m)))
}

/// Decapsulates an ML-KEM-768 ciphertext using a previously derived key pair.
///
/// `ct_m` is borrowed (the caller's `Ciphertext` struct keeps it). Returns
/// the wrapped shared secret.
pub(crate) fn decapsulate_with_keypair(
    kp: &MlKem768KeyPair,
    ct_m: &MlKem768Ciphertext1088,
) -> MlKemSharedSecret {
    let sk_m = kp.private_key();
    let ct_m = ct_m.with_secret(|bytes| MlKem768Ciphertext::from(*bytes));
    MlKemSharedSecret::from(decapsulate(sk_m, &ct_m))
}

/// FIPS 203 section 7.2 encapsulation-key check for ML-KEM-768 public-key bytes.
///
/// Part 1 of that check (the size check) is discharged by the fixed-size
/// wrapper type. Part 2 is the modulus check, which libcrux implements as
/// `ByteEncode_12(ByteDecode_12(ek)) == ek`: every 12-bit coefficient must be
/// below q = 3329, so the byte string is the canonical encoding of the
/// polynomial it decodes to. X-Wing
/// (draft-connolly-cfrg-xwing-kem-07 section 4) makes this a MUST for
/// `ML-KEM-768.Encaps`, and age rejects a recipient that fails it.
///
/// `libcrux_ml_kem::mlkem768::validate_public_key` is `#[cfg(not(eurydice))]`;
/// that gate is never set for a normal cargo build, but the call would be
/// absent under a C-extraction configuration.
pub(crate) fn validate_public_key(pk_m: &MlKem768PublicKey1184) -> CrateResult<()> {
    // Tier-1: the encapsulation key is public wire data, but stays wrapped for
    // the redacted Debug and the type-level length guarantee.
    pk_m.with_secret(|bytes| {
        if mlkem768_validate_public_key(&MlKem768PublicKey::from(*bytes)) {
            Ok(())
        } else {
            Err(Error::InvalidMlKemEncapsulationKey)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A genuinely derived encapsulation key passes the modulus check, so the
    /// check cannot be rejecting honest keys.
    #[test]
    fn derived_public_key_passes_the_modulus_check() {
        let kp = keypair_from_seed(MlKemSeed64::from([7u8; 64]));
        let pk_bytes: [u8; MLKEM768_PK_SIZE] = kp
            .public_key()
            .as_ref()
            .try_into()
            .expect("libcrux public key is MLKEM768_PK_SIZE bytes");
        let pk_m = MlKem768PublicKey1184::from(pk_bytes);
        assert!(validate_public_key(&pk_m).is_ok());
    }

    /// A single out-of-range coefficient is enough to fail the check: byte 0
    /// and the low nibble of byte 1 encode the first 12-bit coefficient, and
    /// 0xFFF = 4095 is greater than q - 1 = 3328.
    #[test]
    fn one_out_of_range_coefficient_fails_the_modulus_check() {
        let kp = keypair_from_seed(MlKemSeed64::from([7u8; 64]));
        let mut pk_bytes: [u8; MLKEM768_PK_SIZE] = kp
            .public_key()
            .as_ref()
            .try_into()
            .expect("libcrux public key is MLKEM768_PK_SIZE bytes");
        pk_bytes[0] = 0xFF;
        pk_bytes[1] |= 0x0F;
        let pk_m = MlKem768PublicKey1184::from(pk_bytes);
        assert!(matches!(
            validate_public_key(&pk_m),
            Err(Error::InvalidMlKemEncapsulationKey)
        ));
    }

    /// An all-zero encapsulation key is *valid* ML-KEM: zero coefficients
    /// round-trip through ByteEncode_12/ByteDecode_12 unchanged. Recorded as a
    /// test so nobody "fixes" the validator into rejecting it — age accepts it
    /// at parse too, and fails later on the X25519 half.
    #[test]
    fn all_zero_public_key_passes_the_modulus_check() {
        let pk_m = MlKem768PublicKey1184::from([0u8; MLKEM768_PK_SIZE]);
        assert!(validate_public_key(&pk_m).is_ok());
    }
}
