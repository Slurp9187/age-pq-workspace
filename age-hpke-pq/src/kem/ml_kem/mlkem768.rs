//! ML-KEM-768 primitive helpers used by the hybrid X-Wing KEM.

use crate::aliases::{MlKem768Ciphertext1088, MlKem768PublicKey1184, MlKemSeed64, Seed32, SharedSecret32};
use crate::error::{Error, Result as CrateResult};
use libcrux_ml_kem::mlkem768::{
    decapsulate, encapsulate, generate_key_pair as mlkem768_generate_key_pair, MlKem768Ciphertext,
    MlKem768KeyPair, MlKem768PublicKey,
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
    // Tier-2 (forced): `into_inner` requires `Default` on the inner type;
    // stdlib only provides `Default` for `[u8; N]` with N <= 32 on MSRV 1.70.
    // The wrapper still drops (zeroizing) at end of function — same end
    // state as Tier-3, just expressed via `with_secret` deref.
    seed.with_secret(|bytes| mlkem768_generate_key_pair(*bytes))
}

/// Encapsulates to an ML-KEM-768 public key using caller-supplied randomness.
///
/// Consumes the randomness wrapper (Tier-3) — libcrux's `encapsulate` takes
/// `[u8; 32]` by value. Returns the wrapped shared secret; ciphertext bytes
/// are public (passed to the wire) and stay as a plain array.
pub(crate) fn encapsulate_with_seed(
    pk_m: &MlKem768PublicKey1184,
    randomness: Seed32,
) -> CrateResult<([u8; MLKEM768_CT_SIZE], SharedSecret32)> {
    let pk_m = pk_m.with_secret(|bytes| MlKem768PublicKey::from(*bytes));
    // Tier-3: libcrux encapsulate takes [u8; 32] randomness by value.
    let r = randomness.into_inner();
    let (ct_m, ss_m) = encapsulate(&pk_m, *r);
    let ct_m_bytes: [u8; MLKEM768_CT_SIZE] =
        ct_m.as_ref().try_into().map_err(|_| Error::ArraySizeError)?;
    Ok((ct_m_bytes, SharedSecret32::from(ss_m)))
}

/// Decapsulates an ML-KEM-768 ciphertext using a previously derived key pair.
///
/// `ct_m` is borrowed (the caller's `Ciphertext` struct keeps it). Returns
/// the wrapped shared secret.
pub(crate) fn decapsulate_with_keypair(
    kp: &MlKem768KeyPair,
    ct_m: &MlKem768Ciphertext1088,
) -> SharedSecret32 {
    let sk_m = kp.private_key();
    let ct_m = ct_m.with_secret(|bytes| MlKem768Ciphertext::from(*bytes));
    SharedSecret32::from(decapsulate(sk_m, &ct_m))
}

/// Minimal parse/shape validation for ML-KEM public-key bytes.
pub(crate) fn validate_public_key(pk_m: &MlKem768PublicKey1184) {
    pk_m.with_secret(|bytes| {
        let _ = MlKem768PublicKey::from(*bytes).as_ref();
    });
}
