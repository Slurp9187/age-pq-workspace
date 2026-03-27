//! X448 primitive helpers used by the hybrid X-Wing KEM.
//!
//! Not yet wired into a hybrid orchestration module; suppress `dead_code` until
//! a concrete ML-KEM + X448 variant calls these helpers.

#![allow(dead_code)]

use crate::aliases::X448Secret56;
use crate::error::{Error, Result as CrateResult};
use secure_gate::{ConstantTimeEq, RevealSecret, RevealSecretMut};
use x448::{PublicKey as X448PublicKey, Secret as X448Secret};

/// Size in bytes of an X448 public key, scalar, and shared secret.
pub(crate) const X448_KEY_SIZE: usize = 56;

/// Clamps an X448 scalar in place per RFC 7748.
///
/// [`X448Secret::from`] also clamps; this function is kept explicit for auditor visibility.
pub fn clamp_x448_scalar(scalar: &mut [u8; X448_KEY_SIZE]) {
    scalar[0] &= 252;
    scalar[55] |= 128;
}

/// Converts raw X448 seed bytes into a clamped secret.
pub(crate) fn secret_from_seed(seed: [u8; X448_KEY_SIZE]) -> X448Secret {
    let mut s = X448Secret56::from(seed);
    s.with_secret_mut(clamp_x448_scalar);
    X448Secret::from(s.with_secret(|scalar| *scalar))
}

/// Derives an X448 public key from raw seed bytes.
pub(crate) fn public_key_from_seed(seed: [u8; X448_KEY_SIZE]) -> X448PublicKey {
    let sk = secret_from_seed(seed);
    X448PublicKey::from(&sk)
}

/// Computes sender-side X448 encapsulation output `(ct_x, ss_x)`.
pub(crate) fn encapsulate_to_public_key(
    ephemeral_seed: [u8; X448_KEY_SIZE],
    recipient_pk: &X448PublicKey,
) -> CrateResult<(X448PublicKey, [u8; X448_KEY_SIZE])> {
    let ephemeral = secret_from_seed(ephemeral_seed);
    let ct_x = X448PublicKey::from(&ephemeral);
    let ss = ephemeral
        .as_diffie_hellman(recipient_pk)
        .ok_or(Error::X448DiffieHellmanFailed)?;
    Ok((ct_x, *ss.as_bytes()))
}

/// Computes recipient-side X448 decapsulation output `(ss_x, pk_x)`.
pub(crate) fn decapsulate_from_private_seed(
    private_seed: [u8; X448_KEY_SIZE],
    ct_x: &X448PublicKey,
) -> CrateResult<([u8; X448_KEY_SIZE], X448PublicKey)> {
    let sk_x = secret_from_seed(private_seed);
    let ss = sk_x
        .as_diffie_hellman(ct_x)
        .ok_or(Error::X448DiffieHellmanFailed)?;
    let pk_x = X448PublicKey::from(&sk_x);
    Ok((*ss.as_bytes(), pk_x))
}

/// Parses and validates an X448 public key.
///
/// Rejects the all-zero point and low-order points via [`X448PublicKey::from_bytes`].
pub(crate) fn parse_public_key(bytes: [u8; X448_KEY_SIZE]) -> CrateResult<X448PublicKey> {
    if bytes.ct_eq(&[0u8; X448_KEY_SIZE]) {
        return Err(Error::InvalidX448PublicKey);
    }
    X448PublicKey::from_bytes(&bytes).ok_or(Error::InvalidX448PublicKey)
}
