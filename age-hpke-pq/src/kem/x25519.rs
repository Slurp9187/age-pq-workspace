//! X25519 primitive helpers used by the hybrid X-Wing KEM.

use crate::aliases::X25519Secret32;
use crate::error::{Error, Result as CrateResult};
use crate::kem::common::CURVE_SEED_SIZE;
use secure_gate::{ConstantTimeEq, RevealSecret, RevealSecretMut};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Size in bytes of an X25519 public key and shared secret.
pub(crate) const X25519_KEY_SIZE: usize = 32;

/// Clamps an X25519 scalar in place per RFC 7748.
pub fn clamp_x25519_scalar(scalar: &mut [u8; CURVE_SEED_SIZE]) {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
}

/// Converts raw X25519 seed bytes into a clamped static secret.
pub(crate) fn static_secret_from_seed(seed: [u8; CURVE_SEED_SIZE]) -> StaticSecret {
    let mut s = X25519Secret32::from(seed);
    s.with_secret_mut(clamp_x25519_scalar);
    StaticSecret::from(s.with_secret(|scalar| *scalar))
}

/// Derives an X25519 public key from raw seed bytes.
pub(crate) fn public_key_from_seed(seed: [u8; CURVE_SEED_SIZE]) -> X25519PublicKey {
    let sk = static_secret_from_seed(seed);
    X25519PublicKey::from(&sk)
}

/// Computes sender-side X25519 encapsulation output `(ct_x, ss_x)`.
pub(crate) fn encapsulate_to_public_key(
    ephemeral_seed: [u8; CURVE_SEED_SIZE],
    recipient_pk: &X25519PublicKey,
) -> (X25519PublicKey, [u8; X25519_KEY_SIZE]) {
    let ephemeral = static_secret_from_seed(ephemeral_seed);
    let ct_x = X25519PublicKey::from(&ephemeral);
    let ss_x = ephemeral.diffie_hellman(recipient_pk).to_bytes();
    (ct_x, ss_x)
}

/// Computes recipient-side X25519 decapsulation output `(ss_x, pk_x)`.
pub(crate) fn decapsulate_from_private_seed(
    private_seed: [u8; CURVE_SEED_SIZE],
    ct_x: &X25519PublicKey,
) -> ([u8; X25519_KEY_SIZE], X25519PublicKey) {
    let sk_x = static_secret_from_seed(private_seed);
    let ss_x = sk_x.diffie_hellman(ct_x).to_bytes();
    let pk_x = X25519PublicKey::from(&sk_x);
    (ss_x, pk_x)
}

/// Parses and validates an X25519 public key.
///
/// Rejects the all-zero point, which is invalid in this crate's key-validation model.
pub(crate) fn parse_public_key(bytes: [u8; X25519_KEY_SIZE]) -> CrateResult<X25519PublicKey> {
    if bytes.ct_eq(&[0u8; X25519_KEY_SIZE]) {
        return Err(Error::InvalidX25519PublicKey);
    }
    Ok(X25519PublicKey::from(bytes))
}
