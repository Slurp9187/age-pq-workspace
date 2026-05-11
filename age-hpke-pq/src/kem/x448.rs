//! X448 primitive helpers used by the hybrid X-Wing KEM.
//!
//! Not yet wired into a hybrid orchestration module; suppress `dead_code` until
//! a concrete ML-KEM + X448 variant calls these helpers.

#![allow(dead_code)]

use crate::aliases::{SharedSecret56, X448Secret56};
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

/// Converts a wrapped X448 seed into a clamped secret.
///
/// Consumes the wrapper — `x448::Secret::from` takes `[u8; 56]` by value.
pub(crate) fn secret_from_seed(seed: X448Secret56) -> X448Secret {
    let mut s = seed;
    s.with_secret_mut(clamp_x448_scalar);
    // Tier-2 (forced): `into_inner` requires `Default` on the inner type;
    // stdlib only provides `Default` for `[u8; N]` with N <= 32 on MSRV
    // 1.70, so we cannot consume via `into_inner` here. The wrapper still
    // drops (zeroizing) at function end.
    s.with_secret(|bytes| X448Secret::from(*bytes))
}

/// Derives an X448 public key from a wrapped seed.
pub(crate) fn public_key_from_seed(seed: X448Secret56) -> X448PublicKey {
    let sk = secret_from_seed(seed);
    X448PublicKey::from(&sk)
}

/// Computes sender-side X448 encapsulation output `(ct_x, ss_x)`.
pub(crate) fn encapsulate_to_public_key(
    ephemeral_seed: X448Secret56,
    recipient_pk: &X448PublicKey,
) -> CrateResult<(X448PublicKey, SharedSecret56)> {
    let ephemeral = secret_from_seed(ephemeral_seed);
    let ct_x = X448PublicKey::from(&ephemeral);
    let dh = ephemeral
        .as_diffie_hellman(recipient_pk)
        .ok_or(Error::X448DiffieHellmanFailed)?;
    // Tier-2: x448::SharedSecret::as_bytes returns &[u8; 56].
    let ss = SharedSecret56::new_with(|out| out.copy_from_slice(dh.as_bytes()));
    Ok((ct_x, ss))
}

/// Computes recipient-side X448 decapsulation output `(ss_x, pk_x)`.
pub(crate) fn decapsulate_from_private_seed(
    private_seed: X448Secret56,
    ct_x: &X448PublicKey,
) -> CrateResult<(SharedSecret56, X448PublicKey)> {
    let sk_x = secret_from_seed(private_seed);
    let pk_x = X448PublicKey::from(&sk_x);
    let dh = sk_x
        .as_diffie_hellman(ct_x)
        .ok_or(Error::X448DiffieHellmanFailed)?;
    // Tier-2: x448::SharedSecret::as_bytes returns &[u8; 56].
    let ss = SharedSecret56::new_with(|out| out.copy_from_slice(dh.as_bytes()));
    Ok((ss, pk_x))
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
