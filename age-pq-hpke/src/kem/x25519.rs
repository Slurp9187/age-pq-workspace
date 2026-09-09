//! X25519 primitive helpers used by the hybrid X-Wing KEM.

use crate::aliases::{X25519Scalar, X25519SharedSecret};
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

/// Converts a raw X25519 seed wrapper into a clamped static secret.
///
/// Consumes the wrapper — `StaticSecret::from` takes `[u8; 32]` by value,
/// and `x25519_dalek::StaticSecret` is itself `ZeroizeOnDrop`, so the
/// secret bytes are zeroize-covered end-to-end. We clamp in place via
/// `with_secret_mut` (Tier-1 mutable) on the wrapper, then consume the
/// wrapper via `into_inner` (Tier-3) to feed `StaticSecret::from`. Clamping
/// must precede consumption — `into_inner` yields a plain value, so there is
/// no wrapper left to mutate through afterwards.
pub(crate) fn static_secret_from_seed(seed: X25519Scalar) -> StaticSecret {
    let mut s = seed;
    s.with_secret_mut(clamp_x25519_scalar);
    // Tier-3: x25519_dalek::StaticSecret::from takes [u8; 32] by value.
    // `into_inner` zeroizes the wrapper's storage and hands back the plain
    // array; `StaticSecret` is itself ZeroizeOnDrop, so the clamped scalar
    // stays covered on the far side of the hand-off.
    StaticSecret::from(s.into_inner())
}

/// Derives an X25519 public key from a wrapped seed.
pub(crate) fn public_key_from_seed(seed: X25519Scalar) -> X25519PublicKey {
    let sk = static_secret_from_seed(seed);
    X25519PublicKey::from(&sk)
}

/// Computes sender-side X25519 encapsulation output `(ct_x, ss_x)`.
///
/// Fails if the recipient public key is a low-order point, which would make
/// the shared secret the all-zero non-contributory value.
///
/// Consumes the ephemeral seed — single-shot use, the wrapper has no role
/// past this call.
pub(crate) fn encapsulate_to_public_key(
    ephemeral_seed: X25519Scalar,
    recipient_pk: &X25519PublicKey,
) -> CrateResult<(X25519PublicKey, X25519SharedSecret)> {
    let ephemeral = static_secret_from_seed(ephemeral_seed);
    let ct_x = X25519PublicKey::from(&ephemeral);
    let dh = ephemeral.diffie_hellman(recipient_pk);
    if !dh.was_contributory() {
        return Err(Error::X25519DiffieHellmanFailed);
    }
    // Tier-2: x25519_dalek::SharedSecret::as_bytes returns &[u8; 32].
    // `dh` is ZeroizeOnDrop and dies at end of statement; the bytes land
    // directly in X25519SharedSecret storage via new_with.
    let ss = X25519SharedSecret::new_with(|out| out.copy_from_slice(dh.as_bytes()));
    Ok((ct_x, ss))
}

/// Computes recipient-side X25519 decapsulation output `(ss_x, pk_x)`.
///
/// Fails if `ct_x` is a low-order point, which would make the shared secret
/// the all-zero non-contributory value.
///
/// Consumes the private seed — callers re-derive it from the master seed
/// on each decapsulation, so the wrapper has no role past this call.
pub(crate) fn decapsulate_from_private_seed(
    private_seed: X25519Scalar,
    ct_x: &X25519PublicKey,
) -> CrateResult<(X25519SharedSecret, X25519PublicKey)> {
    let sk_x = static_secret_from_seed(private_seed);
    let pk_x = X25519PublicKey::from(&sk_x);
    let dh = sk_x.diffie_hellman(ct_x);
    // An attacker-supplied low-order `ct_x` drives the DH output to all-zero,
    // which would pin the classical half of the hybrid to a known constant.
    // `was_contributory` is x25519-dalek's constant-time check for exactly that.
    if !dh.was_contributory() {
        return Err(Error::X25519DiffieHellmanFailed);
    }
    // Tier-2: x25519_dalek::SharedSecret::as_bytes returns &[u8; 32].
    let ss = X25519SharedSecret::new_with(|out| out.copy_from_slice(dh.as_bytes()));
    Ok((ss, pk_x))
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
