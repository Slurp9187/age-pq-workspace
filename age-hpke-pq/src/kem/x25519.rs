//! X25519 primitive helpers used by the hybrid X-Wing KEM.

use crate::aliases::{SharedSecret32, X25519Secret32};
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
/// wrapper via `into_inner` (Tier-3) to feed `StaticSecret::from`.
pub(crate) fn static_secret_from_seed(seed: X25519Secret32) -> StaticSecret {
    let mut s = seed;
    s.with_secret_mut(clamp_x25519_scalar);
    // Tier-3: x25519_dalek::StaticSecret::from takes [u8; 32] by value.
    // InnerSecret is Deref-only (no DerefMut), so any mutation must
    // happen on the wrapper above before consumption.
    let owned = s.into_inner();
    StaticSecret::from(*owned)
    // `owned` drops here, zeroizing the (clamped) buffer.
}

/// Derives an X25519 public key from a wrapped seed.
pub(crate) fn public_key_from_seed(seed: X25519Secret32) -> X25519PublicKey {
    let sk = static_secret_from_seed(seed);
    X25519PublicKey::from(&sk)
}

/// Computes sender-side X25519 encapsulation output `(ct_x, ss_x)`.
///
/// Consumes the ephemeral seed — single-shot use, the wrapper has no role
/// past this call.
pub(crate) fn encapsulate_to_public_key(
    ephemeral_seed: X25519Secret32,
    recipient_pk: &X25519PublicKey,
) -> (X25519PublicKey, SharedSecret32) {
    let ephemeral = static_secret_from_seed(ephemeral_seed);
    let ct_x = X25519PublicKey::from(&ephemeral);
    let dh = ephemeral.diffie_hellman(recipient_pk);
    // Tier-2: x25519_dalek::SharedSecret::as_bytes returns &[u8; 32].
    // `dh` is ZeroizeOnDrop and dies at end of statement; the bytes land
    // directly in SharedSecret32 storage via new_with.
    let ss = SharedSecret32::new_with(|out| out.copy_from_slice(dh.as_bytes()));
    (ct_x, ss)
}

/// Computes recipient-side X25519 decapsulation output `(ss_x, pk_x)`.
///
/// Consumes the private seed — callers re-derive it from the master seed
/// on each decapsulation, so the wrapper has no role past this call.
pub(crate) fn decapsulate_from_private_seed(
    private_seed: X25519Secret32,
    ct_x: &X25519PublicKey,
) -> (SharedSecret32, X25519PublicKey) {
    let sk_x = static_secret_from_seed(private_seed);
    let pk_x = X25519PublicKey::from(&sk_x);
    let dh = sk_x.diffie_hellman(ct_x);
    // Tier-2: x25519_dalek::SharedSecret::as_bytes returns &[u8; 32].
    let ss = SharedSecret32::new_with(|out| out.copy_from_slice(dh.as_bytes()));
    (ss, pk_x)
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
