//! X25519 primitive helpers used by the hybrid X-Wing KEM.

use crate::aliases::{X25519Scalar, X25519SharedSecret};
use crate::error::{Error, Result as CrateResult};
use crate::kem::common::CURVE_SEED_SIZE;
use secure_gate::{ConstantTimeEq, RevealSecret, RevealSecretMut};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// Size in bytes of an X25519 public key and shared secret.
pub(crate) const X25519_KEY_SIZE: usize = 32;

/// Clamps an X25519 scalar in place per RFC 7748.
pub(crate) fn clamp_x25519_scalar(scalar: &mut [u8; CURVE_SEED_SIZE]) {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical small-order X25519 points. Each has a **non-zero encoding**, so
    /// `parse_public_key` accepts them — they are caught only by checking the
    /// Diffie-Hellman *output*, which is the distinction this module's
    /// contributory check exists to make.
    const SMALL_ORDER_POINTS: [[u8; 32]; 2] = [
        [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ],
        [
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ],
    ];

    fn seed() -> X25519Scalar {
        X25519Scalar::from([7u8; 32])
    }

    /// The defect this guards against let a file decrypt that official age and
    /// rage reject: a low-order `ct_x` drives the shared secret to the all-zero
    /// value, pinning the classical half of the hybrid to a known constant.
    /// Covered end-to-end by the CCTV `hybrid_low_order` vector, but that lives
    /// two crates away — this asserts it at the point of the check.
    #[test]
    fn decapsulation_rejects_low_order_points() {
        for (i, bytes) in SMALL_ORDER_POINTS.iter().enumerate() {
            let ct_x = X25519PublicKey::from(*bytes);
            let err = decapsulate_from_private_seed(seed(), &ct_x)
                .expect_err("low-order point must be rejected");
            assert!(
                matches!(err, Error::X25519DiffieHellmanFailed),
                "point {i}: wrong error {err:?}"
            );
        }
    }

    /// The complement: these points are *not* rejected by the encoded-point
    /// check, so `parse_public_key` alone would have let them through. This is
    /// what makes the output check load-bearing rather than redundant.
    #[test]
    fn parse_public_key_alone_does_not_catch_low_order_points() {
        for bytes in SMALL_ORDER_POINTS {
            assert!(
                parse_public_key(bytes).is_ok(),
                "encoded-point validation is not sufficient on its own"
            );
        }
    }

    #[test]
    fn parse_public_key_rejects_the_all_zero_encoding() {
        assert!(matches!(
            parse_public_key([0u8; 32]),
            Err(Error::InvalidX25519PublicKey)
        ));
    }

    #[test]
    fn encapsulation_rejects_low_order_points() {
        for bytes in SMALL_ORDER_POINTS {
            let pk = X25519PublicKey::from(bytes);
            assert!(encapsulate_to_public_key(seed(), &pk).is_err());
        }
    }

    /// Sender and recipient must derive the same secret for an honest key.
    #[test]
    fn encapsulate_and_decapsulate_agree() {
        let recipient_seed = X25519Scalar::from([3u8; 32]);
        let recipient_pk = public_key_from_seed(X25519Scalar::from([3u8; 32]));

        let (ct_x, ss_sender) =
            encapsulate_to_public_key(X25519Scalar::from([9u8; 32]), &recipient_pk).unwrap();
        let (ss_recipient, _pk) = decapsulate_from_private_seed(recipient_seed, &ct_x).unwrap();

        assert_eq!(ss_sender.expose_secret(), ss_recipient.expose_secret());
    }

    /// RFC 7748: clear the low three bits, clear the top bit, set bit 254.
    #[test]
    fn clamping_matches_rfc_7748() {
        let mut scalar = [0xffu8; 32];
        clamp_x25519_scalar(&mut scalar);
        assert_eq!(scalar[0] & 0b0000_0111, 0, "low three bits must be clear");
        assert_eq!(scalar[31] & 0b1000_0000, 0, "top bit must be clear");
        assert_eq!(scalar[31] & 0b0100_0000, 0b0100_0000, "bit 254 must be set");
    }
}
