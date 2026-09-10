//! X448 primitive helpers used by the hybrid X-Wing KEM.
//!
//! Not yet wired into a hybrid orchestration module; suppress `dead_code` until
//! a concrete ML-KEM + X448 variant calls these helpers.

#![allow(dead_code)]

use crate::aliases::{X448Scalar, X448SharedSecret};
use crate::error::{Error, Result as CrateResult};
use secure_gate::{ConstantTimeEq, RevealSecret, RevealSecretMut};
use x448::{PublicKey as X448PublicKey, Secret as X448Secret};

/// Size in bytes of an X448 public key, scalar, and shared secret.
pub(crate) const X448_KEY_SIZE: usize = 56;

/// Clamps an X448 scalar in place per RFC 7748.
///
/// [`X448Secret::from`] also clamps; this function is kept explicit for auditor visibility.
pub(crate) fn clamp_x448_scalar(scalar: &mut [u8; X448_KEY_SIZE]) {
    scalar[0] &= 252;
    scalar[55] |= 128;
}

/// Converts a wrapped X448 seed into a clamped secret.
///
/// Consumes the wrapper — `x448::Secret::from` takes `[u8; 56]` by value.
pub(crate) fn secret_from_seed(seed: X448Scalar) -> X448Secret {
    let mut s = seed;
    s.with_secret_mut(clamp_x448_scalar);
    // Tier-3: x448::Secret::from takes [u8; 56] by value. `into_inner` zeroizes
    // the wrapper's storage and returns the plain array, so the clamp above has
    // to run on the wrapper while one still exists.
    X448Secret::from(s.into_inner())
}

/// Derives an X448 public key from a wrapped seed.
pub(crate) fn public_key_from_seed(seed: X448Scalar) -> X448PublicKey {
    let sk = secret_from_seed(seed);
    X448PublicKey::from(&sk)
}

/// Computes sender-side X448 encapsulation output `(ct_x, ss_x)`.
pub(crate) fn encapsulate_to_public_key(
    ephemeral_seed: X448Scalar,
    recipient_pk: &X448PublicKey,
) -> CrateResult<(X448PublicKey, X448SharedSecret)> {
    let ephemeral = secret_from_seed(ephemeral_seed);
    let ct_x = X448PublicKey::from(&ephemeral);
    let dh = ephemeral
        .as_diffie_hellman(recipient_pk)
        .ok_or(Error::X448DiffieHellmanFailed)?;
    // Tier-2: x448::SharedSecret::as_bytes returns &[u8; 56].
    let ss = X448SharedSecret::new_with(|out| out.copy_from_slice(dh.as_bytes()));
    Ok((ct_x, ss))
}

/// Computes recipient-side X448 decapsulation output `(ss_x, pk_x)`.
pub(crate) fn decapsulate_from_private_seed(
    private_seed: X448Scalar,
    ct_x: &X448PublicKey,
) -> CrateResult<(X448SharedSecret, X448PublicKey)> {
    let sk_x = secret_from_seed(private_seed);
    let pk_x = X448PublicKey::from(&sk_x);
    let dh = sk_x
        .as_diffie_hellman(ct_x)
        .ok_or(Error::X448DiffieHellmanFailed)?;
    // Tier-2: x448::SharedSecret::as_bytes returns &[u8; 56].
    let ss = X448SharedSecret::new_with(|out| out.copy_from_slice(dh.as_bytes()));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> X448Scalar {
        X448Scalar::from([7u8; 56])
    }

    #[test]
    fn parse_public_key_rejects_the_all_zero_encoding() {
        assert!(matches!(
            parse_public_key([0u8; 56]),
            Err(Error::InvalidX448PublicKey)
        ));
    }

    /// X448's `as_diffie_hellman` returns `None` for a non-contributory result,
    /// so the check lives upstream — but this crate depends on it being made, so
    /// assert it rather than assume it. The X25519 path had exactly this gap:
    /// its dalek equivalent returns the secret unconditionally.
    #[test]
    fn decapsulation_rejects_a_low_order_point() {
        // u = 1 encodes a small-order point and is accepted by `from_bytes`.
        let mut bytes = [0u8; 56];
        bytes[0] = 1;
        if let Ok(pk) = parse_public_key(bytes) {
            // `expect_err` would need `Debug` on the Ok type, and `x448::PublicKey`
            // does not implement it — match instead.
            match decapsulate_from_private_seed(seed(), &pk) {
                Err(Error::X448DiffieHellmanFailed) => {}
                Err(e) => panic!("wrong error: {e:?}"),
                Ok(_) => panic!("non-contributory result must be rejected"),
            }
        }
    }

    #[test]
    fn encapsulate_and_decapsulate_agree() {
        let recipient_pk = public_key_from_seed(X448Scalar::from([3u8; 56]));
        let (ct_x, ss_sender) =
            encapsulate_to_public_key(X448Scalar::from([9u8; 56]), &recipient_pk).unwrap();
        let (ss_recipient, _pk) =
            decapsulate_from_private_seed(X448Scalar::from([3u8; 56]), &ct_x).unwrap();
        assert_eq!(ss_sender.expose_secret(), ss_recipient.expose_secret());
    }
}
