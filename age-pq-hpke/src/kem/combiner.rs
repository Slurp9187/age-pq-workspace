use crate::SharedSecret;
use crate::aliases::{
    MlKemSharedSecret, X25519EncapsulationKey, X25519EphemeralShare, X25519SharedSecret,
};
use secure_gate::RevealSecret;
use sha3::{Digest, Sha3_256};

pub(crate) const X_WING_LABEL: &[u8] = br"\.//^\";

/// Combines the ML-KEM and X25519 shared secrets into the single hybrid 32-byte
/// shared secret, per the combiner in `hpke-pq.md`.
///
/// # Why every parameter is a distinct type
///
/// All four inputs are 32 bytes. While they were `&[u8; 32]`, any two could be
/// transposed at a call site and the result was still a valid-looking 32-byte
/// digest — a silently wrong hybrid secret rather than a compile error or a
/// panic. That is the worst failure shape available here: it would decrypt
/// nothing, interoperate with nothing, and look fine in a debugger.
///
/// The types make each transposition unrepresentable. This function is
/// `pub(crate)`, so the property cannot be demonstrated in a doctest here —
/// see the `compile_fail` examples on [`crate::aliases`], which exercise the
/// same nominal-newtype guarantee through public types.
///
/// The digest is written straight into a `SharedSecret` via `new_with`, avoiding
/// an intermediate plaintext stack copy, and consumed with `into_inner` at the
/// return so the wrapper's storage is zeroized on the way out. Protection ends
/// at that call — the returned array is native per the wire-boundary rule;
/// callers who want zeroize-on-drop wrap it via `SharedSecret::new(bytes)`.
///
/// `X_WING_LABEL` is appended as a domain separator, binding the context and
/// preventing cross-protocol attacks.
pub(crate) fn combine_shared_secrets(
    // The post-quantum half: ML-KEM encapsulation (sender) or decapsulation
    // (recipient) output. Carries the lattice-based security of the hybrid.
    ss_pq: &MlKemSharedSecret,
    // The traditional half: the ephemeral-static X25519 Diffie-Hellman result,
    // hedging against weaknesses in ML-KEM.
    ss_t: &X25519SharedSecret,
    // `ct_t`: the sender's ephemeral X25519 public key. The recipient combines
    // it with its static private key to recover `ss_t`.
    ct_t: &X25519EphemeralShare,
    // `ek_t`: the recipient's long-term X25519 public key, hashed in so the
    // derived secret is bound to the intended recipient.
    ek_t: &X25519EncapsulationKey,
) -> [u8; 32] {
    let ss = SharedSecret::new_with(|buf| {
        let mut hasher = Sha3_256::new();
        hasher.update(ss_pq.expose_secret());
        hasher.update(ss_t.expose_secret());
        hasher.update(ct_t.expose_secret());
        hasher.update(ek_t.expose_secret());
        hasher.update(X_WING_LABEL);
        buf.copy_from_slice(&hasher.finalize());
    });
    // Tier-3: consume the wrapper. Its storage is zeroized as the value leaves;
    // protection ends here, which is the boundary this function returns across.
    ss.into_inner()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These live inside the crate rather than in `tests/` because the function
    /// is `pub(crate)`: it is an internal construction detail of the X-Wing KEM,
    /// and exposing four transposable 32-byte parameters was a footgun with no
    /// caller outside this crate to justify it.
    fn inputs() -> (
        MlKemSharedSecret,
        X25519SharedSecret,
        X25519EphemeralShare,
        X25519EncapsulationKey,
    ) {
        (
            MlKemSharedSecret::from([1u8; 32]),
            X25519SharedSecret::from([2u8; 32]),
            X25519EphemeralShare::from([3u8; 32]),
            X25519EncapsulationKey::from([4u8; 32]),
        )
    }

    #[test]
    fn combiner_is_deterministic() {
        let (pq, t, ct, ek) = inputs();
        assert_eq!(
            combine_shared_secrets(&pq, &t, &ct, &ek),
            combine_shared_secrets(&pq, &t, &ct, &ek)
        );
    }

    /// Each input must actually reach the digest. Previously this was expressed
    /// by transposing arguments, which no longer compiles — so vary each input
    /// in place instead, which tests the same property more directly.
    #[test]
    fn every_input_changes_the_output() {
        let (pq, t, ct, ek) = inputs();
        let base = combine_shared_secrets(&pq, &t, &ct, &ek);

        let other_pq = MlKemSharedSecret::from([9u8; 32]);
        let other_t = X25519SharedSecret::from([9u8; 32]);
        let other_ct = X25519EphemeralShare::from([9u8; 32]);
        let other_ek = X25519EncapsulationKey::from([9u8; 32]);

        assert_ne!(
            base,
            combine_shared_secrets(&other_pq, &t, &ct, &ek),
            "ss_pq"
        );
        assert_ne!(
            base,
            combine_shared_secrets(&pq, &other_t, &ct, &ek),
            "ss_t"
        );
        assert_ne!(
            base,
            combine_shared_secrets(&pq, &t, &other_ct, &ek),
            "ct_t"
        );
        assert_ne!(
            base,
            combine_shared_secrets(&pq, &t, &ct, &other_ek),
            "ek_t"
        );
    }

    /// Two inputs holding identical bytes in different roles must still produce
    /// different output — i.e. position is bound, not just content.
    #[test]
    fn identical_bytes_in_different_roles_differ() {
        let same = [7u8; 32];
        let a = combine_shared_secrets(
            &MlKemSharedSecret::from(same),
            &X25519SharedSecret::from([0u8; 32]),
            &X25519EphemeralShare::from([0u8; 32]),
            &X25519EncapsulationKey::from([0u8; 32]),
        );
        let b = combine_shared_secrets(
            &MlKemSharedSecret::from([0u8; 32]),
            &X25519SharedSecret::from(same),
            &X25519EphemeralShare::from([0u8; 32]),
            &X25519EncapsulationKey::from([0u8; 32]),
        );
        assert_ne!(a, b);
    }
}
