//! ML-KEM primitive helpers grouped by parameter set.
//!
//! The default hybrid implementation uses `mlkem768`, and this module
//! re-exports that variant so existing callers can continue importing
//! `super::ml_kem::*` without knowing about the internal submodule split.
//!
//! Additional parameter sets live in their own submodules behind feature gates
//! so future variants can be added without mixing multiple byte sizes and type
//! families into one file.

// Current production variant used by the hybrid orchestration module.
pub(crate) mod mlkem768;
// Optional lower-security / faster variant, not yet wired into a hybrid KEM.
#[cfg(feature = "mlkem512")]
pub(crate) mod mlkem512;
// Optional higher-security variant, not yet wired into a hybrid KEM.
#[cfg(feature = "mlkem1024")]
pub(crate) mod mlkem1024;

// Preserve the pre-split import surface for the current ML-KEM-768 helpers.
pub(crate) use mlkem768::*;

use libcrux_ml_kem::{MlKemKeyPair, MlKemPrivateKey, MlKemPublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// An ML-KEM key pair whose private half is wiped when it drops.
///
/// libcrux-ml-kem (0.0.10, the latest release) implements neither `Zeroize`
/// nor `Drop` on its key types, and `MlKemKeyPair` exposes its private key only
/// by shared reference. So the pair is split with `into_parts` and the private
/// key held here, where `IndexMut<RangeFrom<usize>>` — which libcrux does
/// implement on `MlKemPrivateKey` — reaches its bytes for a volatile wipe.
///
/// What this does **not** reach, stated so nobody reads more into it: libcrux's
/// own stack intermediates during key generation and decapsulation, and any
/// stale copy the compiler leaves in a dead stack slot when the pair is moved
/// (by-value return, `into_parts`). Neither is addressable without `unsafe`.
pub(crate) struct WipingKeyPair<const SK: usize, const PK: usize> {
    sk: MlKemPrivateKey<SK>,
    pk: MlKemPublicKey<PK>,
}

impl<const SK: usize, const PK: usize> WipingKeyPair<SK, PK> {
    /// Takes ownership of a freshly generated libcrux key pair.
    pub(crate) fn new(kp: MlKemKeyPair<SK, PK>) -> Self {
        let (sk, pk) = kp.into_parts();
        Self { sk, pk }
    }

    /// The private (decapsulation) key, for `decapsulate`.
    pub(crate) fn private_key(&self) -> &MlKemPrivateKey<SK> {
        &self.sk
    }

    /// The public (encapsulation) key.
    pub(crate) fn public_key(&self) -> &MlKemPublicKey<PK> {
        &self.pk
    }
}

impl<const SK: usize, const PK: usize> Zeroize for WipingKeyPair<SK, PK> {
    /// Wipes the private key. The public key is public and left alone.
    fn zeroize(&mut self) {
        self.sk[0..].zeroize();
    }
}

impl<const SK: usize, const PK: usize> Drop for WipingKeyPair<SK, PK> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const SK: usize, const PK: usize> ZeroizeOnDrop for WipingKeyPair<SK, PK> {}

#[cfg(test)]
mod tests {
    use super::mlkem768::{MLKEM768_PK_SIZE, MLKEM768_SK_SIZE, keypair_from_seed};
    use super::*;
    use crate::aliases::MlKemSeed64;

    /// `zeroize` is exactly what `Drop` runs, so this checks the wipe logic:
    /// every private-key byte is cleared, and the public key is left alone.
    ///
    /// It cannot check that the *drop* happened on the memory an attacker would
    /// read — that needs `unsafe` pointer reads after drop, which this workspace
    /// forbids, and stack wipes are not observable from safe code at all.
    #[test]
    fn zeroize_clears_the_whole_private_key_and_only_it() {
        let mut kp = keypair_from_seed(&MlKemSeed64::from([7u8; 64]));
        assert_eq!(kp.private_key().as_slice().len(), MLKEM768_SK_SIZE);
        assert!(
            kp.private_key().as_slice().iter().any(|&b| b != 0),
            "a derived private key is not all-zero, so the wipe below is observable"
        );
        let pk_before: [u8; MLKEM768_PK_SIZE] = *kp.public_key().as_slice();

        kp.zeroize();

        assert!(kp.private_key().as_slice().iter().all(|&b| b == 0));
        assert_eq!(kp.public_key().as_slice(), &pk_before);
    }
}
