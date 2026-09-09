// src/hpke_pq.rs
//! Age-specific HPKE utilities for the post-quantum hybrid plugin.

use crate::aliases::{AeadKey32, KdfBytes};
use age_pq_hpke::{kdf::new_kdf, Error};
use secure_gate::RevealSecret;

pub(crate) const KEM_ID: u16 = 0x647a; // XWing768X25519
pub(crate) const KDF_ID: u16 = 0x0001; // HKDF-SHA256
pub(crate) const AEAD_ID: u16 = 0x0003; // ChaCha20Poly1305
const MODE: u8 = 0; // base mode

fn suite_id() -> Vec<u8> {
    let mut sid = Vec::with_capacity(10);
    sid.extend_from_slice(b"HPKE");
    sid.extend_from_slice(&KEM_ID.to_be_bytes());
    sid.extend_from_slice(&KDF_ID.to_be_bytes());
    sid.extend_from_slice(&AEAD_ID.to_be_bytes());
    sid
}

/// Runs the RFC 9180 Base-mode key schedule and returns the AEAD key and base nonce.
///
/// The `Kdf` trait returns native `Vec<u8>` at the API boundary; every output is
/// wrapped in [`KdfBytes`] on arrival so no PRK or OKM lives as a bare vector.
/// The base nonce is public (it is XORed with the sequence number per message)
/// and stays a plain array.
// `pub(crate)` rather than `pub`: this is a binary crate, so nothing outside can
// reach it anyway, and it returns `AeadKey32` — a crate-private role. While that
// was a `fixed_alias!` it expanded to the public `Fixed<[u8; 32]>`, so the
// mismatch was invisible; as a nominal newtype the compiler names it.
pub(crate) fn derive_key_and_nonce(
    shared_secret: &[u8],
    info: &[u8],
) -> Result<(AeadKey32, [u8; 12]), Error> {
    let sid = suite_id();
    let kdf = new_kdf(KDF_ID)?;

    let psk_id_hash = KdfBytes::new(kdf.labeled_extract(&sid, None, "psk_id_hash", &[])?);
    let info_hash = KdfBytes::new(kdf.labeled_extract(&sid, None, "info_hash", info)?);

    let mut ks_context = Vec::new();
    ks_context.push(MODE);
    psk_id_hash.with_secret(|bytes| ks_context.extend_from_slice(bytes));
    info_hash.with_secret(|bytes| ks_context.extend_from_slice(bytes));

    let secret = KdfBytes::new(kdf.labeled_extract(&sid, Some(shared_secret), "secret", &[])?);

    let key = secret.with_secret(|prk| {
        kdf.labeled_expand(&sid, prk, "key", &ks_context, 32)
            .map(KdfBytes::new)
    })?;
    let key = key
        .with_secret(|bytes| AeadKey32::try_from(bytes.as_slice()))
        .map_err(|_| Error::InvalidLength)?;

    let nonce = secret.with_secret(|prk| {
        kdf.labeled_expand(&sid, prk, "base_nonce", &ks_context, 12)
            .map(KdfBytes::new)
    })?;
    let mut base_nonce = [0u8; 12];
    nonce.with_secret(|bytes| base_nonce.copy_from_slice(bytes));

    Ok((key, base_nonce))
}
