// src/hpke_pq.rs
//! Age-specific HPKE utilities for the post-quantum hybrid plugin.

use age_hpke_pq::{kdf::new_kdf, Error, RevealSecret};

pub const KEM_ID: u16 = 0x647a; // XWing768X25519
pub const KDF_ID: u16 = 0x0001; // HKDF-SHA256
pub const AEAD_ID: u16 = 0x0003; // ChaCha20Poly1305
const MODE: u8 = 0; // base mode

fn suite_id() -> Vec<u8> {
    let mut sid = Vec::with_capacity(10);
    sid.extend_from_slice(b"HPKE");
    sid.extend_from_slice(&KEM_ID.to_be_bytes());
    sid.extend_from_slice(&KDF_ID.to_be_bytes());
    sid.extend_from_slice(&AEAD_ID.to_be_bytes());
    sid
}

pub fn derive_key_and_nonce(
    shared_secret: &[u8],
    info: &[u8],
) -> Result<([u8; 32], [u8; 12]), Error> {
    let sid = suite_id();
    let kdf = new_kdf(KDF_ID)?;

    let psk_id_hash = kdf.labeled_extract(&sid, None, "psk_id_hash", &[])?;
    let info_hash = kdf.labeled_extract(&sid, None, "info_hash", info)?;

    let mut ks_context = Vec::new();
    ks_context.push(MODE);
    psk_id_hash.with_secret(|bytes| ks_context.extend_from_slice(bytes));
    info_hash.with_secret(|bytes| ks_context.extend_from_slice(bytes));

    let secret = kdf.labeled_extract(&sid, Some(shared_secret), "secret", &[])?;

    let key_vec =
        secret.with_secret(|bytes| kdf.labeled_expand(&sid, bytes, "key", &ks_context, 32))?;
    let mut key = [0u8; 32];
    key_vec.with_secret(|bytes| key.copy_from_slice(bytes));

    let nonce_vec = secret
        .with_secret(|bytes| kdf.labeled_expand(&sid, bytes, "base_nonce", &ks_context, 12))?;
    let mut base_nonce = [0u8; 12];
    nonce_vec.with_secret(|bytes| base_nonce.copy_from_slice(bytes));

    Ok((key, base_nonce))
}
