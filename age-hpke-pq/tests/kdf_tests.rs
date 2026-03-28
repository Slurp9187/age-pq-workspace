//! KDF smoke tests covering trait metadata and family-specific operation support.
//!
//! Strategy:
//! - verify factory metadata for each registered KDF
//! - check output lengths for supported HKDF/SHAKE operations
//! - assert unsupported family operations return `InvalidOperationForKdf`

use age_hpke_pq::{
    kdf::Kdf, new_kdf, Error, HkdfSha256, HkdfSha384, HkdfSha512, RevealSecret, Shake128Kdf,
    Shake256Kdf,
};

fn assert_hkdf_extract_output_len<K: Kdf>(kdf: K, expected_len: usize) -> Result<(), Error> {
    let result = kdf.labeled_extract(b"suite", Some(b"salt"), "test", b"key")?;
    assert_eq!(result.len(), expected_len);
    Ok(())
}

fn assert_hkdf_expand_output_len<K: Kdf>(kdf: K, random_key: &[u8], length: u16) -> Result<(), Error> {
    let result = kdf.labeled_expand(b"suite", random_key, "test", b"info", length)?;
    assert_eq!(result.len(), length as usize);
    Ok(())
}

fn assert_two_stage_kdf_rejects_labeled_derive<K: Kdf>(kdf: K) {
    let result = kdf.labeled_derive(b"suite", b"key", "test", b"context", 16);
    assert!(matches!(result, Err(Error::InvalidOperationForKdf)));
}

fn assert_one_stage_kdf_output_len<K: Kdf>(kdf: K, length: u16) -> Result<(), Error> {
    let result = kdf.labeled_derive(b"suite", b"key", "test", b"context", length)?;
    assert_eq!(result.len(), length as usize);
    Ok(())
}

fn assert_one_stage_kdf_rejects_extract_and_expand<K: Kdf>(kdf: K) {
    let extract = kdf.labeled_extract(b"suite", Some(b"salt"), "test", b"key");
    assert!(matches!(extract, Err(Error::InvalidOperationForKdf)));

    let expand = kdf.labeled_expand(b"suite", b"random_key", "test", b"info", 16);
    assert!(matches!(expand, Err(Error::InvalidOperationForKdf)));
}

#[test]
fn new_kdf_known_ids_report_expected_metadata() -> Result<(), Error> {
    let hkdf256 = new_kdf(0x0001)?;
    assert_eq!(hkdf256.id(), 0x0001);
    assert_eq!(hkdf256.size(), 32);
    assert!(!hkdf256.one_stage());

    let hkdf384 = new_kdf(0x0002)?;
    assert_eq!(hkdf384.id(), 0x0002);
    assert_eq!(hkdf384.size(), 48);
    assert!(!hkdf384.one_stage());

    let hkdf512 = new_kdf(0x0003)?;
    assert_eq!(hkdf512.id(), 0x0003);
    assert_eq!(hkdf512.size(), 64);
    assert!(!hkdf512.one_stage());

    let shake128 = new_kdf(0x0010)?;
    assert_eq!(shake128.id(), 0x0010);
    assert_eq!(shake128.size(), 32);
    assert!(shake128.one_stage());

    let shake256 = new_kdf(0x0011)?;
    assert_eq!(shake256.id(), 0x0011);
    assert_eq!(shake256.size(), 64);
    assert!(shake256.one_stage());

    Ok(())
}

#[test]
fn new_kdf_unknown_id_is_rejected() {
    assert!(matches!(new_kdf(0x9999), Err(Error::UnsupportedKdf)));
}

#[test]
fn hkdf_sha256_labeled_extract_returns_32_bytes() -> Result<(), Error> {
    assert_hkdf_extract_output_len(HkdfSha256, 32)
}

#[test]
fn hkdf_sha384_labeled_extract_returns_48_bytes() -> Result<(), Error> {
    assert_hkdf_extract_output_len(HkdfSha384, 48)
}

#[test]
fn hkdf_sha512_labeled_extract_returns_64_bytes() -> Result<(), Error> {
    assert_hkdf_extract_output_len(HkdfSha512, 64)
}

#[test]
fn hkdf_sha256_labeled_expand_returns_requested_length() -> Result<(), Error> {
    assert_hkdf_expand_output_len(HkdfSha256, &[0u8; 32], 16)
}

#[test]
fn hkdf_sha384_labeled_expand_returns_requested_length() -> Result<(), Error> {
    assert_hkdf_expand_output_len(HkdfSha384, &[0u8; 48], 16)
}

#[test]
fn hkdf_sha512_labeled_expand_returns_requested_length() -> Result<(), Error> {
    assert_hkdf_expand_output_len(HkdfSha512, &[0u8; 64], 16)
}

#[test]
fn hkdf_sha256_rejects_one_stage_labeled_derive() {
    assert_two_stage_kdf_rejects_labeled_derive(HkdfSha256);
}

#[test]
fn hkdf_sha384_rejects_one_stage_labeled_derive() {
    assert_two_stage_kdf_rejects_labeled_derive(HkdfSha384);
}

#[test]
fn hkdf_sha512_rejects_one_stage_labeled_derive() {
    assert_two_stage_kdf_rejects_labeled_derive(HkdfSha512);
}

#[test]
fn shake128_labeled_derive_returns_requested_length() -> Result<(), Error> {
    assert_one_stage_kdf_output_len(Shake128Kdf, 16)
}

#[test]
fn shake256_labeled_derive_returns_requested_length() -> Result<(), Error> {
    assert_one_stage_kdf_output_len(Shake256Kdf, 16)
}

#[test]
fn shake128_rejects_two_stage_operations() {
    assert_one_stage_kdf_rejects_extract_and_expand(Shake128Kdf);
}

#[test]
fn shake256_rejects_two_stage_operations() {
    assert_one_stage_kdf_rejects_extract_and_expand(Shake256Kdf);
}
