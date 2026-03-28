#[cfg(test)]
use age_hpke_pq::{
    kdf::Kdf, new_kdf, HkdfSha256, HkdfSha384, HkdfSha512, RevealSecret, Shake128Kdf, Shake256Kdf,
};

#[test]
fn test_new_kdf_valid_ids() {
    let hkdf256 = new_kdf(0x0001).unwrap();
    assert_eq!(hkdf256.id(), 0x0001);
    assert_eq!(hkdf256.size(), 32);
    assert!(!hkdf256.one_stage());

    let hkdf384 = new_kdf(0x0002).unwrap();
    assert_eq!(hkdf384.id(), 0x0002);
    assert_eq!(hkdf384.size(), 48);
    assert!(!hkdf384.one_stage());

    let hkdf512 = new_kdf(0x0003).unwrap();
    assert_eq!(hkdf512.id(), 0x0003);
    assert_eq!(hkdf512.size(), 64);
    assert!(!hkdf512.one_stage());

    let shake128 = new_kdf(0x0010).unwrap();
    assert_eq!(shake128.id(), 0x0010);
    assert_eq!(shake128.size(), 32);
    assert!(shake128.one_stage());

    let shake256 = new_kdf(0x0011).unwrap();
    assert_eq!(shake256.id(), 0x0011);
    assert_eq!(shake256.size(), 64);
    assert!(shake256.one_stage());
}

#[test]
fn test_new_kdf_invalid() {
    assert!(new_kdf(0x9999).is_err());
}

#[test]
fn test_hkdf_sha256_labeled_extract() {
    let kdf = HkdfSha256;
    let suite_id = b"suite";
    let _suite_id = b"HPKE\x00\x00\x00\x01\x00\x00\x00\x03";
    let salt = Some(b"salt" as &[u8]);
    let label = "test";
    let input_key = b"key";
    let result = kdf
        .labeled_extract(suite_id, salt, label, input_key)
        .unwrap();
    assert_eq!(result.len(), 32);
}

#[test]
fn test_hkdf_sha256_labeled_expand() {
    let kdf = HkdfSha256;
    let suite_id = b"suite";
    let random_key = &[0u8; 32];
    let label = "test";
    let info = b"info";
    let length = 16;
    let result = kdf
        .labeled_expand(suite_id, random_key, label, info, length)
        .unwrap();
    assert_eq!(result.len(), length as usize);
}

#[test]
fn test_hkdf_sha256_labeled_derive() {
    let kdf = HkdfSha256;
    let suite_id = b"suite";
    let input_key = b"key";
    let label = "test";
    let context = b"context";
    let length = 16;
    assert!(kdf
        .labeled_derive(suite_id, input_key, label, context, length)
        .is_err());
}

#[test]
fn test_hkdf_sha384_labeled_extract() {
    let kdf = HkdfSha384;
    let suite_id = b"suite";
    let _suite_id = b"HPKE\x00\x00\x00\x02\x00\x00\x00\x03";
    let salt = Some(b"salt" as &[u8]);
    let label = "test";
    let input_key = b"key";
    let result = kdf
        .labeled_extract(suite_id, salt, label, input_key)
        .unwrap();
    assert_eq!(result.len(), 48);
}

#[test]
fn test_hkdf_sha384_labeled_expand() {
    let kdf = HkdfSha384;
    let suite_id = b"suite";
    let random_key = &[0u8; 48];
    let label = "test";
    let info = b"info";
    let length = 16;
    let result = kdf
        .labeled_expand(suite_id, random_key, label, info, length)
        .unwrap();
    assert_eq!(result.len(), length as usize);
}

#[test]
fn test_hkdf_sha384_labeled_derive() {
    let kdf = HkdfSha384;
    let suite_id = b"suite";
    let input_key = b"key";
    let label = "test";
    let context = b"context";
    let length = 16;
    assert!(kdf
        .labeled_derive(suite_id, input_key, label, context, length)
        .is_err());
}

#[test]
fn test_hkdf_sha512_labeled_extract() {
    let kdf = HkdfSha512;
    let suite_id = b"suite";
    let _suite_id = b"HPKE\x00\x00\x00\x03\x00\x00\x00\x03";
    let salt = Some(b"salt" as &[u8]);
    let label = "test";
    let input_key = b"key";
    let result = kdf
        .labeled_extract(suite_id, salt, label, input_key)
        .unwrap();
    assert_eq!(result.len(), 64);
}

#[test]
fn test_hkdf_sha512_labeled_expand() {
    let kdf = HkdfSha512;
    let suite_id = b"suite";
    let random_key = &[0u8; 64];
    let label = "test";
    let info = b"info";
    let length = 16;
    let result = kdf
        .labeled_expand(suite_id, random_key, label, info, length)
        .unwrap();
    assert_eq!(result.len(), length as usize);
}

#[test]
fn test_hkdf_sha512_labeled_derive() {
    let kdf = HkdfSha512;
    let suite_id = b"suite";
    let input_key = b"key";
    let label = "test";
    let context = b"context";
    let length = 16;
    assert!(kdf
        .labeled_derive(suite_id, input_key, label, context, length)
        .is_err());
}

#[test]
fn test_shake128_labeled_derive() {
    let kdf = Shake128Kdf;
    let suite_id = b"suite";
    let input_key = b"key";
    let label = "test";
    let context = b"context";
    let length = 16;
    let result = kdf
        .labeled_derive(suite_id, input_key, label, context, length)
        .unwrap();
    assert_eq!(result.len(), length as usize);
}

#[test]
fn test_shake128_labeled_extract() {
    let kdf = Shake128Kdf;
    let suite_id = b"suite";
    let salt = Some(b"salt" as &[u8]);
    let label = "test";
    let input_key = b"key";
    assert!(kdf
        .labeled_extract(suite_id, salt, label, input_key)
        .is_err());
}

#[test]
fn test_shake128_labeled_expand() {
    let kdf = Shake128Kdf;
    let suite_id = b"suite";
    let random_key = b"random_key";
    let label = "test";
    let info = b"info";
    let length = 16;
    assert!(kdf
        .labeled_expand(suite_id, random_key, label, info, length)
        .is_err());
}

#[test]
fn test_shake256_labeled_derive() {
    let kdf = Shake256Kdf;
    let suite_id = b"suite";
    let input_key = b"key";
    let label = "test";
    let context = b"context";
    let length = 16;
    let result = kdf
        .labeled_derive(suite_id, input_key, label, context, length)
        .unwrap();
    assert_eq!(result.len(), length as usize);
}

#[test]
fn test_shake256_labeled_extract() {
    let kdf = Shake256Kdf;
    let suite_id = b"suite";
    let salt = Some(b"salt" as &[u8]);
    let label = "test";
    let input_key = b"key";
    assert!(kdf
        .labeled_extract(suite_id, salt, label, input_key)
        .is_err());
}

#[test]
fn test_shake256_labeled_expand() {
    let kdf = Shake256Kdf;
    let suite_id = b"suite";
    let random_key = b"random_key";
    let label = "test";
    let info = b"info";
    let length = 16;
    assert!(kdf
        .labeled_expand(suite_id, random_key, label, info, length)
        .is_err());
}
