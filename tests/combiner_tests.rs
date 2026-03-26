//! Unit tests for combiner.

use age_hpke_pq::kem::combiner::combine_shared_secrets;
use age_hpke_pq::SHARED_SECRET_SIZE;
use sha3::{Digest, Sha3_256};

#[test]
fn test_combiner_consistency() {
    let ss_pq = [1u8; 32];
    let ss_t = [2u8; 32];
    let ct_t = [3u8; 32];
    let pk_t = [4u8; 32];

    let result1 = combine_shared_secrets(&ss_pq, &ss_t, &ct_t, &pk_t);
    let result2 = combine_shared_secrets(&ss_pq, &ss_t, &ct_t, &pk_t);

    assert_eq!(result1, result2);
    assert_eq!(result1.len(), SHARED_SECRET_SIZE);
}

#[test]
fn test_combiner_different_inputs() {
    let ss_pq = [1u8; 32];
    let ss_t = [2u8; 32];
    let ct_t = [3u8; 32];
    let pk_t = [4u8; 32];

    let result1 = combine_shared_secrets(&ss_pq, &ss_t, &ct_t, &pk_t);
    let result2 = combine_shared_secrets(&ss_t, &ss_pq, &pk_t, &ct_t); // swapped

    assert_ne!(result1, result2);
}

#[test]
fn test_combiner_includes_label() {
    // The label should ensure output differs from plain SHA3-256 of inputs
    let ss_pq = [0u8; 32];
    let ss_t = [0u8; 32];
    let ct_t = [0u8; 32];
    let pk_t = [0u8; 32];

    let plain_hash = Sha3_256::new()
        .chain_update(ss_pq)
        .chain_update(ss_t)
        .chain_update(ct_t)
        .chain_update(pk_t)
        .finalize();
    let combined = combine_shared_secrets(&ss_pq, &ss_t, &ct_t, &pk_t);

    assert_ne!(plain_hash.as_slice(), combined.as_ref());
}

#[test]
fn test_combiner_all_zero_inputs() {
    let ss_pq = [0u8; 32];
    let ss_t = [0u8; 32];
    let ct_t = [0u8; 32];
    let pk_t = [0u8; 32];
    let result = combine_shared_secrets(&ss_pq, &ss_t, &ct_t, &pk_t);
    // Should still produce a non-zero hash due to the label
    assert!(!result.iter().all(|&b| b == 0));
    assert_eq!(result.len(), SHARED_SECRET_SIZE);
}
