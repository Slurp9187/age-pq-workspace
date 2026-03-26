use age_hpke_pq::kem::Kem;
use age_hpke_pq::{
    new_aead, new_kdf, new_recipient, new_sender, AeadKey32, MlKem768X25519, Seed32,
};

#[test]
fn test_seed32_debug_redacted() {
    let seed = Seed32::from_random();
    let redacted = format!("{seed:?}");
    assert!(redacted.contains("[REDACTED]"));
}

#[test]
fn test_aead_key32_debug_redacted() {
    let key = AeadKey32::from_random();
    let redacted = format!("{key:?}");
    assert!(redacted.contains("[REDACTED]"));
}

#[test]
fn test_hpke_roundtrip_with_wrappers() {
    let kem = MlKem768X25519;
    let sk = kem.generate_key().expect("keygen failed");
    let pk = sk.public_key();

    let info = b"secure-gate-hpke";
    let aad = b"secure-gate-aad";
    let plaintext = b"secure-gate plaintext";

    let (enc, mut sender) = new_sender(
        pk,
        new_kdf(0x0001).expect("kdf"),
        new_aead(0x0003).expect("aead"),
        info,
    )
    .expect("new_sender");
    let ciphertext = sender.seal(aad, plaintext).expect("seal");

    let mut recipient = new_recipient(
        sk,
        &enc,
        new_kdf(0x0001).expect("kdf"),
        new_aead(0x0003).expect("aead"),
        info,
    )
    .expect("new_recipient");
    let opened = recipient.open(aad, &ciphertext).expect("open");

    assert_eq!(opened, plaintext);
}
