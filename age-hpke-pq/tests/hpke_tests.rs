// age-hpke-pq/tests/hpke_tests.rs

mod tests {
    use age_hpke_pq::{
        kem::Kem, new_aead, new_kdf, new_recipient, new_sender, new_sender_with_testing_randomness,
        open, seal, ChaCha20Poly1305Aead, Error, HkdfSha256, MlKem768X25519,
    };

    #[test]
    fn test_seal_open_round_trip() {
        let kem = MlKem768X25519;
        let priv_key = kem.generate_key().unwrap();
        let pub_key = priv_key.public_key();

        let kdf = Box::new(HkdfSha256);
        let aead = Box::new(ChaCha20Poly1305Aead);

        let info = b"test info";
        let plaintext = b"hello world";
        let aad = b"additional authenticated data";

        let (enc, mut sender) = new_sender(pub_key, kdf, aead, info).unwrap();
        let ciphertext = sender.seal(aad, plaintext).unwrap();

        let mut recipient = new_recipient(
            priv_key,
            &enc,
            new_kdf(0x0001).unwrap(),
            new_aead(0x0003).unwrap(),
            info,
        )
        .unwrap();
        let decrypted = recipient.open(aad, &ciphertext).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_seal_open_with_testing_randomness() {
        let kem = MlKem768X25519;
        let seed = [0u8; 32];
        let priv_key = kem.new_private_key(&seed).unwrap();
        let pub_key = priv_key.public_key();

        let kdf = Box::new(HkdfSha256);
        let aead = Box::new(ChaCha20Poly1305Aead);

        let info = b"test info";
        let plaintext = b"hello world";
        let aad = b"";

        let testing_rand = vec![0u8; 32 + 32]; // For encap randomness

        let (enc, mut sender) =
            new_sender_with_testing_randomness(pub_key, Some(&testing_rand), kdf, aead, info)
                .unwrap();
        let ciphertext = sender.seal(aad, plaintext).unwrap();

        let mut recipient = new_recipient(
            priv_key,
            &enc,
            new_kdf(0x0001).unwrap(),
            new_aead(0x0003).unwrap(),
            info,
        )
        .unwrap();
        let decrypted = recipient.open(aad, &ciphertext).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_single_use_seal_open() {
        let kem = MlKem768X25519;
        let priv_key = kem.generate_key().unwrap();
        let pub_key = priv_key.public_key();

        let kdf = Box::new(HkdfSha256);
        let aead = Box::new(ChaCha20Poly1305Aead);

        let info = b"test info";
        let plaintext = b"single use test";
        let aad = b"single use aad";

        let combined_ciphertext = seal(pub_key, kdf, aead, info, aad, plaintext).unwrap();

        let decrypted = open(
            priv_key,
            Box::new(HkdfSha256),
            Box::new(ChaCha20Poly1305Aead),
            info,
            aad,
            &combined_ciphertext,
        )
        .unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_multiple_seals_seq_num() {
        let kem = MlKem768X25519;
        let priv_key = kem.generate_key().unwrap();
        let pub_key = priv_key.public_key();

        let info = b"test";
        let (enc, mut sender) = new_sender(
            pub_key,
            new_kdf(0x0001).unwrap(),
            new_aead(0x0003).unwrap(),
            info,
        )
        .unwrap();

        let pt1 = b"first";
        let ct1 = sender.seal(&[], pt1).unwrap();

        let pt2 = b"second";
        let ct2 = sender.seal(&[], pt2).unwrap();

        // Different ciphertexts for different plaintexts due to seq num/nonce increment
        assert_ne!(ct1, ct2);
        assert!(!ct1.is_empty());
        assert!(!ct2.is_empty());

        // Verify opening one of them works
        let mut recipient = new_recipient(
            priv_key,
            &enc,
            new_kdf(0x0001).unwrap(),
            new_aead(0x0003).unwrap(),
            info,
        )
        .unwrap();
        let decrypted1 = recipient.open(&[], &ct1).unwrap();
        assert_eq!(&decrypted1, pt1);
    }

    #[test]
    fn test_export() {
        let kem = MlKem768X25519;
        let priv_key = kem.generate_key().unwrap();
        let pub_key = priv_key.public_key();

        let info = b"test";
        let (enc, sender) = new_sender(
            pub_key,
            new_kdf(0x0001).unwrap(),
            new_aead(0x0003).unwrap(),
            info,
        )
        .unwrap();
        let exported = sender.export(b"exporter", 32).unwrap();
        assert_eq!(exported.len(), 32);

        let recipient = new_recipient(
            priv_key,
            &enc,
            new_kdf(0x0001).unwrap(),
            new_aead(0x0003).unwrap(),
            info,
        )
        .unwrap();
        let exported_rec = recipient.export(b"exporter", 32).unwrap();
        assert_eq!(exported, exported_rec);
    }

    #[test]
    fn test_export_invalid_length() {
        let kem = MlKem768X25519;
        let priv_key = kem.generate_key().unwrap();
        let pub_key = priv_key.public_key();

        let info = b"test";
        let (_enc, sender) = new_sender(
            pub_key,
            new_kdf(0x0001).unwrap(),
            new_aead(0x0003).unwrap(),
            info,
        )
        .unwrap();
        let err = sender
            .export(b"exporter", u16::MAX as usize + 1)
            .unwrap_err();
        assert!(matches!(err, Error::ExporterLengthTooLarge));
    }

    #[test]
    fn test_open_invalid_ciphertext_length() {
        let kem = MlKem768X25519;
        let priv_key = kem.generate_key().unwrap();

        let kdf = Box::new(HkdfSha256);
        let aead = Box::new(ChaCha20Poly1305Aead);

        let info = b"test";
        let invalid_ct = vec![0u8; 10]; // Too short for enc + ct
        let err = open(priv_key, kdf, aead, info, b"", &invalid_ct).unwrap_err();
        assert!(matches!(err, Error::InvalidCiphertextLength));
    }

    #[test]
    fn test_empty_info_aad() {
        let kem = MlKem768X25519;
        let priv_key = kem.generate_key().unwrap();
        let pub_key = priv_key.public_key();

        let kdf = new_kdf(0x0001).unwrap();
        let aead = new_aead(0x0003).unwrap();

        let info = &[];
        let plaintext = b"test";
        let aad = &[];

        let (enc, mut sender) = new_sender(
            pub_key,
            new_kdf(0x0001).unwrap(),
            new_aead(0x0003).unwrap(),
            info,
        )
        .unwrap();
        let ciphertext = sender.seal(aad, plaintext).unwrap();

        let mut recipient = new_recipient(priv_key, &enc, kdf, aead, info).unwrap();
        let decrypted = recipient.open(aad, &ciphertext).unwrap();

        assert_eq!(&decrypted, plaintext);
    }
}
