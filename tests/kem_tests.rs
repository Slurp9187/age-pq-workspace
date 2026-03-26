mod tests {
    use age_hpke_pq::{kem::Kem, Error, MlKem768X25519};

    #[test]
    fn test_mlkem768_properties() {
        let kem = MlKem768X25519;
        assert_eq!(kem.id(), 0x647a);
        assert_eq!(kem.enc_size(), 1088 + 32);
        // Public key size should be enc_size (for ML-KEM pk) + X25519 pk size
        assert_eq!(kem.public_key_size(), 1184 + 32);
    }

    #[test]
    fn test_generate_key() {
        let kem = MlKem768X25519;
        let priv_key = kem.generate_key().unwrap();
        assert_eq!(priv_key.kem().id(), 0x647a);

        let pub_key = priv_key.public_key();
        assert_eq!(pub_key.kem().id(), 0x647a);
        assert_eq!(pub_key.bytes().len(), 1184 + 32);
    }

    #[test]
    fn test_new_private_key() {
        let kem = MlKem768X25519;
        let seed = [0u8; 32];
        let priv_key = kem.new_private_key(&seed).unwrap();
        assert_eq!(priv_key.kem().id(), 0x647a);

        let seed_bytes = priv_key.bytes().unwrap();
        assert_eq!(seed_bytes.len(), 32);
        assert_eq!(seed_bytes, seed);
    }

    #[test]
    fn test_new_public_key() {
        let kem = MlKem768X25519;
        // First create a public key from a private key
        let seed = [0u8; 32];
        let priv_key = kem.new_private_key(&seed).unwrap();
        let pub_key = priv_key.public_key();
        let pub_bytes = pub_key.bytes();

        // Now recreate from bytes
        let pub_key2 = kem.new_public_key(&pub_bytes).unwrap();
        assert_eq!(pub_key2.bytes(), pub_bytes);
    }

    #[test]
    fn test_derive_key_pair() {
        let kem = MlKem768X25519;
        let ikm = b"initial key material";
        let priv_key = kem.derive_key_pair(ikm).unwrap();
        assert_eq!(priv_key.kem().id(), 0x647a);

        // Derive again with same ikm, should get same key
        let priv_key2 = kem.derive_key_pair(ikm).unwrap();
        let pub_key = priv_key.public_key();
        let pub_key2 = priv_key2.public_key();
        assert_eq!(pub_key.bytes(), pub_key2.bytes());

        // Test error on empty IKM
        let _ = kem.derive_key_pair(&[]).unwrap();
        // Just check it succeeds, even for empty IKM
    }

    #[test]
    fn test_encap_decap_round_trip() {
        let kem = MlKem768X25519;
        let seed = [0u8; 32];
        let priv_key = kem.new_private_key(&seed).unwrap();
        let pub_key = priv_key.public_key();

        let (enc, ss1) = pub_key.encap(None).unwrap();
        assert_eq!(enc.len(), kem.enc_size());

        let ss2 = priv_key.decap(&enc).unwrap();
        assert_eq!(ss1.as_ref(), ss2.as_ref());
        // Shared secret should be 32 bytes for hybrid
        assert_eq!(ss1.as_ref().len(), 32);
    }

    #[test]
    fn test_encap_decap_with_testing_randomness() {
        let kem = MlKem768X25519;
        let seed = [0u8; 32];
        let priv_key = kem.new_private_key(&seed).unwrap();
        let pub_key = priv_key.public_key();

        // Use fixed randomness for deterministic test
        let testing_rand = vec![0u8; 64]; // Adjust size if API expects specific (e.g., for ML-KEM + X25519)
        let (enc, ss1) = pub_key.encap(Some(&testing_rand)).unwrap();
        assert_eq!(enc.len(), kem.enc_size());

        let ss2 = priv_key.decap(&enc).unwrap();
        assert_eq!(ss1.as_ref(), ss2.as_ref());
        assert_eq!(ss1.as_ref().len(), 32);
    }

    #[test]
    fn test_new_public_key_invalid_length() {
        let kem = MlKem768X25519;
        let invalid_data = vec![0u8; 100]; // Too short for public key
        assert!(kem.new_public_key(&invalid_data).is_err());
    }

    #[test]
    fn test_new_private_key_invalid_length() {
        let kem = MlKem768X25519;
        let invalid_seed = vec![0u8; 16]; // Wrong size (should be 32)
        assert!(kem.new_private_key(&invalid_seed).is_err());
    }

    #[test]
    fn test_decap_invalid_enc_length() {
        let kem = MlKem768X25519;
        let seed = [0u8; 32];
        let priv_key = kem.new_private_key(&seed).unwrap();
        let invalid_enc = vec![0u8; 100]; // Wrong length
        assert!(priv_key.decap(&invalid_enc).is_err());
    }

    #[test]
    fn test_encap_insufficient_randomness() {
        let kem = MlKem768X25519;
        let seed = [0u8; 32];
        let priv_key = kem.new_private_key(&seed).unwrap();
        let pub_key = priv_key.public_key();
        let insufficient_rand = vec![0u8; 10]; // Too short for testing randomness
        let err = pub_key.encap(Some(&insufficient_rand)).unwrap_err();
        assert!(matches!(err, Error::InsufficientTestingRandomness));
    }

    #[test]
    fn test_encap_decap_different_keys() {
        let kem = MlKem768X25519;
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];
        let priv_key1 = kem.new_private_key(&seed1).unwrap();
        let pub_key1 = priv_key1.public_key();

        let (enc, ss1) = pub_key1.encap(None).unwrap();

        // Decap with wrong private key
        let priv_key2 = kem.new_private_key(&seed2).unwrap();
        let ss2 = priv_key2.decap(&enc).unwrap();
        assert_ne!(ss1.as_ref(), ss2.as_ref());
    }
}
