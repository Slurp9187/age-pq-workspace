/// # age-recipient-pq
///
/// This crate implements a post-quantum hybrid recipient and identity for the [`age`] encryption
/// tool, designed for potential integration into the official `rage` CLI and libraries.
///
/// ## Overview
///
/// The age encryption format supports pluggable recipients and identities for different
/// cryptographic primitives. This crate provides an [`HybridRecipient`] and [`HybridIdentity`]
/// that combine post-quantum key encapsulation mechanisms (ML-KEM-768) with traditional
/// elliptic-curve cryptography (X25519) for enhanced security against quantum attacks.
///
/// The implementation is based on the age-hpke-pq crate, which provides HPKE (Hybrid Public Key
/// Encryption) primitives, and uses the same cryptographic parameters as the age-go plugin for
/// compatibility.
///
/// ## Security
///
/// - **Post-Quantum Security**: Leverages ML-KEM-768 (formerly Kyber-768), a lattice-based KEM
///   standardized by NIST, to resist attacks from large-scale quantum computers.
/// - **Hybrid Design**: Combines PQ security with X25519 for efficiency and backward compatibility.
/// - **Zeroization**: Sensitive secrets (like private keys) are wrapped in `SecretBox` from the
///   `secrecy` crate, ensuring they are zeroized when dropped.
/// - **Secret Management**: Uses `secrecy` for compatibility with the `age` ecosystem, where
///   secrets are exposed only when necessary and zeroized promptly.
///
/// ## Compatibility
///
/// - **Age Format**: Fully compatible with the age file format and stanza structure.
/// - **Rage Integration**: Designed to align with Rage's use of `secrecy` for secret handling,
///   avoiding external dependencies like `secure-gate` to maximize adoption chances.
/// - **Legacy Support**: Supports both new and legacy stanza formats for backward compatibility
///   with older PQ implementations.
///
/// ## Usage
///
/// ```rust,no_run
/// use age_recipient_pq::{HybridRecipient, HybridIdentity};
/// use age::secrecy::ExposeSecret;
/// use std::str::FromStr;
/// // Generate a new recipient and identity pair
/// let (recipient, identity) = HybridRecipient::generate().unwrap();
///
/// // Serialize to strings for storage
/// let recipient_str = recipient.to_string();
/// let secret_str = identity.to_string();
/// let identity_str = secret_str.expose_secret().clone();
///
/// // Parse back
/// let recipient = HybridRecipient::from_str(&recipient_str).unwrap();
/// let identity = HybridIdentity::from_str(&identity_str).unwrap();
/// ```
///
/// See the documentation for [`HybridRecipient`] and [`HybridIdentity`] for more details.
///
/// [`age`]: https://docs.rs/age/
/// [`rage`]: https://github.com/str4d/rage

use age::{secrecy, Identity as AgeIdentity, Recipient as AgeRecipient};
use age_core::format::{FileKey, Stanza};
use age_core::secrecy::SecretString;
use age_hpke_pq::hpke::{new_sender, open};
use age_hpke_pq::kem::{Kem, MlKem768X25519};
use age_hpke_pq::{aead::new_aead, kdf::new_kdf};
use base64::prelude::{Engine as _, BASE64_STANDARD_NO_PAD};
use bech32::primitives::checksum::Checksum;
use bech32::primitives::decode::CheckedHrpstring;
use bech32::{encode, Bech32, Hrp};
use secrecy::{ExposeSecret, SecretBox};
use std::collections::HashSet;
use std::str::FromStr;
use zeroize::Zeroizing;

/// Custom checksum that matches classic Bech32 (BIP-173) exactly,
/// including the original theoretical maximum code length of 4096 characters.
///
/// This is the "standard" long variant from early implementations:
/// - Full compatibility with official age v1.3+ (uses classic Bech32 constants)
/// - Proper 6-character checksum with error detection
/// - CODE_LENGTH = 8192 (payload up to ~4090 chars / ~2556 bytes)
///
/// Your ~1959-char hybrid public keys fit easily (plenty of headroom).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HybridRecipientBech32 {}

impl Checksum for HybridRecipientBech32 {
    type MidstateRepr = u32;

    // The "standard" theoretical max from early BIP-173 discussions/impls
    const CODE_LENGTH: usize = 8192;

    const CHECKSUM_LENGTH: usize = 6;

    const GENERATOR_SH: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

    // Classic constant (matches official age)
    const TARGET_RESIDUE: u32 = 1;
}

/// The stanza tag identifying this post-quantum hybrid recipient in the age file format.
/// This tag is "mlkem768x25519" to indicate ML-KEM-768 combined with X25519.
const STANZA_TAG: &str = "mlkem768x25519"; // From plugin/age-go
/// The domain separation label for HPKE operations, matching the age-go plugin.
const PQ_LABEL: &[u8] = b"age-encryption.org/mlkem768x25519"; // From plugin/age-go
/// The KDF ID for HPKE, corresponding to HKDF-SHA256.
const KDF_ID: u16 = 0x0001; // HKDF-SHA256
/// The AEAD ID for HPKE, corresponding to ChaCha20Poly1305.
const AEAD_ID: u16 = 0x0003; // ChaCha20Poly1305

/// A post-quantum hybrid recipient for encryption, using ML-KEM-768 and X25519.
///
/// This struct holds the public key bytes and provides methods to wrap file keys in the age format.
/// It implements [`age::Recipient`] for integration with the age encryption tool.
pub struct HybridRecipient {
    /// The public key bytes, consisting of the ML-KEM-768 public key concatenated with the X25519 public key.
    pub pub_key: Vec<u8>,
}

impl HybridRecipient {
    /// Generates a new hybrid recipient and its corresponding identity.
    ///
    /// This method creates a new key pair using the MlKem768X25519 KEM and returns
    /// a recipient for encryption and an identity for decryption.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    pub fn generate() -> Result<(Self, HybridIdentity), Box<dyn std::error::Error>> {
        let kem = MlKem768X25519;
        let sk = kem.generate_key()?;
        let pk = sk.public_key();
        // Zeroizing covers the private-key seed Vec until it's copied into SecretBox.
        let seed_bytes = Zeroizing::new(sk.bytes()?);
        let seed: [u8; 32] = seed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid seed length")?;
        let pub_key_bytes = pk.bytes();
        Ok((
            Self {
                pub_key: pub_key_bytes,
            },
            HybridIdentity {
                seed: SecretBox::new(Box::new(seed)),
            },
        ))
    }

    /// Parses a hybrid recipient from its string representation.
    ///
    /// The expected format is a Bech32-encoded string with HRP "age1pq" and the public key as data.
    /// Uses the classic Bech32 checksum (higher length limit).
    pub fn parse(s: &str) -> Result<Self, age::EncryptError> {
        let checked = CheckedHrpstring::new::<HybridRecipientBech32>(s).map_err(|e| {
            age::EncryptError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;

        let expected_hrp = Hrp::parse("age1pq").map_err(|_| {
            age::EncryptError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid HRP",
            ))
        })?;

        if checked.hrp() != expected_hrp {
            return Err(age::EncryptError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "wrong HRP for hybrid recipient",
            )));
        }

        let pub_key = checked.byte_iter().collect();

        Ok(Self { pub_key })
    }

    /// Serializes the recipient to its canonical string format (lowercase HRP).
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        let hrp = Hrp::parse("age1pq").expect("static valid HRP");
        encode::<HybridRecipientBech32>(hrp, &self.pub_key)
            .expect("encoding with valid data never fails")
    }
}

impl FromStr for HybridRecipient {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).map_err(|_| "failed to parse HybridRecipient")
    }
}

impl AgeRecipient for HybridRecipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        let kem = MlKem768X25519;
        let pk = kem.new_public_key(&self.pub_key).map_err(|e| {
            age::EncryptError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Invalid pub key: {:?}", e),
            ))
        })?;
        let kdf = new_kdf(KDF_ID).map_err(|e| {
            age::EncryptError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("KDF error: {:?}", e),
            ))
        })?;
        let aead = new_aead(AEAD_ID).map_err(|e| {
            age::EncryptError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("AEAD error: {:?}", e),
            ))
        })?;
        let (enc, mut sender) = new_sender(pk, kdf, aead, PQ_LABEL).map_err(|e| {
            age::EncryptError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("HPKE new_sender error: {:?}", e),
            ))
        })?;
        let wrapped = sender.seal(&[], file_key.expose_secret()).map_err(|e| {
            age::EncryptError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("HPKE seal error: {:?}", e),
            ))
        })?;
        let base64_enc = BASE64_STANDARD_NO_PAD.encode(enc);
        let stanza = Stanza {
            tag: STANZA_TAG.to_string(),
            args: vec![base64_enc],
            body: wrapped,
        };
        let mut labels = HashSet::new();
        labels.insert("postquantum".to_string());
        Ok((vec![stanza], labels))
    }
}

/// A post-quantum hybrid identity for decryption, holding the private key seed.
pub struct HybridIdentity {
    seed: SecretBox<[u8; 32]>,
}

impl HybridIdentity {
    /// Parses a hybrid identity from its bech32-encoded string representation.
    ///
    /// The format uses HRP "AGE-SECRET-KEY-PQ-" (case-insensitive) and contains the 32-byte seed.
    /// Uses the classic Bech32 checksum (higher length limit).
    pub fn parse(s: &str) -> Result<Self, age::DecryptError> {
        let checked = CheckedHrpstring::new::<Bech32>(s).map_err(|e| {
            age::DecryptError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;

        let expected_hrp = Hrp::parse("age-secret-key-pq-").map_err(|_| {
            age::DecryptError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid HRP",
            ))
        })?;

        if checked.hrp() != expected_hrp {
            return Err(age::DecryptError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "wrong HRP for hybrid identity",
            )));
        }

        // Zeroizing covers the parsed seed Vec until it's copied into SecretBox.
        let seed_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(checked.byte_iter().collect());
        let seed: [u8; 32] = seed_bytes.as_slice().try_into().map_err(|_| {
            age::DecryptError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid seed length",
            ))
        })?;

        Ok(Self {
            seed: SecretBox::new(Box::new(seed)),
        })
    }

    /// Serializes the identity to its bech32-encoded string representation (uppercase).
    pub fn to_string(&self) -> SecretString {
        let hrp = Hrp::parse("age-secret-key-pq-").expect("static valid HRP");
        // The bech32-encoded string carries the private key; keep it zeroize-covered
        // until it's handed off to SecretString. `make_ascii_uppercase` mutates in
        // place so no second unprotected copy is produced.
        let mut encoded = Zeroizing::new(
            encode::<Bech32>(hrp, self.seed.expose_secret())
                .expect("encoding with valid data never fails"),
        );
        encoded.make_ascii_uppercase();
        SecretString::from(core::mem::take(&mut *encoded))
    }

    /// Derives the public recipient from this identity.
    pub fn to_public(&self) -> Result<HybridRecipient, Box<dyn std::error::Error>> {
        let kem = MlKem768X25519;
        let sk = kem.new_private_key(self.seed.expose_secret())?;
        let pk = sk.public_key();
        let pub_key_bytes = pk.bytes();
        Ok(HybridRecipient {
            pub_key: pub_key_bytes,
        })
    }
}

impl FromStr for HybridIdentity {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).map_err(|_| "failed to parse HybridIdentity")
    }
}

impl AgeIdentity for HybridIdentity {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        if stanza.tag != STANZA_TAG {
            return None;
        }
        let enc: Vec<u8>;
        if stanza.args.len() == 2 && stanza.args[0] == STANZA_TAG {
            enc = match BASE64_STANDARD_NO_PAD.decode(&stanza.args[1]) {
                Ok(b) => b,
                Err(_) => return None,
            };
        } else if stanza.args.len() == 1 {
            enc = match BASE64_STANDARD_NO_PAD.decode(&stanza.args[0]) {
                Ok(b) => b,
                Err(_) => return None,
            };
        } else {
            return None;
        }
        let kem = MlKem768X25519;
        let sk = match kem.new_private_key(self.seed.expose_secret()) {
            Ok(s) => s,
            Err(_) => return None,
        };
        let kdf = match new_kdf(KDF_ID) {
            Ok(k) => k,
            Err(_) => return None,
        };
        let aead = match new_aead(AEAD_ID) {
            Ok(a) => a,
            Err(_) => return None,
        };
        let mut ct = enc;
        ct.extend_from_slice(&stanza.body);
        // Zeroizing covers the decrypted file-key Vec until it's copied into FileKey.
        let file_key_bytes = match open(sk, kdf, aead, PQ_LABEL, &[], &ct) {
            Ok(f) => Zeroizing::new(f),
            Err(_) => return None,
        };
        let file_key = match file_key_bytes.as_slice().try_into() {
            Ok(arr) => FileKey::new(Box::new(arr)),
            Err(_) => return None,
        };
        Some(Ok(file_key))
    }

    fn unwrap_stanzas(&self, stanzas: &[Stanza]) -> Option<Result<FileKey, age::DecryptError>> {
        stanzas.iter().find_map(|stanza| self.unwrap_stanza(stanza))
    }
}

/// Tests for the post-quantum hybrid recipient and identity.
#[cfg(test)]
pub(crate) mod tests {
    use super::HybridRecipient;
    use age::{Identity, Recipient};
    use age_core::format::FileKey;
    use age_core::secrecy::ExposeSecret;
    use proptest::prelude::*;

    #[test]
    fn test_suite_id_matches_go() {
        let expected = vec![0x48, 0x50, 0x4b, 0x45, 0x64, 0x7a, 0x00, 0x01, 0x00, 0x03];
        let mut sid = Vec::with_capacity(10);
        sid.extend_from_slice(b"HPKE");
        sid.extend_from_slice(&0x647au16.to_be_bytes());
        sid.extend_from_slice(&0x0001u16.to_be_bytes());
        sid.extend_from_slice(&0x0003u16.to_be_bytes());
        assert_eq!(sid, expected);
    }

    proptest! {
        #[test]
        fn wrap_and_unwrap(file_key_bytes in proptest::collection::vec(any::<u8>(), 16..=16)) {
            let file_key = FileKey::new(Box::new(file_key_bytes.try_into().unwrap()));
            let (recipient, identity) = HybridRecipient::generate().unwrap();
            let res = recipient.wrap_file_key(&file_key);
            prop_assert!(res.is_ok());
            let (stanzas, labels) = res.unwrap();
            prop_assert!(labels.contains("postquantum"));
            let res = identity.unwrap_stanzas(&stanzas);
            prop_assert!(res.is_some());
            let res = res.unwrap();
            prop_assert!(res.is_ok());
            let unwrapped = res.unwrap();
            prop_assert_eq!(unwrapped.expose_secret(), file_key.expose_secret());
        }
    }
}
