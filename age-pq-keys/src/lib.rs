//! # age-pq-keys
//!
//! This crate implements a post-quantum hybrid recipient and identity for the [`age`] encryption
//! tool, designed for potential integration into the official `rage` CLI and libraries.
//!
//! ## Overview
//!
//! The age encryption format supports pluggable recipients and identities for different
//! cryptographic primitives. This crate provides an [`HybridRecipient`] and [`HybridIdentity`]
//! that combine post-quantum key encapsulation mechanisms (ML-KEM-768) with traditional
//! elliptic-curve cryptography (X25519) for enhanced security against quantum attacks.
//!
//! The implementation is based on the age-pq-hpke crate, which provides HPKE (Hybrid Public Key
//! Encryption) primitives, and uses the same cryptographic parameters as the age-go plugin for
//! compatibility.
//!
//! ## Security
//!
//! - **Post-Quantum Security**: Leverages ML-KEM-768 (formerly Kyber-768), a lattice-based KEM
//!   standardized by NIST, to resist attacks from large-scale quantum computers.
//! - **Hybrid Design**: Combines PQ security with X25519 for efficiency and backward compatibility.
//! - **Zeroization**: Sensitive secrets (private-key seeds, decoded bech32 payloads, the
//!   decrypted file key) are held in [`secure-gate`] wrappers, which zeroize on drop and
//!   redact in `Debug`. Access requires an explicit `with_secret` / `expose_secret` call.
//! - **Secret Management**: Secrets stay wrapped for their whole lifetime inside the crate.
//!   Public API in/out types are native Rust types — callers who want zeroize-on-drop wrap
//!   the value themselves.
//!
//! ## Compatibility
//!
//! - **Age Format**: Fully compatible with the age file format and stanza structure.
//! - **Rage Integration**: `age`'s own types (`FileKey`, `Stanza`) are used unchanged at the
//!   trait boundary, so `secrecy` still appears wherever `age` dictates it — `FileKey` is
//!   `age`'s type and keeps `age`'s accessor. Everything this crate owns uses `secure-gate`.
//! - **Strict stanza validation**: A stanza carrying the `mlkem768x25519` tag must have exactly
//!   one argument, a canonical-base64 `enc` of 1120 bytes, and a 32-byte body. Anything else is
//!   a header failure, matching age and rage. Conformance is enforced by the C2SP CCTV testkit
//!   vectors in `tests/testkit.rs`.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use age_pq_keys::{HybridRecipient, HybridIdentity};
//! use std::str::FromStr;
//! // Generate a new recipient and identity pair
//! let (recipient, identity) = HybridRecipient::generate().unwrap();
//!
//! // Serialize to strings for storage. `identity.to_string()` carries the private
//! // key as a plain `String`; wrap it (`zeroize::Zeroizing`, `secure_gate::Dynamic`)
//! // if your threat model wants the buffer wiped on drop.
//! let recipient_str = recipient.to_string();
//! let identity_str = identity.to_string();
//!
//! // Parse back
//! let recipient = HybridRecipient::from_str(&recipient_str).unwrap();
//! let identity = HybridIdentity::from_str(&identity_str).unwrap();
//! ```
//!
//! See the documentation for [`HybridRecipient`] and [`HybridIdentity`] for more details.
//!
//! [`age`]: https://docs.rs/age/
//! [`rage`]: https://github.com/str4d/rage
mod aliases;

use age::{secrecy, Identity as AgeIdentity, Recipient as AgeRecipient};
use age_core::format::{FileKey, Stanza};
use age_pq_hpke::hpke::{new_recipient, new_sender};
use age_pq_hpke::kem::{Kem, MlKem768X25519};
use age_pq_hpke::{aead::new_aead, kdf::new_kdf};
use base64::prelude::{Engine as _, BASE64_STANDARD_NO_PAD};
use bech32::primitives::checksum::Checksum;
use bech32::primitives::decode::CheckedHrpstring;
use bech32::{encode, Bech32, Hrp};
// `ExposeSecret` here is `age`'s (re-exported `secrecy`) trait, needed for `FileKey`.
// secure-gate wrappers are read through `RevealSecret` / `RevealSecretMut` instead, so
// the two never compete: each method resolves on its own receiver type.
use crate::aliases::{FileKeyBytes, IdentityEncoding, Seed32, SeedBytes};
use secrecy::ExposeSecret;
use secure_gate::{RevealSecret, RevealSecretMut};
use std::collections::HashSet;
use std::str::FromStr;

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

/// Size of the stanza's `enc` argument: ML-KEM-768 ciphertext (1088) plus the
/// X25519 ephemeral share (32). A stanza claiming our tag with any other
/// length is malformed, not "addressed to someone else".
const ENC_SIZE: usize = 1120;

/// Size of the stanza body: the 16-byte age file key plus the 16-byte
/// ChaCha20-Poly1305 tag. Checked *before* decrypting, which is the
/// partitioning-oracle mitigation the age spec requires.
const STANZA_BODY_SIZE: usize = 32;

/// A stanza that claims our tag but is malformed fails the whole header.
///
/// Returning `None` here would mean "not for this identity, try the next one",
/// which lets a tampered header be silently skipped instead of rejected. age
/// and rage both treat this as fatal; the CCTV testkit enforces it.
fn header_failure() -> Option<Result<FileKey, age::DecryptError>> {
    Some(Err(age::DecryptError::InvalidHeader))
}

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
        // `PrivateKey::bytes` hands back a native Vec at the API boundary; wrap it
        // on arrival so the seed is never an unprotected buffer inside this crate.
        let seed_bytes = SeedBytes::new(sk.bytes()?);
        let seed = seed_bytes
            .with_secret(|b| Seed32::try_from(b.as_slice()))
            .map_err(|_| "Invalid seed length")?;
        let pub_key_bytes = pk.bytes();
        Ok((
            Self {
                pub_key: pub_key_bytes,
            },
            HybridIdentity { seed },
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
    seed: Seed32,
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

        // The bech32 payload is the private key; wrap it before it is validated.
        let seed_bytes = SeedBytes::new(checked.byte_iter().collect::<Vec<u8>>());
        let seed = seed_bytes
            .with_secret(|b| Seed32::try_from(b.as_slice()))
            .map_err(|_| {
                age::DecryptError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid seed length",
                ))
            })?;

        Ok(Self { seed })
    }

    /// Serializes the identity to its bech32-encoded string representation (uppercase).
    ///
    /// # Security
    ///
    /// The returned `String` **is the private key**. Public API outputs are native Rust
    /// types per the workspace wire-boundary rule, so this buffer is not zeroized on
    /// drop. Wrap it if that matters to you:
    ///
    /// ```rust,no_run
    /// # use age_pq_keys::HybridRecipient;
    /// use secure_gate::Dynamic;
    /// # let (_r, identity) = HybridRecipient::generate().unwrap();
    /// // Zeroized on drop, redacted in `Debug`.
    /// let encoded: Dynamic<String> = Dynamic::new(identity.to_string());
    /// ```
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        let hrp = Hrp::parse("age-secret-key-pq-").expect("static valid HRP");
        // Build and case-normalize inside the wrapper so the only unprotected copy is
        // the one handed to the caller. `make_ascii_uppercase` mutates in place, so no
        // second buffer is produced along the way.
        let mut encoded = IdentityEncoding::new(self.seed.with_secret(|seed| {
            encode::<Bech32>(hrp, seed).expect("encoding with valid data never fails")
        }));
        encoded.with_secret_mut(|s| s.make_ascii_uppercase());
        encoded.with_secret(|s| s.clone())
    }

    /// Derives the public recipient from this identity.
    pub fn to_public(&self) -> Result<HybridRecipient, Box<dyn std::error::Error>> {
        let kem = MlKem768X25519;
        let sk = self.seed.with_secret(|seed| kem.new_private_key(seed))?;
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
        // A different stanza kind genuinely is not ours: skip it, and let another
        // identity try. Everything past this point is a stanza claiming our tag,
        // so malformed input is a header failure, not a miss.
        if stanza.tag != STANZA_TAG {
            return None;
        }

        // Exactly one argument (the base64 `enc`). The old code also accepted a
        // two-argument form that repeated the tag; no age implementation emits
        // that, and accepting it made `hybrid_extra_argument` decrypt-adjacent
        // instead of rejected.
        if stanza.args.len() != 1 {
            return header_failure();
        }
        // Canonical unpadded base64 only — the engine rejects trailing bits.
        let enc = match BASE64_STANDARD_NO_PAD.decode(&stanza.args[0]) {
            Ok(b) => b,
            Err(_) => return header_failure(),
        };
        if enc.len() != ENC_SIZE {
            return header_failure();
        }
        // Length-check the body before any decryption is attempted.
        if stanza.body.len() != STANZA_BODY_SIZE {
            return header_failure();
        }

        let kem = MlKem768X25519;
        let sk = match self.seed.with_secret(|seed| kem.new_private_key(seed)) {
            Ok(s) => s,
            Err(_) => return header_failure(),
        };
        let kdf = match new_kdf(KDF_ID) {
            Ok(k) => k,
            Err(_) => return header_failure(),
        };
        let aead = match new_aead(AEAD_ID) {
            Ok(a) => a,
            Err(_) => return header_failure(),
        };

        // Set up and open as two steps so the failure modes stay distinguishable.
        // Decapsulation failure means the stanza itself is invalid (for example a
        // low-order X25519 share) and is fatal; AEAD failure means the file simply
        // is not addressed to this identity, which is a skip. Collapsing both into
        // `None` is what let `hybrid_low_order` through.
        let mut recipient = match new_recipient(sk, &enc, kdf, aead, PQ_LABEL) {
            Ok(r) => r,
            Err(_) => return header_failure(),
        };
        // `open` returns a native Vec at the API boundary; wrap the decrypted file key
        // on arrival so it is wiped on drop whichever way this function exits.
        let file_key_bytes = match recipient.open(&[], &stanza.body) {
            Ok(f) => FileKeyBytes::new(f),
            Err(_) => return None,
        };
        let file_key = match file_key_bytes.with_secret(|b| <[u8; 16]>::try_from(b.as_slice())) {
            Ok(arr) => FileKey::new(Box::new(arr)),
            // Unreachable given the body-length check above; treat a surprise as
            // malformed rather than silently skipping.
            Err(_) => return header_failure(),
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
