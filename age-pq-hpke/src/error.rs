//! Error types for HPKE (Hybrid Public Key Encryption) operations
//! with X-Wing post-quantum KEM.

use thiserror::Error;

/// Errors that can occur during HPKE operations.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    // === Length / Format Errors ===
    /// The encapsulation key has an invalid length.
    #[error("Invalid encapsulation key length")]
    InvalidEncapsulationKeyLength,

    /// The ciphertext has an invalid length.
    #[error("Invalid ciphertext length")]
    InvalidCiphertextLength,

    /// The decapsulation key has an invalid length.
    #[error("Invalid decapsulation key length")]
    InvalidDecapsulationKeyLength,

    /// Invalid key length for AEAD.
    #[error("Invalid key length")]
    InvalidKeyLength,

    /// Generic length error (used when no more specific variant applies).
    #[error("Invalid length")]
    InvalidLength,

    /// Exporter requested more bytes than the HPKE specification allows.
    #[error("exporter length too large (maximum 65535 bytes)")]
    ExporterLengthTooLarge,

    // === Cryptographic Operation Errors ===
    /// AEAD encryption failed.
    #[error("encryption failed")]
    EncryptionFailed,

    /// Decryption failed (AEAD authentication failure or other).
    #[error("Decryption failed")]
    DecryptionFailed,

    // === State / Protocol Errors ===
    /// Operation attempted on an export-only context (no AEAD key).
    #[error("Export only")]
    ExportOnly,

    /// Sequence number overflow — further encryption would reuse nonces.
    #[error("sequence number overflow")]
    SequenceNumberOverflow,

    // === Other ===
    /// The ML-KEM half of an encapsulation key failed the FIPS 203 section 7.2
    /// encapsulation-key check.
    ///
    /// The check is `ByteEncode_12(ByteDecode_12(ek)) == ek`: every 12-bit
    /// coefficient must be less than q = 3329, so the byte string is the
    /// canonical encoding of the polynomial it decodes to. X-Wing
    /// (draft-connolly-cfrg-xwing-kem-07 section 4) makes this a MUST on the
    /// encapsulation side — and separately waives the section 7.3
    /// decapsulation-key check, which is why nothing on the decap path
    /// produces this variant.
    ///
    /// Distinct from [`Error::InvalidEncapsulationKeyLength`]: the key is the
    /// right size, its contents are not a valid ML-KEM encoding.
    #[error("Invalid ML-KEM encapsulation key")]
    InvalidMlKemEncapsulationKey,

    /// Invalid X25519 public key format.
    #[error("Invalid X25519 public key")]
    InvalidX25519PublicKey,

    /// Invalid X25519 private key.
    #[error("Invalid X25519 private key")]
    InvalidX25519PrivateKey,

    /// X25519 Diffie-Hellman produced the all-zero (non-contributory) shared
    /// secret, which means the peer's public key was a low-order point.
    ///
    /// Accepting this would collapse the classical half of the hybrid KEM to a
    /// known constant, so it is rejected. Official age and rage reject it too;
    /// the CCTV `hybrid_low_order` and `hybrid_identity` vectors cover it.
    #[error("X25519 Diffie-Hellman failed (non-contributory shared secret)")]
    X25519DiffieHellmanFailed,

    /// Invalid X448 public key format.
    #[error("Invalid X448 public key")]
    InvalidX448PublicKey,

    /// Invalid X448 private key.
    #[error("Invalid X448 private key")]
    InvalidX448PrivateKey,

    /// X448 Diffie-Hellman produced a low-order point.
    #[error("X448 Diffie-Hellman failed (low-order point)")]
    X448DiffieHellmanFailed,

    /// Array size conversion failed.
    #[error("Array size conversion failed")]
    ArraySizeError,

    /// Randomness generation error.
    #[error("Randomness generation error")]
    RandomnessError,

    /// Insufficient testing randomness.
    #[error("Insufficient testing randomness")]
    InsufficientTestingRandomness,

    /// Unsupported AEAD algorithm.
    #[error("Unsupported AEAD algorithm")]
    UnsupportedAead,

    /// Unsupported KDF algorithm.
    #[error("Unsupported KDF algorithm")]
    UnsupportedKdf,

    /// Invalid operation for KDF.
    #[error("Invalid operation for KDF")]
    InvalidOperationForKdf,
}

/// Type alias for results in HPKE operations.
pub type Result<T> = core::result::Result<T, Error>;
