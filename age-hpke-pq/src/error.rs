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
    /// Invalid X25519 public key format.
    #[error("Invalid X25519 public key")]
    InvalidX25519PublicKey,

    /// Invalid X25519 private key.
    #[error("Invalid X25519 private key")]
    InvalidX25519PrivateKey,

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
