//! Semantically named secret wrappers owned by this crate.
//!
//! These are **nominal newtypes**, not type aliases. Every 32-byte role here was
//! once a `fixed_alias!`, which expands to a `type` alias — so `Seed32`,
//! `AeadKey32` and the shared secrets were all literally `Fixed<[u8; 32]>`, the
//! *same type*. Passing a decapsulation seed where an AEAD key belonged
//! compiled silently. `fixed_newtype!` emits distinct `struct`s instead, so the
//! compiler rejects a crossed role:
//!
//! ```compile_fail
//! use age_pq_hpke::{AeadKey32, Seed32};
//! fn takes_aead_key(_: AeadKey32) {}
//! // A seed is not a key, even though both are 32 bytes.
//! takes_aead_key(Seed32::from([0u8; 32]));
//! ```
//!
//! The matching correct call does compile, which is what keeps the example
//! above honest — a `compile_fail` block that failed for some unrelated reason
//! (a bad import, say) would prove nothing:
//!
//! ```
//! use age_pq_hpke::AeadKey32;
//! fn takes_aead_key(_: AeadKey32) {}
//! takes_aead_key(AeadKey32::from([0u8; 32]));
//! ```
//!
//! The newtypes are `#[repr(transparent)]` with `#[inline]` delegation, and
//! keep every wrapper guarantee: zeroize on drop, `[REDACTED]` in `Debug`, no
//! `Deref`, access only through `RevealSecret`.

use secure_gate::{dynamic_newtype, fixed_newtype};

// Public aliases (crate surface)
fixed_newtype!(pub Seed32, 32, "32-byte master seed for deterministic key generation.");
fixed_newtype!(
    pub SharedSecret,
    32,
    "Hybrid post-quantum/classical shared secret (32 bytes).",
    derive: [ConstantTimeEq]
);
fixed_newtype!(pub AeadKey32, 32, "ChaCha20-Poly1305 key (32 bytes).");
fixed_newtype!(pub Nonce12, 12, "ChaCha20-Poly1305 nonce (12 bytes).");
fixed_newtype!(
    pub MlKemSeed64,
    64,
    "ML-KEM `d || z` seed (64 bytes), produced by `expand_seed` and consumed by libcrux's keypair generator."
);

// Crate-internal aliases (auditability wrappers)
// Fixed-size aliases — KEM internals
// The combiner takes the ML-KEM and traditional component secrets in a fixed
// order. While both were `SharedSecret32` the compiler could not tell them
// apart, so a swapped pair produced a silently wrong hybrid secret. Splitting
// the role makes that a type error — see `kem::combiner`.
fixed_newtype!(
    pub(crate) MlKemSharedSecret,
    32,
    "Shared secret from ML-KEM encapsulation/decapsulation — the post-quantum component fed to the combiner.",
    derive: [ConstantTimeEq]
);
fixed_newtype!(
    pub(crate) X25519SharedSecret,
    32,
    "Shared secret from X25519 Diffie-Hellman — the traditional component fed to the combiner.",
    derive: [ConstantTimeEq]
);
// `ct_t` and `ek_t` in the combiner are both 32-byte X25519 public keys but play
// different roles, and crossing them also yields a silently wrong hybrid secret.
// Names follow `hpke-pq.md`. Both are distinct from `x25519_dalek::PublicKey`,
// which is the parsed point rather than raw bytes.
fixed_newtype!(
    pub(crate) X25519EphemeralShare,
    32,
    "`ct_t` — the sender's ephemeral X25519 public key, carried in the ciphertext."
);
fixed_newtype!(
    pub(crate) X25519EncapsulationKey,
    32,
    "`ek_t` — the recipient's long-term X25519 public key, bound into the combiner."
);
fixed_newtype!(pub(crate) X25519Scalar, 32, "Raw X25519 scalar, clamped before use.");
fixed_newtype!(
    pub(crate) X448PublicKeyBytes,
    56,
    "Raw X448 public-key bytes. Distinct from `x448::PublicKey`, which is the parsed point."
);
fixed_newtype!(pub(crate) X448Scalar, 56, "Raw X448 scalar, before clamping.");
fixed_newtype!(
    pub(crate) X448SharedSecret,
    56,
    "Shared secret from X448 Diffie-Hellman.",
    derive: [ConstantTimeEq]
);
fixed_newtype!(
    pub(crate) MlKem768PublicKey1184,
    1184,
    "Raw ML-KEM-768 public key."
);
fixed_newtype!(
    pub(crate) MlKem768Ciphertext1088,
    1088,
    "Raw ML-KEM-768 ciphertext."
);
#[cfg(feature = "mlkem512")]
fixed_newtype!(
    pub(crate) MlKem512PublicKey800,
    800,
    "Raw ML-KEM-512 public key."
);
#[cfg(feature = "mlkem512")]
fixed_newtype!(
    pub(crate) MlKem512Ciphertext768,
    768,
    "Raw ML-KEM-512 ciphertext."
);
#[cfg(feature = "mlkem1024")]
fixed_newtype!(
    pub(crate) MlKem1024PublicKey1568,
    1568,
    "Raw ML-KEM-1024 public key."
);
#[cfg(feature = "mlkem1024")]
fixed_newtype!(
    pub(crate) MlKem1024Ciphertext1568,
    1568,
    "Raw ML-KEM-1024 ciphertext."
);
fixed_newtype!(
    pub(crate) ExpandedKeyMaterial96,
    96,
    "96-byte expanded key material buffer for ML-KEM seed and X25519 scalar derivation."
);

// Dynamic aliases — HPKE / KDF buffers
dynamic_newtype!(
    pub(crate) Info,
    Vec<u8>,
    "HPKE info string (public, arbitrary length)."
);
dynamic_newtype!(pub(crate) Aad, Vec<u8>, "Additional authenticated data (public).");
dynamic_newtype!(
    pub Plaintext,
    Vec<u8>,
    "Opt-in wrapper for plaintext bytes. The public API returns raw `Vec<u8>` — callers who want zeroize-on-drop and redacted `Debug` can wrap via `Plaintext::new(bytes)`."
);
dynamic_newtype!(pub(crate) ExporterContext, Vec<u8>, "HPKE exporter context.");
dynamic_newtype!(
    pub KdfBytes,
    Vec<u8>,
    "Heap buffer for HPKE KDF outputs and key-schedule intermediates. Used inside the library to keep PRKs, OKMs, and the HPKE exporter secret wrapped end-to-end. Also re-exported so callers can opt into wrapping their own KDF output via `KdfBytes::new(bytes)`."
);
dynamic_newtype!(
    pub(crate) OneStageSecrets,
    Vec<u8>,
    "One-stage HPKE secrets serialization buffer: len(psk) || len(ss) || ss."
);
dynamic_newtype!(
    pub(crate) LabeledIkm,
    Vec<u8>,
    "HPKE labeled IKM buffer used as HKDF-Extract input."
);
dynamic_newtype!(
    pub(crate) LabeledInfo,
    Vec<u8>,
    "HPKE labeled info buffer used as HKDF-Expand info parameter."
);
dynamic_newtype!(
    pub(crate) Salt,
    Vec<u8>,
    "HKDF-Extract salt. Typically public but named for auditability and self-documentation."
);
