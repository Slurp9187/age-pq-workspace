use secure_gate::{dynamic_alias, fixed_alias};

// Public aliases (crate surface)
fixed_alias!(pub Seed32, 32, "32-byte master seed for deterministic key generation.");
fixed_alias!(
    pub SharedSecret,
    32,
    "Hybrid post-quantum/classical shared secret (32 bytes)."
);
fixed_alias!(pub AeadKey32, 32, "ChaCha20-Poly1305 key (32 bytes).");
fixed_alias!(pub Nonce12, 12, "ChaCha20-Poly1305 nonce (12 bytes).");
fixed_alias!(
    pub MlKemSeed64,
    64,
    "ML-KEM `d || z` seed (64 bytes), produced by `expand_seed` and consumed by libcrux's keypair generator."
);

// Crate-internal aliases (auditability wrappers)
// Fixed-size aliases — KEM internals
fixed_alias!(pub(crate) SharedSecret32, 32, "X-Wing hybrid shared secret (32 bytes).");
fixed_alias!(
    pub(crate) X25519PublicKey32,
    32,
    "Raw X25519 public key / ephemeral point."
);
fixed_alias!(pub(crate) X25519Secret32, 32, "Raw X25519 scalar (clamped).");
fixed_alias!(
    pub(crate) X448PublicKey56,
    56,
    "Raw X448 public key / ephemeral point."
);
fixed_alias!(pub(crate) X448Secret56, 56, "Raw X448 scalar (pre-clamping).");
fixed_alias!(
    pub(crate) SharedSecret56,
    56,
    "X448 Diffie-Hellman shared secret (56 bytes)."
);
fixed_alias!(
    pub(crate) MlKem768PublicKey1184,
    1184,
    "Raw ML-KEM-768 public key."
);
fixed_alias!(
    pub(crate) MlKem768Ciphertext1088,
    1088,
    "Raw ML-KEM-768 ciphertext."
);
#[cfg(feature = "mlkem512")]
fixed_alias!(
    pub(crate) MlKem512PublicKey800,
    800,
    "Raw ML-KEM-512 public key."
);
#[cfg(feature = "mlkem512")]
fixed_alias!(
    pub(crate) MlKem512Ciphertext768,
    768,
    "Raw ML-KEM-512 ciphertext."
);
#[cfg(feature = "mlkem1024")]
fixed_alias!(
    pub(crate) MlKem1024PublicKey1568,
    1568,
    "Raw ML-KEM-1024 public key."
);
#[cfg(feature = "mlkem1024")]
fixed_alias!(
    pub(crate) MlKem1024Ciphertext1568,
    1568,
    "Raw ML-KEM-1024 ciphertext."
);
fixed_alias!(
    pub(crate) ExpandedKeyMaterial96,
    96,
    "96-byte expanded key material buffer for ML-KEM seed and X25519 scalar derivation."
);

// Dynamic aliases — HPKE / KDF buffers
dynamic_alias!(
    pub(crate) Info,
    Vec<u8>,
    "HPKE info string (public, arbitrary length)."
);
dynamic_alias!(pub(crate) Aad, Vec<u8>, "Additional authenticated data (public).");
dynamic_alias!(
    pub Plaintext,
    Vec<u8>,
    "Decrypted HPKE plaintext (returned from `Recipient::open` and one-shot `open`)."
);
dynamic_alias!(
    pub AeadCiphertext,
    Vec<u8>,
    "HPKE AEAD ciphertext + auth tag (returned from `Sender::seal` and one-shot `seal`). Symmetric with `Plaintext` on the open side; named to avoid clashing with the structured `kem::mlkem768x25519::Ciphertext`."
);
dynamic_alias!(pub(crate) ExporterContext, Vec<u8>, "HPKE exporter context.");
dynamic_alias!(
    pub KdfBytes,
    Vec<u8>,
    "Heap buffer for HPKE KDF outputs and key-schedule intermediates. Mirrors hpke-go []byte values used by labeledExtract/labeledExpand/labeledDerive and newContext locals (secret, pskIDHash, infoHash, expSecret)."
);
dynamic_alias!(
    pub(crate) OneStageSecrets,
    Vec<u8>,
    "One-stage HPKE secrets serialization buffer: len(psk) || len(ss) || ss."
);
dynamic_alias!(
    pub(crate) LabeledIkm,
    Vec<u8>,
    "HPKE labeled IKM buffer used as HKDF-Extract input."
);
dynamic_alias!(
    pub(crate) LabeledInfo,
    Vec<u8>,
    "HPKE labeled info buffer used as HKDF-Expand info parameter."
);
dynamic_alias!(
    pub(crate) Salt,
    Vec<u8>,
    "HKDF-Extract salt. Typically public but named for auditability and self-documentation."
);
