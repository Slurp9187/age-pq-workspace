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
    pub(crate) MlKem768PublicKey1184,
    1184,
    "Raw ML-KEM-768 public key."
);
fixed_alias!(
    pub(crate) MlKem768Ciphertext1088,
    1088,
    "Raw ML-KEM-768 ciphertext."
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
dynamic_alias!(pub(crate) Plaintext, Vec<u8>, "Plaintext message to be encrypted.");
dynamic_alias!(pub(crate) ExporterContext, Vec<u8>, "HPKE exporter context.");
dynamic_alias!(
    pub(crate) SerializedKey,
    Vec<u8>,
    "HPKE key-schedule intermediate (key material / exporter secret)."
);
dynamic_alias!(
    pub(crate) LabeledIkm,
    Vec<u8>,
    "HPKE labeled IKM buffer used as HKDF-Extract input."
);
dynamic_alias!(
    pub(crate) LabeledOkm,
    Vec<u8>,
    "HPKE labeled output keying material (OKM) buffer."
);
dynamic_alias!(
    pub(crate) Salt,
    Vec<u8>,
    "HKDF-Extract salt. Typically public but named for auditability and self-documentation."
);
