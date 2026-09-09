//! secure-gate newtype aliases owned by this crate.
//!
//! Everything that carries key material gets a semantically named alias rather
//! than a bare `[u8; N]` / `Vec<u8>` / `String`. Beyond the redacted `Debug` and
//! the greppable type name, the wrappers zeroize on drop — which matters here
//! because the plugin's decrypt loop exits through `continue` on many paths, and
//! a wrapper covers every one of them without a hand-written `.zeroize()` at
//! each exit.

use secure_gate::{dynamic_alias, fixed_alias};

fixed_alias!(
    pub(crate) Seed32,
    32,
    "32-byte hybrid identity seed. This is the private key."
);

fixed_alias!(
    pub(crate) SharedSecret32,
    32,
    "Hybrid shared secret from KEM encapsulation / decapsulation."
);

fixed_alias!(
    pub(crate) AeadKey32,
    32,
    "ChaCha20-Poly1305 key derived by the HPKE key schedule."
);

dynamic_alias!(
    pub(crate) KdfBytes,
    Vec<u8>,
    "HPKE key-schedule intermediates: PRKs and OKMs returned by the `Kdf` trait."
);

dynamic_alias!(
    pub(crate) SeedBytes,
    Vec<u8>,
    "Decoded bech32 payload in transit, before it is validated into a `Seed32`."
);

dynamic_alias!(
    pub(crate) FileKeyBytes,
    Vec<u8>,
    "Decrypted age file key, between AEAD `decrypt` and construction of `FileKey`."
);

dynamic_alias!(
    pub(crate) IdentityEncoding,
    String,
    "Bech32-encoded identity string. Carries the private key."
);

dynamic_alias!(
    pub(crate) SecretText,
    String,
    "Multi-line buffer holding one or more private keys: the keygen output file and \
     the stdin buffer read by `convert_native_identities`."
);
