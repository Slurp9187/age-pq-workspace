//! secure-gate newtype aliases owned by this crate.
//!
//! Every byte buffer or string that carries key material gets a semantically
//! named alias here rather than living as a bare `Vec<u8>` / `String`. The
//! wrappers provide zeroize-on-drop, a `[REDACTED]` `Debug`, and a greppable
//! type name; access goes through the secure-gate 3-tier API.
//!
//! These are crate-internal. Per the workspace wire-boundary rule, the public
//! API of this crate hands out native Rust types and callers wrap for
//! themselves if their threat model warrants it.

use secure_gate::{dynamic_newtype, fixed_newtype};

fixed_newtype!(
    pub(crate) Seed32,
    32,
    "32-byte hybrid identity seed. This is the private key."
);

dynamic_newtype!(
    pub(crate) SeedBytes,
    Vec<u8>,
    "Variable-length seed material in transit, before it is validated into a `Seed32`: \
     the bech32 payload from `HybridIdentity::parse` and the serialization out of \
     `PrivateKey::bytes`."
);

dynamic_newtype!(
    pub(crate) FileKeyBytes,
    Vec<u8>,
    "Decrypted age file key, between HPKE `open` and construction of `age_core`'s `FileKey`."
);

dynamic_newtype!(
    pub(crate) IdentityEncoding,
    String,
    "Bech32-encoded identity string while it is being built and case-normalized. \
     Carries the private key."
);
