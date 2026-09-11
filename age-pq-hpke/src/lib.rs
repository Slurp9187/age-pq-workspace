#![forbid(unsafe_code)]

//! # age-pq-hpke
//!
//! Post-quantum hybrid X-Wing KEM (ML-KEM-768 + X25519) with full HPKE support.
//!
//! This crate implements the hybrid post-quantum KEM construction from the
//! `draft-ietf-hpke-pq` line, using formally verified primitives from `libcrux`
//! and `x25519-dalek`.
//!
//! ## Normative provenance
//!
//! Stated here rather than as a constant. There used to be a
//! `pub const XWING_DRAFT_VERSION: &str = "09"` above; nothing read it, no test
//! asserted it, and it went stale without anything noticing — a conformance
//! claim with no verifier behind it. Provenance belongs in prose; what belongs
//! in code is what can be checked.
//!
//! * The in-tree normative mirror is this crate's `docs/hpke-pq.md`, pinned to
//!   `draft-ietf-hpke-pq-03` / `draft-irtf-cfrg-hybrid-kems-07`. The mirror is
//!   byte-identical to current upstream (`FiloSottile/hpke @ 8aa8a04`), which
//!   still cites the same revisions — so the pin is current, not stale.
//! * The invariants that would break interop — HPKE KEM id `0x647a`,
//!   `Nenc`/`Npk` = 1120/1216, the combiner's input order, and `XWingLabel` —
//!   were checked directly against `draft-connolly-cfrg-xwing-kem-10` and
//!   `draft-ietf-hpke-pq-05` and are unchanged.
//! * The `draft-ietf-hpke-pq` 03 → 05 delta has since been enumerated: the
//!   Hybrid KEMs construction (§4) is byte-identical, and the only change
//!   touching this workspace's citations is Appendix A renaming
//!   `QSF-X25519-MLKEM768` to `MLKEM768-X25519`.
//! * Full provenance — corpus origins, the 03 → 05 delta table, and a
//!   research trap worth not repeating — is in
//!   `docs/design/normative-provenance.md`. The refresh work is tracked in
//!   `docs/plans/normative-source-refresh.md` (issue #25).
//!
//! What actually verifies conformance is the corpus, not a version string: the
//! 19 C2SP CCTV vectors and the age-go differential oracle in `age-pq-keys`.
//!
//! ## Security Properties
//!
//! - **Constant-time operations**: All cryptographic primitives are constant-time to
//!   prevent timing side-channel attacks.
//! - **Memory safety**: Sensitive values are wrapped in `secure-gate::Fixed` and
//!   automatically zeroized on drop via `ZeroizeOnDrop`.
//! - **Explicit secret access**: All access to secret bytes requires an explicit
//!   `with_secret()` or `expose_secret()` call (no `Deref` or `AsRef`).
//! - **Constant-time equality**: Use `ConstantTimeEq` (re-exported) instead of `==`
//!   for secret values.
//!
//! ## Main Types
//!
//! - [`MlKem768X25519`]: The primary hybrid KEM (Level 2).
//! - [`SharedSecret`]: The final 32-byte hybrid shared secret (public API).
//! - [`Kem`]: Trait for generic KEM usage.
//! - [`new_sender`], [`new_recipient`]: High-level HPKE construction functions.
//!
//! ## Usage
//!
//! ```rust
//! use age_pq_hpke::{MlKem768X25519, kem::Kem, RevealSecret, ConstantTimeEq};
//!
//! let kem = MlKem768X25519;
//! let sk = kem.generate_key().unwrap();
//! let pk = sk.public_key();
//!
//! let (enc, ss) = pk.encap(None).unwrap();
//! let ss2 = sk.decap(&enc).unwrap();
//!
//! assert!(ss.ct_eq(&ss2));
//! ```

extern crate alloc;

pub mod error;
// pub mod xwing1024x25519;
// pub mod xwing1024x448;
pub mod aliases;
pub mod kem;

// New modules for HPKE components
pub mod aead;
pub mod hpke;
pub mod kdf;

pub const MASTER_SEED_SIZE: usize = 32;
pub const SHARED_SECRET_SIZE: usize = 32;

pub use aliases::*;
pub use error::{Error, Result};

// Re-export key HPKE components for easy access
pub use crate::aead::{Aead, ChaCha20Poly1305Aead, new_aead};
pub use hpke::{new_recipient, new_sender, new_sender_with_testing_randomness, open, seal};
pub use kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf, Shake128Kdf, Shake256Kdf, new_kdf};
pub use kem::{Kem, PrivateKey, PublicKey};

pub use kem::MlKem768X25519;
pub use secure_gate::{ConstantTimeEq, RevealSecret, SecretLen};

pub use hpke::compute_nonce;
