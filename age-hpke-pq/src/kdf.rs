//! HPKE KDF abstraction layer.
//!
//! Provides a trait-object interface over key derivation functions so that
//! the HPKE key schedule in [`crate::hpke`] stays algorithm-agnostic.
//!
//! Two families are supported:
//!
//! * **Two-stage (HKDF)** -- `labeled_extract` + `labeled_expand` per
//!   RFC 9180 section 4. Registered variants: HKDF-SHA256, HKDF-SHA384,
//!   HKDF-SHA512.
//! * **One-stage (SHAKE)** -- a single `labeled_derive` call that absorbs
//!   all inputs into a SHAKE XOF and squeezes the output, as specified in
//!   `draft-ietf-hpke-pq-03`. Registered variants: SHAKE128, SHAKE256.

use crate::aliases::{KdfBytes, LabeledIkm, LabeledOkm, Salt};
use crate::Error;
use byteorder::{BigEndian, ByteOrder};
use hkdf::Hkdf;
use secure_gate::RevealSecret;
use sha2::{Sha256, Sha384, Sha512};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};
use std::result::Result;

/// Version label prepended to every labeled operation (`"HPKE-v1"`).
pub(crate) const HPKE_VERSION_LABEL: &[u8; 7] = b"HPKE-v1";

// ---------------------------------------------------------------------------
// Algorithm identifiers (RFC 9180 Table 3 + draft-ietf-hpke-pq-03)
// ---------------------------------------------------------------------------

/// HKDF-SHA256 (`KDF_ID = 0x0001`).
pub(crate) const KDF_HKDF_SHA256_ID: u16 = 0x0001;
/// HKDF-SHA384 (`KDF_ID = 0x0002`).
pub(crate) const KDF_HKDF_SHA384_ID: u16 = 0x0002;
/// HKDF-SHA512 (`KDF_ID = 0x0003`).
pub(crate) const KDF_HKDF_SHA512_ID: u16 = 0x0003;
/// SHAKE128 one-stage KDF (`KDF_ID = 0x0010`).
pub(crate) const KDF_SHAKE128_ID: u16 = 0x0010;
/// SHAKE256 one-stage KDF (`KDF_ID = 0x0011`).
pub(crate) const KDF_SHAKE256_ID: u16 = 0x0011;

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// KDF algorithm descriptor used by the HPKE key schedule.
///
/// Implementations must support either the one-stage path (`labeled_derive`)
/// or the two-stage path (`labeled_extract` + `labeled_expand`), returning
/// [`Error::InvalidOperationForKdf`] for the unsupported family.
pub trait Kdf: Send + Sync {
    /// RFC 9180 KDF identifier.
    fn id(&self) -> u16;
    /// Returns `true` for one-stage (SHAKE) KDFs.
    fn one_stage(&self) -> bool;
    /// Output hash length in bytes (`Nh`).
    fn size(&self) -> usize;

    /// One-stage labeled derivation (SHAKE path).
    ///
    /// Returns wrapped keying bytes (`KdfBytes`), analogous to `[]byte`
    /// outputs in hpke-go `labeledDerive`.
    fn labeled_derive(
        &self,
        suite_id: &[u8],
        input_key: &[u8],
        label: &str,
        context: &[u8],
        length: u16,
    ) -> Result<KdfBytes, Error>;

    /// Labeled extract step (HKDF path).
    ///
    /// Returns wrapped keying bytes (`KdfBytes`), analogous to `[]byte`
    /// outputs in hpke-go `labeledExtract`.
    fn labeled_extract(
        &self,
        suite_id: &[u8],
        salt: Option<&[u8]>,
        label: &str,
        input_key: &[u8],
    ) -> Result<KdfBytes, Error>;

    /// Labeled expand step (HKDF path).
    ///
    /// Returns wrapped keying bytes (`KdfBytes`), analogous to `[]byte`
    /// outputs in hpke-go `labeledExpand`.
    fn labeled_expand(
        &self,
        suite_id: &[u8],
        random_key: &[u8],
        label: &str,
        info: &[u8],
        length: u16,
    ) -> Result<KdfBytes, Error>;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Resolves a KDF algorithm by its RFC 9180 identifier.
pub fn new_kdf(id: u16) -> Result<Box<dyn Kdf>, Error> {
    match id {
        KDF_HKDF_SHA256_ID => Ok(Box::new(HkdfSha256)),
        KDF_HKDF_SHA384_ID => Ok(Box::new(HkdfSha384)),
        KDF_HKDF_SHA512_ID => Ok(Box::new(HkdfSha512)),
        KDF_SHAKE128_ID => Ok(Box::new(Shake128Kdf)),
        KDF_SHAKE256_ID => Ok(Box::new(Shake256Kdf)),
        _ => Err(Error::UnsupportedKdf),
    }
}

// ---------------------------------------------------------------------------
// HKDF implementations (two-stage)
// ---------------------------------------------------------------------------

/// HKDF-SHA256 KDF (`Nh = 32`).
pub struct HkdfSha256;
/// HKDF-SHA384 KDF (`Nh = 48`).
pub struct HkdfSha384;
/// HKDF-SHA512 KDF (`Nh = 64`).
pub struct HkdfSha512;

/// Generates `Kdf` trait implementations for all three HKDF-SHA variants.
///
/// `labeled_extract` builds `labeled_ikm = "HPKE-v1" || suite_id || label || ikm`
/// and calls `HKDF-Extract(salt, labeled_ikm)`.
///
/// `labeled_expand` builds `labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info`
/// and calls `HKDF-Expand(prk, labeled_info, L)`.
///
/// `labeled_derive` is unsupported for HKDF variants.
macro_rules! impl_hkdf_kdf {
    ($kdf_ty:ty, $hash_ty:ty, $id:expr, $size:expr) => {
        impl Kdf for $kdf_ty {
            fn id(&self) -> u16 {
                $id
            }

            fn one_stage(&self) -> bool {
                false
            }

            fn size(&self) -> usize {
                $size
            }

            fn labeled_derive(
                &self,
                _suite_id: &[u8],
                _input_key: &[u8],
                _label: &str,
                _context: &[u8],
                _length: u16,
            ) -> Result<KdfBytes, Error> {
                Err(Error::InvalidOperationForKdf)
            }

            fn labeled_extract(
                &self,
                suite_id: &[u8],
                salt: Option<&[u8]>,
                label: &str,
                input_key: &[u8],
            ) -> Result<KdfBytes, Error> {
                let mut labeled_ikm = Vec::new();
                labeled_ikm.extend_from_slice(HPKE_VERSION_LABEL);
                labeled_ikm.extend_from_slice(suite_id);
                labeled_ikm.extend_from_slice(label.as_bytes());
                labeled_ikm.extend_from_slice(input_key);
                let labeled_ikm = LabeledIkm::new(labeled_ikm);
                let salt = Salt::from(salt.unwrap_or(&[]));
                let hk = {
                    let salt_raw: &[u8] = salt.expose_secret();
                    labeled_ikm.with_secret(|ikm| Hkdf::<$hash_ty>::extract(Some(salt_raw), ikm))
                };
                Ok(KdfBytes::new(hk.0.to_vec()))
            }

            fn labeled_expand(
                &self,
                suite_id: &[u8],
                random_key: &[u8],
                label: &str,
                info: &[u8],
                length: u16,
            ) -> Result<KdfBytes, Error> {
                let mut labeled_info = Vec::new();
                let mut buf = [0u8; 2];
                BigEndian::write_u16(&mut buf, length);
                labeled_info.extend_from_slice(&buf);
                labeled_info.extend_from_slice(HPKE_VERSION_LABEL);
                labeled_info.extend_from_slice(suite_id);
                labeled_info.extend_from_slice(label.as_bytes());
                labeled_info.extend_from_slice(info);

                let hk = Hkdf::<$hash_ty>::from_prk(random_key).map_err(|_| Error::InvalidLength)?;
                let mut okm = vec![0u8; length as usize];
                hk.expand(&labeled_info, &mut okm)
                    .map_err(|_| Error::InvalidLength)?;
                let okm = LabeledOkm::new(okm);
                Ok(KdfBytes::new(okm.with_secret(|bytes| bytes.to_vec())))
            }
        }
    };
}

impl_hkdf_kdf!(HkdfSha256, Sha256, KDF_HKDF_SHA256_ID, 32);
impl_hkdf_kdf!(HkdfSha384, Sha384, KDF_HKDF_SHA384_ID, 48);
impl_hkdf_kdf!(HkdfSha512, Sha512, KDF_HKDF_SHA512_ID, 64);

// ---------------------------------------------------------------------------
// SHAKE implementations (one-stage)
// ---------------------------------------------------------------------------

/// SHAKE128 one-stage KDF (`Nh = 32`).
///
/// Absorbs `input_key || "HPKE-v1" || suite_id || I2OSP(len(label), 2) || label || I2OSP(L, 2) || context`
/// and squeezes `L` bytes.
pub struct Shake128Kdf;

impl Kdf for Shake128Kdf {
    fn id(&self) -> u16 {
        KDF_SHAKE128_ID
    }

    fn one_stage(&self) -> bool {
        true
    }

    fn size(&self) -> usize {
        32
    }

    fn labeled_derive(
        &self,
        suite_id: &[u8],
        input_key: &[u8],
        label: &str,
        context: &[u8],
        length: u16,
    ) -> Result<KdfBytes, Error> {
        let mut h = Shake128::default();
        h.update(input_key);
        h.update(HPKE_VERSION_LABEL);
        h.update(suite_id);
        let mut buf = [0u8; 2];
        BigEndian::write_u16(&mut buf, label.len() as u16);
        h.update(&buf);
        h.update(label.as_bytes());
        BigEndian::write_u16(&mut buf, length);
        h.update(&buf);
        h.update(context);
        let mut out = vec![0u8; length as usize];
        h.finalize_xof().read(&mut out);
        Ok(KdfBytes::new(out))
    }

    fn labeled_extract(
        &self,
        _suite_id: &[u8],
        _salt: Option<&[u8]>,
        _label: &str,
        _input_key: &[u8],
    ) -> Result<KdfBytes, Error> {
        Err(Error::InvalidOperationForKdf)
    }

    fn labeled_expand(
        &self,
        _suite_id: &[u8],
        _random_key: &[u8],
        _label: &str,
        _info: &[u8],
        _length: u16,
    ) -> Result<KdfBytes, Error> {
        Err(Error::InvalidOperationForKdf)
    }
}

/// SHAKE256 one-stage KDF (`Nh = 64`).
///
/// Same absorption order as [`Shake128Kdf`] but uses SHAKE256 and a larger
/// output hash length.
pub struct Shake256Kdf;

impl Kdf for Shake256Kdf {
    fn id(&self) -> u16 {
        KDF_SHAKE256_ID
    }

    fn one_stage(&self) -> bool {
        true
    }

    fn size(&self) -> usize {
        64
    }

    fn labeled_derive(
        &self,
        suite_id: &[u8],
        input_key: &[u8],
        label: &str,
        context: &[u8],
        length: u16,
    ) -> Result<KdfBytes, Error> {
        let mut h = Shake256::default();
        h.update(input_key);
        h.update(HPKE_VERSION_LABEL);
        h.update(suite_id);
        let mut buf = [0u8; 2];
        BigEndian::write_u16(&mut buf, label.len() as u16);
        h.update(&buf);
        h.update(label.as_bytes());
        BigEndian::write_u16(&mut buf, length);
        h.update(&buf);
        h.update(context);
        let mut out = vec![0u8; length as usize];
        h.finalize_xof().read(&mut out);
        Ok(KdfBytes::new(out))
    }

    fn labeled_extract(
        &self,
        _suite_id: &[u8],
        _salt: Option<&[u8]>,
        _label: &str,
        _input_key: &[u8],
    ) -> Result<KdfBytes, Error> {
        Err(Error::InvalidOperationForKdf)
    }

    fn labeled_expand(
        &self,
        _suite_id: &[u8],
        _random_key: &[u8],
        _label: &str,
        _info: &[u8],
        _length: u16,
    ) -> Result<KdfBytes, Error> {
        Err(Error::InvalidOperationForKdf)
    }
}
