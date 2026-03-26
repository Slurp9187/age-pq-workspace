use crate::aliases::{LabeledIkm, LabeledOkm, Salt};
use crate::Error;
use byteorder::{BigEndian, ByteOrder};
use hkdf::Hkdf;
use secure_gate::RevealSecret;
use sha2::{Sha256, Sha384, Sha512};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};
use std::result::Result;
pub(crate) const HPKE_VERSION_LABEL: &[u8; 7] = b"HPKE-v1";

/// HPKE KDF algorithm IDs per RFC 9180 Table 3.
pub(crate) const KDF_HKDF_SHA256_ID: u16 = 0x0001;
pub(crate) const KDF_HKDF_SHA384_ID: u16 = 0x0002;
pub(crate) const KDF_HKDF_SHA512_ID: u16 = 0x0003;
pub(crate) const KDF_SHAKE128_ID: u16 = 0x0010;
pub(crate) const KDF_SHAKE256_ID: u16 = 0x0011;

// KDF trait matching Go's KDF interface
pub trait Kdf: Send + Sync {
    fn id(&self) -> u16;
    fn one_stage(&self) -> bool;
    fn size(&self) -> usize; // Nh
    fn labeled_derive(
        &self,
        suite_id: &[u8],
        input_key: &[u8],
        label: &str,
        context: &[u8],
        length: u16,
    ) -> Result<Vec<u8>, Error>;
    fn labeled_extract(
        &self,
        suite_id: &[u8],
        salt: Option<&[u8]>,
        label: &str,
        input_key: &[u8],
    ) -> Result<Vec<u8>, Error>;
    fn labeled_expand(
        &self,
        suite_id: &[u8],
        random_key: &[u8],
        label: &str,
        info: &[u8],
        length: u16,
    ) -> Result<Vec<u8>, Error>;
}

// Factory function matching Go's NewKDF
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

// HKDF-SHA256
pub struct HkdfSha256;
// HKDF-SHA384
pub struct HkdfSha384;
// HKDF-SHA512
pub struct HkdfSha512;

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
            ) -> Result<Vec<u8>, Error> {
                Err(Error::InvalidOperationForKdf)
            }

            fn labeled_extract(
                &self,
                suite_id: &[u8],
                salt: Option<&[u8]>,
                label: &str,
                input_key: &[u8],
            ) -> Result<Vec<u8>, Error> {
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
                Ok(hk.0.to_vec())
            }

            fn labeled_expand(
                &self,
                suite_id: &[u8],
                random_key: &[u8],
                label: &str,
                info: &[u8],
                length: u16,
            ) -> Result<Vec<u8>, Error> {
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
                Ok(okm.with_secret(|bytes| bytes.to_vec()))
            }
        }
    };
}

impl_hkdf_kdf!(HkdfSha256, Sha256, KDF_HKDF_SHA256_ID, 32);
impl_hkdf_kdf!(HkdfSha384, Sha384, KDF_HKDF_SHA384_ID, 48);
impl_hkdf_kdf!(HkdfSha512, Sha512, KDF_HKDF_SHA512_ID, 64);

// SHAKE128
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
    ) -> Result<Vec<u8>, Error> {
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
        Ok(out)
    }

    fn labeled_extract(
        &self,
        _suite_id: &[u8],
        _salt: Option<&[u8]>,
        _label: &str,
        _input_key: &[u8],
    ) -> Result<Vec<u8>, Error> {
        Err(Error::InvalidOperationForKdf)
    }

    fn labeled_expand(
        &self,
        _suite_id: &[u8],
        _random_key: &[u8],
        _label: &str,
        _info: &[u8],
        _length: u16,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::InvalidOperationForKdf)
    }
}

// SHAKE256
pub struct Shake256Kdf;

impl Kdf for Shake256Kdf {
    fn id(&self) -> u16 {
        KDF_SHAKE256_ID
    }

    fn one_stage(&self) -> bool {
        true
    }

    fn size(&self) -> usize {
        64 // As in Go
    }

    fn labeled_derive(
        &self,
        suite_id: &[u8],
        input_key: &[u8],
        label: &str,
        context: &[u8],
        length: u16,
    ) -> Result<Vec<u8>, Error> {
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
        Ok(out)
    }

    fn labeled_extract(
        &self,
        _suite_id: &[u8],
        _salt: Option<&[u8]>,
        _label: &str,
        _input_key: &[u8],
    ) -> Result<Vec<u8>, Error> {
        Err(Error::InvalidOperationForKdf)
    }

    fn labeled_expand(
        &self,
        _suite_id: &[u8],
        _random_key: &[u8],
        _label: &str,
        _info: &[u8],
        _length: u16,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::InvalidOperationForKdf)
    }
}
