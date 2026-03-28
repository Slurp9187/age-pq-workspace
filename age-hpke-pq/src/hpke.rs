//! HPKE encryption context and single-shot helpers.
//!
//! Implements the HPKE Base-mode key schedule (RFC 9180 section 5) and
//! provides [`Sender`] / [`Recipient`] encryption contexts, plus one-shot
//! [`seal`] and [`open`] convenience functions. The key schedule supports
//! both the standard two-stage (extract + expand) HKDF path and the
//! one-stage SHAKE path used by `hpke-pq`.

use crate::aead::{Aead, CipherAead};
use crate::aliases::{Aad, AeadKey32, ExporterContext, Info, KdfBytes, Nonce12, OneStageSecrets, Plaintext};
use crate::kdf::Kdf;
use crate::kem::{PrivateKey, PublicKey};
use crate::Error;
use byteorder::{BigEndian, ByteOrder};
use secure_gate::{RevealSecret, RevealSecretMut};
use std::result::Result;

type ExportFn = Box<dyn Fn(&[u8], u16) -> Result<Vec<u8>, Error> + Send + Sync>;

/// HPKE suite ID prefix (`"HPKE"`) per RFC 9180 section 5.1.
pub(crate) const HPKE_SUITE_PREFIX: &[u8; 4] = b"HPKE";

// ---------------------------------------------------------------------------
// Encryption context and role wrappers
// ---------------------------------------------------------------------------

/// Shared HPKE encryption context holding the keyed AEAD, base nonce,
/// sequence counter, and exporter closure.
pub struct Context {
    export: ExportFn,
    aead: Option<Box<dyn CipherAead>>,
    base_nonce: Nonce12,
    seq_num: u64,
}

/// Sender-side HPKE context (encrypts and exports).
pub struct Sender {
    context: Context,
}

/// Recipient-side HPKE context (decrypts and exports).
pub struct Recipient {
    context: Context,
}

// ---------------------------------------------------------------------------
// Key schedule internals
// ---------------------------------------------------------------------------

/// Builds the 10-byte HPKE suite ID: `"HPKE" || kem_id || kdf_id || aead_id`.
fn suite_id(kem_id: u16, kdf_id: u16, aead_id: u16) -> [u8; 10] {
    let mut sid = [0u8; 10];
    sid[..4].copy_from_slice(HPKE_SUITE_PREFIX);
    BigEndian::write_u16(&mut sid[4..6], kem_id);
    BigEndian::write_u16(&mut sid[6..8], kdf_id);
    BigEndian::write_u16(&mut sid[8..10], aead_id);
    sid
}

/// Executes the HPKE Base-mode key schedule (RFC 9180 section 5.1) and
/// returns a fully initialised [`Context`].
///
/// Two paths are supported depending on [`Kdf::one_stage`]:
///
/// * **One-stage (SHAKE)** -- `hpke-pq` style: serializes psk + shared secret
///   and key-schedule context into a single `labeled_derive` call that
///   produces `key || base_nonce || exporter_secret` in one shot.
///
/// * **Two-stage (HKDF)** -- standard RFC 9180: uses `labeled_extract` to
///   derive a PRK, then three `labeled_expand` calls to extract the key,
///   base nonce, and exporter secret independently.
fn new_context(
    shared_secret: &[u8],
    kem_id: u16,
    kdf: Box<dyn Kdf>,
    aead: Box<dyn Aead>,
    info: &[u8],
) -> Result<Context, Error> {
    let sid = suite_id(kem_id, kdf.id(), aead.id());
    let info = Info::new(info.to_vec());

    let export: ExportFn;

    let (aead_impl, base_nonce) = if kdf.one_stage() {
        // --- One-stage SHAKE path (draft-ietf-hpke-pq-03) ----------------

        // Serialize `secrets = len(psk) || len(ss) || ss`.
        let mut secrets = OneStageSecrets::new(Vec::new());
        let mut buf = [0u8; 2];
        secrets.with_secret_mut(|secrets_bytes| {
            BigEndian::write_u16(&mut buf, 0); // empty psk length
            secrets_bytes.extend_from_slice(&buf);
            BigEndian::write_u16(&mut buf, shared_secret.len() as u16);
            secrets_bytes.extend_from_slice(&buf);
            secrets_bytes.extend_from_slice(shared_secret);
        });

        // Serialize `ks_context = mode || len(psk_id) || len(info) || info`.
        let mut ks_context_bytes = Vec::new();
        ks_context_bytes.push(0); // mode 0 (Base)
        BigEndian::write_u16(&mut buf, 0); // empty psk_id length
        ks_context_bytes.extend_from_slice(&buf);
        {
            let info_bytes = info.expose_secret();
            BigEndian::write_u16(&mut buf, info_bytes.len() as u16);
            ks_context_bytes.extend_from_slice(&buf);
            ks_context_bytes.extend_from_slice(info_bytes);
        }
        let ks_context = KdfBytes::new(ks_context_bytes);

        // Single derive producing `key || base_nonce || exporter_secret`.
        let length = aead.key_size() as u16 + aead.nonce_size() as u16 + kdf.size() as u16;
        let secret = {
            let secrets_raw = secrets.expose_secret();
            let ks_context_raw = ks_context.expose_secret();
            kdf.labeled_derive(&sid, secrets_raw, "secret", ks_context_raw, length)?
        };

        let secret_raw = secret.expose_secret();
        let key = AeadKey32::try_from(&secret_raw[0..aead.key_size()])
            .map_err(|_| Error::InvalidKeyLength)?;
        let bn =
            Nonce12::try_from(&secret_raw[aead.key_size()..aead.key_size() + aead.nonce_size()])
                .map_err(|_| Error::InvalidLength)?;
        let exp_secret = KdfBytes::new(secret_raw[aead.key_size() + aead.nonce_size()..].to_vec());

        let a = key.with_secret(|key_raw| aead.aead(key_raw))?;
        let exp_secret_clone = exp_secret.expose_secret().to_vec();
        export = Box::new(move |exporter_context: &[u8], length: u16| {
            let exporter_context = ExporterContext::new(exporter_context.to_vec());
            exporter_context.with_secret(|ctx| {
                kdf.labeled_derive(&sid, &exp_secret_clone, "sec", ctx, length)
                    .map(|bytes| bytes.with_secret(|b| b.to_vec()))
            })
        });

        (Some(a), bn)
    } else {
        // --- Two-stage HKDF path (RFC 9180 section 5.1) ------------------

        let psk_id_hash = kdf.labeled_extract(&sid, None, "psk_id_hash", &[])?;
        let info_hash =
            info.with_secret(|info_raw| kdf.labeled_extract(&sid, None, "info_hash", info_raw))?;

        // `ks_context = mode || psk_id_hash || info_hash`.
        let mut ks_context_bytes = Vec::new();
        ks_context_bytes.push(0); // mode 0 (Base)
        psk_id_hash
            .with_secret(|psk_id_hash_raw| ks_context_bytes.extend_from_slice(psk_id_hash_raw));
        info_hash.with_secret(|info_hash_raw| ks_context_bytes.extend_from_slice(info_hash_raw));
        let ks_context = KdfBytes::new(ks_context_bytes);

        // Extract the PRK from the shared secret.
        let secret = kdf.labeled_extract(&sid, Some(shared_secret), "secret", &[])?;

        // Expand key, base_nonce, and exporter_secret from the PRK.
        let key = {
            let secret_raw = secret.expose_secret();
            let ks_context_raw = ks_context.expose_secret();
            kdf.labeled_expand(
                &sid,
                secret_raw,
                "key",
                ks_context_raw,
                aead.key_size() as u16,
            )?
        };
        let key = AeadKey32::try_from(key.expose_secret().as_slice())
            .map_err(|_| Error::InvalidKeyLength)?;

        let bn = {
            let secret_raw = secret.expose_secret();
            let ks_context_raw = ks_context.expose_secret();
            kdf.labeled_expand(
                &sid,
                secret_raw,
                "base_nonce",
                ks_context_raw,
                aead.nonce_size() as u16,
            )?
        };
        let bn = Nonce12::try_from(bn.expose_secret().as_slice()).map_err(|_| Error::InvalidLength)?;

        let exp_secret = {
            let secret_raw = secret.expose_secret();
            let ks_context_raw = ks_context.expose_secret();
            kdf.labeled_expand(&sid, secret_raw, "exp", ks_context_raw, kdf.size() as u16)?
        };

        let a = key.with_secret(|key_raw| aead.aead(key_raw))?;
        let exp_secret_clone = exp_secret.expose_secret().to_vec();
        export = Box::new(move |exporter_context: &[u8], length: u16| {
            let exporter_context = ExporterContext::new(exporter_context.to_vec());
            exporter_context.with_secret(|ctx| {
                kdf.labeled_expand(&sid, &exp_secret_clone, "sec", ctx, length)
                    .map(|bytes| bytes.with_secret(|b| b.to_vec()))
            })
        });

        (Some(a), bn)
    };

    Ok(Context {
        export,
        aead: aead_impl,
        base_nonce,
        seq_num: 0,
    })
}

// ---------------------------------------------------------------------------
// Sender / Recipient constructors
// ---------------------------------------------------------------------------

/// Sets up a Base-mode sender context, returning `(enc, Sender)`.
///
/// Encapsulates against `pk`, runs the key schedule, and returns the
/// serialised encapsulation together with a ready-to-use [`Sender`].
pub fn new_sender(
    pk: Box<dyn PublicKey>,
    kdf: Box<dyn Kdf>,
    aead: Box<dyn Aead>,
    info: &[u8],
) -> Result<(Vec<u8>, Sender), Error> {
    new_sender_with_testing_randomness(pk, None, kdf, aead, info)
}

/// Like [`new_sender`] but accepts optional deterministic randomness for
/// known-answer tests.
pub fn new_sender_with_testing_randomness(
    pk: Box<dyn PublicKey>,
    testing_randomness: Option<&[u8]>,
    kdf: Box<dyn Kdf>,
    aead: Box<dyn Aead>,
    info: &[u8],
) -> Result<(Vec<u8>, Sender), Error> {
    let (enc, shared) = pk.encap(testing_randomness)?;
    let context = new_context(shared.expose_secret(), pk.kem().id(), kdf, aead, info)?;
    Ok((enc, Sender { context }))
}

/// Sets up a Base-mode recipient context by decapsulating `enc`.
pub fn new_recipient(
    sk: Box<dyn PrivateKey>,
    enc: &[u8],
    kdf: Box<dyn Kdf>,
    aead: Box<dyn Aead>,
    info: &[u8],
) -> Result<Recipient, Error> {
    let shared = sk.decap(enc)?;
    let context = new_context(shared.expose_secret(), sk.kem().id(), kdf, aead, info)?;
    Ok(Recipient { context })
}

// ---------------------------------------------------------------------------
// Sender methods
// ---------------------------------------------------------------------------

impl Sender {
    /// Encrypts `plaintext` with `aad`, advances the sequence counter, and
    /// returns the ciphertext (including the authentication tag).
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        if self.context.seq_num == u64::MAX {
            return Err(Error::SequenceNumberOverflow);
        }
        let nonce = self
            .context
            .base_nonce
            .with_secret(|base_nonce| compute_nonce(base_nonce, self.context.seq_num));
        let aead = self.context.aead.as_ref().ok_or(Error::ExportOnly)?;
        let aad = Aad::new(aad.to_vec());
        let plaintext = Plaintext::new(plaintext.to_vec());
        let ciphertext = {
            let plaintext_bytes = plaintext.expose_secret();
            let aad_bytes = aad.expose_secret();
            aead.seal(&nonce, plaintext_bytes, aad_bytes)
        }?;
        self.context.seq_num += 1;
        Ok(ciphertext)
    }

    /// Exports keying material of the requested `length` using the HPKE
    /// secret exporter (RFC 9180 section 5.3).
    pub fn export(&self, exporter_context: &[u8], length: usize) -> Result<Vec<u8>, Error> {
        if length > u16::MAX as usize {
            return Err(Error::ExporterLengthTooLarge);
        }
        (self.context.export)(exporter_context, length as u16)
    }
}

// ---------------------------------------------------------------------------
// Recipient methods
// ---------------------------------------------------------------------------

impl Recipient {
    /// Decrypts and verifies `ciphertext` against `aad`, then advances the
    /// sequence counter.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        if self.context.seq_num == u64::MAX {
            return Err(Error::SequenceNumberOverflow);
        }
        let nonce = self
            .context
            .base_nonce
            .with_secret(|base_nonce| compute_nonce(base_nonce, self.context.seq_num));
        let aead = self.context.aead.as_ref().ok_or(Error::ExportOnly)?;
        let aad = Aad::new(aad.to_vec());
        let plaintext = {
            let aad_bytes = aad.expose_secret();
            aead.open(&nonce, ciphertext, aad_bytes)
        }?;
        let plaintext = Plaintext::new(plaintext);
        self.context.seq_num += 1;
        Ok(plaintext.with_secret(|bytes| bytes.to_vec()))
    }

    /// Exports keying material (same semantics as [`Sender::export`]).
    pub fn export(&self, exporter_context: &[u8], length: usize) -> Result<Vec<u8>, Error> {
        if length > u16::MAX as usize {
            return Err(Error::ExporterLengthTooLarge);
        }
        (self.context.export)(exporter_context, length as u16)
    }
}

// ---------------------------------------------------------------------------
// Single-shot helpers
// ---------------------------------------------------------------------------

/// One-shot encrypt: sets up a sender context, seals, and returns
/// `enc || ciphertext || tag`.
pub fn seal(
    pk: Box<dyn PublicKey>,
    kdf: Box<dyn Kdf>,
    aead: Box<dyn Aead>,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let (enc, mut s) = new_sender(pk, kdf, aead, info)?;
    let ct = s.seal(aad, plaintext)?;
    let mut ciphertext = enc;
    ciphertext.extend_from_slice(&ct);
    Ok(ciphertext)
}

/// One-shot decrypt: splits `ciphertext` into `enc || ct`, sets up a
/// recipient context, and opens.
pub fn open(
    sk: Box<dyn PrivateKey>,
    kdf: Box<dyn Kdf>,
    aead: Box<dyn Aead>,
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let enc_size = sk.kem().enc_size();
    if ciphertext.len() < enc_size {
        return Err(Error::InvalidCiphertextLength);
    }
    let enc = &ciphertext[0..enc_size];
    let ct = &ciphertext[enc_size..];
    let mut r = new_recipient(sk, enc, kdf, aead, info)?;
    r.open(aad, ct)
}

// ---------------------------------------------------------------------------
// Nonce computation
// ---------------------------------------------------------------------------

/// Computes the per-message nonce by XOR-ing the sequence number into the
/// last 8 bytes of `base_nonce` (RFC 9180 section 5.2).
pub fn compute_nonce(base_nonce: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *base_nonce;
    let seq_bytes = seq.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }
    nonce
}
