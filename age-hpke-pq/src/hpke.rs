use crate::aead::{Aead, CipherAead};
use crate::aliases::{Aad, AeadKey32, ExporterContext, Info, Nonce12, Plaintext, SerializedKey};
use crate::kdf::Kdf;
use crate::kem::{PrivateKey, PublicKey};
use crate::Error;
use byteorder::{BigEndian, ByteOrder};
use secure_gate::RevealSecret;
use std::result::Result;

type ExportFn = Box<dyn Fn(&[u8], u16) -> Result<Vec<u8>, Error> + Send + Sync>;
pub(crate) const HPKE_SUITE_PREFIX: &[u8; 4] = b"HPKE";

// Assuming X-Wing specific, but generalize for any KEM/KDF/AEAD

pub struct Context {
    export: ExportFn,
    aead: Option<Box<dyn CipherAead>>,
    base_nonce: Nonce12,
    seq_num: u64,
}

pub struct Sender {
    context: Context,
}

pub struct Recipient {
    context: Context,
}

fn suite_id(kem_id: u16, kdf_id: u16, aead_id: u16) -> [u8; 10] {
    let mut sid = [0u8; 10];
    sid[..4].copy_from_slice(HPKE_SUITE_PREFIX);
    BigEndian::write_u16(&mut sid[4..6], kem_id);
    BigEndian::write_u16(&mut sid[6..8], kdf_id);
    BigEndian::write_u16(&mut sid[8..10], aead_id);
    sid
}

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
        let mut secrets_bytes = Vec::new();
        let mut buf = [0u8; 2];
        BigEndian::write_u16(&mut buf, 0); // empty psk
        secrets_bytes.extend_from_slice(&buf);
        BigEndian::write_u16(&mut buf, shared_secret.len() as u16);
        secrets_bytes.extend_from_slice(&buf);
        secrets_bytes.extend_from_slice(shared_secret);
        let secrets = SerializedKey::new(secrets_bytes);

        let mut ks_context_bytes = Vec::new();
        ks_context_bytes.push(0); // mode 0
        BigEndian::write_u16(&mut buf, 0); // empty psk_id
        ks_context_bytes.extend_from_slice(&buf);
        {
            let info_bytes = info.expose_secret();
            BigEndian::write_u16(&mut buf, info_bytes.len() as u16);
            ks_context_bytes.extend_from_slice(&buf);
            ks_context_bytes.extend_from_slice(info_bytes);
        }
        let ks_context = SerializedKey::new(ks_context_bytes);

        let length = aead.key_size() as u16 + aead.nonce_size() as u16 + kdf.size() as u16;
        // Preferred access pattern when a low-level API needs multiple secret slices together.
        let secret = SerializedKey::new({
            let secrets_raw = secrets.expose_secret();
            let ks_context_raw = ks_context.expose_secret();
            kdf.labeled_derive(&sid, secrets_raw, "secret", ks_context_raw, length)?
        });

        // Extract once, then slice all derived values from the same raw bytes.
        let secret_raw = secret.expose_secret();
        let key = AeadKey32::try_from(&secret_raw[0..aead.key_size()])
            .map_err(|_| Error::InvalidKeyLength)?;
        let bn =
            Nonce12::try_from(&secret_raw[aead.key_size()..aead.key_size() + aead.nonce_size()])
                .map_err(|_| Error::InvalidLength)?;
        let exp_secret =
            SerializedKey::new(secret_raw[aead.key_size() + aead.nonce_size()..].to_vec());

        let a = key.with_secret(|key_raw| aead.aead(key_raw))?;
        let exp_secret_clone = exp_secret.expose_secret().to_vec();
        export = Box::new(move |exporter_context: &[u8], length: u16| {
            let exporter_context = ExporterContext::new(exporter_context.to_vec());
            exporter_context.with_secret(|ctx| {
                kdf.labeled_derive(&sid, &exp_secret_clone, "sec", ctx, length)
            })
        });

        (Some(a), bn)
    } else {
        let psk_id_hash =
            SerializedKey::new(kdf.labeled_extract(&sid, None, "psk_id_hash", &[])?);
        let info_hash = SerializedKey::new(
            info.with_secret(|info_raw| kdf.labeled_extract(&sid, None, "info_hash", info_raw))?,
        );

        let mut ks_context_bytes = Vec::new();
        ks_context_bytes.push(0); // mode 0
        psk_id_hash
            .with_secret(|psk_id_hash_raw| ks_context_bytes.extend_from_slice(psk_id_hash_raw));
        info_hash.with_secret(|info_hash_raw| ks_context_bytes.extend_from_slice(info_hash_raw));
        let ks_context = SerializedKey::new(ks_context_bytes);

        let secret =
            SerializedKey::new(kdf.labeled_extract(&sid, Some(shared_secret), "secret", &[])?);

        // Preferred access pattern when deriving from multiple wrapped buffers.
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
        let key = AeadKey32::try_from(key.as_slice()).map_err(|_| Error::InvalidKeyLength)?;
        // Keep exposed borrows scoped to this block to retain auditable lifetimes.
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
        let bn = Nonce12::try_from(bn.as_slice()).map_err(|_| Error::InvalidLength)?;
        // Same scoped exposure approach for exporter secret derivation.
        let exp_secret = SerializedKey::new({
            let secret_raw = secret.expose_secret();
            let ks_context_raw = ks_context.expose_secret();
            kdf.labeled_expand(&sid, secret_raw, "exp", ks_context_raw, kdf.size() as u16)?
        });

        let a = key.with_secret(|key_raw| aead.aead(key_raw))?;
        let exp_secret_clone = exp_secret.expose_secret().to_vec();
        export = Box::new(move |exporter_context: &[u8], length: u16| {
            let exporter_context = ExporterContext::new(exporter_context.to_vec());
            exporter_context.with_secret(|ctx| {
                kdf.labeled_expand(&sid, &exp_secret_clone, "sec", ctx, length)
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

// NewSender
pub fn new_sender(
    pk: Box<dyn PublicKey>,
    kdf: Box<dyn Kdf>,
    aead: Box<dyn Aead>,
    info: &[u8],
) -> Result<(Vec<u8>, Sender), Error> {
    new_sender_with_testing_randomness(pk, None, kdf, aead, info)
}

pub fn new_sender_with_testing_randomness(
    pk: Box<dyn PublicKey>,
    testing_randomness: Option<&[u8]>,
    kdf: Box<dyn Kdf>,
    aead: Box<dyn Aead>,
    info: &[u8],
) -> Result<(Vec<u8>, Sender), Error> {
    let (enc, shared) = pk.encap(testing_randomness)?;
    let context = new_context(shared.as_ref(), pk.kem().id(), kdf, aead, info)?;
    Ok((enc, Sender { context }))
}

pub fn new_recipient(
    sk: Box<dyn PrivateKey>,
    enc: &[u8],
    kdf: Box<dyn Kdf>,
    aead: Box<dyn Aead>,
    info: &[u8],
) -> Result<Recipient, Error> {
    let shared = sk.decap(enc)?;
    let context = new_context(shared.as_ref(), sk.kem().id(), kdf, aead, info)?;
    Ok(Recipient { context })
}

impl Sender {
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
        // Flat, scoped exposure is preferred over nested with_secret closures for paired inputs.
        let ciphertext = {
            let plaintext_bytes = plaintext.expose_secret();
            let aad_bytes = aad.expose_secret();
            aead.seal(&nonce, plaintext_bytes, aad_bytes)
        }?;
        self.context.seq_num += 1;
        Ok(ciphertext)
    }

    pub fn export(&self, exporter_context: &[u8], length: usize) -> Result<Vec<u8>, Error> {
        if length > u16::MAX as usize {
            return Err(Error::ExporterLengthTooLarge);
        }
        (self.context.export)(exporter_context, length as u16)
    }
}

impl Recipient {
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

    pub fn export(&self, exporter_context: &[u8], length: usize) -> Result<Vec<u8>, Error> {
        if length > u16::MAX as usize {
            return Err(Error::ExporterLengthTooLarge);
        }
        (self.context.export)(exporter_context, length as u16)
    }
}

// Single-use Seal
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

// Single-use Open
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

/// Computes the HPKE base_nonce counter-mode nonce for a sequence number (last 8 bytes XORed).
/// Generic for any HPKE AEAD context (12-byte nonce assumed, e.g., ChaCha20Poly1305).
/// See RFC 9180 Section 5.3.
pub fn compute_nonce(base_nonce: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *base_nonce;
    let seq_bytes = seq.to_be_bytes();
    // XOR in the last 8 bytes (positions 4..12)
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }
    nonce
}
