//! Hybrid ML-KEM-768 + X25519 orchestration module.
//!
//! This module implements the concrete X-Wing KEM variant specified in
//! `hpke-pq.md` (MLKEM768-X25519). It owns the hybrid wire format, key
//! types, encapsulation/decapsulation flow, and the call into the SHA3-256
//! combiner. Primitive-specific helpers live in `super::ml_kem` and
//! `super::x25519`; shared traits and constants live in [`super::common`].

use super::combiner;
use super::ml_kem;
use super::x25519;
use crate::aliases::{
    MlKem768Ciphertext1088, MlKem768PublicKey1184, Seed32, X25519PublicKey32, X25519Secret32,
};
use crate::error::{Error, Result as CrateResult};
use crate::kem::common::{
    expand_seed, shake256_labeled_derive, Kem, PrivateKey, PublicKey, KEM_ID, MASTER_SEED_SIZE,
    PRIVATE_KEY_SIZE,
};
use secure_gate::RevealSecret;

use core::fmt;

use libcrux_ml_kem::mlkem768::MlKem768KeyPair;

use rand::rngs::OsRng;
use rand::{TryCryptoRng, TryRngCore};

use x25519_dalek::PublicKey as X25519PublicKey;

// ---------------------------------------------------------------------------
// Wire-format size constants
// ---------------------------------------------------------------------------

/// ML-KEM-768 public-key size, re-exported from the primitive helper.
const MLKEM768_PK_SIZE: usize = ml_kem::MLKEM768_PK_SIZE;
/// ML-KEM-768 ciphertext size, re-exported from the primitive helper.
pub const MLKEM768_CT_SIZE: usize = ml_kem::MLKEM768_CT_SIZE;

/// KEM suite ID prefix per RFC 9180 section 5.3 (`"KEM" || KEM_ID`).
const KEM_SUITE_PREFIX: &[u8; 3] = b"KEM";
/// Label for the `DeriveKeyPair` operation per RFC 9180 section 7.1.3.
const KEM_DERIVE_KEY_PAIR_LABEL: &[u8; 13] = b"DeriveKeyPair";

// ---------------------------------------------------------------------------
// Composite size constants (pk_m || pk_x, ct_m || ct_x)
// ---------------------------------------------------------------------------

/// Serialized encapsulation-key (public key) size: `pk_m || pk_x`.
pub const MLKEM768X25519_ENCAPSULATION_KEY_SIZE: usize = MLKEM768_PK_SIZE + x25519::X25519_KEY_SIZE;
/// Serialized decapsulation-key size (seed only).
pub const MLKEM768X25519_DECAPSULATION_KEY_SIZE: usize = MASTER_SEED_SIZE;
/// Serialized ciphertext size: `ct_m || ct_x`.
pub const MLKEM768X25519_CIPHERTEXT_SIZE: usize = MLKEM768_CT_SIZE + x25519::X25519_KEY_SIZE;

// ---------------------------------------------------------------------------
// Key and ciphertext types
// ---------------------------------------------------------------------------

/// Hybrid encapsulation (public) key: ML-KEM-768 public key + X25519 point.
pub struct EncapsulationKey {
    /// ML-KEM-768 public key (1184 bytes, wrapped in a `Fixed` alias).
    pk_m: MlKem768PublicKey1184,
    /// X25519 public key (32 bytes).
    pk_x: X25519PublicKey,
}

/// Hybrid decapsulation (private) key, stored as a wrapped 32-byte seed.
///
/// The full ML-KEM keypair and X25519 scalar are re-derived on demand via
/// the crate-internal `expand_seed` helper. The `Seed32` wrapper provides
/// zeroize-on-drop and a redacted `Debug` representation; access to the
/// bytes goes through the `secure-gate` 3-tier API.
pub struct DecapsulationKey {
    seed: Seed32,
}

impl fmt::Debug for DecapsulationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DecapsulationKey")
            .field(&"[REDACTED]")
            .finish()
    }
}

/// Hybrid ciphertext: ML-KEM-768 ciphertext + X25519 ephemeral public key.
pub struct Ciphertext {
    /// ML-KEM-768 ciphertext (1088 bytes, wrapped in a `Fixed` alias).
    ct_m: MlKem768Ciphertext1088,
    /// X25519 ephemeral public key (32 bytes).
    ct_x: X25519PublicKey,
}

// ---------------------------------------------------------------------------
// Trait impls: equality and debug
// ---------------------------------------------------------------------------

impl PartialEq for EncapsulationKey {
    fn eq(&self, other: &Self) -> bool {
        self.pk_m.expose_secret() == other.pk_m.expose_secret() && self.pk_x == other.pk_x
    }
}

impl Eq for EncapsulationKey {}

impl PartialEq for Ciphertext {
    fn eq(&self, other: &Self) -> bool {
        self.ct_m.expose_secret() == other.ct_m.expose_secret() && self.ct_x == other.ct_x
    }
}

impl Eq for Ciphertext {}

impl fmt::Debug for EncapsulationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EncapsulationKey")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ciphertext").field(&"[REDACTED]").finish()
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Expands a wrapped 32-byte master seed into an ML-KEM-768 keypair and a
/// wrapped X25519 scalar via [`expand_seed`].
fn expand_key(seed: &Seed32) -> (MlKem768KeyPair, X25519Secret32) {
    let (ml_seed, x_secret) = expand_seed(seed);
    let kp = ml_kem::keypair_from_seed(ml_seed);
    (kp, x_secret)
}

// ---------------------------------------------------------------------------
// EncapsulationKey — encapsulation paths
// ---------------------------------------------------------------------------

impl EncapsulationKey {
    /// Shared inner encapsulation path used by both random and deterministic
    /// entry points.
    ///
    /// 1. ML-KEM-768 encapsulate with `ml_rand_bytes`.
    /// 2. X25519 ephemeral DH with `ephemeral_bytes`.
    /// 3. SHA3-256 combiner producing the final [`SharedSecret`](crate::SharedSecret).
    fn encapsulate_inner(
        &self,
        ml_rand: Seed32,
        ephemeral: X25519Secret32,
    ) -> CrateResult<(Ciphertext, crate::SharedSecret)> {
        let (ct_m_bytes, ss_m) = ml_kem::encapsulate_with_seed(&self.pk_m, ml_rand)?;
        let (ct_x, ss_x) = x25519::encapsulate_to_public_key(ephemeral, &self.pk_x);

        let ct_x_bytes = X25519PublicKey32::from(ct_x.to_bytes());
        let pk_x_bytes = X25519PublicKey32::from(self.pk_x.to_bytes());

        // Tier-2: combiner takes four &[u8; 32]; 4-arg closure nesting would obscure.
        let ss = combiner::combine_shared_secrets(
            ss_m.expose_secret(),
            ss_x.expose_secret(),
            ct_x_bytes.expose_secret(),
            pk_x_bytes.expose_secret(),
        );

        Ok((
            Ciphertext::from_wrapped_components(MlKem768Ciphertext1088::from(ct_m_bytes), ct_x),
            ss,
        ))
    }

    /// Serializes the encapsulation key as `pk_m || pk_x`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; MLKEM768X25519_ENCAPSULATION_KEY_SIZE] {
        let mut buffer = [0u8; MLKEM768X25519_ENCAPSULATION_KEY_SIZE];
        let pk_x_bytes = self.pk_x.to_bytes();
        buffer[..MLKEM768_PK_SIZE].copy_from_slice(self.pk_m.expose_secret());
        buffer[MLKEM768_PK_SIZE..].copy_from_slice(&pk_x_bytes);
        buffer
    }

    /// Encapsulates with fresh randomness from the provided CSPRNG.
    pub fn encapsulate<R: TryRngCore + TryCryptoRng>(
        &self,
        rng: &mut R,
    ) -> CrateResult<(Ciphertext, crate::SharedSecret)> {
        let ml_rand = Seed32::from_rng(rng).map_err(|_| Error::RandomnessError)?;
        let ephemeral = X25519Secret32::from_rng(rng).map_err(|_| Error::RandomnessError)?;
        self.encapsulate_inner(ml_rand, ephemeral)
    }

    /// Returns the raw ML-KEM-768 public-key bytes.
    pub fn pk_m(&self) -> &[u8; MLKEM768_PK_SIZE] {
        self.pk_m.expose_secret()
    }

    /// Returns a reference to the X25519 public key.
    pub fn pk_x(&self) -> &X25519PublicKey {
        &self.pk_x
    }

    /// Deterministically derives an encapsulation key from a 32-byte seed.
    pub fn from_seed(seed: &[u8; MASTER_SEED_SIZE]) -> CrateResult<Self> {
        let seed = Seed32::new_with(|out| out.copy_from_slice(seed));
        let (kp, x_secret) = expand_key(&seed);
        let pk_m_bytes: [u8; MLKEM768_PK_SIZE] = kp
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| Error::ArraySizeError)?;
        let pk_x = x25519::public_key_from_seed(x_secret);
        Ok(Self::from_components(pk_m_bytes, pk_x))
    }

    /// Deterministic encapsulation for known-answer tests.
    ///
    /// `eseed` is split as `eseed[0..32]` for ML-KEM-768 randomness and
    /// `eseed[32..64]` for the X25519 ephemeral scalar.
    pub fn encapsulate_derand(
        &self,
        eseed: &[u8; 64],
    ) -> CrateResult<(Ciphertext, crate::SharedSecret)> {
        // Write each half directly into wrapper storage — no intermediate
        // [u8; 32] stack bindings.
        let ml_rand = Seed32::new_with(|out| out.copy_from_slice(&eseed[0..32]));
        let ephemeral = X25519Secret32::new_with(|out| out.copy_from_slice(&eseed[32..64]));
        self.encapsulate_inner(ml_rand, ephemeral)
    }
}

// ---------------------------------------------------------------------------
// EncapsulationKey — construction and parsing
// ---------------------------------------------------------------------------

impl EncapsulationKey {
    /// Constructs from pre-wrapped components (crate-internal).
    pub(crate) fn from_wrapped_components(pk_m: MlKem768PublicKey1184, pk_x: X25519PublicKey) -> Self {
        Self { pk_m, pk_x }
    }

    /// Constructs from raw byte components.
    pub fn from_components(pk_m: [u8; MLKEM768_PK_SIZE], pk_x: X25519PublicKey) -> Self {
        Self::from_wrapped_components(MlKem768PublicKey1184::from(pk_m), pk_x)
    }
}

/// Parses `pk_m || pk_x` from a byte slice.
impl TryFrom<&[u8]> for EncapsulationKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> CrateResult<Self> {
        if bytes.len() != MLKEM768X25519_ENCAPSULATION_KEY_SIZE {
            return Err(Error::InvalidEncapsulationKeyLength);
        }
        let pk_m = MlKem768PublicKey1184::new_with(|pk_m_bytes| {
            pk_m_bytes.copy_from_slice(&bytes[..MLKEM768_PK_SIZE]);
        });

        let pk_x_bytes: [u8; x25519::X25519_KEY_SIZE] = bytes[MLKEM768_PK_SIZE..]
            .try_into()
            .map_err(|_| Error::ArraySizeError)?;
        let pk_x = x25519::parse_public_key(pk_x_bytes)?;
        ml_kem::validate_public_key(&pk_m);

        Ok(Self::from_wrapped_components(pk_m, pk_x))
    }
}

/// Fixed-size array convenience; delegates to the slice path.
impl TryFrom<&[u8; MLKEM768X25519_ENCAPSULATION_KEY_SIZE]> for EncapsulationKey {
    type Error = Error;

    fn try_from(bytes: &[u8; MLKEM768X25519_ENCAPSULATION_KEY_SIZE]) -> CrateResult<Self> {
        Self::try_from(&bytes[..])
    }
}

// ---------------------------------------------------------------------------
// DecapsulationKey
// ---------------------------------------------------------------------------

impl DecapsulationKey {
    /// Constructs from a 32-byte seed.
    pub fn from_seed(seed: &[u8; MASTER_SEED_SIZE]) -> Self {
        Self {
            seed: Seed32::new_with(|out| out.copy_from_slice(seed)),
        }
    }

    /// Generates a fresh decapsulation key from a CSPRNG.
    pub fn generate<R: TryRngCore + TryCryptoRng>(rng: &mut R) -> Self {
        Self {
            seed: Seed32::from_rng(rng)
                .expect("Failed to generate random bytes for decapsulation key seed"),
        }
    }

    /// Returns the raw seed bytes (for HPKE key-schedule integration).
    ///
    /// Note: this is a Tier-2 leak by current API shape — the bytes leave
    /// the wrapper as a plain array. Phase 2 (PR 5) will change the
    /// `PrivateKey::bytes` trait method to return a wrapper reference,
    /// at which point this method becomes a `&Seed32` accessor.
    pub fn bytes(&self) -> [u8; MASTER_SEED_SIZE] {
        // Tier-2: existing API returns a plain array; PR 5 lifts to &Seed32.
        self.seed.with_secret(|b| *b)
    }

    /// Derives the matching encapsulation (public) key.
    pub fn encapsulation_key(&self) -> CrateResult<EncapsulationKey> {
        let (kp, x_secret) = expand_key(&self.seed);
        let pk_m_bytes: [u8; MLKEM768_PK_SIZE] = kp
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| Error::ArraySizeError)?;
        let pk_x = x25519::public_key_from_seed(x_secret);
        Ok(EncapsulationKey::from_wrapped_components(
            MlKem768PublicKey1184::from(pk_m_bytes),
            pk_x,
        ))
    }

    /// Decapsulates a hybrid ciphertext and returns the shared secret.
    ///
    /// Re-derives the ML-KEM keypair and X25519 scalar from the stored seed,
    /// then feeds both component shared secrets plus the X25519 ciphertext and
    /// public key into the SHA3-256 combiner.
    pub fn decapsulate(&self, ct: &Ciphertext) -> CrateResult<crate::SharedSecret> {
        let (kp, x_secret) = expand_key(&self.seed);
        let ss_m = ml_kem::decapsulate_with_keypair(&kp, &ct.ct_m);
        let (ss_x, pk_x) = x25519::decapsulate_from_private_seed(x_secret, &ct.ct_x);
        let ct_x_bytes = X25519PublicKey32::from(ct.ct_x.to_bytes());
        let pk_x_bytes = X25519PublicKey32::from(pk_x.to_bytes());

        // Tier-2: combiner takes four &[u8; 32]; 4-arg closure nesting would obscure.
        let ss = combiner::combine_shared_secrets(
            ss_m.expose_secret(),
            ss_x.expose_secret(),
            ct_x_bytes.expose_secret(),
            pk_x_bytes.expose_secret(),
        );

        Ok(ss)
    }
}

// ---------------------------------------------------------------------------
// Ciphertext
// ---------------------------------------------------------------------------

impl Ciphertext {
    /// Serializes the ciphertext as `ct_m || ct_x`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; MLKEM768X25519_CIPHERTEXT_SIZE] {
        let mut buffer = [0u8; MLKEM768X25519_CIPHERTEXT_SIZE];
        let ct_x_bytes = self.ct_x.to_bytes();
        buffer[..MLKEM768_CT_SIZE].copy_from_slice(self.ct_m.expose_secret());
        buffer[MLKEM768_CT_SIZE..].copy_from_slice(&ct_x_bytes);
        buffer
    }

    /// Constructs from pre-wrapped components (crate-internal).
    pub(crate) fn from_wrapped_components(ct_m: MlKem768Ciphertext1088, ct_x: X25519PublicKey) -> Self {
        Self { ct_m, ct_x }
    }

    /// Constructs from raw byte components.
    pub fn from_components(ct_m: [u8; MLKEM768_CT_SIZE], ct_x: X25519PublicKey) -> Self {
        Self::from_wrapped_components(MlKem768Ciphertext1088::from(ct_m), ct_x)
    }

    /// Returns the raw ML-KEM-768 ciphertext bytes.
    pub fn ct_m(&self) -> &[u8; MLKEM768_CT_SIZE] {
        self.ct_m.expose_secret()
    }

    /// Returns a reference to the X25519 ephemeral public key.
    pub fn ct_x(&self) -> &X25519PublicKey {
        &self.ct_x
    }
}

/// Parses `ct_m || ct_x` from a byte slice.
impl TryFrom<&[u8]> for Ciphertext {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> CrateResult<Self> {
        if bytes.len() != MLKEM768X25519_CIPHERTEXT_SIZE {
            return Err(Error::InvalidCiphertextLength);
        }
        let ct_m = MlKem768Ciphertext1088::new_with(|ct_m_bytes| {
            ct_m_bytes.copy_from_slice(&bytes[..MLKEM768_CT_SIZE]);
        });

        let ct_x_bytes: [u8; x25519::X25519_KEY_SIZE] = bytes[MLKEM768_CT_SIZE..]
            .try_into()
            .map_err(|_| Error::ArraySizeError)?;
        let ct_x = x25519::parse_public_key(ct_x_bytes)?;

        Ok(Self::from_wrapped_components(ct_m, ct_x))
    }
}

/// Fixed-size array convenience; delegates to the slice path.
impl TryFrom<&[u8; MLKEM768X25519_CIPHERTEXT_SIZE]> for Ciphertext {
    type Error = Error;

    fn try_from(bytes: &[u8; MLKEM768X25519_CIPHERTEXT_SIZE]) -> CrateResult<Self> {
        Self::try_from(&bytes[..])
    }
}

// ---------------------------------------------------------------------------
// Standalone keypair generation
// ---------------------------------------------------------------------------

/// Generates a fresh hybrid keypair from a CSPRNG.
pub fn generate_keypair<R: TryRngCore + TryCryptoRng>(
    rng: &mut R,
) -> CrateResult<(DecapsulationKey, EncapsulationKey)> {
    let sk = DecapsulationKey::generate(rng);
    let pk = sk.encapsulation_key()?;
    Ok((sk, pk))
}

// ---------------------------------------------------------------------------
// MlKem768X25519 — HPKE Kem trait implementation
// ---------------------------------------------------------------------------

/// Unit struct implementing the [`Kem`] trait for MLKEM768-X25519.
#[derive(Clone)]
pub struct MlKem768X25519;

impl Kem for MlKem768X25519 {
    fn id(&self) -> u16 {
        KEM_ID
    }

    fn generate_key(&self) -> CrateResult<Box<dyn PrivateKey>> {
        let seed = Seed32::from_random();
        seed.with_secret(|seed_bytes| self.new_private_key(seed_bytes))
    }

    fn new_public_key(&self, data: &[u8]) -> CrateResult<Box<dyn PublicKey>> {
        if data.len() != MLKEM768X25519_ENCAPSULATION_KEY_SIZE {
            return Err(Error::InvalidEncapsulationKeyLength);
        }
        let pk = EncapsulationKey::try_from(data)?;
        Ok(Box::new(XWingPublicKey { pk }))
    }

    fn new_private_key(&self, r#priv: &[u8]) -> CrateResult<Box<dyn PrivateKey>> {
        if r#priv.len() != PRIVATE_KEY_SIZE {
            return Err(Error::InvalidDecapsulationKeyLength);
        }
        let sk = DecapsulationKey::from_seed(r#priv.try_into().map_err(|_| Error::ArraySizeError)?);
        Ok(Box::new(XWingPrivateKey { sk }))
    }

    /// Deterministic key derivation per RFC 9180 section 7.1.3.
    fn derive_key_pair(&self, ikm: &[u8]) -> CrateResult<Box<dyn PrivateKey>> {
        let suite_id = [KEM_SUITE_PREFIX.as_ref(), &KEM_ID.to_be_bytes()].concat();
        let dk = shake256_labeled_derive(
            &suite_id,
            ikm,
            KEM_DERIVE_KEY_PAIR_LABEL,
            &[],
            PRIVATE_KEY_SIZE,
        )?;
        // Derived bytes never live as a bare `Vec<u8>`; the `KdfBytes` wrapper
        // drops at end of with_secret scope, zeroizing.
        dk.with_secret(|bytes| self.new_private_key(bytes))
    }

    fn enc_size(&self) -> usize {
        MLKEM768X25519_CIPHERTEXT_SIZE
    }

    fn public_key_size(&self) -> usize {
        MLKEM768X25519_ENCAPSULATION_KEY_SIZE
    }
}

// ---------------------------------------------------------------------------
// HPKE trait-object wrappers
// ---------------------------------------------------------------------------

/// Wraps [`EncapsulationKey`] for the HPKE [`PublicKey`] trait.
pub struct XWingPublicKey {
    pk: EncapsulationKey,
}

impl PublicKey for XWingPublicKey {
    fn kem(&self) -> Box<dyn Kem> {
        Box::new(MlKem768X25519)
    }

    fn bytes(&self) -> Vec<u8> {
        self.pk.to_bytes().to_vec()
    }

    fn encap(
        &self,
        testing_randomness: Option<&[u8]>,
    ) -> CrateResult<(Vec<u8>, crate::SharedSecret)> {
        let (ct, ss) = if let Some(rand) = testing_randomness {
            if rand.len() >= 64 {
                self.pk
                    .encapsulate_derand(rand.try_into().map_err(|_| Error::ArraySizeError)?)?
            } else {
                return Err(Error::InsufficientTestingRandomness);
            }
        } else {
            let mut rng = OsRng;
            self.pk.encapsulate(&mut rng)?
        };
        let ct_bytes: [u8; MLKEM768X25519_CIPHERTEXT_SIZE] = ct.to_bytes();
        Ok((ct_bytes.to_vec(), ss))
    }
}

/// Wraps [`DecapsulationKey`] for the HPKE [`PrivateKey`] trait.
pub struct XWingPrivateKey {
    sk: DecapsulationKey,
}

impl PrivateKey for XWingPrivateKey {
    fn kem(&self) -> Box<dyn Kem> {
        Box::new(MlKem768X25519)
    }

    fn bytes(&self) -> CrateResult<Vec<u8>> {
        Ok(self.sk.bytes().to_vec())
    }

    fn public_key(&self) -> Box<dyn PublicKey> {
        Box::new(XWingPublicKey {
            pk: self
                .sk
                .encapsulation_key()
                .expect("DecapsulationKey must always derive a valid encapsulation key"),
        })
    }

    fn decap(&self, enc: &[u8]) -> CrateResult<crate::SharedSecret> {
        let ct = Ciphertext::try_from(enc)?;
        self.sk.decapsulate(&ct)
    }
}
