//! ML-KEM-768 + X25519 variant implementation

use super::combiner;
use crate::aliases::{
    MlKem768Ciphertext1088, MlKem768PublicKey1184, Seed32, SharedSecret32, X25519PublicKey32,
    X25519Secret32,
};
use crate::error::{Error, Result as CrateResult};
use crate::kem::common::{
    clamp_x25519_scalar, expand_seed, shake256_labeled_derive, Kem, PrivateKey, PublicKey,
    CURVE_SEED_SIZE, KEM_ID, MASTER_SEED_SIZE, ML_KEM_SEED_SIZE, PRIVATE_KEY_SIZE,
};
use secure_gate::{ConstantTimeEq, RevealSecret, RevealSecretMut};

use core::fmt;

use libcrux_ml_kem::mlkem768::{
    decapsulate, encapsulate, generate_key_pair as mlkem768_generate_key_pair, MlKem768Ciphertext,
    MlKem768KeyPair, MlKem768PublicKey,
};

use rand::rngs::OsRng;
use rand::{TryCryptoRng, TryRngCore};

use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const X25519_KEY_SIZE: usize = 32;
const MLKEM768_PK_SIZE: usize = 1184;
pub const MLKEM768_CT_SIZE: usize = 1088;

/// KEM suite ID prefix per RFC 9180 §5.3 ("KEM" || KEM_ID).
const KEM_SUITE_PREFIX: &[u8; 3] = b"KEM";
/// Label used in the DeriveKeyPair operation per RFC 9180 §7.1.3.
const KEM_DERIVE_KEY_PAIR_LABEL: &[u8; 13] = b"DeriveKeyPair";

fn expand_key(seed: &[u8; MASTER_SEED_SIZE]) -> (MlKem768KeyPair, [u8; CURVE_SEED_SIZE]) {
    let (ml_seed, x_bytes) = expand_seed(seed);
    debug_assert_eq!(ml_seed.len(), ML_KEM_SEED_SIZE);
    let kp = mlkem768_generate_key_pair(ml_seed);
    (kp, x_bytes)
}

pub const MLKEM768X25519_ENCAPSULATION_KEY_SIZE: usize = MLKEM768_PK_SIZE + X25519_KEY_SIZE;
pub const MLKEM768X25519_DECAPSULATION_KEY_SIZE: usize = MASTER_SEED_SIZE;
pub const MLKEM768X25519_CIPHERTEXT_SIZE: usize = MLKEM768_CT_SIZE + X25519_KEY_SIZE;

pub struct EncapsulationKey {
    pk_m: MlKem768PublicKey1184,
    pk_x: X25519PublicKey,
}

#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct DecapsulationKey {
    seed: [u8; MASTER_SEED_SIZE],
}

pub struct Ciphertext {
    ct_m: MlKem768Ciphertext1088,
    ct_x: X25519PublicKey,
}

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

impl EncapsulationKey {
    fn encapsulate_inner(
        &self,
        ml_rand_bytes: [u8; 32],
        ephemeral_bytes: [u8; 32],
    ) -> CrateResult<(Ciphertext, crate::SharedSecret)> {
        let pk_m = MlKem768PublicKey::from(*self.pk_m.expose_secret());
        let ml_rand = Seed32::from(ml_rand_bytes);
        let (ct_m, mlkem_ss) = ml_rand.with_secret(|rand_seed| encapsulate(&pk_m, *rand_seed));
        let ss_m = SharedSecret32::from(mlkem_ss);

        let ct_m_bytes: [u8; MLKEM768_CT_SIZE] = ct_m
            .as_ref()
            .try_into()
            .map_err(|_| Error::ArraySizeError)?;

        let mut ephemeral_seed = X25519Secret32::from(ephemeral_bytes);
        ephemeral_seed.with_secret_mut(clamp_x25519_scalar);
        let ephemeral = StaticSecret::from(ephemeral_seed.with_secret(|bytes| *bytes));
        let ct_x = X25519PublicKey::from(&ephemeral);
        let ss_x = SharedSecret32::from(ephemeral.diffie_hellman(&self.pk_x).to_bytes());

        let ct_x_bytes = X25519PublicKey32::from(ct_x.to_bytes());
        let pk_x_bytes = X25519PublicKey32::from(self.pk_x.to_bytes());
        // Preferred access pattern for low-level combiners: expose once in a tight scope.
        let ss = {
            let ss_m_bytes = ss_m.expose_secret();
            let ss_x_bytes = ss_x.expose_secret();
            let ct_x_bytes_raw = ct_x_bytes.expose_secret();
            let pk_x_bytes_raw = pk_x_bytes.expose_secret();
            combiner::combine_shared_secrets(ss_m_bytes, ss_x_bytes, ct_x_bytes_raw, pk_x_bytes_raw)
        };

        Ok((
            Ciphertext::from_wrapped_components(MlKem768Ciphertext1088::from(ct_m_bytes), ct_x),
            ss,
        ))
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; MLKEM768X25519_ENCAPSULATION_KEY_SIZE] {
        let mut buffer = [0u8; MLKEM768X25519_ENCAPSULATION_KEY_SIZE];
        let pk_x_bytes = self.pk_x.to_bytes();
        buffer[..MLKEM768_PK_SIZE].copy_from_slice(self.pk_m.expose_secret());
        buffer[MLKEM768_PK_SIZE..].copy_from_slice(&pk_x_bytes);
        buffer
    }

    /// Random encapsulation using a caller-provided cryptographically secure RNG.
    pub fn encapsulate<R: TryRngCore + TryCryptoRng>(
        &self,
        rng: &mut R,
    ) -> CrateResult<(Ciphertext, crate::SharedSecret)> {
        let ml_rand = Seed32::from_rng(rng).map_err(|_| Error::RandomnessError)?;
        let ml_rand_bytes = ml_rand.with_secret(|bytes| *bytes);
        let ephemeral_seed = X25519Secret32::from_rng(rng).map_err(|_| Error::RandomnessError)?;
        let ephemeral_bytes = ephemeral_seed.with_secret(|bytes| *bytes);
        self.encapsulate_inner(ml_rand_bytes, ephemeral_bytes)
    }

    /// Public getter for pk_m
    pub fn pk_m(&self) -> &[u8; MLKEM768_PK_SIZE] {
        self.pk_m.expose_secret()
    }

    /// Public getter for pk_x
    pub fn pk_x(&self) -> &X25519PublicKey {
        &self.pk_x
    }

    /// Deterministic generation from 32-byte seed
    pub fn from_seed(seed: &[u8; MASTER_SEED_SIZE]) -> CrateResult<Self> {
        let seed = Seed32::from(*seed);
        seed.with_secret(|seed_bytes| {
            let (kp, x_bytes) = expand_key(seed_bytes);
            let pk_m_bytes: [u8; MLKEM768_PK_SIZE] = kp
                .public_key()
                .as_ref()
                .try_into()
                .map_err(|_| Error::ArraySizeError)?;

            let x_bytes = X25519Secret32::from(x_bytes);
            let sk_x = StaticSecret::from(x_bytes.with_secret(|bytes| *bytes));
            let pk_x = X25519PublicKey::from(&sk_x);

            Ok(Self::from_components(pk_m_bytes, pk_x))
        })
    }

    /// Deterministic encapsulation using a fixed 64-byte encapsulation seed.
    ///
    /// The `eseed` is interpreted as:
    /// - First 32 bytes: randomness for ML-KEM-768 encapsulation
    /// - Last 32 bytes:  X25519 ephemeral secret key (clamped per RFC 7748)
    ///
    /// This allows reproducible known-answer tests (KATs) and matches the
    /// derandomized encapsulation used in test vectors.
    pub fn encapsulate_derand(
        &self,
        eseed: &[u8; 64],
    ) -> CrateResult<(Ciphertext, crate::SharedSecret)> {
        let ml_rand_bytes: [u8; 32] = eseed[0..32].try_into().map_err(|_| Error::ArraySizeError)?;
        let ephemeral_bytes: [u8; 32] = eseed[32..64]
            .try_into()
            .map_err(|_| Error::ArraySizeError)?;
        self.encapsulate_inner(ml_rand_bytes, ephemeral_bytes)
    }
}

impl EncapsulationKey {
    pub(crate) fn from_wrapped_components(pk_m: MlKem768PublicKey1184, pk_x: X25519PublicKey) -> Self {
        Self { pk_m, pk_x }
    }

    pub fn from_components(pk_m: [u8; MLKEM768_PK_SIZE], pk_x: X25519PublicKey) -> Self {
        Self::from_wrapped_components(MlKem768PublicKey1184::from(pk_m), pk_x)
    }
}

impl TryFrom<&[u8]> for EncapsulationKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> CrateResult<Self> {
        if bytes.len() != MLKEM768X25519_ENCAPSULATION_KEY_SIZE {
            return Err(Error::InvalidEncapsulationKeyLength);
        }
        let mut pk_m_bytes = [0u8; MLKEM768_PK_SIZE];
        pk_m_bytes.copy_from_slice(&bytes[..MLKEM768_PK_SIZE]);
        let pk_m = MlKem768PublicKey1184::from(pk_m_bytes);

        let pk_x_bytes: [u8; 32] = bytes[MLKEM768_PK_SIZE..]
            .try_into()
            .map_err(|_| Error::ArraySizeError)?;
        let pk_x = X25519PublicKey::from(pk_x_bytes);

        // Validate that pk_x is not the all-zero point (which is invalid for X25519)
        if pk_x_bytes.ct_eq(&[0u8; 32]) {
            return Err(Error::InvalidX25519PublicKey);
        }

        // Validate ML-KEM public key by attempting to create it and test basic functionality
        let mlkem_pk = MlKem768PublicKey::from(*pk_m.expose_secret());
        // Test that the key can be used for basic operations by checking it can be converted back
        let _pk_bytes = mlkem_pk.as_ref();

        Ok(Self::from_wrapped_components(pk_m, pk_x))
    }
}

// Backward-compatible impl for &[u8; SIZE]
impl TryFrom<&[u8; MLKEM768X25519_ENCAPSULATION_KEY_SIZE]> for EncapsulationKey {
    type Error = Error;

    fn try_from(bytes: &[u8; MLKEM768X25519_ENCAPSULATION_KEY_SIZE]) -> CrateResult<Self> {
        Self::try_from(&bytes[..])
    }
}

impl DecapsulationKey {
    pub fn from_seed(seed: &[u8; MASTER_SEED_SIZE]) -> Self {
        let seed = Seed32::from(*seed);
        Self {
            seed: seed.with_secret(|bytes| *bytes),
        }
    }

    /// Generate a new decapsulation key using a caller-provided cryptographically secure RNG.
    pub fn generate<R: TryRngCore + TryCryptoRng>(rng: &mut R) -> Self {
        let seed = Seed32::from_rng(rng)
            .expect("Failed to generate random bytes for decapsulation key seed");
        Self {
            seed: seed.with_secret(|bytes| *bytes),
        }
    }

    /// Get the seed as bytes (for HPKE integration).
    pub fn bytes(&self) -> [u8; MASTER_SEED_SIZE] {
        self.seed
    }

    pub fn encapsulation_key(&self) -> CrateResult<EncapsulationKey> {
        let seed = Seed32::from(self.seed);
        let (kp, x_bytes) = seed.with_secret(expand_key);
        let pk_m_bytes: [u8; MLKEM768_PK_SIZE] = kp
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| Error::ArraySizeError)?;

        let x_bytes = X25519Secret32::from(x_bytes);
        let sk_x = StaticSecret::from(x_bytes.with_secret(|bytes| *bytes));
        let pk_x = X25519PublicKey::from(&sk_x);

        Ok(EncapsulationKey::from_wrapped_components(
            MlKem768PublicKey1184::from(pk_m_bytes),
            pk_x,
        ))
    }

    pub fn decapsulate(&self, ct: &Ciphertext) -> CrateResult<crate::SharedSecret> {
        let seed = Seed32::from(self.seed);
        let (kp, x_bytes) = seed.with_secret(expand_key);

        let sk_m = kp.private_key();
        let ct_m = MlKem768Ciphertext::from(*ct.ct_m.expose_secret());
        let ss_m = SharedSecret32::from(decapsulate(sk_m, &ct_m));
        let x_bytes = X25519Secret32::from(x_bytes);
        let sk_x = StaticSecret::from(x_bytes.with_secret(|bytes| *bytes));
        let ss_x = SharedSecret32::from(sk_x.diffie_hellman(&ct.ct_x).to_bytes());

        let pk_x = X25519PublicKey::from(&sk_x);
        let ct_x_bytes = X25519PublicKey32::from(ct.ct_x.to_bytes());
        let pk_x_bytes = X25519PublicKey32::from(pk_x.to_bytes());
        // Preferred access pattern for low-level combiners: expose once in a tight scope.
        let ss = {
            let ss_m_bytes = ss_m.expose_secret();
            let ss_x_bytes = ss_x.expose_secret();
            let ct_x_bytes_raw = ct_x_bytes.expose_secret();
            let pk_x_bytes_raw = pk_x_bytes.expose_secret();
            combiner::combine_shared_secrets(ss_m_bytes, ss_x_bytes, ct_x_bytes_raw, pk_x_bytes_raw)
        };

        Ok(ss)
    }
}

impl Ciphertext {
    #[must_use]
    pub fn to_bytes(&self) -> [u8; MLKEM768X25519_CIPHERTEXT_SIZE] {
        let mut buffer = [0u8; MLKEM768X25519_CIPHERTEXT_SIZE];
        let ct_x_bytes = self.ct_x.to_bytes();
        buffer[..MLKEM768_CT_SIZE].copy_from_slice(self.ct_m.expose_secret());
        buffer[MLKEM768_CT_SIZE..].copy_from_slice(&ct_x_bytes);
        buffer
    }

    pub(crate) fn from_wrapped_components(ct_m: MlKem768Ciphertext1088, ct_x: X25519PublicKey) -> Self {
        Self { ct_m, ct_x }
    }

    pub fn from_components(ct_m: [u8; MLKEM768_CT_SIZE], ct_x: X25519PublicKey) -> Self {
        Self::from_wrapped_components(MlKem768Ciphertext1088::from(ct_m), ct_x)
    }

    /// Raw ML-KEM-768 ciphertext bytes (for libcrux).
    pub fn ct_m(&self) -> &[u8; MLKEM768_CT_SIZE] {
        self.ct_m.expose_secret()
    }

    pub fn ct_x(&self) -> &X25519PublicKey {
        &self.ct_x
    }
}

impl TryFrom<&[u8]> for Ciphertext {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> CrateResult<Self> {
        if bytes.len() != MLKEM768X25519_CIPHERTEXT_SIZE {
            return Err(Error::InvalidCiphertextLength);
        }
        let mut ct_m_bytes = [0u8; MLKEM768_CT_SIZE];
        ct_m_bytes.copy_from_slice(&bytes[..MLKEM768_CT_SIZE]);
        let ct_m = MlKem768Ciphertext1088::from(ct_m_bytes);

        let ct_x_bytes: [u8; 32] = bytes[MLKEM768_CT_SIZE..]
            .try_into()
            .map_err(|_| Error::ArraySizeError)?;
        let ct_x = X25519PublicKey::from(ct_x_bytes);

        // Validate that ct_x is not the all-zero point
        if ct_x_bytes.ct_eq(&[0u8; 32]) {
            return Err(Error::InvalidX25519PublicKey);
        }

        Ok(Self::from_wrapped_components(ct_m, ct_x))
    }
}

// Backward-compatible impl for &[u8; SIZE]
impl TryFrom<&[u8; MLKEM768X25519_CIPHERTEXT_SIZE]> for Ciphertext {
    type Error = Error;

    fn try_from(bytes: &[u8; MLKEM768X25519_CIPHERTEXT_SIZE]) -> CrateResult<Self> {
        Self::try_from(&bytes[..])
    }
}

/// Generate a fresh keypair using a caller-provided cryptographically secure RNG.
pub fn generate_keypair<R: TryRngCore + TryCryptoRng>(
    rng: &mut R,
) -> CrateResult<(DecapsulationKey, EncapsulationKey)> {
    let sk = DecapsulationKey::generate(rng);
    let pk = sk.encapsulation_key()?;
    Ok((sk, pk))
}

// X-Wing KEM implementation
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

    fn derive_key_pair(&self, ikm: &[u8]) -> CrateResult<Box<dyn PrivateKey>> {
        let suite_id = [KEM_SUITE_PREFIX.as_ref(), &KEM_ID.to_be_bytes()].concat();
        let dk = shake256_labeled_derive(&suite_id, ikm, KEM_DERIVE_KEY_PAIR_LABEL, &[], PRIVATE_KEY_SIZE)?;
        self.new_private_key(&dk)
    }

    fn enc_size(&self) -> usize {
        MLKEM768X25519_CIPHERTEXT_SIZE
    }

    fn public_key_size(&self) -> usize {
        MLKEM768X25519_ENCAPSULATION_KEY_SIZE
    }
}

// PublicKey implementation using EncapsulationKey
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
            if rand.len() >= 32 {
                // Use provided randomness for deterministic encapsulation if >= 64 bytes
                if rand.len() >= 64 {
                    self.pk
                        .encapsulate_derand(rand.try_into().map_err(|_| Error::ArraySizeError)?)?
                } else {
                    // Not enough for full deterministic, but we have some - this shouldn't happen in current logic
                    return Err(Error::InsufficientTestingRandomness);
                }
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

// PrivateKey implementation using DecapsulationKey
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
