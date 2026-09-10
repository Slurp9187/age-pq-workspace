# Plan — `age-pq-hpke` secure-gate hardening

Status: **Complete, and partly superseded.** PRs 1–4 landed; PR 5 reduced to
version bump + changelog (see "PR 5 — final scope" below).

`DECIDE-2` / `DECIDE-5` / `DECIDE-6` below settled *return* types only, and were
later extended to parameters and fields — see
[`../design/api-boundary-types.md`](../design/api-boundary-types.md)
(`DECIDE-7`..`DECIDE-10`), which is the current authority on boundary types.
Kept here as the record of how those conclusions were reached.

This file was untracked until the `.gitignore` fix that added it; it predates
being in the repo, so its "next steps" are historical, not open work.

**Locked decisions (final):**

| Decision | Resolution |
|----------|------------|
| DECIDE-2 | **Reverted to Option A** — `Kem::derive_key_pair(&self, ikm: &[u8])` stays. The wrapper-input variant proved to be paternalism: the function absorbs IKM once into SHAKE and discards; the residue concern is the caller's, not the library's. Forcing `KdfBytes::new(slice.to_vec())` at every call site adds a heap allocation for no protection. |
| DECIDE-4 | **`Box<dyn Kdf>` retained** (revised during PR 4). The original plan called for `Arc<dyn Kdf>`, but on close inspection `kdf` is consumed by `move` into the export closure on each branch of the SHAKE/HKDF `if/else`, and no use of `kdf` survives past the closure construction. `Arc` would add an atomic refcount for no benefit — `Box` is sufficient. |
| DECIDE-5 | **Reverted to `Vec<u8>`** — `PrivateKey::bytes() -> Result<Vec<u8>>` stays. Same reasoning as the broader policy revision: wrapped returns force friction on every caller for ambiguous benefit. Callers who want a wrapper construct `Seed32::new_with(...)` themselves; the alias is re-exported `pub` for exactly that purpose. |
| DECIDE-6 | **Dropped, `AeadCiphertext` alias removed.** `Sender::seal` and one-shot `seal` continue to return `Vec<u8>`. The symmetry-with-`open` argument doesn't hold up because the bytes are wire output — they go straight to a socket/file/stanza, where wrapping is friction with no real protection. |
| Version  | **`0.0.6`** — releases the in-progress `0.0.6-dev` working version. Pre-0.1 churn continues; mirrors `libcrux-ml-kem`. Captures PRs 1–4 as a no-API-break improvement set. |

## PR 5 — final scope

The earlier PR 5 plan ("Phase 2 breaking API") is dropped. PRs 1–4 already
delivered the actual security value (no leaked secrets inside the library;
exporter wrapped; AEAD key never materializes outside a wrapper; decap key
seed in `Seed32` for its full in-process lifetime). The originally-planned
public-API breakage — `Recipient::open -> Plaintext`, `Sender::seal ->
AeadCiphertext`, `*::export -> KdfBytes`, `PrivateKey::bytes -> &Seed32`,
`Kem::derive_key_pair(&KdfBytes)` — was reconsidered on direct user
feedback that wrapped return types (as in `rage` / `secrecy`) propagate
friction through caller signatures without proportional benefit. The
ecosystem consensus is "library wraps inside, returns raw bytes outside";
PR 5 conforms.

What PR 5 actually does:

1. Remove the `AeadCiphertext` alias (no method uses it).
2. Re-clarify the `Plaintext` and `KdfBytes` alias docs as "opt-in for
   callers".
3. Workspace `CLAUDE.md`: revise the "wire boundary" section to codify
   *raw bytes at the public API; wrappers inside* as the workspace rule.
4. Bump `age-pq-hpke` to `0.0.6` (releases the `0.0.6-dev` working version).
5. Update `age-pq-hpke/CHANGELOG.md` with a summary of PRs 1–4.

Companion: workspace rules live in `/CLAUDE.md`. This plan applies those rules
to every concrete site in `age-pq-hpke` that currently violates them. The
`age-pq-keys` and `age-plugin-pq` follow-ups are out of scope for this
plan — a separate plan in this folder will cover them once `age-pq-hpke`
lands.

---

## Guiding principles (recap from `/CLAUDE.md`)

1. **Wrap everything cryptographic.** Salts, nonces, public keys, ciphertexts,
   IKM, KDF outputs, AAD, info strings — wrapped, even when the bytes are
   public. The wrapper is a self-documenting newtype with type-level length
   enforcement, redacted `Debug`, and free zeroization when the contents are
   secret.
2. **Tier 1 (`with_secret`) is the default.** Tier 2 (`expose_secret`) is the
   boundary escape hatch — acceptable when (a) an external API requires
   `&[u8]` / `&T` and cannot accept a closure, or (b) a `with_secret`
   refactor would force ≥3 levels of nesting and obscure the operation.
   Every retained `expose_secret` gets a one-line `// Tier-2: <api>` comment.
3. **The public API never returns bare `Vec<u8>` for secret bytes.** Plaintext,
   key material, exporter output, and KDF derivations come back as wrappers.
   Callers explicitly reveal.
4. **`new_with` over `new` for Fixed types** whenever the value is being
   constructed from a slice / closure — avoids the intermediate plaintext
   stack copy.
5. **`ct_eq` on secret wrappers; `==` on public bytes via `expose_secret`.**

---

## Phase 0 — Pre-work

- Confirm the toolchain pin (`rust-toolchain.toml`) and verify
  `cargo +<pin> check --workspace` is green at baseline.
- Confirm workspace `[profile.*]` does not set `panic = "abort"`.
- Inventory: list every `expose_secret`, every raw `[u8; N]` / `Vec<u8>` at
  function boundaries involving secrets, and every `Vec<u8>` at the public
  API. The audit notes from the prior review are the starting point.
- Snapshot a baseline `cargo test --workspace --all-features` to ensure the
  PRs in Phase 1 cause no regressions (Phase 2 changes break tests on
  purpose).

---

## New / changed aliases (`src/aliases.rs`)

**Add:**

| Alias | Backing | Reason |
|-------|---------|--------|
| `MlKemSeed64` | `Fixed<[u8; 64]>` | ML-KEM `d \|\| z` seed currently leaks from `expand_seed` as `[u8; 64]`. |
| `LabeledInfo` | `Dynamic<Vec<u8>>` | HKDF labeled_info buffer (currently a bare `Vec<u8>` in `kdf.rs`). |
| `AeadCiphertext` | `Dynamic<Vec<u8>>` | HPKE AEAD ciphertext + auth tag (wire output of `Sender::seal` and one-shot `seal`). Symmetric with `Plaintext` on the receive side. Named to avoid colliding with `kem::mlkem768x25519::Ciphertext`. |

**Promote:**

| Alias | Action |
|-------|--------|
| `Plaintext` | `pub(crate)` → `pub`. Returned from `Recipient::open`. |

**Keep, unchanged:** `Seed32`, `SharedSecret`, `AeadKey32`, `Nonce12`,
`SharedSecret32`, `X25519PublicKey32`, `X25519Secret32`, `X448PublicKey56`,
`X448Secret56`, `MlKem768PublicKey1184`, `MlKem768Ciphertext1088`,
`MlKem512*`, `MlKem1024*`, `ExpandedKeyMaterial96`, `Info`, `Aad`,
`ExporterContext`, `OneStageSecrets`, `LabeledIkm`, `LabeledOkm`, `Salt`,
`KdfBytes`. Per workspace rule "wrap everything cryptographic" — these all
stay wrapped even when the underlying bytes are public.

**No removals.** Earlier suggestions to drop the public-value aliases are
withdrawn per the principle above.

---

## Phase 1 — Internal hardening (no public API breakage)

Goal: tighten every internal seam without changing public trait signatures
or `pub fn` shapes. Five mostly-independent PRs.

### PR 1.1 — `src/aead.rs`: AEAD key inside `with_secret`

Eliminate the unzeroized `ChaKey` (`GenericArray`) outer binding (`:85`):

```rust
fn aead(&self, key: &[u8]) -> Result<Box<dyn CipherAead>, Error> {
    if key.len() != CHACHA20_POLY1305_KEY_SIZE {
        return Err(Error::InvalidKeyLength);
    }
    // Tier-2: chacha20poly1305::new_from_slice takes &[u8]; caller has
    // already routed the bytes through AeadKey32::expose_secret upstream.
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| Error::InvalidKeyLength)?;
    Ok(Box::new(ChaChaCipher { cipher }))
}
```

Nonces stay wrapped in `Nonce12`; the seal/open paths use `expose_secret`
directly into `ChaNonce::from_slice` rather than `with_secret + deref + re-wrap`:

```rust
fn seal(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    let nonce = Nonce12::try_from(nonce).map_err(|_| Error::InvalidLength)?;
    // Tier-2: chacha20poly1305::Nonce is a GenericArray, takes &[u8].
    let cipher_nonce = ChaNonce::from_slice(nonce.expose_secret());
    self.cipher
        .encrypt(cipher_nonce, Payload { msg: plaintext, aad })
        .map_err(|_| Error::EncryptionFailed)
}
```

### PR 1.2 — `src/kdf.rs`: PRK / OKM assembly

Rewrite the HKDF path so the `GenericArray` PRK from `Hkdf::extract` is
consumed in one statement and the bytes land directly in `KdfBytes`. Drop the
needless `LabeledIkm` / `LabeledOkm` round-trip through `.into_inner().into_zeroizing()`:

```rust
fn labeled_extract(&self, suite_id: &[u8], salt: Option<&[u8]>, label: &str, ikm: &[u8])
    -> Result<KdfBytes, Error>
{
    let mut labeled = Zeroizing::new(Vec::with_capacity(
        HPKE_VERSION_LABEL.len() + suite_id.len() + label.len() + ikm.len()));
    labeled.extend_from_slice(HPKE_VERSION_LABEL);
    labeled.extend_from_slice(suite_id);
    labeled.extend_from_slice(label.as_bytes());
    labeled.extend_from_slice(ikm);

    let labeled = LabeledIkm::new(core::mem::take(&mut *labeled));
    let salt    = Salt::from(salt.unwrap_or(&[]));

    let mut prk = Zeroizing::new(vec![0u8; <$hash_ty as digest::OutputSizeUser>::output_size()]);
    // Tier-2: hkdf::Hkdf::extract takes &[u8].
    let (h, _) = Hkdf::<$hash_ty>::extract(
        Some(salt.expose_secret()),
        labeled.expose_secret(),
    );
    prk.copy_from_slice(&h);
    Ok(KdfBytes::new(core::mem::take(&mut *prk)))
}
```

Similarly for `labeled_expand`: build the `labeled_info` as `LabeledInfo`
(`Dynamic<Vec<u8>>`, new alias), use `expose_secret` into `hk.expand`, write
into a `Zeroizing<Vec<u8>>`, finalize as `KdfBytes`. Same shape for both
SHAKE KDFs — outputs land directly in `KdfBytes`.

### PR 1.3 — `src/kem/x25519.rs` + `src/kem/x448.rs`

Use `into_inner` (Tier-3) to consume the wrapper at the libcrux/x25519-dalek
FFI boundary — `StaticSecret::from` takes `[u8; 32]` by value, so this is the
right tier. The returned `InnerSecret<[u8; 32]>` derefs to the array and
zeroizes on drop automatically, replacing the manual `clamped.zeroize()` of
the earlier sketch:

```rust
pub(crate) fn static_secret_from_seed(seed: X25519Secret32) -> StaticSecret {
    // Tier-3: x25519_dalek::StaticSecret::from takes [u8; 32] by value.
    let mut owned = seed.into_inner();           // InnerSecret<[u8; 32]>
    clamp_x25519_scalar(&mut *owned);
    StaticSecret::from(*owned)
    // `owned` drops here, zeroizing the (clamped) buffer.
}
```

Lift signatures to take wrappers (by value where consumed, by ref where the
caller still needs them):

- `static_secret_from_seed(X25519Secret32) -> StaticSecret`   *(owned, into_inner)*
- `encapsulate_to_public_key(X25519Secret32, &X25519PublicKey)
    -> (X25519PublicKey, SharedSecret32)`   *(ephemeral seed is consumed)*
- `decapsulate_from_private_seed(X25519Secret32, &X25519PublicKey)
    -> (SharedSecret32, X25519PublicKey)`   *(private seed re-derived each call,
    so taking by value is fine)*
- mirror changes in `x448.rs`

`parse_public_key(bytes: [u8; 32]) -> ...` stays — public key bytes; the
`ct_eq` against the all-zero point compares public material, which is fine.

### PR 1.4 — `src/kem/ml_kem/*.rs`

Randomness is consumed via `into_inner` (Tier-3) — libcrux's `encapsulate` and
`generate_key_pair` take their array arguments by value. Public-key bytes
stay borrowed (we keep the `MlKem768PublicKey1184` wrapper around):

```rust
pub(crate) fn encapsulate_with_seed(
    pk_m: &MlKem768PublicKey1184,
    randomness: Seed32,                                  // OWNED
) -> CrateResult<([u8; MLKEM768_CT_SIZE], SharedSecret32)> {
    // Tier-2: MlKem768PublicKey::from takes [u8; 1184] (public bytes).
    let pk = pk_m.with_secret(|b| MlKem768PublicKey::from(*b));
    // Tier-3: libcrux encapsulate takes [u8; 32] by value.
    let r = randomness.into_inner();                     // InnerSecret<[u8; 32]>
    let (ct, ss) = encapsulate(&pk, *r);
    let ct_bytes: [u8; MLKEM768_CT_SIZE] = ct.as_ref().try_into()
        .map_err(|_| Error::ArraySizeError)?;
    Ok((ct_bytes, SharedSecret32::from(ss)))
}

pub(crate) fn keypair_from_seed(seed: MlKemSeed64) -> MlKem768KeyPair {
    // Tier-3: libcrux generate_key_pair takes [u8; 64] by value.
    let owned = seed.into_inner();                       // InnerSecret<[u8; 64]>
    mlkem768_generate_key_pair(*owned)
}

pub(crate) fn decapsulate_with_keypair(
    kp: &MlKem768KeyPair,
    ct_m: &MlKem768Ciphertext1088,
) -> SharedSecret32 {
    // Tier-2: libcrux ciphertext type takes [u8; 1088] (public ciphertext bytes).
    // ct_m is borrowed from the caller's Ciphertext struct, so Tier-3 doesn't apply.
    let ct = ct_m.with_secret(|b| MlKem768Ciphertext::from(*b));
    SharedSecret32::from(decapsulate(kp.private_key(), &ct))
}
```

Apply the same pattern to ml-kem-512 / 1024 if they're built (feature-gated).

### PR 1.5 — `src/kem/common.rs`: `expand_seed`, `shake256_labeled_derive`

`expand_seed` returns wrappers and never names the raw split arrays:

```rust
pub(crate) fn expand_seed(seed: &Seed32) -> (MlKemSeed64, X25519Secret32) {
    seed.with_secret(|seed_bytes| {
        let mut h = Shake256::default();
        h.update(seed_bytes);
        let mut reader = h.finalize_xof();
        let expanded = ExpandedKeyMaterial96::new_with(|out| reader.read(out));
        let ml = expanded.with_secret(|e| {
            MlKemSeed64::new_with(|out| out.copy_from_slice(&e[0..ML_KEM_SEED_SIZE]))
        });
        let x = expanded.with_secret(|e| {
            X25519Secret32::new_with(|out| out.copy_from_slice(&e[ML_KEM_SEED_SIZE..]))
        });
        (ml, x)
    })
}
```

`shake256_labeled_derive` returns `KdfBytes`:

```rust
pub fn shake256_labeled_derive(
    suite_id: &[u8],
    input_key: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> CrateResult<KdfBytes> {
    let mut out = Zeroizing::new(vec![0u8; length]);
    /* ...absorb, squeeze... */
    Ok(KdfBytes::new(core::mem::take(&mut *out)))
}
```

`shake256_labeled_derive(input_key: &[u8])` keeps the `&[u8]` slot — the
helper feeds SHAKE absorb in one statement and doesn't retain. The wrapper
discipline lives one level up, at the `Kem::derive_key_pair` trait method
(DECIDE-2 = B, see Phase 2).

### PR 1.6 — `src/kem/mlkem768x25519.rs`

`DecapsulationKey` stores the seed wrapped, with no manual `Zeroize`/`ZeroizeOnDrop`:

```rust
pub struct DecapsulationKey {
    seed: Seed32,
}

impl fmt::Debug for DecapsulationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DecapsulationKey").field(&"[REDACTED]").finish()
    }
}

impl DecapsulationKey {
    pub fn from_seed(seed: &[u8; MASTER_SEED_SIZE]) -> Self {
        Self { seed: Seed32::new_with(|out| out.copy_from_slice(seed)) }
    }
    pub fn generate<R: TryRngCore + TryCryptoRng>(rng: &mut R) -> Self {
        Self { seed: Seed32::from_rng(rng).expect("CSPRNG failure") }
    }
}
```

`expand_key(seed: &Seed32) -> (MlKem768KeyPair, X25519Secret32)` — the seed
is borrowed (the `DecapsulationKey` keeps it for the lifetime of the key);
the returned `X25519Secret32` is freshly owned and will be consumed by the
next downstream call.

`encapsulate_inner` takes owned randomness wrappers — each call produces fresh
randomness that flows straight through to the FFI boundary and is consumed
via `into_inner`:

```rust
fn encapsulate_inner(
    &self,
    ml_rand: Seed32,                                     // OWNED
    ephemeral: X25519Secret32,                           // OWNED
) -> CrateResult<(Ciphertext, crate::SharedSecret)> {
    let (ct_m_bytes, ss_m) = ml_kem::encapsulate_with_seed(&self.pk_m, ml_rand)?;
    let (ct_x, ss_x) = x25519::encapsulate_to_public_key(ephemeral, &self.pk_x);

    let ct_x_bytes = X25519PublicKey32::from(ct_x.to_bytes());
    let pk_x_bytes = X25519PublicKey32::from(self.pk_x.to_bytes());

    // Tier-2: combiner takes four &[u8; 32]; 4-arg nesting would obscure.
    let ss = combiner::combine_shared_secrets(
        ss_m.expose_secret(),
        ss_x.expose_secret(),
        ct_x_bytes.expose_secret(),
        pk_x_bytes.expose_secret(),
    );
    /* ...assemble Ciphertext... */
}
```

`encapsulate(rng)` constructs the two wrappers via `from_rng` and passes them
by value (consumed).

`encapsulate_derand(eseed: &[u8; 64])` writes the two halves into
`Seed32 / X25519Secret32` via `new_with` and passes them by value.

### PR 1.7 — `src/hpke.rs`: exporter secret + slicing

Exporter secret stays in a wrapper for the lifetime of `Context`. `Kdf` is
captured as `Arc<dyn Kdf>`:

```rust
let exp_secret: KdfBytes = /* sliced from secret, or from labeled_expand */;
let exp_secret = std::sync::Arc::new(exp_secret);
let exp_for_closure = exp_secret.clone();
let kdf_for_closure: Arc<dyn Kdf> = kdf.into();   // change Kdf param to Arc
let sid_for_closure = sid;

export = Box::new(move |ctx, length| {
    let exporter_ctx = ExporterContext::new(ctx.to_vec());
    let raw = exp_for_closure.expose_secret();      // Tier-2: feed kdf API
    let ctx_bytes = exporter_ctx.expose_secret();   // Tier-2: feed kdf API
    if kdf_for_closure.one_stage() {
        kdf_for_closure.labeled_derive(&sid_for_closure, raw, "sec", ctx_bytes, length)
    } else {
        kdf_for_closure.labeled_expand(&sid_for_closure, raw, "sec", ctx_bytes, length)
    }
});
```

Slice the one-stage derive output in a single `expose_secret` scope, writing
each fragment into its wrapper via `new_with`:

```rust
let secret_raw = secret.expose_secret();   // Tier-2: slicing requires &[u8]
let key = AeadKey32::new_with(|out| out.copy_from_slice(&secret_raw[..aead.key_size()]));
let base_nonce = Nonce12::new_with(|out| {
    out.copy_from_slice(&secret_raw[aead.key_size()..aead.key_size() + aead.nonce_size()])
});
let exp_secret = KdfBytes::new(
    secret_raw[aead.key_size() + aead.nonce_size()..].to_vec()
);
```

`Sender::seal` / `Recipient::open` keep `Aad::new` / `Plaintext::new` wraps
and use `expose_secret` to feed `aead.seal` / `aead.open`.

Internal-only changes; public method shapes are unchanged in this PR.

---

## Phase 2 — Public API breakage

Single PR. SemVer bump (see DECIDE-version).

### Trait changes

```rust
pub trait Kem {
    fn id(&self) -> u16;
    fn generate_key(&self) -> CrateResult<Box<dyn PrivateKey>>;
    fn new_public_key(&self, data: &[u8]) -> CrateResult<Box<dyn PublicKey>>;
    fn new_private_key(&self, data: &[u8]) -> CrateResult<Box<dyn PrivateKey>>;

    // DECIDE-2 = B: trait takes a wrapper. RFC 9180 calls IKM opaque bytes;
    // the wrapper makes the secrecy contract explicit at the trait level.
    fn derive_key_pair(&self, ikm: &KdfBytes) -> CrateResult<Box<dyn PrivateKey>>;

    fn enc_size(&self) -> usize;
    fn public_key_size(&self) -> usize;
}

pub trait PrivateKey: Send + Sync + Any {
    fn kem(&self) -> Box<dyn Kem>;
    fn bytes(&self) -> CrateResult<&Seed32>;     // was CrateResult<Vec<u8>>
    fn public_key(&self) -> Box<dyn PublicKey>;
    fn decap(&self, enc: &[u8]) -> CrateResult<crate::SharedSecret>;
}
```

`MlKem768X25519::derive_key_pair` impl bridges the wrapper to the helper:

```rust
fn derive_key_pair(&self, ikm: &KdfBytes) -> CrateResult<Box<dyn PrivateKey>> {
    let suite_id = [KEM_SUITE_PREFIX.as_ref(), &KEM_ID.to_be_bytes()].concat();
    let dk = shake256_labeled_derive(
        &suite_id,
        ikm.expose_secret(),                     // Tier-2: SHAKE absorb takes &[u8]
        KEM_DERIVE_KEY_PAIR_LABEL,
        &[],
        PRIVATE_KEY_SIZE,
    )?;
    dk.with_secret(|bytes| self.new_private_key(bytes))
}
```

`new_private_key(data: &[u8])` stays — callers in this crate route through
`derive_key_pair` (wrapped) or pass parsed-from-disk bytes that came from a
wrapper at the parse boundary. Document the contract in the rustdoc:
*"Treats `data` as secret material. Callers should hand off bytes that came
from a wrapper (`Seed32`, `KdfBytes`, etc.) via a `with_secret` / `expose_secret`
boundary rather than retaining a raw `Vec<u8>`."*

### HPKE Sender/Recipient

```rust
impl Recipient {
    pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> Result<Plaintext, Error>;
    pub fn export(&self, exporter_ctx: &[u8], length: usize) -> Result<KdfBytes, Error>;
}
impl Sender {
    // AEAD output is a crypto primitive result — wrap as AeadCiphertext.
    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Result<AeadCiphertext, Error>;
    pub fn export(&self, exporter_ctx: &[u8], length: usize) -> Result<KdfBytes, Error>;
}
```

`ExportFn` type alias: `Box<dyn Fn(&[u8], u16) -> Result<KdfBytes, Error> + Send + Sync>`.

One-shot helpers are symmetric:

```rust
pub fn open(...) -> Result<Plaintext, Error>;
pub fn seal(...) -> Result<AeadCiphertext, Error>;
```

The one-shot `seal` concatenates the public `enc` bytes (KEM encapsulation,
already a `Vec<u8>` from `PublicKey::encap`) with the AEAD ciphertext, then
wraps the combined wire bytes:

```rust
pub fn seal(pk, kdf, aead, info, aad, plaintext) -> Result<AeadCiphertext, Error> {
    let (enc, mut s) = new_sender(pk, kdf, aead, info)?;
    let ct = s.seal(aad, plaintext)?;
    let mut out = enc;
    ct.with_secret(|c| out.extend_from_slice(c));
    Ok(AeadCiphertext::new(out))
}
```

### Re-exports (`src/lib.rs`)

Add `pub use aliases::{Plaintext, AeadCiphertext, KdfBytes, MlKemSeed64, LabeledInfo};`
to round out the public surface.

### Version

Bump `Cargo.toml` to `version = "0.0.6"` (releases the `0.0.6-dev`
working version — the `-dev` suffix marked work-in-progress). Pre-0.1 experimental cadence
matches `libcrux-ml-kem`.

---

## Phase 3 — `PartialEq` / `Debug` consistency

- `EncapsulationKey::eq`: `self.pk_m.expose_secret() == other.pk_m.expose_secret()
    && self.pk_x == other.pk_x`. Public bytes — `==` is correct.
- `Ciphertext::eq`: same shape on `ct_m`.
- Add manual redacted `Debug` for `DecapsulationKey` (defense in depth even
  though `Seed32`'s `Debug` already redacts).
- Add `Debug` impls for any new public types (`Plaintext`, `Ciphertext` wire
  alias) — secure-gate provides them via the alias macros.

---

## Phase 4 — Tests

Existing `tests/secure_gate_tests.rs`: keep redaction tests, add:

- `DecapsulationKey` Debug redaction
- `Plaintext` (returned from `open`) redaction
- `KdfBytes` (returned from `export`) redaction
- Round-trip: open → `with_secret(|p| p == expected)` instead of `==`

Existing functional tests (`hpke_tests.rs`, `aead_tests.rs`,
`combiner_tests.rs`, `mlkem768x25519_tests.rs`, `derand_tests.rs`,
`determinism_tests.rs`, `kat_tests.rs`, `error_tests.rs`, `kdf_tests.rs`,
`kem_tests.rs`):

- Replace every `let pt = recipient.open(...)?` followed by `assert_eq!(pt, expected)`
  with `recipient.open(...)?.with_secret(|p| assert_eq!(p, expected))`.
- KAT private-key comparisons use `ct_eq` on the wrapper rather than `==` on
  raw bytes.
- KAT random / eseed inputs flow through `Seed32::new_with` / `from(...)` if
  the test currently passes raw `[u8; N]`.

Add a regression test that `Sender::seal` followed by `Recipient::open` on a
mismatched aad fails the `==` check at the AEAD layer (sanity, not a new
property).

---

## Phase 5 — Doc / release

- Update `src/lib.rs` examples to reflect wrapper-returning API.
- Update `README.md` examples (currently call `expose_secret().len()` etc.)
  to prefer `with_secret` and to show the new return types.
- `CHANGELOG.md`: dedicated section under the new version with a one-line
  migration entry per breaking change.
- `cargo doc --no-deps`: verify no broken intradoc links after the trait /
  re-export changes.
- `cargo clippy --workspace --all-features -- -D warnings`.
- `cargo test --workspace --all-features`.
- Verify `panic = "unwind"` still holds in every profile.
- Confirm no new `static` introduces a secret.

---

## PR sequencing

| PR | Scope | Breaking? |
|----|-------|-----------|
| 1 | PR 1.1 (`aead.rs`) + PR 1.2 (`kdf.rs`) + new aliases in `aliases.rs` | No |
| 2 | PR 1.3 + 1.4 (`x25519` / `x448` / `ml_kem` internals) | No |
| 3 | PR 1.5 + 1.6 (`common.rs` `expand_seed`, `mlkem768x25519` internals — wrap `DecapsulationKey.seed`) | No |
| 4 | PR 1.7 (`hpke.rs` exporter capture + slicing; switch `Kdf` to `Arc<dyn Kdf>`) | API ripple from `Box<dyn Kdf>` → `Arc<dyn Kdf>` — minor breakage on the constructor signatures only. May fold into PR 5. |
| 5 | Phase 2 trait + public-API breakage + Phase 3 `PartialEq`/`Debug` | Yes — version bump |
| 6 | Phase 4 test churn (if not folded into the corresponding internal PR) | No |
| 7 | Phase 5 docs + release | No |

PRs 1–3 are independent and could ship in any order. PR 4 depends on PRs 2
and 3 because the `Context` changes assume wrapped exporter secrets. PR 5
depends on PR 4 and is the single breaking-change PR — version bump lives
there.

---

## Open decisions

None. All resolved — see the "Locked decisions" table at the top.

---

## Risks & call-outs

- **`Kdf` trait-object capture in `Context::export`.** Switching to
  `Arc<dyn Kdf>` (DECIDE-4) ripples through every constructor that currently
  takes `Box<dyn Kdf>` — minor surface change but visible. Confirm before
  PR 4.
- **MSRV pin (1.70).** *(Superseded: the workspace moved to MSRV 1.85,
  edition 2024 and secure-gate `main` 0.9.0-rc.9 in `0.2.0-rc.1`. The `half` /
  `unicode-ident` caps described below are gone, and the `Default`-bound
  `into_inner` ceiling in the next bullet no longer exists. Kept as the record
  of what was true during this hardening work.)*
  secure-gate `0.8.0-rc.9`'s manifest declares
  `edition = "2021"`, `rust-version = "1.70"` — matches the workspace
  exactly. The "MSRV 1.85" line in the upstream `lib.rs` doc is stale text,
  not what `cargo check` enforces. The workspace's deliberate version caps
  on `half` (`<2.5`) and `unicode-ident` (`<1.0.23`) keep the transitive
  graph compiling on 1.70. Don't enable secure-gate's `cloneable` /
  `serde-*` features without re-running `cargo check` on the pinned
  toolchain — those features pull additional transitive deps that may
  themselves require a higher MSRV.
- **`into_inner` is gated by `Default` on the inner type.** Discovered in
  PR 2: stdlib only impls `Default for [T; N]` for `N <= 32` on Rust 1.70.
  So `Seed32` / `AeadKey32` / `Nonce12` / `X25519Secret32` / `SharedSecret32`
  can use `into_inner` (Tier-3); `MlKemSeed64` (64), `X448Secret56` (56),
  `ExpandedKeyMaterial96` (96), and the KEM public-key / ciphertext
  wrappers (≥ 800 bytes) cannot. The fallback is the same shape minus the
  `into_inner` call: take the wrapper by value, `with_secret(|bytes| *bytes)`
  at the FFI boundary, wrapper drops at end of fn. Marked at every site
  with `// Tier-2 (forced): [u8; N] lacks Default on MSRV 1.70.`
- **Stack residue at libcrux / x25519-dalek / chacha20poly1305 boundaries.**
  `*r` / `*ct_m` / `*clamped` derefs are unavoidable. Lifetime is one
  statement; the surrounding wrapper drop covers the original. Document each
  with a Tier-2 comment. This is the realistic floor of stack-residue
  protection in safe Rust.
- **`hkdf::Hkdf` `GenericArray` PRK** doesn't zeroize. Lifetime is one
  statement after the rewrite. Mark with a Tier-2 comment; upstream fix is
  out of scope.
- **Test surface.** Every test that currently consumes `open` /
  `bytes` / `export` results breaks on Phase 2. Plan internal PRs first
  (no test churn) so the Phase 2 PR is a clean diff of API + test updates.
- **Downstream** `age-pq-keys` breaks on Phase 2. During development,
  use the workspace path patch (already in `Cargo.toml`); bump the published
  dep after `age-pq-hpke` cuts a release.

---

## Out of scope — `age-pq-keys` (next session)

Tracked in a separate plan to land after this one ships:

1. Migrate consumers of `age-pq-hpke` to the new wrapper API.
2. Audit identity-file I/O — `fs::read_to_string` → `Zeroizing<String>` or
   `Dynamic<String>`; parse buffers wrapped.
3. Audit stanza body buffering — likely large-plaintext `Vec<u8>` chains
   that should be `Dynamic<Vec<u8>>` or streamed.
4. Audit `age-plugin-pq`'s stdio protocol — newline-delimited base64 frames
   that may carry key material.
