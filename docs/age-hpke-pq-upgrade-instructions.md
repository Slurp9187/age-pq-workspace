### Complete Revised Instructions for Upgrading `age-hpke-pq` for Extensible ML-KEM Variants

These instructions are self-contained for implementation in Cursor or Zed IDE, based on our full codebase lessons (lib.rs, kem.rs, hpke.rs, kdf.rs, aead.rs, combiner.rs, error.rs). The goal is to make adding new X-Wing variants (e.g., ML-KEM-1024 + X25519, ML-KEM-1024 + X448) **trivial, clean, and scalable** while keeping the crate secure, draft-compliant, and aligned with [age](https://github.com/FiloSottile/age) naming.

#### Key Decisions

- **Crate Name**: `age-hpke-pq` (Rust package / GitHub repo name; import as `age_hpke_pq`). Describes HPKE with post-quantum KEM in the age ecosystem.
- **Variant Naming**: Rename current `XWing768X25519` → `MlKem768X25519` (matches official age tag "mlkem768x25519", clearer for users/rage).
  - Future: `MlKem512X25519`, `MlKem1024X25519`, `MlKem1024X448`.
  - Keep "X-Wing" in docs/crate description for draft reference.
- **File Naming**: Smashed style — `mlkem768x25519.rs` (matches official tag, readable, no underscore clutter). Rust precedent for compound identifiers.
- **Structure**: New `src/kem/` directory for modularity.

#### Step 1: Update Cargo.toml

- Keep dependencies (libcrux-ml-kem = "0.0.3", x25519-dalek, etc.).
- Add x448 = "0.6.0" if planning X448 variant soon (feature-gated later).
- Version bump to 0.2.0 for refactor.

#### Step 2: Create src/kem/ Directory Structure

```
src/kem/
├── mod.rs                     // Facade: re-exports traits, variants, shared
├── common.rs                  // Shared logic (seed expansion, clamping, helpers)
├── mlkem768x25519.rs          // Current variant (renamed)
├── mlkem1024x25519.rs         // Future placeholder
└── mlkem1024x448.rs           // Future placeholder
```

#### Step 3: Implement kem/common.rs

Move/create shared code:

- `shake256_labeled_derive`
- `x25519_new_private_key` (clamping, validation)
- Seed expansion logic (for generate_key/derive_key_pair)
- Testing randomness handling (consume chunks)
- Validation helpers (key sizes, all-zero rejection)
- Re-export traits: `pub trait Kem { ... }`, `pub trait PublicKey { ... }`, `pub trait PrivateKey { ... }`, `pub type SharedSecret = [u8; 32];`

#### Step 4: Implement kem/mlkem768x25519.rs

- Rename struct: `pub struct MlKem768X25519;`
- Move constants: KEM_ID = 0x647a, PUBLIC_KEY_SIZE = 1216, ENC_SIZE = 1120, etc.
- Impl Kem for MlKem768X25519:
  - Use libcrux_ml_kem::mlkem768
  - generate_key/new_private_key/derive_key_pair → use common.rs expansion
  - new_public_key → parse + validate
  - encap/decap → use common testing randomness + combiner
- Impl PublicKey/PrivateKey structs (or keep inline if simple).

#### Step 5: Implement kem/mod.rs (Facade)

```rust
pub mod common;
pub mod mlkem768x25519;
// pub mod mlkem1024x25519;
// pub mod mlkem1024x448;

pub use common::*;
pub use mlkem768x25519::MlKem768X25519;

// Re-export core
pub use common::{Kem, PrivateKey, PublicKey, SharedSecret};

// Future re-exports:
// pub use mlkem1024x25519::MlKem1024X25519;
// pub use mlkem1024x448::MlKem1024X448;
```

#### Step 6: Update Root src/lib.rs

- Change `pub mod kem;` → keep, but update re-exports:
  ```rust
  pub use kem::{
      Kem, PrivateKey, PublicKey, SharedSecret,
      MlKem768X25519,
      // MlKem1024X25519,
      // MlKem1024X448,
  };
  ```
- Update docs: Emphasize X-Wing draft, age compatibility, extensibility.
- Keep other re-exports (hpke::seal/open, etc.).

#### Step 7: Adding New Variants (Template for mlkem1024x25519.rs)

1. Add file `src/kem/mlkem1024x25519.rs`.
2. Imports: libcrux_ml_kem::mlkem1024 (sizes: PK 1568, CT 1568, SK ~3200).
3. Struct `pub struct MlKem1024X25519;`
4. Constants: KEM_ID same or new if draft assigns, PUBLIC_KEY_SIZE = 1568 + 32, etc.
5. Impl Kem using common.rs (update sizes, mlkem1024 functions).
6. Reuse combiner (works unchanged).
7. Add `pub mod mlkem1024x25519;` in kem/mod.rs.
8. Re-export in kem/mod.rs and lib.rs.

For X448:

- Add x448 dep.
- New file mlkem1024x448.rs.
- Update clamping/DH in common.rs if needed.
- Constants: CURVE_POINT_SIZE = 56, etc.

#### Step 8: General Cleanup & Prep

- Tests: Move to kem/tests/, add variant-specific (use testing_randomness).
- Features: Add optional "mlkem1024" feature to gate heavy variants (#[cfg(feature = "mlkem1024")]).
- Docs: Cargo.toml keywords "xwing", "ml-kem", "post-quantum", "hpke".
- Publish prep: Version 0.2.0, examples for variants.

Implement rename + current variant move first — then adding 1024 is 10-15 minutes. This makes the crate **highly extensible** — rage/age-ready for all levels.
