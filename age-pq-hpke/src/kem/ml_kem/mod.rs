//! ML-KEM primitive helpers grouped by parameter set.
//!
//! The default hybrid implementation uses `mlkem768`, and this module
//! re-exports that variant so existing callers can continue importing
//! `super::ml_kem::*` without knowing about the internal submodule split.
//!
//! Additional parameter sets live in their own submodules behind feature gates
//! so future variants can be added without mixing multiple byte sizes and type
//! families into one file.

// Current production variant used by the hybrid orchestration module.
pub(crate) mod mlkem768;
// Optional lower-security / faster variant, not yet wired into a hybrid KEM.
#[cfg(feature = "mlkem512")]
pub(crate) mod mlkem512;
// Optional higher-security variant, not yet wired into a hybrid KEM.
#[cfg(feature = "mlkem1024")]
pub(crate) mod mlkem1024;

// Preserve the pre-split import surface for the current ML-KEM-768 helpers.
pub(crate) use mlkem768::*;
