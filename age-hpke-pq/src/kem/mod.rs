//! Hybrid KEM modules for the X-Wing construction.
//!
//! This module groups the shared KEM traits and constants, primitive-specific
//! helper modules, and the concrete ML-KEM-768 + X25519 implementation used by
//! this crate.
//!
//! The split is intentionally narrow:
//! - `common` holds shared KEM traits, constants, and hybrid helpers.
//! - `ml_kem` holds ML-KEM primitive wrappers by parameter set.
//! - `x25519` holds X25519 primitive wrappers.
//! - `mlkem768x25519` owns the hybrid wire format and orchestration logic.
//!
//! Future variants can add new orchestration modules without changing the
//! primitive/helper boundaries.

pub mod combiner;
pub mod common;
pub(crate) mod ml_kem;
pub mod mlkem768x25519;
pub(crate) mod x448;
pub(crate) mod x25519;

pub use common::*;
pub use mlkem768x25519::MlKem768X25519;
