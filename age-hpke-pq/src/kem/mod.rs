//! KEM module providing X-Wing hybrid key encapsulation mechanisms.
//!
//! This module contains the trait definitions and implementations for
//! various X-Wing KEM variants combining ML-KEM with X25519/X448.

pub mod combiner;
pub mod common;
pub(crate) mod ml_kem;
pub mod mlkem768x25519;
pub(crate) mod x25519;
// Placeholder for future variants:

// Re-export everything from common
pub use common::*;

pub use mlkem768x25519::MlKem768X25519;

// Future re-exports:
