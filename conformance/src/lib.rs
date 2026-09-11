//! Host crate for the isolated conformance tests. **Intentionally empty.**
//!
//! Cargo needs a library or binary target for a package to exist, and this
//! package exists only to give `tests/` a home whose dependency graph is
//! separate from the shipped workspace's. Nothing here is compiled into
//! anything that ships — `conformance/` is excluded from the root workspace
//! (see `exclude` in the root `Cargo.toml`) and has its own `Cargo.lock`.
//!
//! That separation is not tidiness. rage's `age` crate and the crates.io
//! `age 0.12` this workspace ships against **cannot resolve in one dependency
//! graph**: their `ml-kem` generations require incompatible exact versions of
//! the pre-release `kem` crate. The full measurement, and what that bounds the
//! tests to proving, is in
//! `docs/design/conformance-workspace-isolation.md`.
//!
//! Put tests in `tests/`, not here.

#![forbid(unsafe_code)]
