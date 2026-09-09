# age-pq-keys

⚠️ **WARNING**

This crate has not been independently reviewed and audited by the `age` + `rage` maintainers. Use at your own risk, and consider its security properties carefully.

The key layer for post-quantum hybrid encryption with age: recipient **and**
identity types, keypair generation, the bech32 key formats and their HRPs, and
the `mlkem768x25519` stanza wire format together with its validation.

> **Provenance** — written for the **encrypted-file-vault** project and **not
> published to crates.io**. It implements the public
> [C2SP age format](https://c2sp.org/age) and contains nothing vault-specific,
> so it stands on its own; use it as a git dependency pinned to a tag or exact
> revision.

## Compatibility

- Fully compatible with the age file format. Age CLI v1.3.0+ natively supports ML-KEM-768+X25519 stanzas without a plugin. Versions < v1.3.0 require the age-go plugin for backward compatibility (available from the age repository at https://github.com/FiloSottile/age/blob/0293aca1d732e96b06ac2decb098cc2a6c9a14e5/extra/age-plugin-pq/plugin-pq.go; pre-built binaries may be found through package managers or OS distributions under 'age-plugin-pq').
- Designed for Rage integration without external dependencies.

## Overview

This crate implements a post-quantum hybrid recipient and identity for the [age](https://github.com/str4d/rage) encryption tool. It combines ML-KEM-768 with X25519 for enhanced security against quantum attacks while maintaining compatibility with the age file format.

The library is designed for potential integration into the official `rage` CLI and libraries, using the `secrecy` crate for secret handling to align with Rage's conventions.
## Installation

Since this crate is for development use only and not published on crates.io, use it as a Git dependency.

Add the following to your `Cargo.toml`:

```toml
[dependencies]
age-pq-keys = { git = "https://github.com/Slurp9187/age-pq-keys" }
```

Then, run `cargo build` to include it.

## Usage

Generate a new recipient and identity pair:

```rust,no_run
use age_pq_keys::{HybridRecipient, HybridIdentity};

let (recipient, identity) = HybridRecipient::generate().unwrap();
println!("Recipient: {}", recipient.to_string());
println!("Identity: {}", identity.to_string());
```

Parse from string:

```rust,no_run
use std::str::FromStr;

let recipient = HybridRecipient::from_str("age1pq1...").unwrap();
let identity = HybridIdentity::from_str("AGE-SECRET-KEY-PQ-1...").unwrap();
```

## Security

- Post-quantum security via ML-KEM-768 (NIST standardized).
- Hybrid design with X25519 for efficiency.
- Secrets are zeroized using the `secrecy` crate.

## Testing

The test suite includes comprehensive coverage for key functionality:

- **Unit tests** (`hybrid_recipient_tests.rs`): Verify PQ key generation, serialization, parsing, and basic encrypt/decrypt roundtrips without external dependencies.
- **Stanza tests** (`pq_stanza_tests.rs`): Test low-level PQ stanza wrapping/unwrapping, error handling for malformed inputs, and multi-recipient encryption.
- **CLI interop tests** (`age_cli_interop_tests.rs`, `roundtrip_tests.rs`): Ensure full compatibility with the age CLI by encrypting with the library and decrypting with the CLI (and vice versa). These tests require the age CLI (>= v1.3.0 for native PQ support; < v1.3.0 requires age-go plugin) to be installed; if unavailable, the tests skip gracefully with a clear message.
- **Test data** (`tests/data/`): Contains sample files like `lorem.txt` (plaintext), `lorem.txt.age` (CLI-encrypted), and PQ keys for interop verification.

Run tests with `cargo test`. For CLI interop tests, use `cargo test -- --nocapture` to see skip messages if the age CLI is unavailable or incompatible.

## License

Licensed under Apache License 2.0 or MIT License.

## Contributing

Contributions are welcome. Please ensure code follows Rust best practices, includes appropriate documentation, and attempts to maintain compatibility with `age` and `rage`.
