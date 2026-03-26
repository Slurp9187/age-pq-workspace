# age-pq-workspace

Post-quantum hybrid encryption crates for [age](https://age-encryption.org) /
[rage](https://github.com/str4d/rage), combining ML-KEM-768 with X25519.

> **Warning** — These crates have not been independently audited. Use at your
> own risk and evaluate the security properties carefully before deploying in
> production.

## Crates

| Crate | Description |
|---|---|
| [`age-hpke-pq`](age-hpke-pq/) | X-Wing hybrid KEM (ML-KEM-768 + X25519) with full HPKE support. Uses formally verified `libcrux-ml-kem`, constant-time operations, and automatic secret zeroization. |
| [`age-recipient-pq`](age-recipient-pq/) | age-compatible `HybridRecipient` / `HybridIdentity` types — generate, serialize, parse, encrypt, and decrypt with post-quantum keys. |
| [`age-plugin-pq`](age-plugin-pq/) | age plugin binary (`age-plugin-pq`) implementing the v1 plugin protocol: `--keygen`, `--identity`, and state-machine mode for the age CLI. |

## Quick start

```bash
# Clone
git clone https://github.com/Slurp9187/age-pq-workspace.git
cd age-pq-workspace

# Build (all members)
cargo build

# Test (all members)
cargo test --workspace
```

### Using as a dependency

These crates are not published on crates.io. Pin to a tag or exact revision:

```toml
[dependencies]
age-hpke-pq      = { git = "https://github.com/Slurp9187/age-hpke-pq",      tag = "v0.0.5" }
age-recipient-pq = { git = "https://github.com/Slurp9187/age-recipient-pq",  tag = "v0.0.4" }
```

## Requirements

- **Rust 1.70+** (MSRV, matching `age 0.11.2`)
- age CLI **v1.3.0+** for native PQ stanza support in CLI interop tests
  (older versions require the [age-go PQ plugin](https://github.com/FiloSottile/age);
  tests skip gracefully when the CLI is unavailable)

## Workspace layout

```
age-pq-workspace/
├── Cargo.toml          # workspace root (shared metadata, deps, lints, profiles)
├── Cargo.lock          # authoritative lockfile
├── .gitattributes      # line-ending rules; test fixtures marked binary
├── age-hpke-pq/        # HPKE + KEM core
├── age-recipient-pq/   # age recipient / identity library
└── age-plugin-pq/      # age plugin binary
```

### Workspace conventions

- **One lockfile** — `Cargo.lock` lives at the workspace root; per-crate lockfiles are not used.
- **`[patch]` table** — the root `Cargo.toml` redirects git dependencies between members
  to local paths, so cross-crate edits are tested immediately without publishing.
- **Shared metadata** — `rust-version`, `edition`, `license`, `repository`, `authors`, etc.
  are inherited from `[workspace.package]`.
- **Shared dependencies** — `secure-gate`, `clap`, and MSRV-cap phantom deps (`half`, `unicode-ident`)
  are declared once in `[workspace.dependencies]`.
- **Shared lints** — `[workspace.lints.rust]` and `[workspace.lints.clippy]` enforce a
  consistent lint baseline (RustCrypto/KEMs style; `unsafe_code = "deny"`).
- **Build profiles** — `opt-level = 2` in dev (crypto math is unusably slow at O0);
  debug symbols retained in bench for profiling.

## MSRV policy

MSRV is **Rust 1.70**, matching `age 0.11.2`. Two transitive dependencies require
upper-bound caps to stay within MSRV:

| Dep | Cap | Reason |
|---|---|---|
| `half` | `< 2.5` | `half 2.5.0+` requires rustc 1.81 (transitive via `secure-gate`) |
| `unicode-ident` | `< 1.0.23` | `unicode-ident 1.0.23+` requires rustc 1.71 |

These caps are declared as phantom `[workspace.dependencies]` so `cargo update` respects
them automatically.

## Specification

- X-Wing KEM: [draft-connolly-cfrg-xwing-kem-09](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)
- HPKE-PQ: [draft-ietf-hpke-pq-03](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/)
- Reference: [filippo.io/hpke-pq](https://filippo.io/hpke-pq)

## Security

- Hybrid post-quantum design: ML-KEM-768 (NIST-standardized) + X25519.
- Formally verified ML-KEM via `libcrux-ml-kem`.
- Constant-time validation for X25519 keys and ciphertexts via `secure-gate::ConstantTimeEq`.
- Secrets wrapped in `secure-gate::Fixed` / `secure-gate::Dynamic` with redacted `Debug` and
  automatic `ZeroizeOnDrop`.
- Cryptographic dependencies pinned for reproducibility.

## License

MIT OR Apache-2.0
