# age-pq-workspace

Post-quantum hybrid encryption crates for [age](https://age-encryption.org) /
[rage](https://github.com/str4d/rage), combining ML-KEM-768 with X25519.

**Provenance.** These crates were written for the **encrypted-file-vault**
project and are **not published to crates.io** (`publish = false` is set
workspace-wide and enforced). They implement public specifications — RFC 9180,
the `draft-ietf-hpke-pq` line, and the [C2SP age format](https://c2sp.org/age)
— and contain nothing vault-specific, so they are usable independently.
Consume them as a git dependency pinned to a tag or exact revision. See
*Specification* below for which revision was checked where.

`age-plugin-pq` is the piece most likely to be useful on its own: it works with
**any** age implementation that supports the plugin protocol, including the Go
`age` CLI, not just this workspace.

> **Warning** — These crates have not been independently audited. Use at your
> own risk and evaluate the security properties carefully before deploying in
> production.

## Crates

| Crate | Description |
|---|---|
| [`age-pq-hpke`](age-pq-hpke/) | X-Wing hybrid KEM (ML-KEM-768 + X25519) with full HPKE support. Uses formally verified `libcrux-ml-kem`, constant-time operations, and automatic secret zeroization. |
| [`age-pq-keys`](age-pq-keys/) | age-compatible `HybridRecipient` / `HybridIdentity` types — generate, serialize, parse, encrypt, and decrypt with post-quantum keys. |
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

These crates are not published on crates.io, and they live in **one repository** —
the per-crate repos they once had are archived. Point every dependency at the
workspace and pin a single tag or revision:

```toml
[dependencies]
age-pq-hpke = { git = "https://github.com/Slurp9187/age-pq-workspace", tag = "v0.1.0-rc.1" }
age-pq-keys = { git = "https://github.com/Slurp9187/age-pq-workspace", tag = "v0.1.0-rc.1" }
```

The crates share one version and ship under one tag: `age-pq-keys` and
`age-plugin-pq` depend on `age-pq-hpke` **by path**, so a coherent set is
whatever a single tag points at. Mixing tags between them is not a supported
combination.

**Use a tag that exists.** `git tag -l` is the authority; today that is
`v0.1.0-rc.1`, the frozen MSRV-1.70 line. The `0.2` line (MSRV 1.85, this
branch) is untagged until its own release candidate ships — pin a revision if
you need it before then. No `release/0.*` branch is published yet either; see
[`docs/plans/msrv-1.85-cohort-bump.md`](docs/plans/msrv-1.85-cohort-bump.md)
(DECIDE-13) for how the `0.1` / `0.2` lines split and when a branch appears.

## Requirements

- **Rust 1.85+** (MSRV; edition 2024, Cargo resolver 3). The MSRV-1.70 line is
  frozen at the `v0.1.0-rc.1` tag.
- age CLI **v1.3.0+** for native PQ stanza support in CLI interop tests. Those
  tests are `#[ignore]`d, so an ordinary `cargo test` never needs the binary;
  when you *do* ask for them with `--include-ignored` and it is missing or too
  old, they **panic rather than skip** — see *Running the tests* below.

## Workspace layout

```
age-pq-workspace/
├── Cargo.toml          # workspace root (shared metadata, deps, lints, profiles)
├── Cargo.lock          # authoritative lockfile
├── .gitattributes      # line-ending rules; test fixtures marked binary
├── age-pq-hpke/        # HPKE + KEM core
├── age-pq-keys/   # age recipient / identity library
└── age-plugin-pq/      # age plugin binary
```

### Workspace conventions

- **One lockfile** — `Cargo.lock` lives at the workspace root; per-crate lockfiles are not used.
- **Path dependencies between members** — `age-pq-keys` and `age-plugin-pq` depend on
  `age-pq-hpke` by path, so cross-crate edits are tested immediately and the root
  `Cargo.toml` carries no `[patch]` table at all.
- **Shared metadata** — `rust-version`, `edition`, `license`, `repository`, `authors`, etc.
  are inherited from `[workspace.package]`.
- **Shared dependencies** — `secure-gate`, `clap`, `proptest`, `tempfile` and the capped
  `time` are declared once in `[workspace.dependencies]`.
- **Shared lints** — `[workspace.lints.rust]` only: `unsafe_code = "forbid"`,
  `unreachable_pub`, `unused_qualifications`, `unused_lifetimes`. There is no
  `[workspace.lints.clippy]` table — the clippy cast lints fire on ~19 `usize as u16`
  RFC 9180 length prefixes and are deferred to their own change rather than
  blanket-allowed. **The tables are inert without `[lints] workspace = true` in every
  member manifest**, which is what the pre-1.70 version of them lacked; all three
  members now carry it.
- **Build profiles** — `opt-level = 2` in dev (crypto math is unusably slow at O0);
  debug symbols retained in bench for profiling.

## Running the tests

```sh
cargo test --workspace
```

Interop tests that shell out to the real Go `age` CLI are `#[ignore]`d, so the
command above reports them as *ignored* rather than pretending they passed. To
run them:

```sh
./scripts/install-age.sh ~/.local/bin      # pinned version, sha256-verified
cargo test --workspace -- --include-ignored
```

age **1.3.0 or newer** is required — that is the first release with native
post-quantum support, and Ubuntu packages something far older. If the binary is
missing when you ask for these tests, they fail rather than skip.

Everything else, including the C2SP CCTV conformance vectors, runs with no
external binary.

## MSRV policy

MSRV is **Rust 1.85** as of `0.2.0-rc.1` (edition 2024, Cargo resolver 3). The
1.70 line is frozen at the `v0.1.0-rc.1` tag and is not maintained.

Exactly **one** upper-bound cap survives the bump, and it is not MSRV
scaffolding for a floor we have already left — it is a live constraint:

| Dep | Cap | Reason |
|---|---|---|
| `time` | `>=0.3.40, <0.3.46` | `time 0.3.46+` requires rustc **1.88**, above this workspace's 1.85 floor (verified against the crates.io index: 0.3.45 declares 1.83, 0.3.46 declares 1.88) |

Resolver 3 prefers an MSRV-compatible version, but that is only a preference —
`--ignore-rust-version`, or a consumer resolving this tree on a newer toolchain,
walks straight past it. A manifest cap is a fact, so the cap stays. It is
declared in `[workspace.dependencies]`; `age-plugin-pq` **inherits** that entry
rather than declaring `time` itself, which is what makes the cap govern the
whole graph.

The `half` and `unicode-ident` caps and the `getrandom` / `uuid` lockfile-only
pins that this section used to document are **gone**, removed with the 1.85 bump
(`half` left the graph entirely along with secure-gate 0.8). Do not restore
them: `getrandom` 0.3.1 is a version `rand_core` 0.10 no longer uses.

The lesson those pins taught does survive, and it is worth keeping: their
failure mode — Cargo unable to *parse* an edition-2024 manifest for a
WASI-gated crate it would never build — is invisible to `check` / `build` /
`test` / `clippy`, so a green CI run proves nothing about it. Verify anything
that moves the WASI end of the graph with an all-target fetch, not a test run:

```sh
cargo fetch --target wasm32-wasip2 --target x86_64-unknown-linux-gnu --target x86_64-pc-windows-msvc
```

## Specification

- X-Wing KEM: [draft-connolly-cfrg-xwing-kem-10](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)
- HPKE-PQ: [draft-ietf-hpke-pq-05](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/)
- Reference: [filippo.io/hpke-pq](https://filippo.io/hpke-pq), mirrored in
  `age-pq-hpke/docs/hpke-pq.md` — the mirror cites `-03`/`hybrid-kems-07`, which
  is what upstream still cites; it is byte-identical to current upstream.

The two revisions above are the ones checked directly, and only on the
invariants that would break interop (KEM id, `Nenc`/`Npk`, combiner input order,
`XWingLabel`). The full 03 → 05 delta, and where every test corpus came from,
are in [`docs/design/normative-provenance.md`](docs/design/normative-provenance.md);
the work is tracked by issue #25 in
[`docs/plans/normative-source-refresh.md`](docs/plans/normative-source-refresh.md).
The interop-critical sections are byte-identical or unchanged in substance, and
the affected invariants above are confirmed unchanged. The shipped suite is also
anchored to published vectors directly — `draft-ietf-hpke-pq-05` Appendices A.5
and A.12, in `age-pq-hpke/tests/hpke_pq_draft_vectors.rs`.

## Security

- Hybrid post-quantum design: ML-KEM-768 (NIST-standardized) + X25519.
- The `mlkem768x25519` KEM path uses formally verified ML-KEM via
  `libcrux-ml-kem` (hax/F*). Note that `age` 0.12 links RustCrypto `ml-kem` for
  its own, unrelated `mlkem768p256tag` recipient; that code is present in
  `age-pq-keys`'s dependency graph but is never on our path.
- Constant-time validation for X25519 keys and ciphertexts via `secure-gate::ConstantTimeEq`.
- Secrets wrapped in `secure-gate::Fixed` / `secure-gate::Dynamic` with redacted `Debug` and
  automatic `ZeroizeOnDrop`.
- Cryptographic dependencies pinned for reproducibility.

## License

MIT OR Apache-2.0
