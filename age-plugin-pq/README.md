# age-plugin-pq

An [age](https://age-encryption.org) plugin providing **post-quantum hybrid**
recipients: ML-KEM-768 combined with X25519, in the `mlkem768x25519` format
specified at [c2sp.org/age](https://c2sp.org/age).

It speaks the age plugin protocol, so it works with **any** age implementation
that supports plugins — the Go `age` CLI, `rage`, or your own — not just the
crates in this workspace.

> **Provenance** — developed alongside the **encrypted-file-vault** project and
> **not published to crates.io**. It implements a public specification and
> contains nothing vault-specific. Of the three crates here, this is the one
> most likely to be useful on its own.

> **Warning** — not independently audited. Evaluate the security properties
> yourself before relying on it.

## Do you actually need this?

Possibly not. **age v1.3.0+ and rage both support `mlkem768x25519` natively**,
with no plugin required. This plugin is worth installing when:

- you are on age **older than 1.3**, or
- you want post-quantum recipients from a tool that supports plugins but has no
  native support of its own.

## Install

```sh
cargo install --git https://github.com/Slurp9187/age-pq-workspace age-plugin-pq
```

The binary **must** be named `age-plugin-pq` and be on your `PATH`. age locates
plugins by constructing `age-plugin-<name>` from the identity's HRP
(`AGE-PLUGIN-PQ-` → `pq`); a renamed binary is simply not found.

## Generate a key pair

```sh
# Plugin format — identity is AGE-PLUGIN-PQ-1..., needs this binary to decrypt
age-plugin-pq --keygen -o key.txt

# Native format — identity is AGE-SECRET-KEY-PQ-1..., decryptable by
# age >= 1.3 and rage with no plugin installed
age-plugin-pq --keygen-native -o key.txt
```

Both produce the same recipient (`age1pq1...`); only the identity encoding
differs. Prefer `--keygen-native` unless you specifically need the plugin form —
those keys keep working if you later drop the plugin.

`--identity` converts native identities on stdin into plugin-format identities.

## Use

```sh
age -r age1pq1... -o secret.age secret.txt
age -d -i key.txt -o secret.txt secret.age
```

## Compatibility

| | |
|---|---|
| Stanza tag | `mlkem768x25519` |
| KEM | MLKEM768-X25519, id `0x647a` (`draft-ietf-hpke-pq`) |
| KDF / AEAD | HKDF-SHA256 / ChaCha20-Poly1305 |
| Recipient HRP | `age1pq` |
| Identity HRPs | `AGE-PLUGIN-PQ-` (plugin), `AGE-SECRET-KEY-PQ-` (native) |

Keys and files are byte-compatible with age v1.3+ and rage: a recipient
generated here is accepted by both, and files they produce decrypt here.
Verified against the Go age CLI and the C2SP CCTV test vectors.

## License

Same terms as the rest of the workspace — see the repository root.
