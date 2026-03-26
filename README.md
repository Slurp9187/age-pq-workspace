# age-hpke-pq

Rust implementation of the X-Wing hybrid post-quantum KEM (ML-KEM-768 + X25519) with full HPKE support.

## Features

- Hybrid PQ/classical security (ML-KEM-768 + X25519)
- Uses formally verified `libcrux-ml-kem`
- Constant-time operations
- Sensitive data zeroized on drop
- Optional secure wrapper aliases (`Seed32`, `AeadKey32`, `Nonce12`) re-exported for auditable key/nonce handling

## Installation

Experimental project: not currently published on crates.io. Use a pinned GitHub milestone tag (or exact `rev`) to avoid accidental API drift.

```toml
[dependencies]
age-hpke-pq = { git = "https://github.com/Slurp9187/age-hpke-pq", tag = "v0.0.5" } # replace with your milestone tag
```

## Usage

### Requirements

- Rust 1.70 or newer (MSRV).

### Secure Aliases (optional)

```rust
use age_hpke_pq::{Seed32, RevealSecret};

let seed = Seed32::from_random();
let first_byte = seed.with_secret(|bytes| bytes[0]);
assert!(first_byte <= 255);
```

### KEM

```rust
use age_hpke_pq::{MlKem768X25519, kem::Kem};

let kem = MlKem768X25519;
let sk = kem.generate_key().unwrap();
let pk = sk.public_key();

// Derive from seed (optional)
let ikm = [0u8; 32];
let sk_derived = kem.derive_key_pair(&ikm).unwrap();

let (enc, ss) = pk.encap(None).unwrap();       // sender (None = random)
let ss_recv = sk.decap(&enc).unwrap();         // receiver
assert_eq!(ss, ss_recv);
```

### HPKE

```rust
use age_hpke_pq::{
    MlKem768X25519, kem::Kem, new_sender, new_recipient,
    ChaCha20Poly1305Aead, HkdfSha256, new_aead, new_kdf
};

let kem = MlKem768X25519;
let sk = kem.generate_key().unwrap();
let pk = sk.public_key();

let info = b"session info";
let (enc, mut sender) = new_sender(
    pk,
    Box::new(HkdfSha256),
    Box::new(ChaCha20Poly1305Aead),
    info,
).unwrap();

let ct = sender.seal(b"", b"secret message").unwrap();

let mut recipient = new_recipient(
    sk,
    &enc,
    new_kdf(0x0001).unwrap(),      // HKDF-SHA256
    new_aead(0x0003).unwrap(),     // ChaCha20Poly1305
    info,
).unwrap();

let pt = recipient.open(b"", &ct).unwrap();
```

## Supported Algorithm

- `MlKem768X25519` — ML-KEM-768 + X25519 (draft-compliant)

## Specification

Implements X-Wing per [draft-connolly-cfrg-xwing-kem-09](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/).

Closely follows the reference implementation details at [filippo.io/hpke-pq](https://filippo.io/hpke-pq).

## License

MIT OR Apache-2.0
