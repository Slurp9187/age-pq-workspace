### Revised Instructions for Implementing Superior PQ Recipient in `age-recipient-pq`

Based on our lessons on the codebase (lib.rs, kem.rs, hpke.rs, kdf.rs, aead.rs, combiner.rs, error.rs), the updated `age-plugin-pq` (full HPKE context, multi-file support, native/plugin keygen/convert), official Go pq.go (full HPKE seal/open), and rage x25519.rs (trait impls, generation, parsing, wrap/unwrap, tests), here's the minimum self-contained guide to refactor `age-recipient-pq` into a superior, official-compliant native PQ recipient that works for encrypted-file-vault and is rage-merge-ready:

#### Goal

- Migrate from old concrete `EncapsulationKey` etc. to modern trait-based `XWing768X25519` from kem.rs.
- Use **full HPKE single-shot seal/open** (from hpke.rs) for wrapping/unwrapping (exact RFC 9180 base mode compliance, matching official Go).
- Support multi-file wrapping/unwrapping (seq = file_idx for nonce, matching updated plugin).
- Fix stanza format: args = vec!["mlkem768x25519", base64(enc)].
- Use official HRPs: "age1pq1" (recipient, add "1" if spec finalizes), "AGE-SECRET-KEY-PQ-1" (identity, uppercase, add "1").
- Add keygen-native/plugin modes and convert_native_identities like plugin.
- Mirror rage x25519.rs: clear docs, tests (roundtrip proptest), zeroization, secrecy.
- For encrypted-file-vault: Expose generate_native() for vault keys, wrap/unwrap for file encryption protocol.
- Ensure superior: Full domain separation, postquantum label, no manual AEAD (use hpke seal/open).

#### Step 1: Update Cargo.toml Dependencies

- Depend on `age-hpke-pq` path (latest with kem.rs).
- Keep/add: `age = "0.11"`, `age-core = "0.11"`, `base64 = "0.22"`, `bech32 = "0.9"`, `clap = { version = "4.5", features = ["derive"] }`, `chacha20poly1305 = "0.10"`, `rand = { version = "0.9", features = ["std", "os_rng"] }`, `secrecy = "0.8"`, `time = { version = "0.3", features = ["formatting"] }`, `zeroize = "1.8"`.
- For tests: `proptest = "1"`, `tempfile = "3"`.

#### Step 2: Update Imports in pq.rs

- Remove old `use pq_xwing_hpke::xwing768x25519::{...}`.
- Add `use pq_xwing_hpke::{kem::{Kem, XWing768X25519, PrivateKey, PublicKey}, hpke::{seal, open, compute_nonce}}`.
- Add `use pq_xwing_hpke::{kdf::new_kdf, aead::new_aead}`.
- Keep hpke_pq.rs (update to full context below).
- Add `use clap::{Parser, CommandFactory}` for keygen/convert CLI if adding.
- Add `use time::{OffsetDateTime, format_description::well_known::Rfc3339}` for created timestamp.

#### Step 3: Update hpke_pq.rs to Full Official HPKE Base Mode

- Keep constants: KEM_ID 0x647a, KDF_ID 0x0001, AEAD_ID 0x0003, MODE 0.
- Update `suite_id()`: return b"HPKE" + be_bytes for IDs.
- Update `derive_key_and_nonce(shared_secret, info)`: full context as in updated plugin hpke_pq.rs (psk_id_hash on empty, info_hash on info = pq_label, ks_context = mode + psk_id_hash + info_hash, secret = labeled_extract(shared_secret, "secret", ""), key/ base_nonce = labeled_expand("key"/"base_nonce", ks_context)).
- Keep compute_nonce (XOR seq be_bytes into nonce[4..12]).
- Remove map errors if not used; add for age Encrypt/DecryptError.

#### Step 4: Update HybridRecipient

- Struct: pub struct HybridRecipient { pub_key: Box<dyn PublicKey> }.
- Generate: kem = XWing768X25519; sk = kem.generate_key()?; pk = sk.public_key(); (Self { pub_key: pk }, HybridIdentity { seed: SecretBox::new(Box::new(sk.bytes()?)) }).
- Parse(s): decode bech32 "age1pq1", kem.new_public_key(bytes)?.
- to_string: bech32 "age1pq1" + pub_key.bytes().to_base32().
- Add from_str impl.

#### Step 5: Update wrap_file_key

- kem = XWing768X25519.
- kdf = new_kdf(KDF_ID)?; aead = new_aead(AEAD_ID)?.
- (enc, sender) = hpke::new_sender(pub_key, kdf, aead, pq_label)?.
- wrapped = sender.seal(&[], file_key.expose_secret())?.
- base64_enc = BASE64_STANDARD_NO_PAD.encode(&enc).
- Stanza: tag = "mlkem768x25519", args = vec!["mlkem768x25519", base64_enc], body = wrapped.
- Labels: HashSet "postquantum".
- For multi-file: loop over file_keys, seq = i, but since age::Recipient trait is single file_key, keep single; note for vault if multi.

#### Step 6: Update HybridIdentity

- Struct: pub struct HybridIdentity { seed: SecretBox<[u8;32]> }.
- Parse(s): decode "AGE-SECRET-KEY-PQ-1" (uppercase), seed = bytes.try_into()?.
- to_string: bech32 "AGE-SECRET-KEY-PQ-1" + seed.to_base32(), uppercase.
- unwrap_stanza: if tag != "mlkem768x25519" or args.len() != 2 or args[0] != "mlkem768x25519" return None; enc = BASE64 decode args[1]; kem = XWing768X25519; sk = kem.new_private_key(seed)?; kdf = new_kdf(KDF_ID)?; aead = new_aead(AEAD_ID)?; ct = [enc + body]; file_key_bytes = open(sk, kdf, aead, pq_label, ct)?; FileKey from bytes.
- unwrap_stanzas: iter find_map unwrap_stanza.
- Add to_public(): kem.new_private_key(seed)?.public_key() → HybridRecipient.

#### Step 7: Add Plugin/Convert Features

- Add keygen_native: generate seed, sk, pk; format "# created: ... \n# recipient: ...\n identity".
- Add keygen_plugin: same, but HRP "AGE-PLUGIN-PQ-".
- Add convert_native_identities(): read stdin lines, parse "AGE-SECRET-KEY-PQ-1", re-encode "AGE-PLUGIN-PQ-".
- Add CLI with clap: -keygen, -keygen-native, -identity, -o output.

#### Step 8: Tests

- Add roundtrip like rage: proptest sk_bytes, wrap file_key, unwrap, assert eq.
- Add interop: manual encrypt/decrypt sample.

#### Step 9: Integration with encrypted-file-vault

- In vault: HybridIdentity::generate_native(), store identity.to_string() securely.
- Encrypt: HybridRecipient.parse(pub_str)?, wrap file_key, encrypt payload with HKDF(file_key, "payload").
- Decrypt: HybridIdentity.parse(sec_str)?, unwrap stanza to file_key, decrypt payload.

This creates a superior compliant implementation — rage can integrate with minimal tweaks, vault gets PQ encryption. Debug format/parse errors first.
