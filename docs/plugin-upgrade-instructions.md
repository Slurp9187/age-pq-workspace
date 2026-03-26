### Full Instructions for Fixing/Upgrading `age-plugin-pq`

Based on our lessons on the codebase (pq-xwing-hpke with kem.rs/hpke.rs full HPKE, official Go pq.go using hpke.Seal/Open, updated plugin with full context/multi-file, and rage x25519.rs style), the official `age-plugin` crate API (v0.6.1 with PluginHandler, run_state_machine, IdentityPluginV1/RecipientPluginV1, error enums, callbacks), and the dummy "unencrypted" rage example (handlers, main with clap, wrap/unwrap dummies), here's the minimum self-contained guide to upgrade `age-plugin-pq` into a superior, compliant bridge plugin matching the latest code:

#### Goal
- Keep as compatibility bridge for pre-v1.3.0 age/rage clients.
- Switch to modern `kem.rs` trait-based API (XWing768X25519, Box<dyn PublicKey/PrivateKey>).
- Use **full HPKE base mode seal/open** (from hpke.rs) for wrap/unwrap (simpler, exact spec, superior to manual derivation).
- Remove manual AEAD/derivation in hpke_pq.rs (unneeded with full HPKE).
- Fix stanza: args = vec!["mlkem768x25519", base64(enc)] (matching official).
- Support multi-file (seq = file_idx for nonce in manual fallback, but HPKE sender handles internally).
- Update HRPs to official ("age1pq1" recipient, "AGE-SECRET-KEY-PQ-1" native, "AGE-PLUGIN-PQ-1" plugin).
- Keep keygen/convert CLI, add native mode.
- Ensure zeroization, labels "postquantum", error enum like official (Recipient, Identity, Internal, Stanza).
- Mirror rage dummy example: handlers, main clap, callbacks if needed (not for non-interactive).
- Add tests (roundtrip, interop with native).

#### Step 1: Update Cargo.toml
- Depend on latest `pq-xwing-hpke` path (with kem.rs/hpke.rs).
- Keep age-plugin = "0.6", age-core = "0.11", secrecy = "0.8", clap derive, rand os_rng, time formatting, zeroize, base64, bech32.
- Remove chacha20poly1305 (unneeded with hpke aead).
- For tests: proptest, tempfile.

#### Step 2: Update Imports in main.rs
- Remove old `use pq_xwing_hpke::xwing768x25519::{...}`.
- Add `use pq_xwing_hpke::{kem::{Kem, XWing768X25519, PrivateKey, PublicKey}, hpke::{new_sender, new_sender_with_testing_randomness, new_recipient, seal, open}}`.
- Add `use pq_xwing_hpke::{kdf::new_kdf, aead::new_aead}`.
- Remove hpke_pq.rs (full HPKE replaces manual derivation).
- Add `use age_plugin::print_new_identity` for convert.

#### Step 3: Remove hpke_pq.rs
- Full HPKE seal/open replaces all derivation + AEAD — no need for custom helpers.

#### Step 4: Update RecipientPlugin wrap_file_keys
- For each recipient: kem = XWing768X25519; kdf = new_kdf(0x0001)?; aead = new_aead(0x0003)?.
- (enc, sender) = new_sender(pk, kdf.clone(), aead.clone(), PQ_LABEL)? (use new_sender_with_testing_randomness if test).
- For each file_key i: wrapped = sender.seal(&[], file_key.expose_secret())? (sender auto increments seq).
- base64_enc = STANDARD_NO_PAD.encode(&enc).
- Stanza: tag "mlkem768x25519", args vec!["mlkem768x25519", base64_enc], body wrapped.
- If errors, collect and return Err(errors).
- Labels: HashSet "postquantum" for PQ isolation.

#### Step 5: Update IdentityPlugin unwrap_file_keys
- For each stanza: if tag != "mlkem768x25519" or args.len() != 2 or args[0] != "mlkem768x25519" continue.
- enc = STANDARD_NO_PAD.decode(args[1])?.
- For each sk: kem = XWing768X25519; sk = kem.new_private_key(seed)?.
- ct = enc + body (Vec concat).
- kdf = new_kdf(0x0001)?; aead = new_aead(0x0003)?.
- file_key_bytes = open(sk, kdf, aead, PQ_LABEL, &ct)? (handles seq=file_idx internally if multi, but single-shot).
- FileKey from bytes, insert results[file_idx] = Ok(file_key).
- If errors, collect stanza_errors, insert Err if no success.

#### Step 6: Update CLI/Keygen/Convert
- Update HRPs: "age1pq1" recipient, "AGE-SECRET-KEY-PQ-1" native, "AGE-PLUGIN-PQ-1" plugin (add "1" for spec).
- keygen: kem.generate_key(), pk = sk.public_key(), recipient = bech32 "age1pq1" + pk.bytes().to_base32().
- identity = bech32 hrp (native or plugin) + sk.bytes()? .to_base32(), uppercase.
- convert_native_identities(): parse "AGE-SECRET-KEY-PQ-1", re-encode "AGE-PLUGIN-PQ-1", print (use print_new_identity if needed).

#### Step 7: Tests
- Add multi-file wrap/unwrap roundtrip like lessons (proptest seed, wrap Vec<FileKey>, unwrap, assert eq).
- Interop: Encrypt with native, decrypt with plugin (and vice versa).
- Add integration.rs for CLI tests (tempfile for output).

This upgrades to full HPKE, compliant stanza, modern API — superior to original (simplified/random nonce), matching Go. Debug stanza args/format first.