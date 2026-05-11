// src/main.rs
use age_core::{
    format::{FileKey, Stanza},
    secrecy::ExposeSecret,
};
use age_hpke_pq::compute_nonce;
use age_hpke_pq::kem::mlkem768x25519::{Ciphertext, DecapsulationKey, EncapsulationKey};
use age_hpke_pq::RevealSecret;
use age_plugin::{
    identity::{self, IdentityPluginV1},
    recipient::{self, RecipientPluginV1},
    run_state_machine, Callbacks, PluginHandler,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use bech32::primitives::checksum::Checksum;
use bech32::primitives::decode::CheckedHrpstring;
use bech32::{encode as bech32_encode, Bech32, Hrp};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use clap::{CommandFactory, Parser};
use rand::{rngs::OsRng, TryRngCore};
use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use zeroize::{Zeroize, Zeroizing};

mod hpke_pq;
use hpke_pq::derive_key_and_nonce;

const PLUGIN_NAME: &str = "pq";
const STANZA_TAG: &str = "mlkem768x25519";
const PQ_LABEL: &[u8] = b"age-encryption.org/mlkem768x25519";
const RECIPIENT_BECH32_HRP: &str = "age1pq";
const IDENTITY_BECH32_HRP: &str = "AGE-PLUGIN-PQ-";
const NATIVE_IDENTITY_HRP: &str = "AGE-SECRET-KEY-PQ-";

/// Custom Bech32 checksum matching the classic BIP-173 constants used by the
/// official age Go implementation. The standard `bech32::Bech32` caps strings
/// at 1023 characters; PQ public keys are ~1959 characters and require the
/// extended CODE_LENGTH of 8192 used here (same as age-recipient-pq).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum HybridRecipientBech32 {}

impl Checksum for HybridRecipientBech32 {
    type MidstateRepr = u32;
    const CODE_LENGTH: usize = 8192;
    const CHECKSUM_LENGTH: usize = 6;
    const GENERATOR_SH: [u32; 5] =
        [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    const TARGET_RESIDUE: u32 = 1;
}

struct FullHandler;
impl PluginHandler for FullHandler {
    type RecipientV1 = RecipientPlugin;
    type IdentityV1 = IdentityPlugin;

    fn recipient_v1(self) -> io::Result<Self::RecipientV1> {
        Ok(RecipientPlugin::default())
    }
    fn identity_v1(self) -> io::Result<Self::IdentityV1> {
        Ok(IdentityPlugin::default())
    }
}

struct RecipientHandler;
impl PluginHandler for RecipientHandler {
    type RecipientV1 = RecipientPlugin;
    type IdentityV1 = std::convert::Infallible;

    fn recipient_v1(self) -> io::Result<Self::RecipientV1> {
        Ok(RecipientPlugin::default())
    }
    fn identity_v1(self) -> io::Result<Self::IdentityV1> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "identity-only mode",
        ))
    }
}

struct IdentityHandler;
impl PluginHandler for IdentityHandler {
    type RecipientV1 = std::convert::Infallible;
    type IdentityV1 = IdentityPlugin;

    fn recipient_v1(self) -> io::Result<Self::RecipientV1> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "recipient-only mode",
        ))
    }
    fn identity_v1(self) -> io::Result<Self::IdentityV1> {
        Ok(IdentityPlugin::default())
    }
}

#[derive(Default)]
struct RecipientPlugin {
    recipients: Vec<EncapsulationKey>,
}

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipient(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        if plugin_name != PLUGIN_NAME {
            return Err(recipient::Error::Recipient {
                index,
                message: "wrong plugin".into(),
            });
        }
        let pk = EncapsulationKey::try_from(bytes).map_err(|_| recipient::Error::Recipient {
            index,
            message: "invalid public key".into(),
        })?;
        self.recipients.push(pk);
        Ok(())
    }

    fn add_identity(
        &mut self,
        _: usize,
        _: &str,
        _: &[u8],
    ) -> Result<(), recipient::Error> {
        Err(recipient::Error::Internal {
            message: "identities not supported for encryption".into(),
        })
    }

    fn labels(&mut self) -> HashSet<String> {
        let mut set = HashSet::new();
        set.insert("postquantum".to_string());
        set
    }

    fn wrap_file_keys(
        &mut self,
        file_keys: Vec<FileKey>,
        _: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        if self.recipients.is_empty() {
            return Ok(Err(vec![recipient::Error::Internal {
                message: "no recipients".into(),
            }]));
        }

        let num_files = file_keys.len();
        let mut stanzas_per_file: Vec<Vec<Stanza>> =
            (0..num_files).map(|_| vec![]).collect();
        let mut errors = vec![];

        for (recip_idx, pk) in self.recipients.iter().enumerate() {
            let (ct, mut ss) = pk
                .encapsulate(&mut OsRng)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "encapsulation failed"))?;

            let (mut key_bytes, base_nonce) = derive_key_and_nonce(ss.expose_secret(), PQ_LABEL)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "key derivation failed"))?;

            // Feed the key into the cipher directly via `new_from_slice`; the
            // previous `Key::from(key_bytes)` step materialised a non-Zeroize
            // `GenericArray` outer binding holding the key bytes until end of
            // scope. The cipher copies the bytes into its own zeroize-on-drop
            // state, so once we zeroize `key_bytes` the only live copy is the
            // cipher's internal one.
            let aead = ChaCha20Poly1305::new_from_slice(&key_bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid AEAD key"))?;
            key_bytes.zeroize();
            ss.zeroize();
            let ct_b64 = STANDARD_NO_PAD.encode(ct.to_bytes());

            let mut ok = true;
            for i in 0..num_files {
                let nonce_bytes = compute_nonce(&base_nonce, i as u64);
                let nonce = Nonce::from(nonce_bytes);

                if let Ok(body) =
                    aead.encrypt(&nonce, file_keys[i].expose_secret().as_slice())
                {
                    stanzas_per_file[i].push(Stanza {
                        tag: STANZA_TAG.to_string(),
                        args: vec![ct_b64.clone()],
                        body,
                    });
                } else {
                    ok = false;
                }
            }

            if !ok {
                errors.push(recipient::Error::Recipient {
                    index: recip_idx,
                    message: "AEAD encryption failed".into(),
                });
            }
        }

        if errors.is_empty() {
            Ok(Ok(stanzas_per_file))
        } else {
            Ok(Err(errors))
        }
    }
}

#[derive(Default)]
struct IdentityPlugin {
    identities: Vec<DecapsulationKey>,
}

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), identity::Error> {
        if plugin_name != PLUGIN_NAME {
            return Err(identity::Error::Identity {
                index,
                message: "wrong plugin".into(),
            });
        }
        if bytes.len() != 32 {
            return Err(identity::Error::Identity {
                index,
                message: "seed must be 32 bytes".into(),
            });
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(bytes);
        let sk = DecapsulationKey::from_seed(&seed);
        // `from_seed` copied the bytes into its own `Seed32` wrapper; zeroize
        // the local stack copy so the only live copy of the private key is
        // inside the wrapper.
        seed.zeroize();
        self.identities.push(sk);
        Ok(())
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        _: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        let mut results = HashMap::new();

        'files: for (file_idx, stanzas) in files.into_iter().enumerate() {
            let mut stanza_errors = Vec::new();

            for (stanza_idx, stanza) in stanzas.into_iter().enumerate() {
                if stanza.tag != STANZA_TAG {
                    continue;
                }
                if stanza.args.len() != 1 {
                    stanza_errors.push(identity::Error::Stanza {
                        file_index: file_idx,
                        stanza_index: stanza_idx,
                        message: "expected exactly one arg".into(),
                    });
                    continue;
                }

                let ct_bytes = match STANDARD_NO_PAD.decode(&stanza.args[0]) {
                    Ok(b) => b,
                    Err(_) => {
                        stanza_errors.push(identity::Error::Stanza {
                            file_index: file_idx,
                            stanza_index: stanza_idx,
                            message: "invalid base64".into(),
                        });
                        continue;
                    }
                };

                let ct = match Ciphertext::try_from(&ct_bytes[..]) {
                    Ok(c) => c,
                    Err(_) => {
                        stanza_errors.push(identity::Error::Stanza {
                            file_index: file_idx,
                            stanza_index: stanza_idx,
                            message: "invalid ciphertext".into(),
                        });
                        continue;
                    }
                };

                for sk in &self.identities {
                    let mut ss = match sk.decapsulate(&ct) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };

                    let (mut key_bytes, base_nonce) =
                        match derive_key_and_nonce(ss.expose_secret(), PQ_LABEL) {
                            Ok(r) => r,
                            Err(_) => {
                                ss.zeroize();
                                continue;
                            }
                        };

                    let nonce_bytes = compute_nonce(&base_nonce, file_idx as u64);
                    let nonce = Nonce::from(nonce_bytes);
                    // Same shape as wrap_file_keys: feed `key_bytes` into the
                    // cipher via `new_from_slice` to avoid the non-Zeroize
                    // `Key` (GenericArray) outer binding.
                    let aead = match ChaCha20Poly1305::new_from_slice(&key_bytes) {
                        Ok(a) => a,
                        Err(_) => {
                            key_bytes.zeroize();
                            ss.zeroize();
                            continue;
                        }
                    };
                    key_bytes.zeroize();

                    // The decrypted body is the 16-byte FileKey. Wrap the Vec
                    // in Zeroizing so the heap buffer is zeroized when it
                    // drops, before the bytes are copied into FileKey.
                    let plaintext = match aead.decrypt(&nonce, &*stanza.body) {
                        Ok(p) => Zeroizing::new(p),
                        Err(_) => {
                            ss.zeroize();
                            continue;
                        }
                    };

                    ss.zeroize();

                    if plaintext.len() != 16 {
                        continue;
                    }

                    let mut fk = [0u8; 16];
                    fk.copy_from_slice(&plaintext);
                    let file_key = FileKey::new(Box::new(fk));

                    results.insert(file_idx, Ok(file_key));
                    continue 'files;
                }

                stanza_errors.push(identity::Error::Stanza {
                    file_index: file_idx,
                    stanza_index: stanza_idx,
                    message: "decapsulation failed".into(),
                });
            }

            if !results.contains_key(&file_idx) && !stanza_errors.is_empty() {
                results.insert(file_idx, Err(stanza_errors));
            }
        }

        Ok(results)
    }
}

#[derive(Parser)]
#[command(name = "age-plugin-pq", about = "Post-quantum age plugin")]
struct Cli {
    #[arg(long = "age-plugin")]
    age_plugin: Option<String>,

    #[arg(long = "version")]
    version: bool,

    #[arg(long = "identity")]
    identity: bool,

    #[arg(
        long = "keygen",
        help = "Generate a post-quantum key pair in plugin format (AGE-PLUGIN-PQ-...)"
    )]
    keygen: bool,

    #[arg(
        long = "keygen-native",
        help = "Generate a post-quantum key pair in native age format (AGE-SECRET-KEY-PQ-...)"
    )]
    keygen_native: bool,

    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<String>,
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    if cli.version {
        println!("age-plugin-pq {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if cli.identity {
        return convert_native_identities();
    }

    if cli.keygen {
        return keygen(cli.output, false);
    }

    if cli.keygen_native {
        return keygen(cli.output, true);
    }

    let Some(state_machine) = cli.age_plugin else {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    };

    let mode_opt = std::env::var("AGEPLUGIN_HALF_PLUGIN").ok();
    let mode = mode_opt.as_deref();
    match mode {
        Some("recipient") => run_state_machine(&state_machine, RecipientHandler),
        Some("identity") => run_state_machine(&state_machine, IdentityHandler),
        _ => run_state_machine(&state_machine, FullHandler),
    }
}

fn keygen(output: Option<String>, native: bool) -> io::Result<()> {
    // `seed` carries the private key; Zeroizing covers it across all paths,
    // including the `?`-driven early returns below.
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(&mut seed[..])
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let sk = DecapsulationKey::from_seed(&seed);
    let pk = sk
        .encapsulation_key()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "keygen failed"))?;

    let created = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let recipient_hrp = Hrp::parse(RECIPIENT_BECH32_HRP)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let recipient = bech32_encode::<HybridRecipientBech32>(recipient_hrp, pk.to_bytes().as_ref())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let identity_hrp_str = if native { NATIVE_IDENTITY_HRP } else { IDENTITY_BECH32_HRP };
    let identity_hrp = Hrp::parse(identity_hrp_str)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    // Bech32-encoded private key carries the seed; keep the String wrapped
    // until it's embedded in the final output buffer (which is itself wrapped).
    // `make_ascii_uppercase` mutates in place so no second unprotected copy.
    let mut identity = Zeroizing::new(
        bech32_encode::<Bech32>(identity_hrp, seed.as_ref())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?,
    );
    identity.make_ascii_uppercase();

    let output_text = Zeroizing::new(format!(
        "# created: {created}\n# public key: {recipient}\n{}",
        identity.as_str()
    ));

    if let Some(path) = output {
        if std::path::Path::new(&path).exists() {
            eprintln!("Warning: {path} exists – refusing to overwrite");
        } else {
            std::fs::write(&path, &*output_text)?;
            eprintln!("Public key: {recipient}");
        }
    } else {
        println!("{}", output_text.as_str());
    }

    Ok(())
}

fn convert_native_identities() -> io::Result<()> {
    // `input` holds the entire stdin buffer — potentially multiple native PQ
    // private keys in bech32 form. Wrap so the heap buffer zeroizes on drop.
    let mut input = Zeroizing::new(String::new());
    io::stdin().read_to_string(&mut input)?;

    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parsed = CheckedHrpstring::new::<Bech32>(line)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid bech32"))?;

        if !parsed.hrp().as_str().eq_ignore_ascii_case(NATIVE_IDENTITY_HRP) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a native PQ identity",
            ));
        }

        // Per-line decoded seed bytes; wrap so the heap Vec zeroizes when it
        // falls out of scope at the end of the iteration.
        let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(parsed.byte_iter().collect());
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "wrong seed length"))?,
        );

        let sk = DecapsulationKey::from_seed(&seed);
        let _pk = sk
            .encapsulation_key()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key derivation"))?;

        let plugin_hrp = Hrp::parse(IDENTITY_BECH32_HRP)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        // Re-encoded plugin-format private key; same wrap-and-mutate-in-place
        // pattern as keygen to avoid the second plaintext String from
        // `to_uppercase()`.
        let mut plugin_identity = Zeroizing::new(
            bech32_encode::<Bech32>(plugin_hrp, seed.as_ref())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?,
        );
        plugin_identity.make_ascii_uppercase();
        println!("{}", plugin_identity.as_str());
    }

    Ok(())
}
