#![forbid(unsafe_code)]

// src/main.rs
use age_core::{
    format::{FileKey, Stanza},
    secrecy::ExposeSecret,
};
use age_plugin::{
    identity::{self, IdentityPluginV1},
    recipient::{self, RecipientPluginV1},
    run_state_machine, Callbacks, PluginHandler,
};
use age_pq_hpke::compute_nonce;
use age_pq_hpke::kem::mlkem768x25519::MLKEM768X25519_ENCAPSULATION_KEY_SIZE;
use age_pq_hpke::kem::mlkem768x25519::{Ciphertext, DecapsulationKey, EncapsulationKey};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use clap::{CommandFactory, Parser};
use rand::rngs::SysRng;
use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
mod aliases;

use crate::aliases::{FileKeyBytes, IdentityEncoding, SecretText, Seed32, SharedSecret32};
use secure_gate::{bech32_code_length, Case, RevealSecret, RevealSecretMut, SecretLen, ToBech32};

mod hpke_pq;
use hpke_pq::derive_key_and_nonce;

const PLUGIN_NAME: &str = "pq";
const STANZA_TAG: &str = "mlkem768x25519";
const PQ_LABEL: &[u8] = b"age-encryption.org/mlkem768x25519";
const RECIPIENT_BECH32_HRP: &str = "age1pq";
const IDENTITY_BECH32_HRP: &str = "AGE-PLUGIN-PQ-";
const NATIVE_IDENTITY_HRP: &str = "AGE-SECRET-KEY-PQ-";

/// Bech32 code length for an `age1pq` recipient, derived from the key size.
///
/// Replaces a hand-rolled `Checksum` impl with `CODE_LENGTH = 8192` that was
/// byte-identical to the one in `age-pq-keys` - the duplication issue #11 is
/// about. The code length is a length gate and never enters the checksum, so
/// the encoded output is unchanged.
const RECIPIENT_CODE_LENGTH: usize = bech32_code_length(
    RECIPIENT_BECH32_HRP.len(),
    MLKEM768X25519_ENCAPSULATION_KEY_SIZE,
);

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

    fn add_identity(&mut self, _: usize, _: &str, _: &[u8]) -> Result<(), recipient::Error> {
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
        let mut stanzas_per_file: Vec<Vec<Stanza>> = (0..num_files).map(|_| vec![]).collect();
        let mut errors = vec![];

        for (recip_idx, pk) in self.recipients.iter().enumerate() {
            let (ct, ss) = pk
                .encapsulate(&mut SysRng)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "encapsulation failed"))?;

            // `encapsulate` hands back a native [u8; 32]; wrap it so the shared
            // secret is wiped on drop rather than by hand at each exit.
            let ss = SharedSecret32::from(ss);
            let (key, base_nonce) = ss
                .with_secret(|s| derive_key_and_nonce(s, PQ_LABEL))
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "key derivation failed"))?;

            // Feed the key into the cipher via `new_from_slice`; `Key::from(..)`
            // would materialise a non-Zeroize `GenericArray` binding holding the
            // key bytes until end of scope. The cipher copies into its own
            // zeroize-on-drop state, and `key` wipes itself when it drops.
            let aead = key
                .with_secret(|k| ChaCha20Poly1305::new_from_slice(k))
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid AEAD key"))?;
            drop(key);
            drop(ss);
            let ct_b64 = STANDARD_NO_PAD.encode(ct.to_bytes());

            let mut ok = true;
            for i in 0..num_files {
                let nonce_bytes = compute_nonce(&base_nonce, i as u64);
                let nonce = Nonce::from(nonce_bytes);

                if let Ok(body) = aead.encrypt(&nonce, file_keys[i].expose_secret().as_slice()) {
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
        // `new_with` writes straight into the wrapper's storage, so the seed
        // never exists as a bare local; it is wiped when `seed` drops.
        let seed = Seed32::new_with(|out| out.copy_from_slice(bytes));
        let sk = seed.with_secret(DecapsulationKey::from_seed);
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
                    // Every binding below is a secure-gate wrapper, so each of the
                    // `continue` paths in this loop wipes its secrets on drop. The
                    // previous shape needed a hand-written `.zeroize()` at each of
                    // the six exits and had to keep them in sync.
                    let ss = match sk.decapsulate(&ct) {
                        Ok(s) => SharedSecret32::from(s),
                        Err(_) => continue,
                    };

                    let (key, base_nonce) =
                        match ss.with_secret(|s| derive_key_and_nonce(s, PQ_LABEL)) {
                            Ok(r) => r,
                            Err(_) => continue,
                        };

                    let nonce_bytes = compute_nonce(&base_nonce, file_idx as u64);
                    let nonce = Nonce::from(nonce_bytes);
                    // Same shape as wrap_file_keys: `new_from_slice` avoids the
                    // non-Zeroize `Key` (GenericArray) outer binding.
                    let aead = match key.with_secret(|k| ChaCha20Poly1305::new_from_slice(k)) {
                        Ok(a) => a,
                        Err(_) => continue,
                    };
                    drop(key);

                    // The decrypted body is the 16-byte FileKey.
                    let plaintext = match aead.decrypt(&nonce, &*stanza.body) {
                        Ok(p) => FileKeyBytes::new(p),
                        Err(_) => continue,
                    };
                    drop(ss);

                    if plaintext.len() != 16 {
                        continue;
                    }

                    let fk = match plaintext.with_secret(|p| <[u8; 16]>::try_from(p.as_slice())) {
                        Ok(arr) => arr,
                        Err(_) => continue,
                    };
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
    // `from_rng` fills the wrapper's own storage straight from the CSPRNG, so the
    // seed never exists as an unprotected buffer. It is wiped on drop, including
    // on the `?`-driven early returns below.
    let seed = Seed32::from_rng(&mut SysRng)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let sk = seed.with_secret(DecapsulationKey::from_seed);
    let pk = sk
        .encapsulation_key()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "keygen failed"))?;

    let created = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let recipient = pk
        .to_bytes()
        .try_to_bech32_sized::<RECIPIENT_CODE_LENGTH>(RECIPIENT_BECH32_HRP, Case::Lower)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to encode recipient"))?
        .into_inner();

    let identity_hrp = if native {
        NATIVE_IDENTITY_HRP
    } else {
        IDENTITY_BECH32_HRP
    };
    // `Case::Upper` happens inside the encoder, on the buffer it already owns:
    // no second plaintext copy, and no separate uppercase step to forget. The
    // error carries no payload - the input is the private key.
    let identity = IdentityEncoding::new(
        seed.try_to_bech32(identity_hrp, Case::Upper)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to encode identity"))?
            .into_inner(),
    );

    let output_text = SecretText::new(
        identity.with_secret(|id| format!("# created: {created}\n# public key: {recipient}\n{id}")),
    );

    if let Some(path) = output {
        if std::path::Path::new(&path).exists() {
            eprintln!("Warning: {path} exists – refusing to overwrite");
        } else {
            output_text.with_secret(|t| std::fs::write(&path, t))?;
            eprintln!("Public key: {recipient}");
        }
    } else {
        output_text.with_secret(|t| println!("{t}"));
    }

    Ok(())
}

fn convert_native_identities() -> io::Result<()> {
    // `input` holds the entire stdin buffer — potentially multiple native PQ
    // private keys in bech32 form. Wrap so the heap buffer zeroizes on drop.
    let mut input = SecretText::new(String::new());
    input.with_secret_mut(|buf| io::stdin().read_to_string(buf))?;

    // One borrow for the whole loop rather than re-opening the wrapper per line.
    input.with_secret(|input| -> io::Result<()> {
        for line in input.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Decodes and length-validates in one step, straight into the
            // wrapper's storage - no intermediate heap Vec of seed bytes. HRP
            // comparison is case-insensitive, as before.
            let seed = Seed32::try_from_bech32(line, NATIVE_IDENTITY_HRP).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "not a native PQ identity")
            })?;

            let sk = seed.with_secret(DecapsulationKey::from_seed);
            let _pk = sk.encapsulation_key().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid key derivation")
            })?;

            let plugin_identity = IdentityEncoding::new(
                seed.try_to_bech32(IDENTITY_BECH32_HRP, Case::Upper)
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to encode identity"))?
                    .into_inner(),
            );
            plugin_identity.with_secret(|s| println!("{s}"));
        }

        Ok(())
    })
}
