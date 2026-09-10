use age_pq_keys::HybridRecipient;
use clap::{Arg, ArgAction, Command};
use secure_gate::{Dynamic, RevealSecret};
use std::io::Write;
use std::path::Path;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("pq-keygen")
        // Read from Cargo rather than hardcoded: a literal here has to be kept
        // in sync by hand, and has drifted before (see CHANGELOG 0.0.5).
        .version(env!("CARGO_PKG_VERSION"))
        .about("Generate a post-quantum hybrid ML-KEM-768 + X25519 key pair")
        .disable_version_flag(true)
        .after_help(
            "Examples:\n    \
             $ cargo run --example pq-keygen\n    \
             # created: 2023-01-01T12:00:00Z\n    \
             # public key: age1pq[...]\n    \
             AGE-SECRET-KEY-PQ-[...]\n    \
             \n    \
             $ cargo run --example pq-keygen -o key.txt\n    \
             Public key: age1pq[...]\n    \
             \n    \
             $ cargo run --example pq-keygen -o mykey -s\n    \
              Keypair output to: mykey.keypair, mykey_recipient.key, and mykey_identity.key",
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Write the result to the file at path FILE"),
        )
        .arg(
            Arg::new("split")
                .short('s')
                .long("split")
                .action(ArgAction::SetTrue)
                .help(
                    "Output combined keypair file along with separate recipient and identity files",
                ),
        )
        .arg(
            Arg::new("force")
                .short('f')
                .long("force")
                .action(ArgAction::SetTrue)
                .help("Overwrite existing output file"),
        )
        .arg(
            Arg::new("version")
                .short('v')
                .long("version")
                .action(ArgAction::Version)
                .help("Print the version information"),
        )
        .get_matches();

    let output_path = matches.get_one::<String>("output").map(|s| s.as_str());
    let split = matches.get_flag("split");
    let force = matches.get_flag("force");

    let (recipient, identity) = HybridRecipient::generate()?;

    let created = OffsetDateTime::now_utc().format(&Rfc3339)?;
    // Carries the bech32-encoded private identity key. `to_string` hands back a
    // plain String at the API boundary, so wrap it here: the Dynamic wipes the heap
    // buffer on drop instead of leaving it for the allocator to reuse.
    let output_text: Dynamic<String> = Dynamic::new(format!(
        "# created: {}\n# public key: {}\n{}",
        created,
        recipient.to_string(),
        identity.to_string()
    ));

    if split {
        if let Some(base) = output_path {
            // Strip extension from base to avoid double .key
            let base_stem = Path::new(base)
                .with_extension("")
                .to_string_lossy()
                .to_string();
            let keypair_path = format!("{}.keypair", base_stem);
            let recipient_path = format!("{}_recipient.key", base_stem);
            let identity_path = format!("{}_identity.key", base_stem);

            // Check if any file exists and not force, refuse overwrite
            if (Path::new(&keypair_path).exists()
                || Path::new(&recipient_path).exists()
                || Path::new(&identity_path).exists())
                && !force
            {
                eprintln!(
                    "pq-keygen: error: output files \"{}.keypair\", \"{}_recipient.key\", and \"{}_identity.key\" already exist (use -f to overwrite)",
                    base_stem, base_stem, base_stem
                );
                std::process::exit(1);
            }

            // Create parent directories if needed
            if let Some(parent) = Path::new(&recipient_path).parent() {
                std::fs::create_dir_all(parent)?;
            }

            output_text.with_secret(|s| std::fs::write(&keypair_path, s.as_bytes()))?;
            std::fs::write(&recipient_path, recipient.to_string())?;
            std::fs::write(&identity_path, identity.to_string())?;
            println!(
                "Keypair output to: {}, {}, and {}",
                keypair_path, recipient_path, identity_path
            );
        } else {
            eprintln!("pq-keygen: error: --split requires -o/--output");
            std::process::exit(1);
        }
    } else if let Some(ref path) = output_path {
        // Check if file exists and not force, refuse overwrite
        if Path::new(path).exists() && !force {
            eprintln!(
                "pq-keygen: error: failed to open output file \"{}\": file exists",
                path
            );
            std::process::exit(1);
        }
        let mut file = std::fs::File::create(path)?;
        output_text.with_secret(|s| file.write_all(s.as_bytes()))?;
        // Print public key to stderr if outputting to file
        eprintln!("Public key: {}", recipient.to_string());
    } else {
        // Output to stdout
        output_text.with_secret(|s| println!("{}", s));
    }

    Ok(())
}
