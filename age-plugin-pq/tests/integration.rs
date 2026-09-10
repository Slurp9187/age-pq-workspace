//! Integration tests for the `age-plugin-pq` binary.
//!
//! Cargo builds the binary before running these and hands us its path in
//! `CARGO_BIN_EXE_age-plugin-pq`, so nothing here searches `target/` or depends
//! on the plugin being installed on `PATH`. The previous version did both, and
//! silently reported success when it found neither.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use tempfile::TempDir;

/// Path to the freshly built plugin binary, supplied by Cargo.
const PLUGIN_EXE: &str = env!("CARGO_BIN_EXE_age-plugin-pq");

/// age 1.3.0 is the first release with native post-quantum support.
const MIN_AGE_MAJOR: u32 = 1;
const MIN_AGE_MINOR: u32 = 3;

/// Asserts an age CLI of at least 1.3.0 is on `PATH`, returning its version.
///
/// Panics rather than skipping. Callers are `#[ignore]`d, so reaching this means
/// the runner explicitly asked for the test, and a missing binary is a failure
/// rather than a reason to report success.
fn require_age_cli() -> String {
    let output = Command::new("age")
        .arg("--version")
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "age CLI not found on PATH ({e}). This test is #[ignore]d and only runs when \
                 explicitly requested. Install age >= {MIN_AGE_MAJOR}.{MIN_AGE_MINOR}.0 - \
                 scripts/install-age.sh does it with a pinned, checksum-verified release."
            )
        });
    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let version = raw.trim_start_matches('v');
    let parts: Vec<&str> = version.split('.').collect();
    let major: u32 = parts.first().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor: u32 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);
    if major < MIN_AGE_MAJOR || (major == MIN_AGE_MAJOR && minor < MIN_AGE_MINOR) {
        panic!(
            "requires age CLI >= {MIN_AGE_MAJOR}.{MIN_AGE_MINOR}.0 \
             (first release with native post-quantum support), found {raw:?}"
        );
    }
    raw
}

/// Runs the plugin with `--keygen` and returns `(recipient, identity)`.
fn keygen() -> (String, String) {
    let out = Command::new(PLUGIN_EXE)
        .arg("--keygen")
        .output()
        .expect("failed to run the plugin binary");
    assert!(
        out.status.success(),
        "--keygen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let recipient = stdout
        .lines()
        .find_map(|l| l.strip_prefix("# public key: "))
        .expect("no recipient line in --keygen output")
        .trim()
        .to_owned();
    let identity = stdout
        .lines()
        .find(|l| l.starts_with("AGE-PLUGIN-"))
        .expect("no plugin identity in --keygen output")
        .trim()
        .to_owned();
    (recipient, identity)
}

/// An `age` command that can discover the plugin **this run just built**.
///
/// age spawns `age-plugin-pq` by name and resolves it through `PATH`, so the
/// binary's directory has to be there. Do not rely on Cargo for this: Cargo adds
/// the build directory to the *dynamic library* search path, which happens to be
/// `PATH` on Windows but is `LD_LIBRARY_PATH` on Unix — so depending on it
/// passes on Windows and fails on Linux CI. (It did.)
///
/// Prepending is deliberate: it guarantees age spawns the build from this run
/// rather than an older copy installed globally.
fn age_with_fresh_plugin_on_path() -> Command {
    let plugin_dir = Path::new(PLUGIN_EXE)
        .parent()
        .expect("plugin path has a parent directory")
        .to_path_buf();
    let mut paths = vec![plugin_dir];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let mut cmd = Command::new("age");
    cmd.env(
        "PATH",
        std::env::join_paths(paths).expect("failed to build PATH with the plugin directory"),
    );
    cmd
}

#[test]
fn test_data_fixtures_exist() {
    for f in ["tests/data/lorem.txt", "tests/data/age_go_identity.txt"] {
        assert!(fs::metadata(f).is_ok(), "{f} not found");
    }
}

/// The binary's name is load-bearing, and nothing else checks it.
///
/// age locates a plugin by *constructing* the path `"age-plugin-" + name`,
/// where `name` comes from the identity's HRP. If the binary is renamed - say
/// for consistency with its `age-pq-*` siblings - or the HRP changes, discovery
/// breaks **silently**: age reports the plugin as not found rather than failing
/// to build, and no other test here goes through that path.
///
/// So derive the name age would look for from the HRP the plugin itself emits,
/// and compare it against the binary Cargo just built. This keeps the coupling
/// as an executable assertion instead of a comment someone has to notice.
#[test]
fn identity_hrp_matches_the_binary_name_age_will_look_for() {
    let (_recipient, identity) = keygen();

    // Identity is `AGE-PLUGIN-<NAME>-1<data>`: the HRP, then bech32's `1`.
    let after_prefix = identity
        .strip_prefix("AGE-PLUGIN-")
        .expect("plugin identity must start with AGE-PLUGIN-");
    let name = after_prefix
        .split('-')
        .next()
        .expect("HRP must have a name segment")
        .to_ascii_lowercase();
    let expected_binary = format!("age-plugin-{name}");

    let actual_binary = Path::new(PLUGIN_EXE)
        .file_stem()
        .expect("binary path has a file name")
        .to_string_lossy()
        .into_owned();

    assert_eq!(
        actual_binary,
        expected_binary,
        "age derives the plugin binary name from the identity HRP, so with \
         AGE-PLUGIN-{}- it will look for `{expected_binary}` - but this crate builds \
         `{actual_binary}`. age would report the plugin as not found. Either rename the \
         binary back or change the HRP to match.",
        name.to_ascii_uppercase(),
    );
}

/// The plugin identity HRP must be **uppercase**, and since `age-plugin` 0.7 /
/// `age` 0.12 that is a correctness requirement rather than a cosmetic one.
///
/// Both crates recognise a plugin identity by testing
/// `hrp.as_str().starts_with("AGE-PLUGIN-")`. Two things changed together in
/// that release pair, and only the combination bites:
///
/// * the prefix constant flipped from `"age-plugin-"` to `"AGE-PLUGIN-"`
///   (`age-plugin-0.7.0/src/lib.rs:193`, `age-0.12.1/src/plugin.rs:32`), and
/// * `bech32` 0.9 -> 0.11 made `Hrp` **case-preserving**, where 0.9's `decode`
///   returned the HRP pre-lowercased.
///
/// Under 0.6.1 / 0.11.2 a lowercased plugin identity therefore matched; under
/// 0.7.0 / 0.12.1 it is rejected as an invalid HRP. We emit `Case::Upper`
/// (`main.rs`, both `try_to_bech32` call sites), so nothing breaks — but the
/// constraint is now load-bearing and invisible, because every fixture and
/// every keygen path in this workspace already produces uppercase. Switching
/// the encoder to `Case::Lower` would still emit valid bech32 and still round
/// trip through our own parser, while silently becoming undiscoverable to
/// every age client on the 0.12 generation.
///
/// Note the asymmetry, so this is not over-read: `age::x25519` is unaffected,
/// because it compares `Hrp == Hrp` and that `PartialEq` is explicitly
/// case-insensitive. The narrowing applies to the *plugin* prefix test only.
#[test]
fn plugin_identity_hrp_is_uppercase_as_age_0_12_requires() {
    let (_recipient, from_keygen) = keygen();
    let from_conversion = convert_native_fixture_to_plugin_identity();

    // Both emitters, because mutating one alone leaves the other's test green.
    for (source, identity) in [
        ("--keygen (main.rs:439)", &from_keygen),
        ("--identity conversion (main.rs:489)", &from_conversion),
    ] {
        // The HRP is everything up to bech32's separator; the data part that
        // follows is lowercase by construction and must not be inspected here.
        let sep = identity
            .rfind('1')
            .expect("bech32 string must contain the '1' separator");
        let hrp = &identity[..sep];

        assert!(
            !hrp.chars().any(|c| c.is_ascii_lowercase()),
            "plugin identity HRP {hrp:?} from {source} contains lowercase. age-plugin 0.7 and \
             age 0.12 match plugin identities with a case-SENSITIVE \
             `starts_with(\"AGE-PLUGIN-\")` against a case-preserving bech32 Hrp, so a \
             lowercased HRP is rejected as invalid and the plugin becomes undiscoverable. \
             Emit Case::Upper."
        );
        assert!(
            hrp.starts_with("AGE-PLUGIN-"),
            "plugin identity HRP {hrp:?} from {source} must start with the exact uppercase \
             `AGE-PLUGIN-` prefix that age-plugin 0.7 and age 0.12 test for"
        );
    }
}

/// Feeds the native PQ identity fixture through `--identity` and returns the
/// plugin-format identity the binary prints.
///
/// This is the *second* of the two places the plugin emits an `AGE-PLUGIN-PQ-`
/// HRP (`main.rs:489`); `keygen` is the first (`main.rs:439`). Both are checked
/// by `plugin_identity_hrp_is_uppercase_as_age_0_12_requires`, because mutating
/// either one alone leaves the other's test green.
fn convert_native_fixture_to_plugin_identity() -> String {
    let native = fs::read_to_string("tests/data/age_go_identity.txt")
        .expect("failed to read tests/data/age_go_identity.txt")
        .trim()
        .to_owned();
    assert!(
        native.starts_with("AGE-SECRET-KEY-PQ-"),
        "fixture is not a native PQ identity"
    );

    let mut child = Command::new(PLUGIN_EXE)
        .arg("--identity")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn the plugin");
    child
        .stdin
        .as_mut()
        .expect("stdin piped")
        .write_all(native.as_bytes())
        .expect("failed to write to plugin stdin");

    let out = child.wait_with_output().expect("failed to wait for plugin");
    assert!(
        out.status.success(),
        "identity conversion failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// Converting a native identity to plugin format needs only our own binary.
#[test]
fn plugin_converts_native_identity_to_plugin_format() {
    let native = fs::read_to_string("tests/data/age_go_identity.txt")
        .expect("failed to read tests/data/age_go_identity.txt")
        .trim()
        .to_owned();
    let converted = convert_native_fixture_to_plugin_identity();
    assert!(
        converted.starts_with("AGE-PLUGIN-PQ-"),
        "output is not a plugin identity"
    );
    assert_ne!(converted, native, "conversion must change the HRP");
}

/// Full round trip through the real age CLI: plugin discovery, the recipient
/// wire format and the stanza, exercised together.
///
/// `#[ignore]` because it shells out to a binary that may not be installed; a
/// normal `cargo test` reports it as ignored rather than silently passing. CI
/// runs it with `--include-ignored`.
///
/// This genuinely exercises **plugin discovery by name**: age spawns
/// `age-plugin-pq` itself and resolves it through `PATH`, which
/// `age_with_fresh_plugin_on_path` points at the binary built by this run.
///
/// Nothing needs to be installed, and nothing should be: a globally installed
/// plugin would be shadowed by the fresh one here, which is the intent — this
/// must test the current build, not whatever is on the machine.
///
/// `identity_hrp_matches_the_binary_name_age_will_look_for` covers the naming
/// half of the same coupling with no age binary at all.
#[test]
#[ignore = "requires age CLI >= 1.3; run with --include-ignored"]
fn full_encrypt_decrypt_cycle_through_the_age_cli() {
    let age_version = require_age_cli();
    eprintln!("plugin round trip against age {age_version}");

    let plaintext = fs::read("tests/data/lorem.txt").expect("failed to read lorem.txt");
    let (recipient, identity) = keygen();

    // Scratch files go in a temp dir, not tests/data: fixed names under the
    // fixture directory are not parallel-safe and leak on a failed assertion.
    let dir = TempDir::new().expect("failed to create temp dir");
    let recipient_file = dir.path().join("recipient.txt");
    let identity_file = dir.path().join("identity.key");
    let encrypted_file = dir.path().join("lorem.age");
    let decrypted_file = dir.path().join("lorem.out");
    fs::write(&recipient_file, recipient).expect("failed to write recipient");
    fs::write(&identity_file, identity).expect("failed to write identity");

    let encrypt = age_with_fresh_plugin_on_path()
        .arg("--encrypt")
        .arg("-R")
        .arg(&recipient_file)
        .arg("-o")
        .arg(&encrypted_file)
        .arg("tests/data/lorem.txt")
        .output()
        .expect("failed to run age --encrypt");
    assert!(
        encrypt.status.success(),
        "encryption failed: {}",
        String::from_utf8_lossy(&encrypt.stderr)
    );

    let decrypt = age_with_fresh_plugin_on_path()
        .arg("--decrypt")
        .arg("-i")
        .arg(&identity_file)
        .arg("-o")
        .arg(&decrypted_file)
        .arg(&encrypted_file)
        .output()
        .expect("failed to run age --decrypt");
    assert!(
        decrypt.status.success(),
        "decryption failed (age must be able to spawn age-plugin-pq): {}",
        String::from_utf8_lossy(&decrypt.stderr)
    );

    let decrypted = fs::read(&decrypted_file).expect("failed to read decrypted output");
    assert_eq!(
        decrypted, plaintext,
        "round trip did not reproduce the plaintext"
    );
}
