use age::Encryptor;
use age_pq_keys::HybridRecipient;
use std::fs;
use std::io::Write;
use std::iter::once;
use tempfile::NamedTempFile;

mod common;

const LOREM_FILE: &str = "tests/data/lorem.txt";

/// Encrypts with this crate and decrypts with the **real Go age CLI**, proving
/// the ciphertext we produce is readable by another implementation.
///
/// `#[ignore]` because it shells out to a binary that is not guaranteed to be
/// installed. A normal `cargo test` reports it as `ignored` — visibly, in the
/// result line — rather than silently passing. CI runs it via
/// `--include-ignored`, where a missing binary is a hard failure.
#[test]
#[ignore = "requires age CLI >= 1.3 on PATH; run with --include-ignored"]
fn test_create_and_verify_pq_encryption_with_cli() {
    let age_version = common::require_age_cli();
    eprintln!("interop against age {age_version}");

    // Generate PQ keys (same as binary)
    let (recipient, identity) = HybridRecipient::generate().unwrap();
    let recipient_str = recipient.to_string();
    let secret_str = identity.to_string();
    let identity_str = &secret_str;

    // Write to temp files (auto-cleaned up)
    let mut temp_recipient = NamedTempFile::new().unwrap();
    temp_recipient.write_all(recipient_str.as_bytes()).unwrap();
    let mut temp_identity = NamedTempFile::new().unwrap();
    temp_identity.write_all(identity_str.as_bytes()).unwrap();

    // Encrypt plaintext from lorem.txt
    let plaintext = fs::read(LOREM_FILE).unwrap();
    let mut encrypted = Vec::new();
    {
        let encryptor =
            Encryptor::with_recipients(once(&recipient as &dyn age::Recipient)).unwrap();
        let mut e = encryptor.wrap_output(&mut encrypted).unwrap();
        e.write_all(&plaintext).unwrap();
        e.finish().unwrap();
    }

    // Save encrypted to temp file
    let mut temp_encrypted = NamedTempFile::new().unwrap();
    temp_encrypted.write_all(&encrypted).unwrap();

    // Save decrypted to temp file
    let temp_decrypted = NamedTempFile::new().unwrap();

    // The identity must be age's *native* format. If this ever became
    // AGE-PLUGIN-PQ-, age would route to our own plugin and this test would
    // quietly stop being cross-implementation evidence.
    assert!(
        identity_str.starts_with("AGE-SECRET-KEY-PQ-"),
        "interop must use age's native identity format, got: {:.24}...",
        identity_str
    );

    // Decrypt with a PATH that cannot reach any age plugin, so age is forced
    // down its own native code path. See common::age_command_without_plugins.
    let output = common::age_command_without_plugins()
        .args([
            "-d",
            "-i",
            temp_identity.path().to_str().unwrap(),
            "-o",
            temp_decrypted.path().to_str().unwrap(),
            temp_encrypted.path().to_str().unwrap(),
        ])
        .output()
        .expect("age CLI failed");

    // Routed through `safe_stderr` rather than printed raw. `age -d -i FILE`
    // happens not to echo the key (it names the file instead), but the filter
    // is what makes that a property of the harness rather than of the callee.
    assert!(
        output.status.success(),
        "age CLI decryption failed: {}",
        common::safe_stderr(&output.stderr)
    );

    // Verify decrypted file matches lorem.txt exactly byte-for-byte
    assert_eq!(fs::read(temp_decrypted.path()).unwrap(), plaintext);
}

/// Self-test for the safeguard above, against synthetic input.
///
/// A filter that quietly matched nothing would restore the exact circularity it
/// exists to prevent, and every test would still pass. This checks the filter
/// itself rather than whatever the build left in `target/debug`, so it does not
/// depend on which crates were compiled.
#[test]
fn plugin_free_path_removes_directories_holding_plugins() {
    use std::path::PathBuf;

    let with_plugin = tempfile::tempdir().expect("tempdir");
    let clean = tempfile::tempdir().expect("tempdir");
    let odd_case = tempfile::tempdir().expect("tempdir");

    fs::write(with_plugin.path().join("age-plugin-synthetic"), b"x").expect("write");
    fs::write(clean.path().join("some-other-binary"), b"x").expect("write");
    // Windows and macOS filesystems are case-insensitive, so age would run this.
    fs::write(odd_case.path().join("AGE-PLUGIN-SYNTHETIC.EXE"), b"x").expect("write");

    let input: Vec<PathBuf> = vec![
        with_plugin.path().to_path_buf(),
        clean.path().to_path_buf(),
        odd_case.path().to_path_buf(),
    ];
    let kept = common::without_plugin_dirs(input);

    assert_eq!(
        kept,
        vec![clean.path().to_path_buf()],
        "only the directory with no age-plugin-* entry should survive"
    );
}
