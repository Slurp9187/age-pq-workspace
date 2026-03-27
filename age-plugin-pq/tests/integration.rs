use std::process::Command;
use std::fs;

// Note: This test requires:
// 1. The age CLI binary to be available in PATH
// 2. The age-plugin-xwing binary to be available in PATH or in target/debug/

#[test]
fn test_files_exist() {
    // Simple test to verify test data exists
    assert!(fs::metadata("tests/data/lorem.txt").is_ok(), "lorem.txt not found");
    assert!(fs::metadata("tests/data/age_go_identity.txt").is_ok(), "age_go_identity.txt not found");
}

#[test]
fn test_plugin_identity_conversion() {
    // Test that the plugin can convert native identities to plugin format
    // This is a core plugin functionality test that doesn't require age CLI

    // Find the plugin binary
    let plugin_path = if fs::metadata("target/debug/age-plugin-pq.exe").is_ok() {
        "target/debug/age-plugin-pq.exe"
    } else if fs::metadata("target/debug/age-plugin-pq").is_ok() {
        "target/debug/age-plugin-pq"
    } else if Command::new("age-plugin-pq").arg("--version").output().is_ok() {
        "age-plugin-pq"
    } else {
        println!("Skipping identity conversion test: age-plugin-pq binary not found");
        return;
    };

    println!("Testing identity conversion with: {}", plugin_path);

    // Use the native identity from our test data
    let native_identity = fs::read_to_string("tests/data/age_go_identity.txt")
        .expect("Failed to read tests/data/age_go_identity.txt")
        .trim()
        .to_string();

    // Verify it's a native PQ identity
    assert!(native_identity.starts_with("AGE-SECRET-KEY-PQ-"), "Test identity is not a native PQ identity");

    // Convert to plugin format
    println!("Converting: {}... (truncated)", &native_identity[..50]);
    let convert_output = Command::new(plugin_path)
        .args(["--identity"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn plugin for identity conversion");

    // Write the native identity to stdin
    {
        let mut stdin = convert_output.stdin.as_ref().unwrap();
        use std::io::Write;
        stdin.write_all(native_identity.as_bytes()).expect("Failed to write to plugin stdin");
    }

    let convert_result = convert_output.wait_with_output().expect("Failed to wait for plugin");
    assert!(convert_result.status.success(), "Identity conversion failed: {:?}", String::from_utf8_lossy(&convert_result.stderr));

    let plugin_identity = String::from_utf8_lossy(&convert_result.stdout).trim().to_string();
    println!("Converted to: {}... (truncated)", &plugin_identity[..50]);

    // Verify the conversion
    assert!(plugin_identity.starts_with("AGE-PLUGIN-PQ-"), "Output is not a plugin identity");
    assert!(plugin_identity.len() > 20, "Plugin identity seems too short");

    // Verify it's different from the input (different HRP)
    assert_ne!(plugin_identity, native_identity, "Plugin identity should be different from native identity");

    println!("✅ Identity conversion test passed");
}

#[test]
fn test_plugin_full_encrypt_decrypt_cycle() {
    // Test the complete plugin workflow: generate keys, encrypt, decrypt

    // Skip test if required binaries are not available
    if Command::new("age").arg("--version").output().is_err() {
        println!("Skipping full cycle test: age CLI not found in PATH");
        return;
    }

    let original_plaintext = fs::read("tests/data/lorem.txt")
        .expect("Failed to read tests/data/lorem.txt");

    // Find the plugin binary
    let plugin_path = if fs::metadata("target/debug/age-plugin-pq.exe").is_ok() {
        "target/debug/age-plugin-pq.exe"
    } else if fs::metadata("target/debug/age-plugin-pq").is_ok() {
        "target/debug/age-plugin-pq"
    } else if Command::new("age-plugin-pq").arg("--version").output().is_ok() {
        "age-plugin-pq"
    } else {
        println!("Skipping full cycle test: age-plugin-pq binary not found");
        return;
    };

    println!("Testing full plugin cycle with: {}", plugin_path);

    // Generate a plugin keypair
    let keygen_output = Command::new(plugin_path)
        .args(["--keygen"])
        .output()
        .expect("Failed to generate plugin keypair");

    assert!(keygen_output.status.success(), "Keygen failed: {:?}", String::from_utf8_lossy(&keygen_output.stderr));

    let keygen_stdout = String::from_utf8_lossy(&keygen_output.stdout);
    let lines: Vec<&str> = keygen_stdout.lines().collect();

    // Extract recipient and identity from keygen output
    // Format: ["# created: ...", "# public key: age1pq...", "AGE-PLUGIN-PQ-..."]
    let recipient_line = lines.get(1)
        .and_then(|line| line.strip_prefix("# public key: "))
        .expect("Could not extract recipient from keygen output");
    let identity_line = lines.last().expect("No identity found in keygen output");

    // Write to temp files
    let recipient_file = "tests/data/temp_recipient.txt";
    let identity_file = "tests/data/temp_identity.key";
    let encrypted_file = "tests/data/temp_encrypted.age";

    fs::write(recipient_file, recipient_line).expect("Failed to write recipient file");
    fs::write(identity_file, identity_line).expect("Failed to write identity file");

    // Encrypt with age CLI using plugin recipient
    let encrypt_output = Command::new("age")
        .args(["--encrypt", "-R", recipient_file, "-o", encrypted_file, "tests/data/lorem.txt"])
        .output()
        .expect("Failed to encrypt");

    assert!(encrypt_output.status.success(), "Encryption failed: {:?}", String::from_utf8_lossy(&encrypt_output.stderr));

    // Decrypt with age CLI using plugin identity
    let decrypt_output = Command::new("age")
        .args(["--decrypt", "-i", identity_file, "-o", "tests/data/temp_decrypted.txt", encrypted_file])
        .output()
        .expect("Failed to decrypt");

    assert!(decrypt_output.status.success(), "Decryption failed: {:?}", String::from_utf8_lossy(&decrypt_output.stderr));

    // Verify the decrypted content
    let decrypted = fs::read("tests/data/temp_decrypted.txt").expect("Failed to read decrypted file");
    assert_eq!(decrypted, original_plaintext, "Round-trip encryption/decryption failed");

    // Cleanup
    let _ = fs::remove_file(recipient_file);
    let _ = fs::remove_file(identity_file);
    let _ = fs::remove_file(encrypted_file);
    let _ = fs::remove_file("tests/data/temp_decrypted.txt");
}
