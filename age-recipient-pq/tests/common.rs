use std::process::Command;

pub fn check_age_cli_version() -> bool {
    // Check age CLI version >= 1.3.0
    let version_output = match Command::new("age").arg("--version").output() {
        Ok(output) => output,
        Err(_) => return false, // age CLI not found
    };
    let version_raw = String::from_utf8_lossy(&version_output.stdout)
        .trim()
        .to_string();
    let version = version_raw.trim_start_matches('v');
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() < 2 {
        panic!("Invalid version format: {}", version_raw);
    }
    let major: u32 = parts[0].parse().unwrap_or(0);
    let minor: u32 = parts[1].parse().unwrap_or(0);
    if major < 1 || (major == 1 && minor < 3) {
        panic!("Test requires age CLI >= 1.3.0, found: {}", version_raw);
    }
    true
}
