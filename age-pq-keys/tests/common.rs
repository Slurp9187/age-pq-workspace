use std::process::Command;

/// Minimum age CLI version: 1.3.0 is the first release with native
/// post-quantum support (`mlkem768x25519`).
const MIN_MAJOR: u32 = 1;
const MIN_MINOR: u32 = 3;

/// Asserts an age CLI of at least 1.3.0 is on `PATH`, returning its version.
///
/// This **panics** rather than skipping. Tests that need the binary are marked
/// `#[ignore]`, so reaching this function means the runner explicitly asked for
/// them (`--include-ignored`) — at which point a missing binary is a failure,
/// not a reason to report success.
///
/// The previous design auto-detected the binary and returned `false` to skip.
/// That was worse than it looked: the libtest harness captures stderr for
/// passing tests, so the `SKIPPED` notice was never displayed, and a developer
/// without the binary saw a plain `ok`. `#[ignore]` puts the same information
/// in the result line itself, where it cannot be swallowed.
#[allow(dead_code)] // not every test binary including this module uses it
pub fn require_age_cli() -> String {
    let output = Command::new("age")
        .arg("--version")
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "age CLI not found on PATH ({e}). These tests are #[ignore]d and only run when \
             explicitly requested. Install age >= {MIN_MAJOR}.{MIN_MINOR}.0 — \
             scripts/install-age.sh does it with a pinned, checksum-verified release."
            )
        });

    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let version = raw.trim_start_matches('v');
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() < 2 {
        panic!("could not parse age CLI version: {raw:?}");
    }
    let major: u32 = parts[0].parse().unwrap_or(0);
    let minor: u32 = parts[1].parse().unwrap_or(0);
    if major < MIN_MAJOR || (major == MIN_MAJOR && minor < MIN_MINOR) {
        panic!(
            "these tests require age CLI >= {MIN_MAJOR}.{MIN_MINOR}.0 \
             (first release with native post-quantum support), found {raw:?}"
        );
    }
    raw
}
