use std::process::Command;

/// Setting this makes a missing `age` CLI a hard failure instead of a skip.
///
/// A skipped test reports as **passed**. Without this gate an interop suite is
/// green whether or not it ever ran, which is indistinguishable, in any
/// dashboard, from a suite that actually passed. CI sets it; local runs
/// generally do not, so developers without the binary still get a useful run.
const REQUIRED_ENV: &str = "AGE_INTEROP_REQUIRED";

/// Minimum age CLI version: 1.3.0 is the first release with native
/// post-quantum support (`mlkem768x25519`).
const MIN_MAJOR: u32 = 1;
const MIN_MINOR: u32 = 3;

/// Returns the reported version string, or `None` if the binary is absent or
/// unrunnable.
fn age_cli_version() -> Option<String> {
    let output = Command::new("age").arg("--version").output().ok()?;
    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if raw.is_empty() {
        return None;
    }
    Some(raw)
}

/// Returns `true` when the caller should proceed with an age-CLI interop test.
///
/// * binary present and new enough — `true`
/// * binary present but too old — panics; that is a misconfigured environment,
///   not a reason to silently pass
/// * binary absent — panics when `AGE_INTEROP_REQUIRED` is set, otherwise
///   prints a skip notice and returns `false`
#[allow(dead_code)] // not every test binary that includes this module uses it
pub fn require_age_cli() -> bool {
    let raw = match age_cli_version() {
        Some(v) => v,
        None => {
            if std::env::var_os(REQUIRED_ENV).is_some() {
                panic!(
                    "age CLI not found, but {REQUIRED_ENV} is set. Install age \
                     >= {MIN_MAJOR}.{MIN_MINOR}.0 or unset {REQUIRED_ENV} to skip."
                );
            }
            eprintln!(
                "SKIPPED: age CLI not available (set {REQUIRED_ENV}=1 to make this a failure)"
            );
            return false;
        }
    };

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
             (native post-quantum support), found {raw:?}"
        );
    }
    true
}
