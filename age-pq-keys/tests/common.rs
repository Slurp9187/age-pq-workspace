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

/// Removes every directory containing an `age-plugin-*` binary.
///
/// Pure so it can be tested against synthetic input rather than whatever the
/// build happened to leave in `target/debug`.
#[allow(dead_code)]
pub fn without_plugin_dirs(paths: Vec<std::path::PathBuf>) -> Vec<std::path::PathBuf> {
    paths
        .into_iter()
        .filter(|d| !contains_age_plugin(d))
        .collect()
}

/// The process `PATH`, minus any directory holding an age plugin.
///
/// This matters more than it looks. Cargo puts the build output directory
/// (`target/debug`) on `PATH` for test processes, so `age-plugin-pq` — built by
/// this very workspace — is reachable by default. If an identity in these tests
/// ever routed through that plugin, "interoperability with the Go age CLI"
/// would silently become "interoperability with our own code", and the test
/// would keep passing while proving nothing.
///
/// `PATH` is the only lever needed: age-go resolves plugins with
/// `exec.Command("age-plugin-" + name)` and rage with `which::which`. Neither
/// consults an environment variable, a plugin directory, or a config file, and
/// on Go 1.19+ `exec` no longer resolves silently from the working directory.
///
/// The plugin's own tests deliberately do the opposite — see
/// `age-plugin-pq/tests/integration.rs`, where Cargo putting the fresh binary
/// on `PATH` is exactly what makes discovery testable.
#[allow(dead_code)]
pub fn plugin_free_path() -> Vec<std::path::PathBuf> {
    without_plugin_dirs(
        std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
            .unwrap_or_default(),
    )
}

/// Builds an `age` command that cannot reach any age plugin.
#[allow(dead_code)]
pub fn age_command_without_plugins() -> Command {
    let mut cmd = Command::new("age");
    match std::env::join_paths(plugin_free_path()) {
        Ok(path) => {
            cmd.env("PATH", path);
        }
        // Refuse to fall back to the unfiltered PATH: a silently circular test
        // is worse than a failing one.
        Err(e) => panic!("could not rebuild a plugin-free PATH: {e}"),
    }
    cmd
}

/// True if `dir` holds anything named `age-plugin-*`.
///
/// Case-insensitive on purpose: Windows and macOS filesystems are, so age would
/// happily execute `AGE-PLUGIN-PQ.EXE` when looking for `age-plugin-pq`. A
/// case-sensitive check would miss it. The prefix match also covers the
/// `PATHEXT` variants (`.exe`, `.bat`, `.cmd`) and the `.exe` form rage looks
/// for when running under WSL.
#[allow(dead_code)]
pub fn contains_age_plugin(dir: &std::path::Path) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    entries.filter_map(Result::ok).any(|e| {
        e.file_name()
            .to_string_lossy()
            .to_ascii_lowercase()
            .starts_with("age-plugin-")
    })
}
