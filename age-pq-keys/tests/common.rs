// Shared helper module, included via `mod common;` by several test binaries.
// `unreachable_pub` is allowed here because that include idiom is exactly what
// the lint flags: each binary compiles the whole module but uses only part of
// it, and there is no crate boundary for these helpers to be reachable across.
#![allow(unreachable_pub)]

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
///
/// The gate goes through [`age_command_without_plugins`] rather than a bare
/// `Command::new("age")` on purpose: the version this returns is printed in test
/// banners and is the only record in a CI log of *what was exercised*. If the
/// gate and the differentials resolved the program differently — a wrapper
/// script, a shim, an extensionless file earlier on `PATH` — the banner would
/// name a binary that never ran.
#[allow(dead_code)] // not every test binary including this module uses it
pub fn require_age_cli() -> String {
    require_cli("age", age_command_without_plugins())
}

/// The same gate for `age-keygen`, which is a separate binary and can be a
/// separate version.
///
/// `age-keygen` is checked separately rather than folded into
/// [`require_age_cli`] because most interop tests here never spawn it; a box
/// with `age` but no `age-keygen` should fail at the gate of the tests that
/// need it, naming the missing binary, rather than inside a differential.
#[allow(dead_code)]
pub fn require_age_keygen_cli() -> String {
    require_cli("age-keygen", age_keygen_command_without_plugins())
}

/// Shared body of the two gates: run `<program> --version`, parse `vMAJOR.MINOR`,
/// and panic with an actionable message on anything short of the minimum.
fn require_cli(program: &str, mut command: Command) -> String {
    let output = command.arg("--version").output().unwrap_or_else(|e| {
        panic!(
            "{program} not found on PATH ({e}). These tests are #[ignore]d and only run when \
             explicitly requested. Install age >= {MIN_MAJOR}.{MIN_MINOR}.0 — \
             scripts/install-age.sh does it with a pinned, checksum-verified release."
        )
    });

    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let version = raw.trim_start_matches('v');
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() < 2 {
        panic!("could not parse the {program} version: {raw:?}");
    }
    let major: u32 = parts[0].parse().unwrap_or(0);
    let minor: u32 = parts[1].parse().unwrap_or(0);
    if major < MIN_MAJOR || (major == MIN_MAJOR && minor < MIN_MINOR) {
        panic!(
            "these tests require {program} >= {MIN_MAJOR}.{MIN_MINOR}.0 \
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
/// This matters more than it looks. If an identity in these tests ever routed
/// through an age plugin, "interoperability with the Go age CLI" would silently
/// become "interoperability with our own code", and the test would keep passing
/// while proving nothing.
///
/// Two ways that becomes reachable:
///
/// * **A globally installed plugin.** Anyone who has run `cargo install` for
///   `age-plugin-pq`, on any platform, has it on `PATH`.
/// * **On Windows, the build directory itself.** Cargo adds the build output
///   directory to the *dynamic library* search path for test processes — which
///   is `PATH` on Windows, but `LD_LIBRARY_PATH` on Unix. So `target/debug` is
///   on `PATH` for Windows test runs and not for Linux ones. Do not rely on
///   that asymmetry in either direction; it is incidental.
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

/// Resolves `program` to an absolute path using the **unfiltered** `PATH`.
///
/// Program resolution and plugin blocking are two different jobs, and conflating
/// them is a real hazard rather than a theoretical one: the WinGet `age` package
/// ships `age-plugin-batchpass.exe` in the *same directory* as `age.exe`, so
/// [`plugin_free_path`] strips the only directory that holds age itself.
///
/// That is survivable on Windows purely by accident — when the child's `PATH`
/// does not resolve the program, Rust falls back to the parent's. On Unix, Rust
/// deliberately avoids `posix_spawnp` once the environment is overridden and
/// resolves through the *child's* `PATH`, so the same layout would fail to spawn
/// with `ENOENT`. Resolving to an absolute path first removes the whole class of
/// problem, and leaves the filtered `PATH` doing only the job it exists for:
/// what the child sees when *it* goes looking for `age-plugin-*`.
///
/// Returns `None` if nothing matched, in which case the caller falls back to the
/// bare name and lets `Command` produce its own error.
///
/// The two ordering/acceptance rules below exist so this matches what the OS
/// itself would have done, rather than approximating it:
///
/// * **Unix: the exec bit is part of the match.** `execvp` skips a
///   non-executable candidate and keeps searching; returning one here would
///   turn a resolvable program into a hard `EACCES` spawn failure.
/// * **Windows: PATHEXT variants come first.** `CreateProcess` appends an
///   extension before trying the bare name, so an extensionless MSYS-style
///   `age` shim earlier on `PATH` must not win over a later `age.exe` — it
///   would spawn and fail with "not a valid Win32 application".
#[allow(dead_code)]
fn resolve_on_unfiltered_path(program: &str) -> Option<std::path::PathBuf> {
    // On Windows a bare name is not executable on its own; PATHEXT decides, and
    // the extension variants are tried *before* it.
    let mut candidates: Vec<String> = Vec::new();
    if cfg!(windows) {
        let pathext = std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_owned())
            .to_ascii_lowercase();
        for ext in pathext.split(';').filter(|e| !e.is_empty()) {
            candidates.push(format!("{program}{ext}"));
        }
    }
    candidates.push(program.to_owned());

    let raw = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&raw) {
        for name in &candidates {
            let candidate = dir.join(name);
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

/// A regular file the OS would actually be willing to execute.
#[cfg(unix)]
#[allow(dead_code)]
fn is_executable_file(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|md| md.is_file() && md.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// Windows has no exec bit; PATHEXT (handled by the caller) is the whole story.
#[cfg(not(unix))]
#[allow(dead_code)]
fn is_executable_file(path: &std::path::Path) -> bool {
    path.is_file()
}

/// Builds a command for `program`, resolved absolutely, whose child `PATH`
/// cannot reach any age plugin.
#[allow(dead_code)]
fn command_without_plugins(program: &str) -> Command {
    let resolved =
        resolve_on_unfiltered_path(program).unwrap_or_else(|| std::path::PathBuf::from(program));
    let mut cmd = Command::new(resolved);
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

/// Builds an `age` command that cannot reach any age plugin.
#[allow(dead_code)]
pub fn age_command_without_plugins() -> Command {
    command_without_plugins("age")
}

/// Builds an `age-keygen` command that cannot reach any age plugin.
///
/// `age-keygen` never spawns a plugin itself, so the filtered `PATH` is
/// belt-and-braces here — but going through the same constructor as `age` means
/// there is no second, unfiltered spawn path for someone to reach for later.
#[allow(dead_code)]
pub fn age_keygen_command_without_plugins() -> Command {
    command_without_plugins("age-keygen")
}

/// Renders a child's stderr for a panic message with identity strings removed.
///
/// Not paranoia: `age-keygen -y` echoes the **entire** input identity in its
/// error when it cannot parse it (`unknown identity type: "age-secret-key-pq-…"`,
/// verified by exact-substring match against the full key). `age -d -i FILE`
/// does not — it substitutes the filename — so the behaviour is asymmetric and
/// cannot be reasoned about per call site reliably. Filter at the one place that
/// turns bytes into a message instead.
///
/// Whitespace is collapsed as a side effect. That is fine for a diagnostic and
/// is what makes the token filter simple enough to be obviously correct.
#[allow(dead_code)]
pub fn safe_stderr(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .split_whitespace()
        .map(|token| {
            if token.to_ascii_uppercase().contains("AGE-SECRET-KEY") {
                "[REDACTED-IDENTITY]"
            } else {
                token
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
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
