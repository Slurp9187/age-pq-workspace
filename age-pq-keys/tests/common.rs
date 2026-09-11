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

// ---------------------------------------------------------------------------
// rage CLI gates
// ---------------------------------------------------------------------------
//
// rage's post-quantum work lives on its `pq` branch, which has no tagged
// release, so there is no installer to point at the way `scripts/install-age.sh`
// points at a pinned age tarball. The binary is located by environment variable
// first and `PATH` second.

/// Environment variable naming the `rage` binary to test against.
#[allow(dead_code)]
pub const RAGE_BIN_ENV: &str = "RAGE_BIN";

/// Environment variable naming the `rage-keygen` binary to test against.
#[allow(dead_code)]
pub const RAGE_KEYGEN_BIN_ENV: &str = "RAGE_KEYGEN_BIN";

/// Minimum rage version. rage 0.12's `pq` branch is the first to carry
/// `mlkem768x25519`; the released 0.12.1 carries only `mlkem768p256tag`, so the
/// version gate alone cannot tell them apart — see [`require_rage_cli`].
const RAGE_MIN_MAJOR: u32 = 0;
const RAGE_MIN_MINOR: u32 = 12;

/// Asserts a `pq`-capable rage is available, returning its version string.
///
/// Panics rather than skipping, for the reason spelled out on
/// [`require_age_cli`]: these tests are `#[ignore]`d, so arriving here means the
/// runner asked for them explicitly and a missing binary is a failure.
///
/// **The version number is not sufficient evidence.** rage 0.12.1 exists as a
/// release *and* as the `pq` branch, and only the branch build implements
/// `mlkem768x25519`; both answer `--version` identically. So the real gate is
/// [`require_rage_pq_support`], which asks the binary to produce a pq keypair
/// and fails if it cannot. A version check alone would let a released rage
/// silently turn every differential below into a no-op.
#[allow(dead_code)]
pub fn require_rage_cli() -> String {
    require_rage_version("rage", rage_command())
}

/// The same gate for `rage-keygen`, a separate binary.
#[allow(dead_code)]
pub fn require_rage_keygen_cli() -> String {
    require_rage_version("rage-keygen", rage_keygen_command())
}

fn require_rage_version(program: &str, mut command: Command) -> String {
    let output = command.arg("--version").output().unwrap_or_else(|e| {
        panic!(
            "{program} not found ({e}). These tests are #[ignore]d and only run when explicitly \
             requested. Build rage's `pq` branch and point {RAGE_BIN_ENV} / \
             {RAGE_KEYGEN_BIN_ENV} at the binaries, or put them on PATH. The released rage is \
             NOT sufficient: only the `pq` branch implements mlkem768x25519."
        )
    });
    if !output.status.success() {
        panic!("{program} --version exited {:?}", output.status.code());
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let version = text.split_whitespace().nth(1).unwrap_or_default();
    let mut parts = version.split('.');
    let major: u32 = parts.next().unwrap_or("0").parse().unwrap_or(0);
    let minor: u32 = parts.next().unwrap_or("0").parse().unwrap_or(0);
    if (major, minor) < (RAGE_MIN_MAJOR, RAGE_MIN_MINOR) {
        panic!(
            "{program} {version} is older than {RAGE_MIN_MAJOR}.{RAGE_MIN_MINOR}; \
             mlkem768x25519 needs rage's `pq` branch"
        );
    }
    text
}

/// Proves the located rage actually implements `mlkem768x25519`, not merely
/// that it reports a new enough version.
///
/// Returns the recipient it generated, so the caller can assert on its HRP.
/// This is the check that distinguishes a `pq`-branch build from the released
/// 0.12.1, which answers `--version` the same way and would otherwise make
/// every differential here pass by never exercising the format.
#[allow(dead_code)]
pub fn require_rage_pq_support() -> String {
    let output = rage_keygen_command()
        .output()
        .expect("rage-keygen must run after the version gate passed");
    if !output.status.success() {
        panic!("rage-keygen failed: {}", safe_stderr(&output.stderr));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let recipient = text
        .lines()
        .find_map(|l| l.strip_prefix("# public key: "))
        .unwrap_or_else(|| {
            panic!("rage-keygen printed no `# public key:` line; output shape changed")
        })
        .trim()
        .to_string();
    assert!(
        recipient.starts_with("age1pq"),
        "rage-keygen produced a `{}` recipient, not `age1pq…`. This is the released rage, which \
         has no mlkem768x25519 — build the `pq` branch and point {RAGE_BIN_ENV} at it.",
        &recipient[..recipient.len().min(8)]
    );
    recipient
}

fn rage_program() -> std::path::PathBuf {
    if let Some(p) = std::env::var_os(RAGE_BIN_ENV) {
        return std::path::PathBuf::from(p);
    }
    resolve_on_unfiltered_path("rage").unwrap_or_else(|| std::path::PathBuf::from("rage"))
}

fn rage_keygen_program() -> std::path::PathBuf {
    if let Some(p) = std::env::var_os(RAGE_KEYGEN_BIN_ENV) {
        return std::path::PathBuf::from(p);
    }
    resolve_on_unfiltered_path("rage-keygen")
        .unwrap_or_else(|| std::path::PathBuf::from("rage-keygen"))
}

fn rage_command_for(program: std::path::PathBuf) -> Command {
    let mut cmd = Command::new(program);
    // Same reasoning as `command_without_plugins`: rage resolves plugins with
    // `which::which`, so an installed `age-plugin-pq` on PATH would let it test
    // our plugin instead of its own native path.
    match std::env::join_paths(plugin_free_path()) {
        Ok(path) => {
            cmd.env("PATH", path);
        }
        Err(e) => panic!("could not rebuild a plugin-free PATH: {e}"),
    }
    cmd
}

/// A `rage` command whose child `PATH` cannot reach any age plugin.
#[allow(dead_code)]
pub fn rage_command() -> Command {
    rage_command_for(rage_program())
}

/// A `rage-keygen` command whose child `PATH` cannot reach any age plugin.
#[allow(dead_code)]
pub fn rage_keygen_command() -> Command {
    rage_command_for(rage_keygen_program())
}

// ---------------------------------------------------------------------------
// Shared differential-oracle case generation
// ---------------------------------------------------------------------------
//
// Lives here rather than in one oracle file because there are now two oracles
// — the Go `age` CLI and rage — and they deliberately run the **same matrix**.
// That is the point: when two implementations disagree, you want the
// disagreement attributable to the implementation and not to the inputs. Two
// copies of this generator would be two places for the matrices to drift apart,
// at which point "rage agrees with us" and "age-go agrees with us" would stop
// being comparable statements.

use secure_gate::{Case, EncodedSecret, ToBech32, fixed_newtype};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

fixed_newtype!(
    pub OracleSeed32,
    32,
    "Per-case oracle seed, derived from the case index. This is a private key."
);

/// Re-declared rather than imported from `age_pq_keys`, where it is private —
/// and that is the point. If the crate's HRP ever changed, the oracles would
/// keep emitting this one, `HybridIdentity::parse` would reject it, and the
/// change would fail loudly instead of silently redefining what is compared.
///
/// Lowercase, with `Case::Upper`: the encoder uppercases the whole string, HRP
/// included. Passing an already-uppercase HRP is a different (and wrong) thing.
#[allow(dead_code)]
pub const IDENTITY_HRP: &str = "age-secret-key-pq-";

/// Domain separators for the derived case matrix.
///
/// **The literals still say `differential-age-go` and must not be renamed.**
/// These bytes are an input to every derived seed and plaintext, so changing
/// the string moves every case in the matrix and invalidates
/// `GENERATOR_DIGEST` — a digest that was pinned from a run in which all 64
/// derivation cases passed against a real age-go binary. The name is
/// historical; the matrix is shared by both oracles. Renaming the Rust
/// constants is free, renaming the bytes is not.
const SEED_DOMAIN: &[u8] = b"age-pq-workspace/differential-age-go/v1/seed";
const PLAINTEXT_DOMAIN: &[u8] = b"age-pq-workspace/differential-age-go/v1/plaintext";

/// Plaintext sizes, cycled by case index.
///
/// 65_536 is age's STREAM chunk size (`age-0.12.1/src/primitives/stream.rs:22`,
/// `CHUNK_SIZE = 64 * 1024`); 131_072 is exactly two chunks. Those two are the
/// interesting ones: an exact multiple forces the encryptor to flag a *full*
/// chunk as last rather than emit an empty one, and the reader rejects an empty
/// final chunk outright. The small sizes bracket the AEAD block boundary.
#[allow(dead_code)]
pub const PLAINTEXT_LENGTHS: &[usize] =
    &[0, 1, 15, 16, 17, 64, 1024, 65_535, 65_536, 65_537, 131_072];

/// How many individual failures a panic message lists before summarising.
const MAX_REPORTED_FAILURES: usize = 10;

/// The per-case seed: `SHA-256(domain ‖ be32(case))`.
///
/// Derived rather than sampled so a failure at case 41 is reproducible on any
/// machine by running case 41 — which matters enormously here, because the
/// input that reproduces the failure is a private key and must never be
/// printed. Randomised cases would force the harness to choose between an
/// unreproducible failure and dumping key material into CI logs.
#[allow(dead_code)]
pub fn seed_for_case(case: usize) -> OracleSeed32 {
    let mut h = Sha256::new();
    h.update(SEED_DOMAIN);
    h.update((case as u32).to_be_bytes());
    let digest = h.finalize();
    // `new_with` writes straight into the wrapper's storage; `new` would move a
    // value that briefly existed on this frame.
    OracleSeed32::new_with(|out| out.copy_from_slice(&digest))
}

/// The case's identity in age's native uppercase form.
///
/// `EncodedSecret` zeroizes on drop and cannot be `Display`ed, so this value
/// cannot reach a panic message by accident.
#[allow(dead_code)]
pub fn identity_for_case(case: usize) -> EncodedSecret {
    seed_for_case(case)
        .try_to_bech32(IDENTITY_HRP, Case::Upper)
        .expect("a 32-byte seed always encodes")
}

/// Public, deterministic plaintext for a case: SHA-256 counter mode, truncated.
#[allow(dead_code)]
pub fn plaintext_for_case(case: usize) -> Vec<u8> {
    let len = PLAINTEXT_LENGTHS[case % PLAINTEXT_LENGTHS.len()];
    let mut out = Vec::with_capacity(len);
    let mut block: u32 = 0;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(PLAINTEXT_DOMAIN);
        h.update((case as u32).to_be_bytes());
        h.update(block.to_be_bytes());
        let digest = h.finalize();
        let take = std::cmp::min(digest.len(), len - out.len());
        out.extend_from_slice(&digest[..take]);
        block += 1;
    }
    out
}

/// `encoding-hex` is not enabled on secure-gate in this workspace, so hex is
/// hand-rolled — only ever applied to public digests.
#[allow(dead_code)]
pub fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// A short, stable handle for a **public** string.
///
/// Cases drawn from an implementation's own CSPRNG cannot be re-run by index
/// and need *some* correlator across several messages. The recipient itself is
/// public and would do, but it is ~1959 characters; eight failing cases once
/// emitted ~16 KB of bech32 into one panic message and buried the part a reader
/// needs. A truncated digest plus the length is enough to correlate.
#[allow(dead_code)]
pub fn public_handle(s: &str) -> String {
    let digest = hex_encode(&Sha256::digest(s.as_bytes()));
    format!("sha256:{}… ({} chars)", &digest[..12], s.len())
}

/// Turns per-case failures into one panic, capped so a systemic break cannot
/// bury the log.
///
/// `oracle` names the implementation under test, so a reader of a bare CI log
/// can tell an age-go disagreement from a rage one without checking which
/// target produced it.
#[allow(dead_code)]
pub fn report(differential: &str, oracle: &str, total: usize, failures: Vec<String>) {
    if failures.is_empty() {
        return;
    }
    let mut msg = format!(
        "{differential}: {} of {total} case(s) failed against {oracle}\n",
        failures.len()
    );
    for line in failures.iter().take(MAX_REPORTED_FAILURES) {
        msg.push_str("  - ");
        msg.push_str(line);
        msg.push('\n');
    }
    if failures.len() > MAX_REPORTED_FAILURES {
        let _ = writeln!(
            msg,
            "  … and {} more",
            failures.len() - MAX_REPORTED_FAILURES
        );
    }
    msg.push_str(
        "re-run a single case by index; the inputs are derived, so nothing secret needs printing",
    );
    panic!("{msg}");
}
