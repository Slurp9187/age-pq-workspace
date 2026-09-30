//! Source guard: no `into_inner()` on secret wrappers anywhere under `src/kem/`.
//!
//! `into_inner` moves a secret out of its zeroize-on-drop wrapper into a plain
//! value, which is how the ML-KEM seed, the encapsulation randomness, the
//! X25519/X448 scalars and the combined shared secret used to leave `kem/` as
//! unwiped arrays. Every one of those now goes through `with_secret` (the
//! wrapper keeps ownership and wipes its own storage) or stays wrapped.
//!
//! Everything a `kem/` wrapper holds is secret or is wrapped for auditability,
//! so this is a blanket ban on the directory rather than a per-type list that
//! could miss a new alias. If a genuine need ever arises, change this test in
//! the same commit and say why there.
//!
//! A textual scan is a lower bound, not proof (CLAUDE.md: *an audit grep is a
//! lower bound*). It catches the method-call spelling, which is the only one
//! the code has ever used; a UFCS `RevealSecret::into_inner(x)` would also
//! match, because the pattern is the method name followed by `(`.

use std::fs;
use std::path::{Path, PathBuf};

const PATTERN: &str = "into_inner(";

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("src/kem is readable") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Code part of a line: everything before a `//` comment. Good enough here —
/// no string literal in `kem/` contains `//` next to the pattern.
fn code_of(line: &str) -> &str {
    line.split("//").next().unwrap_or("")
}

fn offenders(source: &str) -> Vec<usize> {
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| code_of(line).contains(PATTERN))
        .map(|(i, _)| i + 1)
        .collect()
}

#[test]
fn no_into_inner_on_secret_wrappers_in_kem() {
    let kem = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/kem");
    let mut files = Vec::new();
    rust_files(&kem, &mut files);

    // Guard the guard: a wrong path or an emptied directory must fail, not
    // pass vacuously. `kem/` holds 10 files today (mod, common, combiner,
    // x25519, x448, mlkem768x25519, ml_kem/{mod,512,768,1024}).
    assert!(
        files.len() >= 10,
        "scanned only {} files under {} — the scan is not looking where the code is",
        files.len(),
        kem.display()
    );

    let mut hits = Vec::new();
    for file in &files {
        let source = fs::read_to_string(file).expect("source file is readable");
        for line in offenders(&source) {
            hits.push(format!("{}:{line}", file.display()));
        }
    }
    assert!(
        hits.is_empty(),
        "`into_inner()` moves a secret out of its wrapper into an unwiped value; \
         use `with_secret(|s| ...)` instead:\n  {}",
        hits.join("\n  ")
    );
}

/// The matcher itself: flags code, ignores comments. Without this, a matcher
/// that never matched anything would keep the guard above green forever.
#[test]
fn the_matcher_flags_code_and_ignores_comments() {
    assert_eq!(offenders("    X::from(s.into_inner())"), vec![1]);
    assert_eq!(offenders("    RevealSecret::into_inner(s)"), vec![1]);
    assert_eq!(
        offenders("    // `into_inner()` would move it out"),
        Vec::<usize>::new()
    );
    assert_eq!(
        offenders("let a = 1; // s.into_inner()"),
        Vec::<usize>::new()
    );
}
