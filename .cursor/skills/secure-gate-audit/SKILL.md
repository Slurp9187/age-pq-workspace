---
name: secure-gate-audit
description: Audit and refactor Rust cryptographic code for compliance with Secure-Gate rules on type aliases, secret-memory hygiene, constant-time/anti-pattern constraints, test hygiene, and documentation maintenance. Use when the user asks for secure-gate compliance checks, crypto code audits, test quality audits, changelog/README reviews, or refactors to enforce the Secure-Gate rule files.
---

# Secure-Gate Audit Agent

## Purpose

Audit and refactor Rust code to comply with the Secure-Gate rule set used in this workspace.
Prioritize security and correctness over ergonomics.

Rule sources to enforce:
- `.cursor/rules/crypto-type-safety.mdc`
- `.cursor/rules/crypto-memory-safety.mdc`
- `.cursor/rules/crypto-comparison-antipatterns.mdc`
- `.cursor/rules/test-hygiene.mdc`
- `.cursor/rules/docs-changelog-readme.mdc`

## When to Apply

Apply this skill when the user asks to:
- audit crypto code
- enforce secure-gate conventions
- refactor for alias/type safety
- improve secret handling and zeroization
- check constant-time and anti-pattern compliance
- audit or improve test structure, naming, or quality
- review or update CHANGELOG.md and README.md for compliance

## Non-Negotiable Priorities

1. Security: type safety, memory hygiene, redaction, zeroization
2. Correctness: protocol and API contracts
3. Ergonomics: only where it does not weaken (1) or (2)

If a change removes wrappers for convenience or performance, reject it.

## Audit Workflow

1. Scope
   - Identify target files/modules from user request.
   - If unspecified, audit the crate/module currently being changed.

2. Load rules
   - Read all 5 Secure-Gate rule files before reporting findings.

3. Run a five-pass audit
   - Type Safety pass
   - Memory Safety pass
   - Comparison and Anti-Patterns pass
   - Test Hygiene pass
   - Documentation pass

4. Report findings first
   - List issues by severity and file.
   - Include why each issue matters and the required fix shape.

5. Refactor only with user confirmation
   - Apply minimal, targeted edits.
   - Re-run lints/tests where feasible.
   - Return a concise change summary plus remaining risks.

## Type Safety Pass Checklist

- Crypto data uses semantic aliases, not raw `[u8; N]` / `Vec<u8>`.
- Alias declarations are centralized in a single `aliases.rs` for the crate.
- Fixed alias names include byte-size suffix (`AeadKey32`, `Nonce12`, etc.).
- Visibility is minimally scoped (`pub` vs `pub(crate)`).
- If external naming is required, thin alias points to canonical size-suffixed alias.
- APIs accept `&AliasType` and return `AliasType` for crypto values.
- No `Display` implementations on secret-bearing types.
- Crates handling secret material use `#![forbid(unsafe_code)]` (or stricter).

## Memory Safety Pass Checklist

- `Fixed::new_with` used where in-place construction is feasible.
- Secret intermediates are wrapped with `zeroize::Zeroizing<T>`.
- Secret-bearing buffers are explicitly zeroized when required.
- No secrets stored in `static`.
- Panic/log/error strings do not interpolate secret values.
- Secret `Vec<u8>` uses pre-allocation when size is known.
- `CloneableSecret` / `SerializableSecret` uses are justified and audited.
- No `.to_vec()` / `.to_owned()` on `expose_secret()` output.
- No `Clone` or `Copy` derived on secret-bearing types.
- `Serialize` / `Deserialize` implemented manually (not derived) for secret types, with binary or Base64 format.
- Serialization error paths tested; no panic or log leakage on malformed input.
- RNG for real secrets is CSPRNG-backed; deterministic RNG stays in tests.
- Access patterns keep exposure scoped (`with_secret` preferred; tightly-scoped `expose_secret` allowed where nesting harms clarity).

## Comparison and Anti-Pattern Pass Checklist

- Crypto comparisons use `.ct_eq()` instead of `==`.
- No `PartialOrd` / `Ord` derived or implemented on crypto types.
- Bech32/bech32m decoding uses HRP-validated constructors unless explicitly justified.
- No broad raw-byte escape helpers (`get_bytes()`-style convenience APIs).
- No alias scattering across modules.
- Internal `pub(crate)` aliases re-exported via `pub use` are annotated `#[doc(hidden)]`.
- No forbidden anti-pattern from `.cursor/rules/crypto-comparison-antipatterns.mdc`.

## Test Hygiene Pass Checklist

- Test files use flat `tests/{area}_tests.rs` layout by default; suites use `tests/{area}_suite/` with submodule files.
- No `#[test]` functions hidden in `mod.rs` -- `mod.rs` may only declare submodules and apply feature gates.
- Single-concern features use a flat file, not a directory.
- Inline `#[cfg(test)] mod tests` in `src/` only for simple proof-of-concept tests; complex tests belong in `tests/*.rs`.
- Test files open with a `//!` doc comment describing scope and strategy.
- Test function names follow `{type_or_feature}_{scenario}` pattern; no `fn test_foo()` style.
- No duplicate tests covering the same contract with the same inputs.
- Every `#[test]` fn asserts something meaningful and will fail if the contract breaks.
- Shared helpers and fixtures live in `tests/common.rs`, not duplicated.
- Tests requiring optional features are gated with `#[cfg(feature = "...")]`.
- Tests requiring global state or custom harness are in their own top-level `tests/*.rs` binary.
- Compile-fail invariants live in `tests/compile-fail/` with `.stderr` golden files and a trybuild driver.
- KAT test vectors are sourced from published specs and labeled with the source (RFC, NIST, etc.).
- Proptest suites exist for contracts that must hold across all valid inputs (roundtrips, CT-eq symmetry).
- `#[should_panic]` not used; error variants are asserted explicitly.
- `#[ignore]` has an explanatory comment; no silent ignored tests.
- `-> Result<(), E>` test signatures used where applicable.
- If `rust-version` is declared in `Cargo.toml`, all test/clippy/doc runs use the MSRV toolchain (`cargo +{msrv} test`).
- `cargo test --doc --tests`, `cargo clippy --all-targets -- -D warnings`, and `cargo doc --no-deps` all pass.
- If optional features exist, `--all-features` and `--no-default-features` runs are also required and any issues are fixed.
- `cargo miri test` passes on core crypto and zeroization test paths.

## Documentation Pass Checklist

- Every user-visible change in scope has a corresponding `[Unreleased]` entry in the appropriate CHANGELOG.md.
- Entry is in the correct changelog (package-scoped change → package changelog; cross-cutting → workspace root changelog; multi-crate → both with summary at root).
- No entry duplicates full text across package and workspace changelogs.
- No entry incorrectly placed under a dated release heading (only acceptable as an explicit amendment with a date note).
- README.md examples still match the current public API.
- No stale feature flags, installation instructions, or algorithm tables in any README.
- README code blocks use the correct fence annotation (` ```rust `, ` ```rust,no_run `, or ` ```rust,ignore `).

## Refactor Guidance

- Preserve public API unless user requested API changes.
- Prefer small, reviewable edits over broad rewrites.
- Keep wrappers canonical and explicit.
- Keep secret exposure windows as short as possible.

## Required Search Terms During Audit

Search for explicit exposure/materialization points:
- `expose_secret`
- `expose_secret_mut`
- `with_secret`
- `with_secret_mut`
- `to_vec`, `to_owned` (near `expose_secret`)
- `derive(Clone)`, `derive(Copy)` (on types containing wrappers)
- `derive(Serialize)`, `derive(Deserialize)` (on secret types)
- `to_hex`
- `to_base64url`
- `try_to_bech32`
- `try_to_bech32m`

## Output Format

When returning an audit or refactor summary, use:

```markdown
## Secure-Gate Audit

- Scope: <files/modules>
- Rules checked: type-safety, memory-safety, comparison/anti-patterns, test-hygiene, documentation
- Critical: <count>
- High: <count>
- Medium: <count>
- Low: <count>

### Findings
- [Severity] <file>: <issue> -> <required fix>

### Refactor Plan
- <edit 1>
- <edit 2>

### Applied Changes
- <what was changed>

### Remaining Risks / Open Questions
- <item>
```

## Anti-Patterns for This Skill

Avoid:
- vague "looks good" reviews without rule-mapped checks
- security claims without code evidence
- large speculative refactors unrelated to violations
- skipping lints/tests after substantive edits when verification is available
