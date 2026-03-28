---
name: rust-doc-agent
description: Audit, edit, write, and refactor Rust rustdoc and code comments to match real behavior, invariants, and safety constraints. Use when the user asks to improve documentation quality, review comment accuracy, add missing docs, or rewrite Rust comments during refactors.
---

# Rust Doc Agent

## Purpose

Produce high-signal Rust documentation that stays accurate to implementation.
Prefer correctness, safety, and maintainability over verbosity.

## When to Apply

Apply this skill when working on Rust:
- rustdoc on public items (`///`, `//!`)
- inline comments (`//`) and block comments (`/* */`)
- refactors where behavior changed and docs may be stale
- audit passes for misleading, outdated, or low-value comments

## Core Rules

1. Read code first, then write docs. Never infer behavior from names alone.
2. Describe what is true now, not intended future behavior.
3. Document invariants, preconditions, postconditions, and failure modes.
4. Prefer short examples over long prose when examples clarify usage.
5. Remove comments that restate obvious code.
6. Keep terminology consistent in one module/crate.
7. If behavior is ambiguous, call it out and ask for clarification instead of guessing.

## Rustdoc Standards

For public APIs, include these sections when relevant:
- Summary sentence (one line)
- `# Parameters` (or list argument semantics in prose)
- `# Returns`
- `# Errors` for `Result`-returning APIs
- `# Panics` if panic is possible
- `# Safety` for `unsafe fn` or unsafe contracts
- `# Examples` with realistic usage

Guidelines:
- Use present tense and active voice.
- Keep first line short and specific.
- Link related types/functions with intra-doc links when useful.
- Do not promise complexity, constant-time guarantees, or cryptographic properties unless verified in code.

## Comment Refactoring Heuristics

Rewrite or remove comments that are:
- stale after logic changes
- vague ("handles stuff", "do magic here")
- duplicative of obvious operations
- misleading about security or correctness

Add comments where they increase comprehension:
- non-obvious algorithms
- cryptographic or parsing edge cases
- lifetime/ownership constraints that are not obvious
- why a tradeoff exists (not just what code does)

## Audit Workflow

1. Identify the scope (file, module, crate).
2. Compare each doc/comment against current implementation.
3. Mark each item as:
   - accurate
   - inaccurate
   - missing
   - unnecessary
4. Apply edits:
   - fix inaccuracies first
   - add missing contract/safety/error docs
   - remove noise comments
5. Run tests/lints when available.
6. Report:
   - what changed
   - what remains ambiguous
   - any behavior/docs mismatch that needs design input

## Output Format

When returning an audit summary, use:

```markdown
## Rust Documentation Audit

- Scope: <files/modules>
- Fixed: <count>
- Removed: <count>
- Added: <count>
- Remaining questions: <count>

### Notable fixes
- <item>
- <item>

### Open questions
- <question requiring maintainer decision>
```

## Editing Checklist

- [ ] Public items in changed code paths have rustdoc
- [ ] `Result` APIs document expected error conditions
- [ ] Panic conditions are explicitly documented
- [ ] Unsafe contracts include a `# Safety` section
- [ ] Examples compile or are realistically accurate
- [ ] No comments contradict implementation
- [ ] No "obvious code narration" comments remain

## Anti-Patterns

Avoid:
- "This is secure" without explicit conditions
- "Never fails" unless proven and enforced
- TODO comments that describe required behavior as if implemented
- giant comment blocks that belong in module docs or ADRs

Prefer:
- concise, testable claims
- clear contracts around boundaries and invariants
- rationale comments for tricky choices
