---
name: age-pq-changelog-protocol
description: age-pq-workspace's changelog and release facts — version of record, release marker, what a bump touches, and what enforces it. Use when adding a changelog entry, bumping the version, cutting or tagging a release, or when a heading looks out of step with the manifest or the tags.
---

# Changelog protocol — age-pq-workspace

The protocol, the invariants and the heading format live in the global `changelog-protocol`
skill. This file records only what is true of **this** repository. Tag mechanics (annotated
tags, `--follow-tags`, moving a pre-release tag) are the global `publish-prep` skill's.

## Version of record

`Cargo.toml` — `[workspace.package] version`. All three members inherit it
(`version.workspace = true`); the crates share one version and ship on one tag.

Two lockfiles record it, and both move with a bump:

- `Cargo.lock` — `age-pq-hpke`, `age-pq-keys`, `age-plugin-pq`.
- `conformance/Cargo.lock` — `age-pq-hpke`, `age-pq-keys`. CI runs conformance with
  `--locked`, so a bump that misses this file fails that job. Regenerate it from
  `conformance/` with `cargo metadata --offline --format-version 1 > /dev/null`, which
  touches only the path-dependency versions.

`conformance/Cargo.toml` is `0.0.0` **by design**: excluded from the workspace, never
published, never tagged. It is not drift.

## Heading format

Global format: `## [0.2.0-rc.4] - 2026-09-15` / `## [0.2.0-rc.4] - Unreleased`.

Legacy deviation: in-flight sections were written `- unreleased` (lowercase) until the
`0.2.0-rc.4` line, which was normalized when this profile was adopted. Dated headings already
conform. No normalization pass over history is needed or wanted.

## Release marker

Tag `v<version>`, annotated — all four published tags are (`v0.1.0-rc.1`,
`v0.2.0-rc.1`..`rc.3`). No non-release tags exist to exclude.

The tag is the release, not an input to one: consumers depend on a git tag
(`{ git = "…", tag = "v…" }`), so "released" and "tagged" are the same property here. What
counts is the **remote** tag list, `git ls-remote --tags origin | grep -v '\^{}'`, never
`git tag -l` — see CLAUDE.md, *Verifying the question you were actually asked*.

## Registry

None. `publish = false` at the workspace root, inherited by every member. There is no
registry axis; the third invariant of the global skill does not apply.

## What a bump touches

One commit, the first change after a tagged state:

- `Cargo.toml` — `[workspace.package] version`
- `Cargo.lock`
- `conformance/Cargo.lock`
- `CHANGELOG.md` — new `## [<next>] - Unreleased` at the top

**Moved at the cut, not the bump** — README tag pins, because the checker requires every
pinned tag to *exist* in `pending` mode and to name the release in `release` mode:

- `README.md` — the two `tag = "v…"` pins (~line 52) and "the current tag is" (~line 75)
- `age-pq-hpke/README.md` (~line 26), `age-pq-keys/README.md` (~line 35)

Never moved: statements recording when something happened — "landed in `0.2.0-rc.1`",
"fixed … in `0.2.0-rc.3`" in `docs/`, and anything under `docs/plans/`.

## Changelogs

One, at the root. Crate-specific entries go under `### age-pq-hpke` / `### age-pq-keys` /
`### age-plugin-pq` inside the release section. The three crate `CHANGELOG.md` files are
frozen (standalone `<!-- changelog-protocol: frozen -->` marker above the first heading)
and keep history through `0.1.0-rc.1`.

## Enforcement

Automated: the `Changelog protocol` step in `.github/workflows/ci.yml`, `--mode release` on
`refs/tags/*` and `pending` everywhere else. The workflow triggers on `tags: ["v*"]` and
checks out with `fetch-depth: 0`, so tags are present.

`scripts/check_changelog.py` here is a **vendored copy of the global skill's checker** and
must stay byte-identical to it — CI cannot read `~/.claude`, which is the only reason the copy
exists. It is not a place to add rules. To change the checker, change the global one and
re-copy:

```sh
diff --strip-trailing-cr ~/.claude/skills/changelog-protocol/scripts/check_changelog.py \
  .claude/skills/age-pq-changelog-protocol/scripts/check_changelog.py
```

## Exempt history

- `## [0.1.0] - 2026-03-25` has no `v0.1.0` tag. It predates the tag scheme; the checker only
  reads the newest section.
- The frozen crate changelogs.
- `release/0.1` follows the protocol by hand and has no CI check. `0.1.0-rc.1` is dated and
  `v0.1.0-rc.1` exists; its in-flight `[0.1.0-rc.2]` is still spelled `- unreleased`, because
  that branch was not touched by this adoption. Normalize it on that branch's next commit.

## What did not transfer

- **The previous 347-line `changelog-protocol` skill in this directory.** It had grown from a
  profile into a fork of the protocol, under the bare name that shadowed the global skill.
  Its generic content is in the global `changelog-protocol` skill; its tag-pushing section is
  in `publish-prep`. Replaced by this profile when the directory was renamed.
- **Invariant 3 is kept**, and is the one rule here the global `SKILL.md` does not spell out:
  a dated top section must sit at its own tag's commit, so the next commit after a tag opens
  the next version. The shared checker enforces it, in both modes; CLAUDE.md states it.
- **Entry dating** is stated in CLAUDE.md (*Changelog protocol*) and is not repeated here.
- **Grouping by change type** (`### Added` / `### Fixed` …) from the old file was never
  followed here: entries group by crate and by `### Changed` / `### Docs`. Nothing checks it.
