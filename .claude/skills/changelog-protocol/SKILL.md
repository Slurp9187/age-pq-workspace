---
name: changelog-protocol
description: Keep CHANGELOG files honest by making the release date a verifiable claim. Use when writing or reviewing changelog entries, cutting a release, bumping a version, or setting up changelog CI. Also use when a changelog section's version or date looks out of step with the manifest or the git tags.
---

# Changelog protocol

A changelog is a set of claims about what shipped and when. This protocol keeps
each claim checkable, because the failure mode is silent: a section that says
`## [1.2.0] - 2026-09-10` when `v1.2.0` was never tagged reads as released
forever, and nothing complains.

## The two invariants

**1. The top version section matches the manifest version.**

Whatever the package manifest says the current version is, the newest section in
the changelog is headed with that exact string.

**2. A version heading carries a date if and only if that tag exists.**

```
## [1.2.0] - unreleased      while the work is in flight
## [1.2.0] - 2026-09-10      the moment the tag is cut
```

One separator, two possible values. The date **is** the release marker; it is
not decoration and not the date the work happened.

## Consequences worth stating

**No standing empty `## [Unreleased]` section.** Under this protocol the
versioned-but-undated section *is* the unreleased one. Keeping both leaves a
reader unable to tell which section describes the code they have — the exact
ambiguity the protocol exists to remove.

Use a bare `## [Unreleased]` only if the project genuinely cannot know its next
version number until release time. If versions are bumped when a line opens,
the number is always known, so name it.

**Do not date individual entries as bookkeeping.** Git already records when
each change landed, precisely and without drift. A hand-typed date is a lossy
copy that can go wrong, costs a decision per entry, and answers a question no
changelog reader asks. They ask *"what changed between the version I have and
the one I am considering?"* — dates between releases do not help.

**Do date an entry when the date is part of the claim.** The test:

> Does the reader need the date to know how *stale an observation* is?

If yes, it belongs in the entry, because git dates the commit, not the
measurement. If it is just "when I did this", drop it.

```markdown
<!-- KEEP — the date bounds the evidence -->
- Verified against the Go CLI v1.3.1; not reproduced on v1.3.2 as of 2026-09-09.
- Facts read from the upstream checkout @ `1268205e` on 2026-09-09.

<!-- DROP — git already knows -->
- Moved encoding into the shared crate (2026-09-08).
```

## The release flow

1. **Open a line.** Bump the manifest version, add
   `## [X.Y.Z] - unreleased` at the top of every changelog in the project.
2. **Accumulate.** Entries go under that heading, grouped by type
   (`### Added` / `### Changed` / `### Fixed` / `### Removed`). No dates unless
   the date is evidence.
3. **Cut.** Replace `- unreleased` with the ISO date, commit, tag from that
   commit. The tag name is the version with the project's usual prefix
   (commonly `v`).
4. **Repeat.** The next bump opens a new section. Never leave a standing empty
   one.

Pre-release candidates work the same way: `## [1.2.0-rc.1] - unreleased`
becomes `## [1.2.0-rc.1] - 2026-09-10` when `v1.2.0-rc.1` is tagged, and
`## [1.2.0-rc.2]` opens next.

## Enforcing it

`scripts/check_changelog.py` checks both invariants and is meant to run in CI.
It reads the version from the manifest, reads the top section of each changelog,
and compares against the tags actually present.

```sh
python .claude/skills/changelog-protocol/scripts/check_changelog.py
python .claude/skills/changelog-protocol/scripts/check_changelog.py --changelog CHANGELOG.md docs/CHANGELOG.md
```

It deliberately checks **only the newest section** in each file. Historical
sections are frozen, and old projects accumulate legitimate oddities — a
renumbering, a scheme that predates the current one, a tag deleted years ago.
Checking them produces failures nobody can act on, and a check nobody can act on
gets disabled. The newest section is where the error actually happens, because
that is the one being edited at release time.

**In CI, tags must be fetched.** `actions/checkout` does not fetch them by
default, and without tags every dated section looks untagged:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0        # or: fetch-tags: true
- run: python .claude/skills/changelog-protocol/scripts/check_changelog.py
```

## Porting this to another project

The script auto-detects the version from `Cargo.toml` (including
`[workspace.package]`), `package.json`, `pyproject.toml`, or a `VERSION` file,
and finds `CHANGELOG.md` at the root and one level down. Override with
`--version`, `--changelog` and `--tag-prefix` when a project does something else.

Only two things are project-specific:

- **the tag prefix** (`v` by default, `--tag-prefix ''` if tags are bare)
- **which changelogs exist** (auto-discovered, or listed explicitly)

Copy the whole `changelog-protocol` directory into another project's
`.claude/skills/`. Nothing in it is repository-specific.
