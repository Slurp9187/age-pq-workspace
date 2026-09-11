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

**3. A dated top section must sit at its own tag's commit.**

Invariants 1 and 2 can both hold while the changelog is silently wrong. After a
release, the manifest still matches the heading and the heading still matches a
real tag — but commits keep landing, and the newest section now describes a
release rather than the tree in front of you.

So: once a tag is cut, the next commit to that branch opens the next version.
Bump the manifest and add `## [<next>] - unreleased` in the same commit.

```
::error::[1.2.0] is released (v1.2.0) but HEAD is 3 commit(s) past it, so this
changelog no longer describes the tree.
```

This is the marginal invariant of the three, and worth holding loosely. It
charges a real tax — a README typo fix after a tag still has to open a version
section — to prevent something milder than a false release claim: a changelog
that is merely behind. Adopt it where releases are frequent and the section
would be opened anyway; drop it if it fires three times without catching
anything you cared about. A rule that only ever produces false positives trains
people to ignore the rules that matter.

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

## Pushing tags with commits

Self-contained; lift this whole section into a commit/push skill if you keep one.

`gh` does not push tags. Use git. Create an **annotated** tag, then push the
branch and that tag together:

```sh
git tag -a vX.Y.Z -m "vX.Y.Z"
git push --follow-tags
```

`--follow-tags` pushes the usual branch/commits **and** annotated tags reachable
from those commits that are missing on the remote. It does **not** push
lightweight tags, and it does **not** push unrelated local tags.

### Tag types

- Annotated — required for `--follow-tags`: `git tag -a vX.Y.Z -m "vX.Y.Z"`
- Lightweight — local-only unless pushed by name: `git tag vX.Y.Z`

### Moving a tag

`--follow-tags` only pushes tags **missing** from the remote. It will not move
one that already exists: it reports `Everything up-to-date` and the remote
silently keeps the old commit while your local tag points somewhere else.
Measured, not inferred:

```
push --follow-tags (new tag)     * [new tag] v0.0.98-rc.1
move locally, push again         Everything up-to-date
                                 remote 4a86d0b · local 08e98a8   <- diverged
git push -f origin v0.0.98-rc.1  + 4a86d0b...08e98a8 (forced update)
```

So moving a tag is always `git push -f origin vX.Y.Z`, by name. This matters
wherever pre-release tags are deliberately movable — the no-op is reported as
success, which is the worst shape a failure can take.

### When `--follow-tags` is wrong

- **Lightweight tag** — push by name: `git push origin vX.Y.Z`
- **Moving an existing tag** — force by name, as above
- `--tags` **alone** pushes tags only, not the branch

### Do not

- **`git push --tags`, unless you have audited `git tag -l` against the remote.**
  It publishes *every* local tag — old experiments, abandoned lines, scratch
  markers. Under tag protection rules that can be irreversible: a pushed tag
  matching an immutability rule cannot be deleted without first disabling the
  rule. Check first:

  ```sh
  # tags you have locally that the remote does not
  git tag -l > /tmp/local.txt
  git ls-remote --tags origin | grep -v '\^{}' | sed 's|.*refs/tags/||' | sort > /tmp/remote.txt
  comm -23 <(sort /tmp/local.txt) /tmp/remote.txt
  ```

- Assume `git push --tags` also updates the current branch. It does not.
- Reach for `gh release create` merely to push a tag, unless a GitHub Release is
  actually wanted.

### If CI validates anything tag-dependent

This protocol creates such a case: between dating a heading and creating the
tag, the tree fails its own check —

```
::error::[X.Y.Z] is dated 2026-09-10 but tag vX.Y.Z does not exist
```

— so the tag must be visible to the workflow when it runs. `--follow-tags`
sends both refs in one push and should satisfy that, but if you want certainty
rather than reasoning, push the tag first and the branch second. That removes
the timing question instead of arguing about it.

## One changelog or many?

Per-crate / per-package changelogs are justified by **independent versioning and
independent distribution**. A workspace whose members share one version and ship
as a single tag has neither, and per-package files then duplicate one release's
story N times while giving invariant 1 N places to drift.

Prefer **one changelog at the root**, with a `### <package>` heading inside each
release section for changes that are genuinely package-specific. Split only when
packages are versioned and released separately.

### Freezing a superseded changelog

When consolidating, do not delete or re-shuffle the old files — rewriting
history loses more than the tidiness gains. Mark them frozen:

```markdown
<!-- changelog-protocol: frozen -->

> **Frozen.** Historical record up to `X.Y.Z`. Later changes are in the
> [root `CHANGELOG.md`](../CHANGELOG.md).
```

The marker must be a **standalone line above the first version heading**. That is
not fussiness: a changelog that *describes* this protocol quotes the marker in
prose, and a whole-file substring test then marks that file frozen and skips it.
Exactly that happened here — the root changelog excluded itself the first time
it documented the freezing rule, and the run reported success having inspected
nothing.

The checker skips any frozen file and **says so on every run** — an unexplained
skip is how a check quietly stops covering what people believe it covers. It
also fails if *every* discovered file is frozen, because a check that passes
while inspecting nothing is not a check. That guard is what caught the
self-exclusion bug above, rather than a person noticing.

## Enforcing it

`scripts/check_changelog.py` checks all three invariants and is meant to run in CI.
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
