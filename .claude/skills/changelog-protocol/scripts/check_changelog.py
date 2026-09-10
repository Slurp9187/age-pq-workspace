#!/usr/bin/env python3
"""Check the two changelog-protocol invariants.

  1. The top version section matches the manifest version.
  2. A version heading carries a date iff that tag exists.

Only the newest section of each changelog is checked; see SKILL.md for why.
Exits 0 on success, 1 on any violation. Portable across projects: the version
and the changelog list are auto-detected, and both can be overridden.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

HEADING = re.compile(r"^##\s*\[(?P<version>[^\]]+)\]\s*-\s*(?P<marker>.+?)\s*$")
ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
UNRELEASED = "unreleased"


def detect_version(root: pathlib.Path) -> tuple[str, str] | tuple[None, None]:
    """Return (version, where-it-came-from), or (None, None)."""
    cargo = root / "Cargo.toml"
    if cargo.is_file():
        text = cargo.read_text(encoding="utf-8")
        # [workspace.package] wins when present: members inherit it.
        for section in ("workspace.package", "package"):
            block = re.search(
                rf"^\[{re.escape(section)}\](?P<body>.*?)(?=^\[|\Z)",
                text,
                re.S | re.M,
            )
            if block:
                found = re.search(
                    r'^version\s*=\s*"([^"]+)"', block.group("body"), re.M
                )
                if found:
                    return found.group(1), f"Cargo.toml [{section}]"

    pkg = root / "package.json"
    if pkg.is_file():
        found = re.search(r'"version"\s*:\s*"([^"]+)"', pkg.read_text(encoding="utf-8"))
        if found:
            return found.group(1), "package.json"

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        found = re.search(
            r'^version\s*=\s*"([^"]+)"', pyproject.read_text(encoding="utf-8"), re.M
        )
        if found:
            return found.group(1), "pyproject.toml"

    version_file = root / "VERSION"
    if version_file.is_file():
        return version_file.read_text(encoding="utf-8").strip(), "VERSION"

    return None, None


def discover_changelogs(root: pathlib.Path) -> list[pathlib.Path]:
    """CHANGELOG.md at the root and one level down, skipping build dirs."""
    skip = {"target", "node_modules", "dist", "build", ".git", "vendor"}
    found = []
    if (root / "CHANGELOG.md").is_file():
        found.append(root / "CHANGELOG.md")
    for child in sorted(root.iterdir()):
        if child.is_dir() and child.name not in skip and not child.name.startswith("."):
            candidate = child / "CHANGELOG.md"
            if candidate.is_file():
                found.append(candidate)
    return found


def existing_tags() -> set[str]:
    try:
        out = subprocess.run(
            ["git", "tag", "--list"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return set()
    return {line.strip() for line in out.stdout.splitlines() if line.strip()}


def top_heading(path: pathlib.Path) -> tuple[int, str, str] | None:
    """(line number, version, marker) of the newest version section."""
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = HEADING.match(line)
        if match:
            return number, match.group("version"), match.group("marker")
        # A bare `## [Unreleased]` has no marker and is reported separately.
        if re.match(r"^##\s*\[unreleased\]\s*$", line, re.I):
            return number, "Unreleased", ""
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="project root (default: .)")
    parser.add_argument("--version", help="override the detected version")
    parser.add_argument("--changelog", nargs="+", help="explicit changelog paths")
    parser.add_argument(
        "--tag-prefix",
        default="v",
        help="tag prefix; use --tag-prefix '' for bare tags (default: v)",
    )
    args = parser.parse_args()

    root = pathlib.Path(args.root).resolve()

    if args.version:
        version, source = args.version, "--version"
    else:
        version, source = detect_version(root)
    if not version:
        print("::error::could not detect a project version; pass --version")
        return 1

    changelogs = (
        [pathlib.Path(p) for p in args.changelog]
        if args.changelog
        else discover_changelogs(root)
    )
    if not changelogs:
        print("::error::no CHANGELOG.md found; pass --changelog")
        return 1

    tags = existing_tags()
    if not tags:
        print(
            "::error::no git tags visible. In CI use actions/checkout with "
            "fetch-depth: 0 (or fetch-tags: true), or every dated section "
            "will look untagged."
        )
        return 1

    expected_tag = f"{args.tag_prefix}{version}"
    tag_exists = expected_tag in tags
    print(f"version {version} (from {source}); tag {expected_tag}: "
          f"{'present' if tag_exists else 'absent'}")

    failures = 0
    for path in changelogs:
        rel = path.relative_to(root) if path.is_absolute() else path
        head = top_heading(path)
        if head is None:
            print(f"::error file={rel}::no version heading found")
            failures += 1
            continue

        line_no, found_version, marker = head

        if found_version == "Unreleased":
            print(
                f"::error file={rel},line={line_no}::bare '## [Unreleased]' "
                f"heading. Name the section for the version in flight: "
                f"'## [{version}] - unreleased'."
            )
            failures += 1
            continue

        # Invariant 1
        if found_version != version:
            print(
                f"::error file={rel},line={line_no}::top section is "
                f"[{found_version}] but the project version is {version}."
            )
            failures += 1
            continue

        # Invariant 2
        dated = bool(ISO_DATE.match(marker))
        if not dated and marker.lower() != UNRELEASED:
            print(
                f"::error file={rel},line={line_no}::marker {marker!r} is "
                f"neither an ISO date nor 'unreleased'."
            )
            failures += 1
        elif dated and not tag_exists:
            print(
                f"::error file={rel},line={line_no}::[{version}] is dated "
                f"{marker} but tag {expected_tag} does not exist. A date is the "
                f"release marker: use '- unreleased' until the tag is cut."
            )
            failures += 1
        elif not dated and tag_exists:
            print(
                f"::error file={rel},line={line_no}::tag {expected_tag} exists "
                f"but [{version}] is still marked unreleased. Replace "
                f"'- unreleased' with the release date."
            )
            failures += 1
        else:
            print(f"  ok  {rel}:{line_no}  [{version}] - {marker}")

    if failures:
        print(f"::error::{failures} changelog protocol violation(s)")
        return 1
    print(f"changelog protocol: {len(changelogs)} file(s) ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
