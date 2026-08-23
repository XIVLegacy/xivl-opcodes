#!/usr/bin/env python3
"""Validate tracked Markdown indexes under docs/ in both directions."""

from __future__ import annotations

import posixpath
import re
import subprocess
import sys
from pathlib import Path

from _json_io import REPO_ROOT

DOCS = "docs"
ROOT_INDEX = "docs/README.md"
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def tracked_markdown() -> set[str] | None:
    """Return tracked docs paths so the ignored maintainer island is excluded."""
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", DOCS],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        print(f"docs-index validation FAILED: git ls-files failed: {detail}", file=sys.stderr)
        return None

    paths = result.stdout.decode("utf-8").split("\0")
    return {
        path
        for path in paths
        if path.lower().endswith(".md")
    }


def resolve_markdown_link(index_path: str, raw_target: str) -> str | None:
    """Resolve a relative Markdown target that stays inside docs/."""
    target = raw_target.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1]
    target = target.split("#", 1)[0].split("?", 1)[0]
    if not target or "://" in target or target.startswith("/"):
        return None
    if not target.lower().endswith(".md"):
        return None

    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(index_path), target))
    if not resolved.startswith(f"{DOCS}/"):
        return None
    return resolved


def links_from(index_path: str) -> set[str]:
    path = REPO_ROOT / Path(*index_path.split("/"))
    text = path.read_text(encoding="utf-8")
    return {
        resolved
        for raw_target in LINK_RE.findall(text)
        if (resolved := resolve_markdown_link(index_path, raw_target)) is not None
    }


def main() -> int:
    tracked = tracked_markdown()
    if tracked is None:
        return 1
    if ROOT_INDEX not in tracked:
        print(f"docs-index validation FAILED: {ROOT_INDEX} not found", file=sys.stderr)
        return 1

    errors: list[str] = []
    docs_by_dir: dict[str, set[str]] = {}
    indexes: set[str] = set()
    for path in tracked:
        directory = posixpath.dirname(path)
        if posixpath.basename(path) == "README.md":
            indexes.add(path)
        else:
            docs_by_dir.setdefault(directory, set()).add(path)
    for index_path in indexes:
        docs_by_dir.setdefault(posixpath.dirname(index_path), set())

    for directory, pages in sorted(docs_by_dir.items()):
        index_path = f"{directory}/README.md"
        if index_path not in indexes:
            errors.append(f"missing index: {index_path} is required for tracked Markdown pages")
            continue

        linked_same_dir = {
            path
            for path in links_from(index_path)
            if posixpath.dirname(path) == directory
        }
        for page in sorted(pages - linked_same_dir):
            errors.append(f"orphan: {page} is not linked from {index_path}")
        for link in sorted(linked_same_dir - tracked):
            errors.append(f"dangling: {index_path} links {link}, but it is not tracked")

    nested_indexes = {
        path for path in indexes if posixpath.dirname(path) != DOCS
    }
    root_links = links_from(ROOT_INDEX)
    for index_path in sorted(nested_indexes - root_links):
        errors.append(f"orphan: {index_path} is not linked from {ROOT_INDEX}")
    for link in sorted(
        path for path in root_links if posixpath.dirname(path) != DOCS and path not in tracked
    ):
        errors.append(f"dangling: {ROOT_INDEX} links {link}, but it is not tracked")

    if errors:
        print(f"docs-index validation FAILED ({len(errors)} problem(s)):", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    page_count = len(tracked - indexes)
    print(
        f"docs-index OK ({page_count} tracked pages across "
        f"{len(docs_by_dir)} indexed directories; no dangling rows)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
