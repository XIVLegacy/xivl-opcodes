#!/usr/bin/env python3
"""Check local Markdown paths listed by documentation indexes."""

from __future__ import annotations

import posixpath
import re
import subprocess
import sys
from pathlib import Path

from _json_io import REPO_ROOT

DOCS = "docs"
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

    errors: list[str] = []
    indexes = sorted(
        path for path in tracked if posixpath.basename(path) == "README.md"
    )
    for index_path in indexes:
        for link in sorted(links_from(index_path) - tracked):
            errors.append(f"dangling: {index_path} links {link}, but it is not tracked")

    if errors:
        print(f"docs-index validation FAILED ({len(errors)} problem(s)):", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(f"docs-index OK ({len(indexes)} indexes; no dangling Markdown links).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
