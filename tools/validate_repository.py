#!/usr/bin/env python3
"""Run the complete repository validation gate."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from _json_io import REPO_ROOT


VALIDATORS = (
    ("Vendor provenance", "validate_vendor.py"),
    ("Corpus", "validate_corpus.py"),
    ("Client opcode semantics", "validate_client_opcode_semantics.py"),
    ("Docs index", "validate_docs_index.py"),
    ("Payload framing", "audit_payload_framing.py"),
)


def json_files() -> list[Path]:
    """Return repository JSON files without traversing Git or junctions."""
    paths: list[Path] = []
    is_junction = getattr(os.path, "isjunction", lambda _path: False)
    for directory, subdirectories, filenames in os.walk(REPO_ROOT, followlinks=False):
        base = Path(directory)
        subdirectories[:] = [
            name
            for name in subdirectories
            if name != ".git"
            and not (base / name).is_symlink()
            and not is_junction(base / name)
        ]
        paths.extend(
            base / name for name in filenames if Path(name).suffix.lower() == ".json"
        )
    return sorted(paths)


def validate_json_syntax() -> int:
    paths = json_files()
    for path in paths:
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            label = path.relative_to(REPO_ROOT)
            print(f"JSON syntax FAILED: {label}: {exc}", file=sys.stderr)
            return 1
    print(f"JSON syntax OK ({len(paths)} files).")
    return 0


def main() -> int:
    print("== JSON syntax ==", flush=True)
    if validate_json_syntax() != 0:
        return 1

    tools_dir = Path(__file__).resolve().parent
    for label, script in VALIDATORS:
        print(f"\n== {label} ==", flush=True)
        result = subprocess.run(
            [sys.executable, str(tools_dir / script)],
            cwd=REPO_ROOT,
            check=False,
        )
        if result.returncode != 0:
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
