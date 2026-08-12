"""Shared JSON writer and paths for the catalog tools.

Generated JSON uses two-space indentation, verbatim non-ASCII, LF endings, and
one trailing newline. Root opcodes.json and constants.json are the single
consumer-facing catalog home; data/ holds supporting evidence.

The module cannot be called _io -- that shadows CPython's built-in _io module.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
OPCODES_PATH = REPO_ROOT / "opcodes.json"
CONSTANTS_PATH = REPO_ROOT / "constants.json"


def write_json(path, obj) -> None:
    """Write UTF-8 JSON with two-space indentation and one trailing LF."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")
