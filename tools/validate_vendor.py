#!/usr/bin/env python3
"""Validate data/vendor/ files against each directory's PROVENANCE.json hashes."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
VENDOR = REPO / "data" / "vendor"

HEX64 = re.compile(r"[0-9a-f]{64}")
REFRESH_MODES = {"copy", "derive"}


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_entry(directory: Path, entry: object, errors: list[str]) -> str | None:
    """Validate one PROVENANCE entry; return the declared file name, if any."""
    label = f"{directory.relative_to(REPO)}/PROVENANCE.json"
    if not isinstance(entry, dict):
        errors.append(f"{label}: files[] entries must be objects")
        return None

    name = entry.get("file")
    if not isinstance(name, str) or not name:
        errors.append(f"{label}: an entry has no file name")
        return None
    if "/" in name or "\\" in name or name == "PROVENANCE.json":
        errors.append(f"{label}: {name} must be a plain file name in this directory")
        return None

    for field in ("sourceRepo", "sourcePath", "evidenceTier", "transformation"):
        if not isinstance(entry.get(field), str) or not entry[field]:
            errors.append(f"{label}: {name} is missing {field}")

    mode = entry.get("refreshMode")
    if mode not in REFRESH_MODES:
        errors.append(f"{label}: {name} refreshMode must be one of {sorted(REFRESH_MODES)}")
    elif mode == "derive" and not entry.get("deriver"):
        errors.append(f"{label}: {name} refreshMode derive needs a deriver name")

    declared = entry.get("sha256")
    if not isinstance(declared, str) or not HEX64.fullmatch(declared):
        errors.append(f"{label}: {name} sha256 must be a 64-hex lowercase digest")
        return name

    path = directory / name
    if not path.is_file():
        errors.append(f"{label}: {name} is declared but missing on disk")
        return name

    actual = sha256_of(path)
    if actual != declared:
        errors.append(
            f"{path.relative_to(REPO)}: sha256 {actual} does not match PROVENANCE {declared}; "
            f"the promoted copy drifted from {entry.get('sourceRepo')}:{entry.get('sourcePath')} "
            f"(restore with tools/refresh_vendor.py)"
        )
    return name


def main() -> int:
    errors: list[str] = []
    if not VENDOR.is_dir():
        print(f"error: {VENDOR} not found", file=sys.stderr)
        return 1

    checked = 0
    for directory in sorted(p for p in VENDOR.iterdir() if p.is_dir()):
        rel = directory.relative_to(REPO)
        provenance_path = directory / "PROVENANCE.json"
        if not provenance_path.is_file():
            errors.append(f"{rel}: no PROVENANCE.json; every vendor directory must declare its files")
            continue

        try:
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{rel}/PROVENANCE.json: cannot read: {exc}")
            continue
        if not isinstance(provenance, dict) or not isinstance(provenance.get("files"), list):
            errors.append(f"{rel}/PROVENANCE.json: files must be an array")
            continue

        declared = set()
        for entry in provenance["files"]:
            name = check_entry(directory, entry, errors)
            if name is not None:
                if name in declared:
                    errors.append(f"{rel}/PROVENANCE.json: duplicate entry for {name}")
                declared.add(name)
                checked += 1

        for path in sorted(directory.iterdir()):
            if path.name == "PROVENANCE.json" or not path.is_file():
                continue
            if path.name not in declared:
                errors.append(
                    f"{path.relative_to(REPO)}: promoted file has no PROVENANCE entry; "
                    f"declare it via tools/refresh_vendor.py or delete it"
                )

    if errors:
        for message in errors:
            print(f"vendor: {message}", file=sys.stderr)
        print(f"vendor validation FAILED ({len(errors)} problems).", file=sys.stderr)
        return 1

    print(f"vendor validation OK ({checked} files hash-matched against PROVENANCE).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
