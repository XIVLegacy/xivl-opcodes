#!/usr/bin/env python3
"""Run the complete repository validation gate."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import _schema_check
import verify_retail_zone_dispatch as retail_verifier
from _json_io import REPO_ROOT


VALIDATORS = (
    ("Vendor provenance", "validate_vendor.py"),
    ("Corpus", "validate_corpus.py"),
    ("Client opcode semantics", "validate_client_opcode_semantics.py"),
    ("Battle result semantics", "validate_battle_result_semantics.py"),
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


def validate_retail_contract() -> int:
    """Validate the asset-free retail contract and any published attestation."""
    errors: list[str] = []
    try:
        errors.extend(retail_verifier.verify())
        schema = _schema_check.load_schema(retail_verifier.DEFAULT_SCHEMA)
        for status in ("pass", "fail"):
            sample = retail_verifier.build_attestation(status, "1" * 40)
            errors.extend(
                f"{status} attestation: {problem}"
                for problem in _schema_check.validate(sample, schema)
            )
        evidence_root = REPO_ROOT / "data" / "retail_evidence"
        if evidence_root.is_symlink():
            errors.append("tracked retail evidence root is a symlink")
        elif evidence_root.exists():
            expected_name = "zone-dispatch-0x018d-slot.json"
            entries = sorted(evidence_root.iterdir(), key=lambda path: path.name)
            if (
                evidence_root.is_symlink()
                or len(entries) != 1
                or entries[0].name != expected_name
                or entries[0].is_symlink()
                or not entries[0].is_file()
            ):
                errors.append("tracked retail evidence allowlist differs")
            else:
                document = json.loads(entries[0].read_text(encoding="ascii"))
                errors.extend(
                    f"tracked retail evidence: {problem}"
                    for problem in _schema_check.validate(document, schema)
                )
                if document.get("result") != {"status": "pass"}:
                    errors.append("tracked retail evidence is not a pass")
    except (
        OSError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        _schema_check.SchemaError,
        retail_verifier.VerificationError,
    ) as exc:
        errors.append(f"retail contract could not be validated: {exc}")

    if errors:
        print(f"Retail dispatch FAILED ({len(errors)} problem(s)):", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("Retail dispatch OK (fixed asset-free contract).")
    return 0


def main() -> int:
    print("== JSON syntax ==", flush=True)
    if validate_json_syntax() != 0:
        return 1

    print("\n== Retail dispatch ==", flush=True)
    if validate_retail_contract() != 0:
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
