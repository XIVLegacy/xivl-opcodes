#!/usr/bin/env python3
"""Audit catalog framing against promoted inner-body lengths.

See docs/ai_agents/verification.md for framing, allow-list, and exit contracts.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from _json_io import OPCODES_PATH, REPO_ROOT

FRAMING_BYTES = 32
FIXTURE = REPO_ROOT / "data" / "vendor" / "client-structs" / "payload-inner-lengths.json"
MANIFESTS = (
    ("c2s_payload_decoding.json", "payloadStructs", None),
    ("s2c_payload_decoding_lua_bound.json", "payloadStructs", None),
    ("c2s_payload_schemas.json", "schemas", "c2s"),
    ("opcode_payload_schemas.json", "schemas", "c2s"),
    ("inbound_payload_schemas.json", "schemas", "s2c"),
)

ALLOWLIST: dict[tuple[str, int], str] = {
    ("c2s", 0x0130): "catalog 32 is the legacy client builder totalSize, not the 48-byte full wire size",
    ("c2s", 0x0131): "catalog payloadLengths is an empty legacy placeholder despite the resolved 8-byte body",
    ("c2s", 0x0132): "catalog 24 is the legacy client builder totalSize, not the 40-byte full wire size",
    ("s2c", 0x01A4): "catalog 40 is retail padding; both implementations deliberately send a 4-byte body",
}


class AuditFatalError(Exception):
    """An input cannot be audited reliably."""


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AuditFatalError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise AuditFatalError(f"invalid JSON in {path}: {exc}") from exc


def _require_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AuditFatalError(f"{label} must be an integer")
    return value


def load_schema_lengths(manifests_dir: Path) -> dict[tuple[str, int], int]:
    return {key: length for key, (length, _) in load_schema_lengths_with_sources(manifests_dir).items()}


def load_schema_lengths_with_sources(manifests_dir: Path) -> dict[tuple[str, int], tuple[int, str]]:
    """Merge lengths while retaining the source manifest for each key."""
    lengths: dict[tuple[str, int], int] = {}
    sources: dict[tuple[str, int], str] = {}

    for filename, collection_key, fixed_direction in MANIFESTS:
        path = manifests_dir / filename
        if not path.is_file():
            raise AuditFatalError(f"required manifest not found: {path}")
        document = _load_json(path)
        if not isinstance(document, dict) or not isinstance(document.get(collection_key), dict):
            raise AuditFatalError(f"{path}: {collection_key} must be an object")

        for item_key, record in document[collection_key].items():
            if not isinstance(record, dict):
                raise AuditFatalError(f"{path}: {collection_key}/{item_key} must be an object")
            direction = fixed_direction or record.get("direction")
            if direction not in {"c2s", "s2c"}:
                raise AuditFatalError(f"{path}: {collection_key}/{item_key} has invalid direction")
            if collection_key == "payloadStructs":
                opcode = _require_int(record.get("opcode"), f"{path}: {item_key}/opcode")
                inner_len = _require_int(record.get("payloadSize"), f"{path}: {item_key}/payloadSize")
            else:
                try:
                    opcode = int(item_key, 16)
                except (TypeError, ValueError) as exc:
                    raise AuditFatalError(f"{path}: invalid opcode key {item_key!r}") from exc
                inner_len = _require_int(record.get("innerLen"), f"{path}: {item_key}/innerLen")

            key = (direction, opcode)
            if key in lengths and lengths[key] != inner_len:
                old = sources[key]
                raise AuditFatalError(
                    f"conflicting inner lengths for {direction} 0x{opcode:04x}: "
                    f"{lengths[key]} in {old}, {inner_len} in {filename}"
                )
            lengths[key] = inner_len
            sources[key] = filename

    return {key: (length, sources[key]) for key, length in lengths.items()}


def load_fixture_lengths(fixture_path: Path) -> dict[tuple[str, int], int]:
    if not fixture_path.is_file():
        raise AuditFatalError(f"payload inner-length fixture not found: {fixture_path}")
    document = _load_json(fixture_path)
    if not isinstance(document, dict) or not isinstance(document.get("innerLengths"), list):
        raise AuditFatalError(f"{fixture_path}: innerLengths must be a list")

    lengths: dict[tuple[str, int], int] = {}
    for i, record in enumerate(document["innerLengths"]):
        if not isinstance(record, dict):
            raise AuditFatalError(f"{fixture_path}: innerLengths[{i}] must be an object")
        direction = record.get("direction")
        if direction not in {"c2s", "s2c"}:
            raise AuditFatalError(f"{fixture_path}: innerLengths[{i}] has invalid direction")
        opcode = _require_int(record.get("opcode"), f"{fixture_path}: innerLengths[{i}]/opcode")
        inner_len = _require_int(record.get("innerLen"), f"{fixture_path}: innerLengths[{i}]/innerLen")
        lengths[(direction, opcode)] = inner_len
    return lengths


def audit_catalog(
    catalog: object,
    schema_lengths: dict[tuple[str, int], int],
    allowlist: dict[tuple[str, int], str],
) -> tuple[list[str], int, int]:
    if not isinstance(catalog, list) or len(catalog) != 1 or not isinstance(catalog[0], dict):
        raise AuditFatalError("catalog root must contain exactly one object")
    lists = catalog[0].get("lists")
    if not isinstance(lists, dict):
        raise AuditFatalError("catalog lists must be an object")

    findings: list[str] = []
    reconciled = 0
    allowed = 0
    for bucket, entries in lists.items():
        if not isinstance(entries, list):
            raise AuditFatalError(f"catalog bucket {bucket} must be an array")
        for entry in entries:
            if not isinstance(entry, dict) or "payloadLengths" not in entry:
                continue
            direction = {"serverbound": "c2s", "clientbound": "s2c"}.get(entry.get("direction"))
            opcode = entry.get("opcode")
            if direction is None or isinstance(opcode, bool) or not isinstance(opcode, int):
                continue
            key = (direction, opcode)
            inner_len = schema_lengths.get(key)
            if inner_len is None:
                continue
            lengths = entry.get("payloadLengths")
            if not isinstance(lengths, list) or any(isinstance(v, bool) or not isinstance(v, int) for v in lengths):
                raise AuditFatalError(f"{bucket}/0x{opcode:04x}: payloadLengths must be an integer array")

            reconciled += 1
            expected = inner_len + FRAMING_BYTES
            if expected in lengths:
                continue
            if key in allowlist:
                allowed += 1
                continue
            findings.append(
                f"{bucket}/0x{opcode:04x} {entry.get('name', '?')}: "
                f"payloadLengths {lengths} does not contain {inner_len} + 32 = {expected}"
            )

    return findings, reconciled, allowed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", default=str(OPCODES_PATH))
    parser.add_argument(
        "--manifests",
        default=None,
        help="research override: read an explicit client-ABI manifests directory "
        "instead of the promoted fixture",
    )
    parser.add_argument(
        "--no-allowlist",
        action="store_true",
        help="disable documented framing exceptions",
    )
    args = parser.parse_args()

    catalog_path = Path(args.catalog)

    try:
        if args.manifests is not None:
            manifests_dir = Path(args.manifests)
            if not manifests_dir.is_dir():
                raise AuditFatalError(f"--manifests {manifests_dir}: not a directory")
            schema_lengths = load_schema_lengths(manifests_dir)
        else:
            schema_lengths = load_fixture_lengths(FIXTURE)
        catalog = _load_json(catalog_path)
        allowlist = {} if args.no_allowlist else ALLOWLIST
        findings, reconciled, allowed = audit_catalog(catalog, schema_lengths, allowlist)
    except AuditFatalError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2

    if findings:
        print(f"payload framing audit FAILED ({len(findings)} finding(s)):", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        print(f"reconciled {reconciled} catalog entries; {allowed} allow-listed.", file=sys.stderr)
        return 1

    print(f"payload framing audit OK ({reconciled} reconciled; {allowed} allow-listed).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
