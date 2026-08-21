#!/usr/bin/env python3
"""Verify the fixed retail ZoneProtoDown dispatch observation contract."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _schema_check  # noqa: E402


REPO = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = REPO / "tools" / "fixtures" / "retail_zone_dispatch_observations.json"
DEFAULT_CHECK = REPO / "data" / "retail_zone_dispatch_check.json"
DEFAULT_RETAIL_INPUTS = REPO / "data" / "retail_inputs.json"
DEFAULT_SCHEMA = REPO / "schemas" / "retail-evidence-attestation-v1.schema.json"
DEFAULT_ZONE_MAP = REPO / "data" / "zone_dispatch_map.json"
DEFAULT_SEMANTICS = REPO / "data" / "client_opcode_semantics.json"
DEFAULT_CATALOG = REPO / "opcodes.json"
DEFAULT_EXPORTER = REPO / "tools" / "ghidra_scripts" / "ExportZoneDispatchRoute.java"

CHECK_ID = "zone-dispatch-0x018d-slot-v1"
INPUT_ID = "ffxivgame-1.23b"
INPUT_FILENAME = "ffxivgame.exe"
INPUT_SIZE = 15996808
INPUT_SHA256 = "9341f2b4567440b310a4d494f5cc5599ca334ba51c8042247317ff466492f2e9"
PRIVATE_REPOSITORY = "XIVLegacy/xivl-private-assets"
PRIVATE_COMMIT = "aeb52f6dbde95a793ee6d52be28de9f28a885b15"
PRIVATE_PATH = "ffxivgame.exe"
SCHEMA_VERSION = 1
ATTESTATION_FILENAME = "retail-evidence-attestation.json"
TOOL_VERSIONS = {
    "ghidra": "12.1.3",
    "jdk": "21.0.12.1+1",
    "verifier": "1.0",
}

DISPATCHER_VA = "0x00dbfd10"
OPCODE = "0x018d"
BYTE_TABLE_VA = "0x00dc1274"
DWORD_TABLE_VA = "0x00dc0f5c"
BYTE_TABLE_ENTRY_VA = "0x00dc1400"
EXPECTED_CASE_INDEX = 134
EXPECTED_VTABLE_SLOT = 136

ADDRESS_RE = re.compile(r"^0x[0-9a-f]{8}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")

CHECK_KEYS = frozenset({
    "schema_version", "check", "input_id", "locator", "expected",
})
OBSERVATION_KEYS = frozenset({
    "schema_version", "check_id", "input_id", "dispatcher_va", "opcode",
    "byte_table_va", "dword_table_va", "byte_table_entry_va", "case_index",
    "vtable_slot",
})


class VerificationError(Exception):
    """Malformed input that is safe to report without its contents."""


EXPORTER_REQUIRED_SNIPPETS = (
    "validateDispatcherPacketPath(dispatcher, opcodeLoad)",
    "\"EAX\".equalsIgnoreCase(((Register) object).getName())",
    "validateNormalization(normalized)",
    "validateBound(bound, opcodeBase, opcode)",
    "validateByteTableLoad(byteLoad, byteTableVa)",
    "validateDwordTableJump(jump, dwordTableVa)",
    "readUnsignedByte(byteTableEntryVa)",
    "long dwordEntryVa = dwordTableVa + ((long) caseIndex * 4L)",
    "readUnsignedDword(dwordEntryVa)",
    "validateLoadRegister(body[0], \"ESI\", \"ECX\", 0L)",
    "validateAdd(body[1], \"EAX\", PAYLOAD_OFFSET)",
    "validateCallbackLoad(body[3])",
    "validateIndirectCall(body[7], \"EAX\")",
    "return displacement / 4",
    "StandardCharsets.US_ASCII",
    "StandardCopyOption.ATOMIC_MOVE",
)
EXPORTER_EXPECTATION_LITERAL_RE = re.compile(
    r"(?<![0-9A-Za-z_])(?:134|136|0x0*86[lL]?|0x0*88[lL]?)(?![0-9A-Za-z_])"
)


def exporter_source_errors(source: str) -> list[str]:
    """Reject a widened or expectation-seeded exporter contract."""
    errors = [
        "exporter data-flow contract is incomplete"
        for snippet in EXPORTER_REQUIRED_SNIPPETS
        if snippet not in source
    ]
    if EXPORTER_EXPECTATION_LITERAL_RE.search(source):
        errors.append("exporter contains an expected result literal")
    return errors


def _read_json(path: Path) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        document: dict[str, Any] = {}
        for key, value in pairs:
            if key in document:
                raise VerificationError("JSON input contains a duplicate field")
            document[key] = value
        return document

    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle, object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError("JSON input could not be read") from exc


def _read_observation(path: Path) -> Any:
    document = _read_json(path)
    try:
        text = path.read_bytes().decode("ascii")
    except (OSError, UnicodeError) as exc:
        raise VerificationError("observation is not ASCII") from exc
    canonical = json.dumps(
        document, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ) + "\n"
    if text != canonical:
        raise VerificationError("observation serialization is not canonical")
    return document


def _retail_input_errors(document: Any) -> list[str]:
    expected = {
        "schema_version": 1,
        "inputs": [{
            "id": INPUT_ID,
            "filename": INPUT_FILENAME,
            "size": INPUT_SIZE,
            "sha256": INPUT_SHA256,
            "source": {
                "repository": PRIVATE_REPOSITORY,
                "commit": PRIVATE_COMMIT,
                "path": PRIVATE_PATH,
            },
            "allowed_checks": [CHECK_ID],
        }],
    }
    if (
        document == expected
        and type(document.get("schema_version")) is int
        and type(document["inputs"][0].get("size")) is int
    ):
        return []
    return ["retail input grant drifted"]


def _expected_check() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "check": {"id": CHECK_ID, "version": 1},
        "input_id": INPUT_ID,
        "locator": {
            "dispatcher_va": DISPATCHER_VA,
            "opcode": OPCODE,
            "byte_table_va": BYTE_TABLE_VA,
            "dword_table_va": DWORD_TABLE_VA,
        },
        "expected": {
            "byte_table_entry_va": BYTE_TABLE_ENTRY_VA,
            "case_index": EXPECTED_CASE_INDEX,
            "vtable_slot": EXPECTED_VTABLE_SLOT,
        },
    }


def _check_errors(document: Any) -> list[str]:
    if not isinstance(document, dict) or frozenset(document) != CHECK_KEYS:
        return ["check document shape is invalid"]
    if (
        document == _expected_check()
        and type(document.get("schema_version")) is int
        and type(document.get("check", {}).get("version")) is int
        and type(document.get("expected", {}).get("case_index")) is int
        and type(document.get("expected", {}).get("vtable_slot")) is int
    ):
        return []
    return ["check document drifted"]


def _observation_errors(document: Any) -> list[str]:
    if not isinstance(document, dict) or frozenset(document) != OBSERVATION_KEYS:
        return ["observation document shape is invalid"]
    errors: list[str] = []
    addresses = (
        "dispatcher_va", "byte_table_va", "dword_table_va",
        "byte_table_entry_va",
    )
    if any(not isinstance(document.get(name), str)
           or not ADDRESS_RE.fullmatch(document[name]) for name in addresses):
        errors.append("observation address is malformed")
    if (
        document.get("schema_version") != SCHEMA_VERSION
        or document.get("check_id") != CHECK_ID
        or document.get("input_id") != INPUT_ID
        or document.get("dispatcher_va") != DISPATCHER_VA
        or document.get("opcode") != OPCODE
        or document.get("byte_table_va") != BYTE_TABLE_VA
        or document.get("dword_table_va") != DWORD_TABLE_VA
        or document.get("byte_table_entry_va") != BYTE_TABLE_ENTRY_VA
        or document.get("case_index") != EXPECTED_CASE_INDEX
        or document.get("vtable_slot") != EXPECTED_VTABLE_SLOT
        or type(document.get("schema_version")) is not int
        or isinstance(document.get("case_index"), bool)
        or isinstance(document.get("vtable_slot"), bool)
    ):
        errors.append("observation identity or result is invalid")
    return errors


def _tracked_source_errors(zone_map: Any, semantics: Any, catalog: Any) -> list[str]:
    errors: list[str] = []
    cases = zone_map.get("cases") if isinstance(zone_map, dict) else None
    matches = [
        row for row in cases or []
        if isinstance(row, dict) and OPCODE in row.get("opcodes", [])
    ]
    if len(matches) != 1:
        errors.append("tracked dispatch row is not unique")
    elif matches[0] != {
        "case": EXPECTED_CASE_INDEX,
        "vtable_slot": EXPECTED_VTABLE_SLOT,
        "opcodes": [OPCODE],
        "is_catchall": False,
    } or matches[0].get("is_catchall") is not False:
        errors.append("tracked dispatch row drifted")

    rows = semantics.get("rows") if isinstance(semantics, dict) else None
    semantic_matches = [
        row for row in rows or []
        if isinstance(row, dict) and row.get("id") == "s2c-018d"
    ]
    if len(semantic_matches) != 1:
        errors.append("tracked semantic row is not unique")
    elif any(semantic_matches[0].get(name) != value for name, value in {
        "opcodeHex": OPCODE,
        "direction": "clientbound",
        "function": "FUN_00575550",
        "status": "closed",
    }.items()):
        errors.append("tracked semantic row drifted")

    catalog_rows = []
    if isinstance(catalog, list):
        for document in catalog:
            if isinstance(document, dict):
                lists = document.get("lists")
                if isinstance(lists, dict) and isinstance(lists.get("MapClientbound"), list):
                    catalog_rows.extend(lists["MapClientbound"])
    catalog_matches = [
        row for row in catalog_rows
        if isinstance(row, dict) and row.get("opcodeHex") == OPCODE
    ]
    if len(catalog_matches) != 1:
        errors.append("tracked MapClientbound row is not unique")
    else:
        row = catalog_matches[0]
        expected_fields = {
            "opcode": 397,
            "opcodeHex": OPCODE,
            "direction": "clientbound",
            "implementationAnchor": None,
            "decompAnchor": "FUN_00575550",
            "confidence": "decomp_routed",
        }
        if any(row.get(name) != value for name, value in expected_fields.items()):
            errors.append("tracked MapClientbound row drifted")
    return errors


def _git_commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO,
            check=True,
            capture_output=True,
            text=True,
        )
        commit = result.stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise VerificationError("public repository commit could not be resolved") from exc
    if not COMMIT_RE.fullmatch(commit):
        raise VerificationError("public repository commit is not a full lowercase SHA")
    return commit


def build_attestation(status: str, public_commit: str | None = None) -> dict[str, Any]:
    if status not in {"pass", "fail"}:
        raise ValueError("attestation status is invalid")
    commit = public_commit if public_commit is not None else _git_commit()
    if not COMMIT_RE.fullmatch(commit) or set(commit) == {"0"}:
        raise ValueError("public repository commit is invalid")
    return {
        "schemaVersion": SCHEMA_VERSION,
        "publicRepositoryCommit": commit,
        "approvedInputSha256": INPUT_SHA256,
        "toolVersions": dict(TOOL_VERSIONS),
        "check": {"id": CHECK_ID, "version": 1},
        "result": {"status": status},
    }


def verify(
    input_path: Path = DEFAULT_INPUT,
    check_path: Path = DEFAULT_CHECK,
    retail_inputs_path: Path = DEFAULT_RETAIL_INPUTS,
    zone_map_path: Path = DEFAULT_ZONE_MAP,
    semantics_path: Path = DEFAULT_SEMANTICS,
    catalog_path: Path = DEFAULT_CATALOG,
    exporter_path: Path = DEFAULT_EXPORTER,
) -> list[str]:
    observations = _read_observation(input_path)
    check = _read_json(check_path)
    retail_inputs = _read_json(retail_inputs_path)
    zone_map = _read_json(zone_map_path)
    semantics = _read_json(semantics_path)
    catalog = _read_json(catalog_path)
    try:
        exporter_source = exporter_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise VerificationError("exporter source could not be read") from exc
    errors = _retail_input_errors(retail_inputs)
    errors.extend(_check_errors(check))
    errors.extend(_tracked_source_errors(zone_map, semantics, catalog))
    errors.extend(_observation_errors(observations))
    errors.extend(exporter_source_errors(exporter_source))
    return errors


def dispatch_errors(event_name: str, ref: str, sha: str, head: str | None) -> list[str]:
    if event_name != "workflow_dispatch":
        return ["dispatch event is unauthorized"]
    if ref != "refs/heads/main":
        return ["dispatch ref is unauthorized"]
    if not COMMIT_RE.fullmatch(sha or "") or not COMMIT_RE.fullmatch(head or ""):
        return ["dispatch revision is unauthorized"]
    if sha != head:
        return ["dispatch revision does not match HEAD"]
    return []


def retained_output_errors(directory: Path) -> list[str]:
    if not directory.is_dir() or directory.is_symlink():
        return ["retained output root is invalid"]
    try:
        entries = list(directory.iterdir())
    except OSError:
        return ["retained output root is unreadable"]
    if len(entries) != 1 or entries[0].name != ATTESTATION_FILENAME:
        return ["retained output allowlist differs"]
    path = entries[0]
    try:
        if path.is_symlink() or not path.is_file():
            return ["retained attestation is not a regular file"]
        if path.stat().st_size > 4096:
            return ["retained attestation is too large"]
        raw = path.read_bytes()
        raw.decode("ascii")
        attestation = json.loads(raw.decode("ascii"))
        schema = _schema_check.load_schema(DEFAULT_SCHEMA)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError,
            _schema_check.SchemaError):
        return ["retained attestation could not be validated"]
    return ["retained attestation schema rejected output"] if _schema_check.validate(
        attestation, schema
    ) else []


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, dest="input_path")
    parser.add_argument("--check", type=Path, default=DEFAULT_CHECK, dest="check_path")
    parser.add_argument("--retail-inputs", type=Path, default=DEFAULT_RETAIL_INPUTS)
    parser.add_argument("--zone-map", type=Path, default=DEFAULT_ZONE_MAP)
    parser.add_argument("--semantics", type=Path, default=DEFAULT_SEMANTICS)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--check-dispatch", action="store_true")
    parser.add_argument("--validate-retained-output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.check_dispatch:
        try:
            head = _git_commit()
        except VerificationError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        errors = dispatch_errors(
            os.environ.get("GITHUB_EVENT_NAME", ""),
            os.environ.get("GITHUB_REF", ""),
            os.environ.get("GITHUB_SHA", ""),
            head,
        )
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1 if errors else 0
    if args.validate_retained_output is not None:
        errors = retained_output_errors(args.validate_retained_output)
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1 if errors else 0

    try:
        errors = verify(
            args.input_path,
            args.check_path,
            args.retail_inputs,
            args.zone_map,
            args.semantics,
            args.catalog,
        )
        public_commit = _git_commit()
        attestation = build_attestation("pass" if not errors else "fail", public_commit)
    except (VerificationError, OSError, KeyError, TypeError, ValueError):
        errors = ["verification input is malformed"]
        try:
            attestation = build_attestation("fail")
        except (VerificationError, ValueError):
            for error in errors:
                print(f"ERROR: {error}", file=sys.stderr)
            return 1
    try:
        schema = _schema_check.load_schema(DEFAULT_SCHEMA)
        schema_errors = _schema_check.validate(attestation, schema)
    except (OSError, ValueError, _schema_check.SchemaError):
        schema_errors = ["schema unavailable"]
    if schema_errors:
        errors.append("attestation schema rejected output")
        attestation["result"] = {"status": "fail"}
    payload = json.dumps(
        attestation, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii") + b"\n"
    sys.stdout.buffer.write(payload)
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
