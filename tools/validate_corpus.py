#!/usr/bin/env python3
"""Validate schemas and catalog invariants; schema checks require jsonschema."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from _json_io import CONSTANTS_PATH, DATA_DIR, OPCODES_PATH, REPO_ROOT

SCHEMAS = REPO_ROOT / "schemas"
# Gate inputs are promoted fixtures in this repository. PROVENANCE.json records their origin.
CAPTURES_INDEX = REPO_ROOT / "data" / "vendor" / "captures-index" / "captures.json"
BCSY_INDEX = REPO_ROOT / "data" / "vendor" / "client-structs" / "bcsy-ids.json"
BCSY_OPCODE_BINDINGS = (
    REPO_ROOT / "data" / "vendor" / "client-structs" / "bcsy-opcode-bindings.json"
)
BCSY_EXPECTED_GAPS = REPO_ROOT / "data" / "sibling_sync_expected_gaps.json"

# Enforce each bucket's (service, direction) pair; JSON Schema cannot express it.
BUCKET_MAP = {
    "LobbyServerbound": ("lobby", "serverbound"),
    "LobbyClientbound": ("lobby", "clientbound"),
    "WorldServerbound": ("world", "serverbound"),
    "WorldClientbound": ("world", "clientbound"),
    "MapServerbound": ("map", "serverbound"),
    "MapClientbound": ("map", "clientbound"),
    "WorldMapBackend": ("world_map_backend", "backend"),
}

BCSY_RE = re.compile(r"BCS-Y-\d+")

try:
    import jsonschema  # noqa: PLC0415

    _HAVE_JSONSCHEMA = True
except ImportError:
    _HAVE_JSONSCHEMA = False

errors: list[str] = []
reverse_sync_report: dict[str, object] = {}


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def validate_schemas() -> None:
    if not _HAVE_JSONSCHEMA:
        return
    pairs = [
        (OPCODES_PATH, SCHEMAS / "opcodes.schema.json", "opcodes.json"),
        (CONSTANTS_PATH, SCHEMAS / "constants.schema.json", "constants.json"),
    ]
    for inst_path, schema_path, label in pairs:
        if not inst_path.is_file():
            errors.append(f"{label}: file missing")
            continue
        if not schema_path.is_file():
            errors.append(f"{label}: schema {schema_path.name} missing")
            continue
        validator = jsonschema.Draft202012Validator(_load(schema_path))
        for err in sorted(validator.iter_errors(_load(inst_path)), key=lambda e: list(e.path)):
            loc = "/".join(str(p) for p in err.path) or "(root)"
            errors.append(f"{label}: schema violation at {loc}: {err.message}")


def load_capture_names(captures_dir) -> set[str]:
    """Resolve observedIn names from the promoted fixture or explicit research input."""
    if captures_dir is not None:
        if not captures_dir.is_dir():
            errors.append(f"--captures-dir {captures_dir}: not a directory")
            return set()
        return {p.name for p in captures_dir.glob("*.pcapng")}
    if not CAPTURES_INDEX.is_file():
        errors.append(f"{CAPTURES_INDEX}: capture-name fixture missing")
        return set()
    return set(_load(CAPTURES_INDEX).get("captureNames", []))


def validate_catalog(cap_names: set[str]) -> None:
    cat_path = OPCODES_PATH
    const_path = CONSTANTS_PATH
    if not cat_path.is_file():
        errors.append("opcodes.json: file missing")
        return
    catalog = _load(cat_path)
    if not isinstance(catalog, list) or len(catalog) != 1 or not isinstance(catalog[0], dict):
        errors.append("opcodes.json: root must contain exactly one catalog object")
        return
    top = catalog[0]
    constants = _load(const_path) if const_path.is_file() else {}
    region = top.get("region")
    declared = constants.get(region) if isinstance(constants, dict) else None
    if not isinstance(declared, dict):
        errors.append(f"constants.json: no metadata object for catalog region {region!r}")
        declared = {}
    elif declared.get("Version") != top.get("version"):
        errors.append(
            f"constants.json: {region}/Version {declared.get('Version')!r} "
            f"!= catalog version {top.get('version')!r}"
        )
    services = set(declared.get("Services", []))
    directions = set(declared.get("Directions", []))
    confidences = set(declared.get("ConfidenceLabels", []))

    for bucket, entries in top.get("lists", {}).items():
        expect = BUCKET_MAP.get(bucket)
        if expect is None:
            errors.append(f"lists: unknown bucket {bucket}")
        for entry in entries:
            opcode = entry.get("opcode")
            tag = f"{bucket}/{entry.get('opcodeHex', opcode)} {entry.get('name', '?')}"

            if "opcodeHex" in entry and isinstance(opcode, int):
                want = f"0x{opcode:04x}"
                if entry["opcodeHex"] != want:
                    errors.append(f"{tag}: opcodeHex {entry['opcodeHex']} != {want}")

            if expect is not None:
                if entry.get("service") != expect[0]:
                    errors.append(
                        f"{tag}: service {entry.get('service')} != {expect[0]} for bucket {bucket}"
                    )
                if entry.get("direction") != expect[1]:
                    errors.append(
                        f"{tag}: direction {entry.get('direction')} != {expect[1]} for bucket {bucket}"
                    )

            if services and entry.get("service") not in services:
                errors.append(f"{tag}: service {entry.get('service')} not declared in constants.json")
            if directions and entry.get("direction") not in directions:
                errors.append(f"{tag}: direction {entry.get('direction')} not declared in constants.json")
            if confidences and entry.get("confidence") not in confidences:
                errors.append(
                    f"{tag}: confidence {entry.get('confidence')} not declared in constants.json"
                )

            for observed in entry.get("observedIn", []):
                if observed not in cap_names:
                    errors.append(f"{tag}: observedIn '{observed}' not in the capture-name index")

            # Reject stale no_pcap_evidence when observedIn is populated.
            if "no_pcap_evidence" in (entry.get("notes") or "") and entry.get("observedIn"):
                errors.append(f"{tag}: notes say 'no_pcap_evidence' but observedIn is non-empty")

            # Reject stale "pcap_observations merged" when observedIn is empty.
            if "pcap_observations merged" in (entry.get("notes") or "") and not entry.get("observedIn"):
                errors.append(f"{tag}: notes claim 'pcap_observations merged' but observedIn is empty")

            # Lobby rows cannot carry pcap evidence; enforce PCAP_LOBBY_PURGE.
            if entry.get("service") == "lobby" and entry.get("observedIn"):
                errors.append(f"{tag}: lobby-service row must not carry pcap observedIn")

    # Pcap keys are direction+opcode only; shared services require pcap_service_ambiguous.
    obs_by_dir_op = {}
    for bucket, entries in top.get("lists", {}).items():
        for entry in entries:
            if entry.get("service") != "lobby" and entry.get("observedIn"):
                key = (entry.get("direction"), entry.get("opcode"))
                obs_by_dir_op.setdefault(key, []).append(entry)
    for (direction, opcode), rows in obs_by_dir_op.items():
        services = {r.get("service") for r in rows}
        if len(services) > 1:
            for r in rows:
                if "pcap_service_ambiguous" not in (r.get("notes") or ""):
                    rtag = f"{r.get('service')}/{r.get('opcodeHex')} {r.get('name', '?')}"
                    errors.append(
                        f"{rtag}: pcap evidence shared across services "
                        f"{sorted(services)} but notes lack pcap_service_ambiguous"
                    )


def validate_bcsy_refs(symbols_path) -> None:
    """Validate BCS-Y-NNNN references against the promoted or explicit symbol index."""
    if symbols_path is not None:
        if not symbols_path.is_file():
            errors.append(f"--symbols {symbols_path}: file missing")
            return
        symbol_ids = set(BCSY_RE.findall(symbols_path.read_text(encoding="utf-8")))
    else:
        if not BCSY_INDEX.is_file():
            errors.append(f"{BCSY_INDEX}: BCS-Y id fixture missing")
            return
        symbol_ids = set(_load(BCSY_INDEX).get("bcsyIds", []))

    for path in [OPCODES_PATH, *sorted(DATA_DIR.glob("*.json"))]:
        if not path.is_file():
            continue
        refs = set(BCSY_RE.findall(path.read_text(encoding="utf-8")))
        label = path.relative_to(REPO_ROOT).as_posix()
        for ref in sorted(refs - symbol_ids):
            errors.append(f"{label}: {ref} not found in BCS-Y id index")


def validate_reverse_bcsy_sync(expected_gaps_path: Path) -> None:
    """Report opcode-bound sibling symbols that the root catalogs do not cite.

    A BCS-Y entry is a sync candidate exactly when the pinned sibling IR lists
    its id in ``relationships.opcodes[].symbols``. That is a structured,
    direction-qualified opcode binding. Mere presence in the BCS-Y id space,
    including an entry carrying only a vtable or RTTI name, does not qualify.
    Reflection is id-based and intentionally does not choose a catalog name:
    either root catalog must cite the candidate id. Known gaps are explicit so
    newly introduced or stale gaps fail while catalog naming remains manual.
    """
    global reverse_sync_report

    if not BCSY_OPCODE_BINDINGS.is_file():
        errors.append(f"{BCSY_OPCODE_BINDINGS}: BCS-Y opcode-binding fixture missing")
        return
    if not expected_gaps_path.is_file():
        errors.append(f"{expected_gaps_path}: expected sibling-sync gap set missing")
        return

    fixture = _load(BCSY_OPCODE_BINDINGS)
    raw_candidates = fixture.get("syncCandidates", [])
    if not isinstance(raw_candidates, list):
        errors.append(f"{BCSY_OPCODE_BINDINGS}: syncCandidates must be an array")
        return

    candidates: dict[str, dict] = {}
    for candidate in raw_candidates:
        if not isinstance(candidate, dict):
            errors.append(f"{BCSY_OPCODE_BINDINGS}: each sync candidate must be an object")
            continue
        symbol_id = candidate.get("bcsyId")
        bindings = candidate.get("opcodeBindings")
        if not isinstance(symbol_id, str) or not BCSY_RE.fullmatch(symbol_id):
            errors.append(f"{BCSY_OPCODE_BINDINGS}: invalid candidate id {symbol_id!r}")
            continue
        if symbol_id in candidates:
            errors.append(f"{BCSY_OPCODE_BINDINGS}: duplicate candidate {symbol_id}")
            continue
        if not isinstance(bindings, list) or not bindings:
            errors.append(f"{BCSY_OPCODE_BINDINGS}: {symbol_id} has no opcode bindings")
            continue
        seen_bindings: set[tuple[str, str]] = set()
        malformed = False
        for binding in bindings:
            if not isinstance(binding, dict):
                malformed = True
                break
            direction = binding.get("direction")
            opcode_hex = binding.get("opcodeHex")
            if (
                direction not in {"c2s", "s2c"}
                or not isinstance(opcode_hex, str)
                or re.fullmatch(r"0x[0-9a-f]{4}", opcode_hex) is None
            ):
                malformed = True
                break
            seen_bindings.add((direction, opcode_hex))
        if malformed or len(seen_bindings) != len(bindings):
            errors.append(f"{BCSY_OPCODE_BINDINGS}: {symbol_id} has malformed or duplicate bindings")
            continue
        candidates[symbol_id] = candidate

    expected_doc = _load(expected_gaps_path)
    raw_expected = expected_doc.get("expectedMissingBcsyIds", [])
    if not isinstance(raw_expected, list) or not all(isinstance(item, str) for item in raw_expected):
        errors.append(f"{expected_gaps_path}: expectedMissingBcsyIds must be a string array")
        return
    expected = set(raw_expected)
    if len(expected) != len(raw_expected):
        errors.append(f"{expected_gaps_path}: expectedMissingBcsyIds contains duplicates")

    root_refs: set[str] = set()
    for path in (OPCODES_PATH, CONSTANTS_PATH):
        if path.is_file():
            root_refs.update(BCSY_RE.findall(path.read_text(encoding="utf-8")))
    candidate_ids = set(candidates)
    reflected = candidate_ids & root_refs
    missing = candidate_ids - reflected

    for symbol_id in sorted(missing - expected):
        errors.append(f"sibling sync: unacknowledged opcode-bound candidate {symbol_id}")
    for symbol_id in sorted(expected - missing):
        state = "already reflected" if symbol_id in reflected else "not a current candidate"
        errors.append(f"sibling sync: stale expected gap {symbol_id} ({state})")

    reverse_sync_report = {
        "candidate_count": len(candidate_ids),
        "reflected_count": len(reflected),
        "missing_count": len(missing),
        "missing": [candidates[symbol_id] for symbol_id in sorted(missing)],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Opcode-corpus schema + referential-integrity gate.")
    ap.add_argument(
        "--json",
        action="store_true",
        help="print findings as JSON on stdout instead of a text report; exit code unchanged",
    )
    ap.add_argument(
        "--captures-dir",
        type=Path,
        default=None,
        help="research override: list an explicit packet-capture directory instead of "
        "the promoted fixture",
    )
    ap.add_argument(
        "--symbols",
        type=Path,
        default=None,
        help="research override: read an explicit client-ABI symbols.json instead of "
        "the promoted fixture",
    )
    ap.add_argument(
        "--expected-sibling-gaps",
        type=Path,
        default=BCSY_EXPECTED_GAPS,
        help="test override: expected-gap baseline for the reverse sibling-sync check",
    )
    args = ap.parse_args()

    # Keep --json stdout machine-readable by suppressing the dependency advisory.
    if not _HAVE_JSONSCHEMA and not args.json:
        print(
            "note: jsonschema not installed; schema checks skipped "
            "(referential checks still run). pip install jsonschema",
            file=sys.stderr,
        )
    validate_schemas()
    cap_names = load_capture_names(args.captures_dir)
    validate_catalog(cap_names)
    validate_bcsy_refs(args.symbols)
    validate_reverse_bcsy_sync(args.expected_sibling_gaps)

    if args.json:
        print(json.dumps({
            "ok": not errors,
            "error_count": len(errors),
            "errors": errors,
            "sibling_sync": reverse_sync_report,
        }, indent=2))
        return 1 if errors else 0

    if reverse_sync_report:
        print(
            "sibling sync: "
            f"{reverse_sync_report['candidate_count']} opcode-bound candidate(s), "
            f"{reverse_sync_report['reflected_count']} reflected, "
            f"{reverse_sync_report['missing_count']} expected gap(s)"
        )

    if errors:
        print(f"corpus validation FAILED ({len(errors)} problem(s)):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print(
        "corpus validation OK "
        "(schemas, catalog invariants, observedIn, BCS-Y refs, sibling sync)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
