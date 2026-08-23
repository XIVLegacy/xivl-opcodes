#!/usr/bin/env python3
"""Validate the managed 0x0139..0x013C battle-result contract."""

from __future__ import annotations

import json
import sys

from _json_io import OPCODES_PATH, REPO_ROOT


EVIDENCE_PATH = REPO_ROOT / "data" / "battle_result_semantics.json"
EXPECTED_SCHEMA_VERSION = 1
EXPECTED_BINARY = {
    "name": "ffxivgame.exe",
    "version": "1.23b",
    "sha256": "9341f2b4567440b310a4d494f5cc5599ca334ba51c8042247317ff466492f2e9",
}
EXPECTED_SOURCE_REFS = {
    "xivl-client-structs:manifests/battle_result_field_semantics.json",
    "xivl-client-structs:manifests/battle_result_text_mapping.json",
    "xivl-captures:derived/observations.json#inner_opcodes.s2c.0x0139-0x013c",
    "xivl-captures:derived/payload_layouts.json#s2c-0x0139-0x013c",
    "xivl-captures:studies/battle-result-backfit/derived/world-master-message-contexts.json",
}
EXPECTED = {
    "0x0139": ("CommandResultX01Packet", "FUN_0058C880", 1, 438, 21, 50, 88),
    "0x013a": ("CommandResultX10Packet", "FUN_0058C930", 10, 66, 6, 14, 216),
    "0x013b": ("CommandResultX18Packet", "FUN_0058C990", 18, 0, 0, 0, 328),
    "0x013c": ("CommandResultX00Packet", "FUN_0058C7D0", 0, 27, 6, 18, 72),
}


def fail(message: str) -> None:
    print(f"Battle result semantics FAILED: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
    catalog = json.loads(OPCODES_PATH.read_text(encoding="utf-8"))
    if evidence.get("schemaVersion") != EXPECTED_SCHEMA_VERSION:
        fail(f"schemaVersion is {evidence.get('schemaVersion')!r}")
    if evidence.get("binary") != EXPECTED_BINARY:
        fail("retail binary identity drifted")
    if set(evidence.get("sourceRefs", [])) != EXPECTED_SOURCE_REFS:
        fail("sourceRefs must retain the client route, text map, and capture evidence locators")
    evidence_rows = evidence["rows"]
    rows = {row["opcodeHex"]: row for row in evidence_rows}
    if len(evidence_rows) != len(EXPECTED) or len(rows) != len(EXPECTED):
        fail("evidence must contain exactly one row for each managed opcode")
    if set(rows) != set(EXPECTED):
        fail(f"evidence opcode set is {sorted(rows)}, expected {sorted(EXPECTED)}")

    matched_catalog_rows = [
        row
        for row in catalog[0]["lists"]["MapClientbound"]
        if row["opcodeHex"] in EXPECTED
    ]
    if len(matched_catalog_rows) != len(EXPECTED):
        fail(f"MapClientbound has {len(matched_catalog_rows)} matching rows, expected {len(EXPECTED)}")
    catalog_rows = {
        row["opcodeHex"]: row
        for row in matched_catalog_rows
    }
    if set(catalog_rows) != set(EXPECTED):
        fail("all four rows must exist exactly once in MapClientbound")

    for opcode_hex, expected in EXPECTED.items():
        name, function, capacity, occurrences, captures, samples, size = expected
        evidence_row = rows[opcode_hex]
        exact = (
            evidence_row["name"],
            evidence_row["function"],
            evidence_row["rowCapacity"],
            evidence_row["observedOccurrences"],
            evidence_row["captureCount"],
            evidence_row["retainedSamples"],
            evidence_row["subpacketSize"],
        )
        if exact != expected:
            fail(f"{opcode_hex} evidence tuple {exact!r} != {expected!r}")

        row = catalog_rows[opcode_hex]
        if row["name"] != name:
            fail(f"{opcode_hex} name is {row['name']!r}, expected {name!r}")
        if row.get("implementationAnchor") is not None:
            fail(f"{opcode_hex} implementationAnchor must be null")
        if row.get("decompAnchor") != function:
            fail(f"{opcode_hex} decompAnchor is {row.get('decompAnchor')!r}")
        if row.get("confidence") != "decomp_routed":
            fail(f"{opcode_hex} confidence is {row.get('confidence')!r}")
        expected_lengths = [] if opcode_hex == "0x013b" else [size]
        if row.get("payloadLengths") != expected_lengths:
            fail(f"{opcode_hex} payloadLengths is {row.get('payloadLengths')!r}")
        if len(row.get("observedIn", [])) != captures:
            fail(f"{opcode_hex} observedIn count is {len(row.get('observedIn', []))}, expected {captures}")
        notes = row.get("notes", "")
        for token in (
            "battle_result_semantics=data/battle_result_semantics.json",
            f"row_capacity={capacity}",
            f"observed_occurrences={occurrences}",
            f"capture_count={captures}",
            f"retained_samples={samples}",
            "prior_implementation_anchor_conflict=",
            "client_data_boundary=",
        ):
            if token not in notes:
                fail(f"{opcode_hex} is missing note token {token!r}")
        if opcode_hex == "0x013b" and row.get("observedIn"):
            fail("0x013b must remain capture-empty")
    queue = evidence["normalizedQueue"]
    if (queue["recordSize"], queue["headerSize"], queue["rowOffset"], queue["rowStride"], queue["rowCapacity"]) != (416, 56, 56, 20, 18):
        fail("normalized queue dimensions drifted")
    if "runtime naming" not in evidence["unresolvedBoundaries"][0]:
        fail("0x013b runtime-name boundary is missing")

    print("Battle result semantics OK (4 rows, 18-row queue, 0x013B capture-empty).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
