#!/usr/bin/env python3
"""Validate the s2c 0x0003 Map chat wire-layout contract."""

from __future__ import annotations

import json
import re
import sys

from _json_io import OPCODES_PATH, REPO_ROOT

EVIDENCE_PATH = REPO_ROOT / "data" / "s2c_0003_wire_layout.json"
HEADER_PATH = REPO_ROOT / "structs" / "map" / "clientbound.h"
EXPECTED_BINARY = {
    "name": "ffxivgame.exe",
    "version": "1.23b",
    "sha256": "9341f2b4567440b310a4d494f5cc5599ca334ba51c8042247317ff466492f2e9",
}
EXPECTED_FRAMING = {
    "subpacketSize": 584,
    "subpacketHeaderSize": 16,
    "gameMessageHeaderSize": 16,
    "applicationOffsetFromSubpacket": 32,
    "applicationSize": 552,
    "consumedExtent": 548,
}
EXPECTED_FIELDS = (
    (0x00, 0x20, "senderName"),
    (0x20, 0x02, "displayType"),
    (0x22, 0x02, "unread22"),
    (0x24, 0x200, "text"),
    (0x224, 0x04, "unreadTail"),
)
EXPECTED_ROUTE = {
    "dispatcher": "FUN_004DC690",
    "byteTableVa": "0x004DD414",
    "byteTableIndex": 1,
    "dwordTableVa": "0x004DD3D0",
    "dwordTableIndex": 1,
    "caseEntry": "0x004DC750",
    "stringCopy": "FUN_00447260",
    "sink": "FUN_004D8560",
}
EXPECTED_CAPTURE = {
    "file": "login.pcapng",
    "sha256": "28e06b54fe559870031f077f8549b9244caafa7e5177dbca08a7feae6c2b1b62",
    "retainedSamples": 4,
    "identicalSamples": True,
    "subpacketSize": 584,
    "nonzeroApplicationBytes": [{"offset": 32, "value": 29}],
}
CATALOG_NOTE = "wire_layout=data/s2c_0003_wire_layout.json"
STRUCT_RE = re.compile(
    r"// 0x0003 \(opcode 3\) - sub_size=584B body=560B samples=4\s+"
    r"struct SendMessageBody\s*\{(?P<body>.*?)\};\s+"
    r'static_assert\(sizeof\(SendMessageBody\) == 560, "SendMessageBody size mismatch"\);',
    re.S,
)
HEADER_FIELDS = (
    ("uint8_t", "gameMessagePreamble", 8),
    ("uint8_t", "senderName", 32),
    ("uint16_t", "displayType", 1),
    ("uint8_t", "unread22", 2),
    ("uint8_t", "text", 512),
    ("uint8_t", "unreadTail", 4),
)


def check_document(doc: dict, errors: list[str]) -> None:
    if doc.get("schemaVersion") != 1:
        errors.append("schemaVersion must be 1")
    if doc.get("binary") != EXPECTED_BINARY:
        errors.append("binary identity differs")
    for key, value in (
        ("opcodeHex", "0x0003"),
        ("direction", "clientbound"),
        ("service", "map"),
        ("name", "SendMessagePacket"),
    ):
        if doc.get(key) != value:
            errors.append(f"{key} must be {value}")
    route = doc.get("route", {})
    for key, value in EXPECTED_ROUTE.items():
        if route.get(key) != value:
            errors.append(f"route.{key} must be {value}")
    framing = doc.get("framing", {})
    for key, value in EXPECTED_FRAMING.items():
        if framing.get(key) != value:
            errors.append(f"framing.{key} must be {value}")
    if framing.get("subpacketHeaderSize", 0) + framing.get(
        "gameMessageHeaderSize", 0
    ) != framing.get("applicationOffsetFromSubpacket"):
        errors.append("application offset must follow both headers")
    if framing.get("applicationOffsetFromSubpacket", 0) + framing.get(
        "applicationSize", 0
    ) != framing.get("subpacketSize"):
        errors.append("application must end at the subpacket size")

    fields = doc.get("application", {}).get("fields", [])
    observed = tuple((f.get("offset"), f.get("width"), f.get("name")) for f in fields)
    if observed != EXPECTED_FIELDS:
        errors.append("application fields differ from the reviewed layout")
    cursor = 0
    for field in fields:
        if field.get("offset") != cursor:
            errors.append(f"field {field.get('name')} leaves a gap or overlap")
        cursor = field.get("offset", 0) + field.get("width", 0)
    if cursor != framing.get("applicationSize"):
        errors.append("fields must cover the application exactly")
    if fields and fields[-1].get("offset") != framing.get("consumedExtent"):
        errors.append("consumedExtent must equal the unread tail offset")

    capture = doc.get("capture", {})
    for key, value in EXPECTED_CAPTURE.items():
        if capture.get(key) != value:
            errors.append(f"capture.{key} must be {value}")
    if capture.get("subpacketSize") != framing.get("subpacketSize"):
        errors.append("capture subpacket size must match the framing")


def check_catalog(errors: list[str]) -> None:
    catalog = json.loads(OPCODES_PATH.read_text(encoding="utf-8"))[0]
    rows = [
        entry
        for entry in catalog["lists"]["MapClientbound"]
        if entry["opcodeHex"] == "0x0003"
    ]
    if len(rows) != 1 or rows[0]["name"] != "SendMessagePacket":
        errors.append("MapClientbound must hold one SendMessagePacket row at 0x0003")
        return
    if CATALOG_NOTE not in rows[0].get("notes", ""):
        errors.append("the MapClientbound 0x0003 notes must cite the wire layout")


def check_header(errors: list[str]) -> None:
    match = STRUCT_RE.search(HEADER_PATH.read_text(encoding="ascii"))
    if match is None:
        errors.append("structs/map/clientbound.h lacks the reviewed SendMessageBody")
        return
    declared = re.findall(
        r"(uint8_t|uint16_t)\s+(\w+?)(?:\[(\d+)\])?\s*;", match.group("body")
    )
    observed = tuple((t, n, int(c) if c else 1) for t, n, c in declared)
    if observed != HEADER_FIELDS:
        errors.append("SendMessageBody fields differ from the reviewed layout")


def main() -> int:
    errors: list[str] = []
    try:
        doc = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        check_document(doc, errors)
        check_catalog(errors)
        check_header(errors)
    except (OSError, UnicodeError, ValueError, KeyError, IndexError) as exc:
        errors.append(f"could not read the contract: {exc}")
    if errors:
        print(f"0x0003 wire layout FAILED ({len(errors)} problem(s)):", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("0x0003 wire layout OK.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
