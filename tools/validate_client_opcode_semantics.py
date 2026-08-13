#!/usr/bin/env python3
"""Validate the independent client-opcode semantic evidence ledger."""

from __future__ import annotations

import json
import re

from _json_io import OPCODES_PATH, REPO_ROOT


EVIDENCE_PATH = REPO_ROOT / "data" / "client_opcode_semantics.json"
EXPECTED_SCHEMA_VERSION = 1
EXPECTED_BINARY = {
    "name": "ffxivgame.exe",
    "version": "1.23b",
    "sha256": "9341f2b4567440b310a4d494f5cc5599ca334ba51c8042247317ff466492f2e9",
}
EXPECTED_INBOUND = {
    "0x0143",
    "0x0146",
    "0x016d",
    "0x016e",
    "0x017a",
    *{f"0x{opcode:04x}" for opcode in range(0x017D, 0x018C)},
    "0x018d",
    "0x018f",
    "0x0190",
    "0x0191",
    "0x0193",
    "0x0196",
    "0x0198",
    "0x01a3",
}
EXPECTED_OUTBOUND = {
    "0x00c8",
    "0x00c9",
    "0x012d",
    "0x012e",
    "0x012f",
    "0x0131",
    "0x0132",
    "0x0134",
    "0x0135",
}
EXPECTED_OPEN = set()
OUTBOUND_OBSERVATION_FRAGMENTS = {
    "c2s-00c8": ("opcode 0x00c8", "size 0x230", "four qwords", "0x80 dwords", "FUN_00DB3E30"),
    "c2s-00c9": (
        "opcode 0x00c9",
        "body size 0x218",
        "u32 selector argument at application offset 0",
        "0x200-byte field at application offset 4",
        "chat message",
        "FUN_00DB3E30",
    ),
    "c2s-012d": ("opcode 0x012d", "body size 0xc8", "four u32", "one u8", "FUN_00DAE010", "216-byte total subpacket"),
    "c2s-012e": ("opcode 0x012e", "body size 0x68", "sixteen dwords", "FUN_004D6D30", "120-byte total subpacket"),
    "c2s-012f": ("opcode 0x012f", "body size 0x38", "request-id dword", "32 bytes", "FUN_004D6D30", "72-byte total subpacket"),
    "c2s-0131": ("opcode 0x0131", "size 0x18", "u32", "u8", "FUN_004D6D30"),
    "c2s-0132": ("opcode 0x0132", "size 0x18", "u32", "u16", "u8", "FUN_004D6D30"),
    "c2s-0134": (
        "opcode 0x0134",
        "body size 0x28",
        "u32 argument at application offset 0",
        "u32 token-helper result at offset 4",
        "16-byte nonce buffer",
        "15 generated ASCII letters",
        "trailing NUL",
        "offsets 8 through 0x17",
        "two qwords",
        "FUN_004D6D30",
    ),
    "c2s-0135": (
        "opcode 0x0135",
        "body size 0x18",
        "one u32 payload value to application offset 0",
        "FUN_004D6D30",
    ),
}
EXPECTED_OPEN_MISSING_FRAGMENTS = {}
BARE_FUNCTION = re.compile(r"^FUN_[0-9A-F]{8}$")
SOURCE_REF = re.compile(r"^(xivl-client-structs|xivl-captures|retail):")
EXPECTED_CAPTURE_ROWS = {"c2s-00c9", "c2s-012d", "c2s-012e", "c2s-012f"}


def main() -> int:
    errors: list[str] = []
    evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
    rows = evidence.get("rows", [])
    catalog = json.loads(OPCODES_PATH.read_text(encoding="utf-8"))[0]
    entries = [entry for bucket in catalog["lists"].values() for entry in bucket]

    if evidence.get("schemaVersion") != EXPECTED_SCHEMA_VERSION:
        errors.append("evidence schemaVersion drifted")
    if evidence.get("binary") != EXPECTED_BINARY:
        errors.append("retail binary metadata or pinned SHA-256 drifted")

    if len(rows) != 37:
        errors.append(f"evidence row count is {len(rows)}, expected 37")
    if {row.get("dependencyOrdinal") for row in rows} != set(range(37)):
        errors.append("dependencyOrdinal values must be exactly 0 through 36")

    inbound = {row.get("opcodeHex") for row in rows if row.get("direction") == "clientbound"}
    outbound = {row.get("opcodeHex") for row in rows if row.get("direction") == "serverbound"}
    if inbound != EXPECTED_INBOUND:
        errors.append("clientbound opcode set does not match the 28-row ledger slice")
    if outbound != EXPECTED_OUTBOUND:
        errors.append("serverbound opcode set does not match the 9-row ledger slice")

    ids = [row.get("id") for row in rows]
    if len(ids) != len(set(ids)):
        errors.append("evidence row ids are not unique")
    keys = [(row.get("direction"), row.get("opcodeHex")) for row in rows]
    if len(keys) != len(set(keys)):
        errors.append("direction/opcode evidence keys are not unique")
    open_ids = {row.get("id") for row in rows if row.get("status") == "open"}
    if open_ids != EXPECTED_OPEN:
        errors.append(f"open-row set drifted: {sorted(open_ids)}")

    for row in rows:
        label = row.get("id", "<missing-id>")
        for field in (
            "opcodeHex",
            "direction",
            "function",
            "status",
            "supportedLabel",
            "tool",
            "observation",
            "sourceRefs",
        ):
            if not row.get(field):
                errors.append(f"{label}: missing {field}")
        if not BARE_FUNCTION.fullmatch(row.get("function", "")):
            errors.append(f"{label}: function is not a bare Ghidra FUN_ symbol")
        if row.get("status") not in {"closed", "open"}:
            errors.append(f"{label}: invalid status {row.get('status')!r}")
        if row.get("status") == "open" and not row.get("missingEvidence"):
            errors.append(f"{label}: open row lacks missingEvidence")
        if row.get("status") == "closed" and row.get("missingEvidence"):
            errors.append(f"{label}: closed row must not carry missingEvidence")
        if not row.get("tool", "").startswith("XIVLegacy "):
            errors.append(f"{label}: tool is not identified as organization-owned")
        source_refs = row.get("sourceRefs", [])
        if not isinstance(source_refs, list) or not source_refs:
            errors.append(f"{label}: sourceRefs must be a nonempty list")
        elif not any(ref.startswith("xivl-client-structs:") for ref in source_refs):
            errors.append(f"{label}: sourceRefs lack a client-analysis locator")
        if label in EXPECTED_CAPTURE_ROWS and not any(
            ref.startswith("xivl-captures:") for ref in source_refs
        ):
            errors.append(f"{label}: sourceRefs lack the required capture locator")
        for ref in source_refs:
            if not isinstance(ref, str) or not SOURCE_REF.match(ref):
                errors.append(f"{label}: invalid source reference {ref!r}")

        missing_evidence = row.get("missingEvidence", "")
        for fragment in EXPECTED_OPEN_MISSING_FRAGMENTS.get(label, ()):
            if fragment not in missing_evidence:
                errors.append(
                    f"{label}: missing-evidence text lacks required fact {fragment!r}"
                )

        if row.get("direction") == "serverbound":
            observation = row.get("observation", "")
            for fragment in OUTBOUND_OBSERVATION_FRAGMENTS.get(label, ()):
                if fragment not in observation:
                    errors.append(
                        f"{label}: outbound observation lacks required fact {fragment!r}"
                    )
        matches = [
            entry
            for entry in entries
            if entry.get("opcodeHex") == row.get("opcodeHex")
            and entry.get("direction") == row.get("direction")
            and entry.get("decompAnchor") == row.get("function")
        ]
        if len(matches) != 1:
            errors.append(f"{label}: matched {len(matches)} catalog entries")
            continue
        notes = matches[0].get("notes", "")
        evidence_token = f"client_semantics_evidence=data/client_opcode_semantics.json#{label}"
        status_token = f"dependency_status={row.get('status')}"
        if evidence_token not in notes or status_token not in notes:
            errors.append(f"{label}: catalog notes lack evidence/status tokens")
        has_anchor_citation = "decomp_anchor_evidence=" in notes
        local_anchor_token = (
            f"decomp_anchor_evidence=data/client_opcode_semantics.json#{label}"
        )
        if row.get("status") == "closed" and has_anchor_citation:
            errors.append(f"{label}: closed row retains a redundant anchor citation")
        if row.get("status") == "open" and local_anchor_token not in notes:
            errors.append(f"{label}: open row lost the required local anchor citation")

    anchors = [entry["decompAnchor"] for entry in entries if entry.get("decompAnchor")]
    if len(anchors) != 45:
        errors.append(f"catalog has {len(anchors)} decompAnchor values, expected 45")
    bad_anchors = [anchor for anchor in anchors if not BARE_FUNCTION.fullmatch(anchor)]
    if bad_anchors:
        errors.append(f"non-bare decompAnchor values: {bad_anchors}")

    achievement_entry = next(
        entry
        for entry in entries
        if entry.get("opcodeHex") == "0x0135"
        and entry.get("direction") == "serverbound"
        and entry.get("decompAnchor") == "FUN_0075ECD0"
    )
    achievement_notes = achievement_entry.get("notes", "")
    if achievement_entry.get("name") != "AchievementRateRequestPacket":
        errors.append("c2s-0135 canonical name must reflect the registered client operation")
    if achievement_entry.get("implementationAnchor") is not None:
        errors.append("c2s-0135 must not invent an implementation enum anchor")
    if achievement_entry.get("confidence") != "decomp_routed":
        errors.append("c2s-0135 confidence must remain decomp_routed without pcap evidence")
    if "EXE decomp is the authority" in achievement_notes:
        errors.append("c2s-0135 retained the retired authority claim")
    if "_getAchievementRate" not in achievement_notes:
        errors.append("c2s-0135 notes lost the retail achievement-rate binding")
    if "achievement-id lookup key" not in achievement_notes:
        errors.append("c2s-0135 notes lost the valid-path payload semantic")
    if "naming=tentative" not in achievement_notes:
        errors.append("c2s-0135 notes must keep the client-derived name tentative")
    if "conflict=prior implementation label unsupported by retail" not in achievement_notes:
        errors.append("c2s-0135 notes lost the prior-label conflict")

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    closed = sum(row["status"] == "closed" for row in rows)
    opened = sum(row["status"] == "open" for row in rows)
    print(
        "Client opcode semantics OK "
        f"({len(rows)} rows, {closed} closed, {opened} open, {len(anchors)} bare anchors)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
