#!/usr/bin/env python3
"""Validate the independent client-opcode semantic evidence ledger."""

from __future__ import annotations

import json
import re

from _json_io import OPCODES_PATH, REPO_ROOT


EVIDENCE_PATH = REPO_ROOT / "data" / "client_opcode_semantics.json"
CAPTURE_LAYOUTS_PATH = REPO_ROOT / "data" / "vendor" / "captures" / "payload_layouts.json"
CAPTURE_SAMPLES_PATH = REPO_ROOT / "data" / "vendor" / "captures" / "payload_samples.json"
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
    "0x01cb",
}
EXPECTED_OUTBOUND = {
    "0x00c8",
    "0x00c9",
    "0x00ce",
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
    "c2s-00ce": (
        "FUN_00763DC0",
        "FUN_0076D610",
        "opcode 0x00ce",
        "record size 0x38",
        "FUN_004D6D10",
        "FUN_004E0240",
        "FUN_00DAE010",
        "72-byte subpackets",
        "56-byte builder record",
        "40-byte application payload",
    ),
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
    "c2s-012f": ("opcode 0x012f", "record size 0x38", "leading dword", "32-byte", "four-byte stack tail", "_updateWork", "FUN_004D6D30", "72-byte subpackets"),
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
EXPECTED_CAPTURE_ROWS = {"c2s-00c9", "c2s-00ce", "c2s-012d", "c2s-012e", "c2s-012f", "s2c-0187", "s2c-018b", "s2c-018d", "s2c-018f", "s2c-0190", "s2c-0191", "s2c-0193", "s2c-0196"}


def main() -> int:
    errors: list[str] = []
    evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
    capture_layouts = json.loads(CAPTURE_LAYOUTS_PATH.read_text(encoding="utf-8"))
    capture_samples = json.loads(CAPTURE_SAMPLES_PATH.read_text(encoding="utf-8"))
    rows = evidence.get("rows", [])
    catalog = json.loads(OPCODES_PATH.read_text(encoding="utf-8"))[0]
    entries = [entry for bucket in catalog["lists"].values() for entry in bucket]

    if evidence.get("schemaVersion") != EXPECTED_SCHEMA_VERSION:
        errors.append("evidence schemaVersion drifted")
    if evidence.get("binary") != EXPECTED_BINARY:
        errors.append("retail binary metadata or pinned SHA-256 drifted")

    if len(rows) != 39:
        errors.append(f"evidence row count is {len(rows)}, expected 39")
    if {row.get("dependencyOrdinal") for row in rows} != set(range(39)):
        errors.append("dependencyOrdinal values must be exactly 0 through 38")

    inbound = {row.get("opcodeHex") for row in rows if row.get("direction") == "clientbound"}
    outbound = {row.get("opcodeHex") for row in rows if row.get("direction") == "serverbound"}
    if inbound != EXPECTED_INBOUND:
        errors.append("clientbound opcode set does not match the 29-row ledger slice")
    if outbound != EXPECTED_OUTBOUND:
        errors.append("serverbound opcode set does not match the 10-row ledger slice")

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
    if len(anchors) != 47:
        errors.append(f"catalog has {len(anchors)} decompAnchor values, expected 47")
    bad_anchors = [anchor for anchor in anchors if not BARE_FUNCTION.fullmatch(anchor)]
    if bad_anchors:
        errors.append(f"non-bare decompAnchor values: {bad_anchors}")

    opaque_entry = next(
        entry
        for entry in entries
        if entry.get("opcodeHex") == "0x00ce"
        and entry.get("direction") == "serverbound"
        and entry.get("decompAnchor") == "FUN_00763DC0"
    )
    opaque_notes = opaque_entry.get("notes", "")
    if opaque_entry.get("name") != "_0x00CEHandler":
        errors.append("c2s-00ce must retain its placeholder name")
    if opaque_entry.get("implementationAnchor") is not None:
        errors.append("c2s-00ce must not retain an unsupported implementation anchor")
    if opaque_entry.get("confidence") != "decomp_routed":
        errors.append("c2s-00ce confidence must remain decomp_routed")
    if opaque_entry.get("payloadLengths") != [72]:
        errors.append("c2s-00ce must retain the observed 72-byte wire length")
    for fragment in (
        "FUN_00763DC0 and FUN_0076D610",
        "record size 0x38",
        "application_payload=40 bytes",
        "prior_label=MapClientOpcode::Opaque0xCE",
    ):
        if fragment not in opaque_notes:
            errors.append(f"c2s-00ce notes lost required fact {fragment!r}")

    blacklist_row = next(row for row in rows if row.get("id") == "s2c-01cb")
    blacklist_observation = blacklist_row.get("observation", "")
    for fragment in (
        "callback slot 173",
        "FUN_00DB8FA0",
        "immediately returns",
        "reads no packet fields",
        "FUN_004CA100",
        "opposite-direction use",
    ):
        if fragment not in blacklist_observation:
            errors.append(f"s2c-01cb observation lost required fact {fragment!r}")
    blacklist_entry = next(
        entry
        for entry in entries
        if entry.get("opcodeHex") == "0x01cb"
        and entry.get("direction") == "clientbound"
        and entry.get("decompAnchor") == "FUN_00DB8FA0"
    )
    blacklist_notes = blacklist_entry.get("notes", "")
    if blacklist_entry.get("name") != "_0x01CB":
        errors.append("s2c-01cb must retain a placeholder clientbound name")
    if blacklist_entry.get("implementationAnchor") is not None:
        errors.append("s2c-01cb must not retain a server implementation anchor")
    if blacklist_entry.get("confidence") != "decomp_routed":
        errors.append("s2c-01cb confidence must remain decomp_routed")
    for fragment in (
        "callback_body=ret 0xc",
        "prior_label=MapServerOpcode::SendBlacklist",
        "separate_direction=c2s FUN_004CA100",
    ):
        if fragment not in blacklist_notes:
            errors.append(f"s2c-01cb notes lost required fact {fragment!r}")

    special_row = next(row for row in rows if row.get("id") == "s2c-0196")
    special_observation = special_row.get("observation", "")
    for fragment in (
        "FUN_00576050",
        "application byte +1",
        "eight flags",
        "eight u16 values",
        "FUN_0075D2D0",
        "+0x84..+0x8b",
        "+0x8c..+0x9a",
        "WorldMaster _getSpecialEventWork",
        "FUN_0075D390",
        "FUN_0075D3A0",
        "11 retained subpackets",
        "56 bytes",
        "8 captures",
        "aggregate corpus count is 12",
        "eventWork6=1",
        "zero six-byte tail",
    ):
        if fragment not in special_observation:
            errors.append(f"s2c-0196 observation lost required fact: {fragment}")

    special_layout = capture_layouts["layouts"]["s2c"]["0x0196"]
    special_samples = capture_samples["samples"]["s2c"]["0x0196"]
    retained_special = special_samples.get("samples", [])
    special_apps = [bytes.fromhex(sample["bytes"])[16:40] for sample in retained_special]
    expected_special_app = bytes.fromhex("000000000000000000000000000001000000000000000000")
    if special_samples.get("sampleCount") != 11 or len(retained_special) != 11:
        errors.append("s2c-0196 retained sample count drifted from 11")
    if {sample.get("sub_size") for sample in retained_special} != {56}:
        errors.append("s2c-0196 retained subpacket length drifted from 56")
    if len({sample.get("capture") for sample in retained_special}) != 8:
        errors.append("s2c-0196 retained capture count drifted from 8")
    if set(special_apps) != {expected_special_app}:
        errors.append("s2c-0196 retained flag/work/tail values drifted")
    if (
        special_layout.get("sample_count") != 11
        or special_layout.get("sub_size_distribution") != {"56": 11}
        or special_layout.get("body_length") != 40
        or special_layout.get("body_length", 0) - 16 != 24
    ):
        errors.append("s2c-0196 pinned layout summary drifted")

    special_entry = next(
        entry
        for entry in entries
        if entry.get("opcodeHex") == "0x0196"
        and entry.get("direction") == "clientbound"
        and entry.get("decompAnchor") == "FUN_00576050"
    )
    special_notes = special_entry.get("notes", "")
    if special_entry.get("name") != "SetSpecialEventWorkPacket":
        errors.append("s2c-0196 lost its client-supported operation name")
    if special_entry.get("implementationAnchor") is not None:
        errors.append("s2c-0196 must not retain an unproven server implementation anchor")
    if special_entry.get("confidence") != "decomp_routed":
        errors.append("s2c-0196 confidence must remain decomp_routed")
    for fragment in (
        "FUN_00576050",
        "FUN_0075D2D0",
        "WorldMaster._getSpecialEventWork",
        "application_payload=24 bytes",
        "observed=11 retained 56-byte subpackets across 8 captures",
        "retained_values=flags zero,eventWork6 one,other eventWork values zero,tail zero",
        "corpus_aggregate=12 events",
        "naming=client-derived",
        "client_only=",
        "conflict=implementation anchor lacks a source-owned declaration",
        "BCS-Y-0585,BCS-Y-0226",
    ):
        if fragment not in special_notes:
            errors.append(f"s2c-0196 notes lost required fragment: {fragment}")

    manager_row = next(row for row in rows if row.get("id") == "s2c-018a")
    manager_observation = manager_row.get("observation", "")
    for fragment in (
        "FUN_00576380",
        "FUN_006C82A0",
        "FUN_006C6A70",
        "signed low byte",
        "application offset 0x60",
        "+0x40+4*i",
        "+8*i",
        "FUN_006C58C0",
        "120-byte application payload",
        "20-byte tail",
        "one aggregate event",
        "no payload samples or layout",
        "SetActiveLinkshell packet noun",
    ):
        if fragment not in manager_observation:
            errors.append(f"s2c-018a observation lost required fact: {fragment}")

    manager_entry = next(
        entry
        for entry in entries
        if entry.get("opcodeHex") == "0x018a"
        and entry.get("direction") == "clientbound"
        and entry.get("decompAnchor") == "FUN_00576380"
    )
    manager_notes = manager_entry.get("notes", "")
    if manager_entry.get("name") != "_0x018A":
        errors.append("s2c-018a must retain its placeholder packet name")
    if manager_entry.get("implementationAnchor") is not None:
        errors.append("s2c-018a must not retain an unproven server implementation anchor")
    if manager_entry.get("confidence") != "decomp_routed":
        errors.append("s2c-018a confidence must remain decomp_routed")
    if manager_entry.get("observedIn") != [] or manager_entry.get("payloadLengths") != []:
        errors.append("s2c-018a must not invent retained capture metadata")
    for fragment in (
        "FUN_00576380",
        "FUN_006C82A0",
        "FUN_006C6A70",
        "application_payload=120 bytes",
        "u64[8] at +0 plus u32[8] at +0x40",
        "loop_bound=signed low byte at +0x60",
        "unread_tail=20 bytes at +0x64..+0x77",
        "commit_boundary=unresolved FUN_006C58C0",
        "corpus_aggregate=1 event",
        "retained_payload_evidence=none",
        "naming=placeholder retained",
        "candidate_label=SetActiveLinkshellPacket is an imported source-manifest term, not retail-proven",
        "client_only=",
        "conflict=implementation anchor and packet noun lack a source-owned declaration",
        "BCS-Y-0578,BCS-Y-0888",
    ):
        if fragment not in manager_notes:
            errors.append(f"s2c-018a notes lost required fragment: {fragment}")

    control_row = next(row for row in rows if row.get("id") == "s2c-0193")
    control_observation = control_row.get("observation", "")
    for fragment in (
        "FUN_00578C90",
        "first application u32",
        "below 0x10",
        "FUN_0075F3E0",
        "0x10 through 0x12 and 0x16",
        "0x13",
        "0x14",
        "0x15",
        "FUN_00576020",
        "9 retained subpackets",
        "40 bytes",
        "8 captures",
        "9 aggregate events",
        "0x14 in 8 samples and 0x12 in 1 sample",
        "exact low-range/string/0x15 semantics",
    ):
        if fragment not in control_observation:
            errors.append(f"s2c-0193 observation lost required fact: {fragment}")

    control_layout = capture_layouts["layouts"]["s2c"]["0x0193"]
    control_samples = capture_samples["samples"]["s2c"]["0x0193"]
    retained_control = control_samples.get("samples", [])
    subops: dict[int, int] = {}
    for sample in retained_control:
        payload = bytes.fromhex(sample["bytes"])[16:24]
        subop = int.from_bytes(payload[:4], "little")
        subops[subop] = subops.get(subop, 0) + 1
    if control_samples.get("sampleCount") != 9 or len(retained_control) != 9:
        errors.append("s2c-0193 retained sample count drifted from 9")
    if {sample.get("sub_size") for sample in retained_control} != {40}:
        errors.append("s2c-0193 retained subpacket length drifted from 40")
    if len({sample.get("capture") for sample in retained_control}) != 8:
        errors.append("s2c-0193 retained capture count drifted from 8")
    if subops != {0x14: 8, 0x12: 1}:
        errors.append(f"s2c-0193 retained subopcode distribution drifted: {subops}")
    if (
        control_layout.get("sample_count") != 9
        or control_layout.get("sub_size_distribution") != {"40": 9}
        or control_layout.get("body_length") != 24
        or control_layout.get("body_length", 0) - 16 != 8
    ):
        errors.append("s2c-0193 pinned layout summary drifted")

    control_entry = next(
        entry
        for entry in entries
        if entry.get("opcodeHex") == "0x0193"
        and entry.get("direction") == "clientbound"
        and entry.get("decompAnchor") == "FUN_00578C90"
    )
    control_notes = control_entry.get("notes", "")
    if control_entry.get("name") != "_0x0193":
        errors.append("s2c-0193 must retain its placeholder packet name")
    if control_entry.get("implementationAnchor") is not None:
        errors.append("s2c-0193 must not retain an unproven server implementation anchor")
    if control_entry.get("confidence") != "decomp_routed":
        errors.append("s2c-0193 confidence must remain decomp_routed")
    for fragment in (
        "FUN_00578C90",
        "application_payload=8 bytes",
        "<0x10 to FUN_0075F3E0",
        "0x13 string/config path",
        "0x14 one-time init gate",
        "0x15 unresolved FUN_00576020",
        "observed=9 retained 40-byte subpackets across 8 captures",
        "retained_subops=0x14 x8, 0x12 x1",
        "corpus_aggregate=9 events",
        "unresolved=low-range,0x13 string/config,0x15 helper semantics",
        "naming=placeholder retained",
        "candidate_label=SetControlStatePacket is an imported source-manifest term, not retail-proven",
        "client_only=",
        "conflict=implementation anchor and packet noun lack a source-owned declaration",
        "BCS-Y-0584,BCS-Y-0990",
    ):
        if fragment not in control_notes:
            errors.append(f"s2c-0193 notes lost required fragment: {fragment}")

    setup_row = next(row for row in rows if row.get("id") == "s2c-018f")
    setup_observation = setup_row.get("observation", "")
    for fragment in (
        "FUN_00576C60",
        "FUN_0076BE30",
        "no direct application-field loads",
        "FUN_0076B950",
        "FUN_0075F720",
        "FUN_00759220 only writes a local byte value of 0xff",
        "15 retained subpackets",
        "40 bytes",
        "8 captures",
        "8-byte application payloads are zero",
        "28 aggregate events",
        "not a field semantic",
        "helper semantics remain unresolved",
    ):
        if fragment not in setup_observation:
            errors.append(f"s2c-018f observation lost required fact: {fragment}")

    setup_layout = capture_layouts["layouts"]["s2c"]["0x018f"]
    setup_samples = capture_samples["samples"]["s2c"]["0x018f"]
    retained_setup = setup_samples.get("samples", [])
    if setup_samples.get("sampleCount") != 15 or len(retained_setup) != 15:
        errors.append("s2c-018f retained sample count drifted from 15")
    if {sample.get("sub_size") for sample in retained_setup} != {40}:
        errors.append("s2c-018f retained subpacket length drifted from 40")
    if len({sample.get("capture") for sample in retained_setup}) != 8:
        errors.append("s2c-018f retained capture count drifted from 8")
    if any(bytes.fromhex(sample["bytes"])[16:24] != bytes(8) for sample in retained_setup):
        errors.append("s2c-018f retained application payload is no longer all zero")
    if (
        setup_layout.get("sample_count") != 15
        or setup_layout.get("sub_size_distribution") != {"40": 15}
        or setup_layout.get("body_length") != 24
        or setup_layout.get("body_length", 0) - 16 != 8
    ):
        errors.append("s2c-018f pinned layout summary drifted")

    setup_entry = next(
        entry
        for entry in entries
        if entry.get("opcodeHex") == "0x018f"
        and entry.get("direction") == "clientbound"
        and entry.get("decompAnchor") == "FUN_00576C60"
    )
    setup_notes = setup_entry.get("notes", "")
    if setup_entry.get("name") != "_0x018F":
        errors.append("s2c-018f must retain its placeholder packet name")
    if setup_entry.get("implementationAnchor") is not None:
        errors.append("s2c-018f must not retain an unproven server implementation anchor")
    if setup_entry.get("confidence") != "decomp_routed":
        errors.append("s2c-018f confidence must remain decomp_routed")
    for fragment in (
        "FUN_00576C60",
        "FUN_0076BE30",
        "direct_payload_reads=none",
        "application_payload=8 bytes",
        "semantically unknown",
        "shared_helper_boundary=FUN_0076B950,FUN_0075F720",
        "FUN_00759220 only writes a local byte 0xff",
        "observed=15 retained 40-byte subpackets across 8 captures",
        "corpus_aggregate=28 events",
        "naming=placeholder retained",
        "candidate_label=MassSetItemModifierBeginPacket is an imported source-manifest term, not retail-proven",
        "client_only=",
        "conflict=implementation anchor and packet noun lack a source-owned declaration",
        "BCS-Y-0581,BCS-Y-0722,BCS-Y-0954",
    ):
        if fragment not in setup_notes:
            errors.append(f"s2c-018f notes lost required fragment: {fragment}")

    finalization_row = next(row for row in rows if row.get("id") == "s2c-0191")
    finalization_observation = finalization_row.get("observation", "")
    for fragment in (
        "FUN_00576D40",
        "FUN_0076BF10",
        "no direct application-field loads",
        "FUN_0076B950",
        "FUN_0076BA10",
        "FUN_00768B10",
        "FUN_007840D0",
        "15 retained subpackets",
        "40 bytes",
        "8 captures",
        "8-byte application payloads are zero",
        "28 aggregate events",
        "not a field semantic",
        "helper-chain semantics remain unresolved",
    ):
        if fragment not in finalization_observation:
            errors.append(f"s2c-0191 observation lost required fact: {fragment}")

    finalization_layout = capture_layouts["layouts"]["s2c"]["0x0191"]
    finalization_samples = capture_samples["samples"]["s2c"]["0x0191"]
    retained_finalization = finalization_samples.get("samples", [])
    if finalization_samples.get("sampleCount") != 15 or len(retained_finalization) != 15:
        errors.append("s2c-0191 retained sample count drifted from 15")
    if {sample.get("sub_size") for sample in retained_finalization} != {40}:
        errors.append("s2c-0191 retained subpacket length drifted from 40")
    if len({sample.get("capture") for sample in retained_finalization}) != 8:
        errors.append("s2c-0191 retained capture count drifted from 8")
    if any(bytes.fromhex(sample["bytes"])[16:24] != bytes(8) for sample in retained_finalization):
        errors.append("s2c-0191 retained application payload is no longer all zero")
    if (
        finalization_layout.get("sample_count") != 15
        or finalization_layout.get("sub_size_distribution") != {"40": 15}
        or finalization_layout.get("body_length") != 24
        or finalization_layout.get("body_length", 0) - 16 != 8
    ):
        errors.append("s2c-0191 pinned layout summary drifted")

    finalization_entry = next(
        entry
        for entry in entries
        if entry.get("opcodeHex") == "0x0191"
        and entry.get("direction") == "clientbound"
        and entry.get("decompAnchor") == "FUN_00576D40"
    )
    finalization_notes = finalization_entry.get("notes", "")
    if finalization_entry.get("name") != "_0x0191":
        errors.append("s2c-0191 must retain its placeholder packet name")
    if finalization_entry.get("implementationAnchor") is not None:
        errors.append("s2c-0191 must not retain an unproven server implementation anchor")
    if finalization_entry.get("confidence") != "decomp_routed":
        errors.append("s2c-0191 confidence must remain decomp_routed")
    for fragment in (
        "FUN_00576D40",
        "FUN_0076BF10",
        "direct_payload_reads=none",
        "application_payload=8 bytes",
        "semantically unknown",
        "shared_helper_boundary=FUN_0076B950",
        "observed=15 retained 40-byte subpackets across 8 captures",
        "corpus_aggregate=28 events",
        "naming=placeholder retained",
        "candidate_label=MassSetItemModifierEndPacket is an imported source-manifest term, not retail-proven",
        "client_only=",
        "conflict=implementation anchor and packet noun lack a source-owned declaration",
        "BCS-Y-0583,BCS-Y-0723,BCS-Y-0955",
    ):
        if fragment not in finalization_notes:
            errors.append(f"s2c-0191 notes lost required fragment: {fragment}")

    modifier_row = next(row for row in rows if row.get("id") == "s2c-0190")
    modifier_observation = modifier_row.get("observation", "")
    for fragment in (
        "FUN_00576CD0",
        "FUN_0076BE60",
        "FUN_00768C40",
        "0x68-byte application payload",
        "offsets +0 and +4",
        "+8 through +0x47",
        "72 application bytes read",
        "32-byte application tail at +0x48 through +0x67 unread",
        "32 retained subpackets",
        "136 bytes",
        "8 captures",
        "5,569 aggregate events",
    ):
        if fragment not in modifier_observation:
            errors.append(f"s2c-0190 observation lost required fact: {fragment}")

    modifier_layout = capture_layouts["layouts"]["s2c"]["0x0190"]
    modifier_samples = capture_samples["samples"]["s2c"]["0x0190"]
    retained_modifiers = modifier_samples.get("samples", [])
    if modifier_samples.get("sampleCount") != 32 or len(retained_modifiers) != 32:
        errors.append("s2c-0190 retained sample count drifted from 32")
    if {sample.get("sub_size") for sample in retained_modifiers} != {136}:
        errors.append("s2c-0190 retained subpacket length drifted from 136")
    if len({sample.get("capture") for sample in retained_modifiers}) != 8:
        errors.append("s2c-0190 retained capture count drifted from 8")
    if (
        modifier_layout.get("sample_count") != 32
        or modifier_layout.get("sub_size_distribution") != {"136": 32}
        or modifier_layout.get("body_length") != 120
        or modifier_layout.get("body_length", 0) - 16 != 104
    ):
        errors.append("s2c-0190 pinned layout summary drifted")

    modifier_entry = next(
        entry
        for entry in entries
        if entry.get("opcodeHex") == "0x0190"
        and entry.get("direction") == "clientbound"
        and entry.get("decompAnchor") == "FUN_00576CD0"
    )
    modifier_notes = modifier_entry.get("notes", "")
    if modifier_entry.get("name") != "_0x0190":
        errors.append("s2c-0190 must retain its placeholder packet name")
    if modifier_entry.get("implementationAnchor") is not None:
        errors.append("s2c-0190 must not retain an unproven server implementation anchor")
    if modifier_entry.get("confidence") != "decomp_routed":
        errors.append("s2c-0190 confidence must remain decomp_routed")
    for fragment in (
        "FUN_00576CD0",
        "FUN_0076BE60",
        "FUN_00768C40",
        "application_payload=0x68",
        "words[16]",
        "unread 32-byte tail at +0x48..+0x67",
        "observed=32 retained 136-byte subpackets across 8 captures",
        "corpus_aggregate=5569 events",
        "field_semantics=unresolved",
        "naming=placeholder retained",
        "candidate_label=MassSetItemModifierPacket is an imported source-manifest term, not retail-proven",
        "client_only=",
        "conflict=implementation anchor and packet noun lack a source-owned declaration",
        "BCS-Y-0582,BCS-Y-0721,BCS-Y-0951,BCS-Y-0952,BCS-Y-0953",
    ):
        if fragment not in modifier_notes:
            errors.append(f"s2c-0190 notes lost required fragment: {fragment}")

    occupancy_row = next(row for row in rows if row.get("id") == "s2c-0187")
    occupancy_observation = occupancy_row.get("observation", "")
    for fragment in (
        "FUN_00576390",
        "FUN_006C8340",
        "FUN_006C6B20",
        "0x40-byte application payload",
        "opaque 16-byte group header",
        "offset 0x10",
        "0x18",
        "0x1c",
        "33 retained subpackets",
        "96 bytes",
        "13 captures",
    ):
        if fragment not in occupancy_observation:
            errors.append(f"s2c-0187 observation lost required fact: {fragment}")

    occupancy_layout = capture_layouts["layouts"]["s2c"]["0x0187"]
    occupancy_samples = capture_samples["samples"]["s2c"]["0x0187"]
    retained_occupancy = occupancy_samples.get("samples", [])
    if occupancy_samples.get("sampleCount") != 33 or len(retained_occupancy) != 33:
        errors.append("s2c-0187 retained sample count drifted from 33")
    if {sample.get("sub_size") for sample in retained_occupancy} != {96}:
        errors.append("s2c-0187 retained subpacket length drifted from 96")
    if len({sample.get("capture") for sample in retained_occupancy}) != 13:
        errors.append("s2c-0187 retained capture count drifted from 13")
    if (
        occupancy_layout.get("sample_count") != 33
        or occupancy_layout.get("sub_size_distribution") != {"96": 33}
        or occupancy_layout.get("body_length") != 80
    ):
        errors.append("s2c-0187 pinned layout summary drifted")

    occupancy_entry = next(
        entry
        for entry in entries
        if entry.get("opcodeHex") == "0x0187"
        and entry.get("direction") == "clientbound"
        and entry.get("decompAnchor") == "FUN_00576390"
    )
    occupancy_notes = occupancy_entry.get("notes", "")
    if occupancy_entry.get("name") != "SetOccupancyGroupPacket":
        errors.append("s2c-0187 canonical name must reflect the client occupancy path")
    if occupancy_entry.get("implementationAnchor") is not None:
        errors.append("s2c-0187 must not retain an unproven server implementation anchor")
    if occupancy_entry.get("confidence") != "decomp_routed":
        errors.append("s2c-0187 confidence must remain decomp_routed")
    for fragment in (
        "FUN_00576390",
        "FUN_006C8340",
        "FUN_006C6B20",
        "application_payload=0x40",
        "opaque 16-byte group header",
        "observed=33 retained 96-byte subpackets across 13 captures",
        "client_only=",
        "conflict=implementation anchor lacks a source-owned declaration",
        "BCS-Y-0575",
        "BCS-Y-0885",
    ):
        if fragment not in occupancy_notes:
            errors.append(f"s2c-0187 notes lost required fragment: {fragment}")

    group_layout_row = next(row for row in rows if row.get("id") == "s2c-018b")
    group_layout_observation = group_layout_row.get("observation", "")
    for fragment in (
        "FUN_005763A0",
        "FUN_006C5DF0",
        "FUN_006C5240",
        "0x38-byte application payload",
        "opaque 8-byte group header",
        "+0x08",
        "+0x0c",
        "+0x10",
        "unresolved layout-kind byte at +0x14",
        "unresolved reserved byte at +0x15",
        "+0x16",
        "31 retained subpackets",
        "88 bytes",
        "13 captures",
    ):
        if fragment not in group_layout_observation:
            errors.append(f"s2c-018b observation lost required fact: {fragment}")

    group_layout_layout = capture_layouts["layouts"]["s2c"]["0x018b"]
    group_layout_samples = capture_samples["samples"]["s2c"]["0x018b"]
    retained_group_layout = group_layout_samples.get("samples", [])
    if group_layout_samples.get("sampleCount") != 31 or len(retained_group_layout) != 31:
        errors.append("s2c-018b retained sample count drifted from 31")
    if {sample.get("sub_size") for sample in retained_group_layout} != {88}:
        errors.append("s2c-018b retained subpacket length drifted from 88")
    if len({sample.get("capture") for sample in retained_group_layout}) != 13:
        errors.append("s2c-018b retained capture count drifted from 13")
    if (
        group_layout_layout.get("sample_count") != 31
        or group_layout_layout.get("sub_size_distribution") != {"88": 31}
        or group_layout_layout.get("body_length") != 72
        or group_layout_layout.get("body_length", 0) - 16 != 56
    ):
        errors.append("s2c-018b pinned layout summary drifted")

    group_layout_entry = next(
        entry
        for entry in entries
        if entry.get("opcodeHex") == "0x018b"
        and entry.get("direction") == "clientbound"
        and entry.get("decompAnchor") == "FUN_005763A0"
    )
    group_layout_notes = group_layout_entry.get("notes", "")
    if group_layout_entry.get("name") != "SetGroupLayoutIDPacket":
        errors.append("s2c-018b canonical name must reflect the client group-layout path")
    if group_layout_entry.get("implementationAnchor") is not None:
        errors.append("s2c-018b must not retain an unproven server implementation anchor")
    if group_layout_entry.get("confidence") != "decomp_routed":
        errors.append("s2c-018b confidence must remain decomp_routed")
    for fragment in (
        "FUN_005763A0",
        "FUN_006C5DF0",
        "FUN_006C5240",
        "application_payload=0x38",
        "opaque 8-byte group header",
        "unresolved layout-kind byte at +0x14",
        "unresolved reserved byte at +0x15",
        "observed=31 retained 88-byte subpackets across 13 captures",
        "client_only=",
        "alternate_spelling=SetGroupLayoutIdPacket",
        "conflict=implementation anchor lacks a source-owned declaration",
        "BCS-Y-0579",
        "BCS-Y-0889",
    ):
        if fragment not in group_layout_notes:
            errors.append(f"s2c-018b notes lost required fragment: {fragment}")

    party_marker_row = next(row for row in rows if row.get("id") == "s2c-018d")
    party_marker_observation = party_marker_row.get("observation", "")
    for fragment in (
        "FUN_00575550",
        "FUN_0055CF70",
        "0x290",
        "0x28-byte",
        "All 60 retained subpackets are 696-byte subpackets",
        "observed max=2",
        "no compare or clamp to 16",
    ):
        if fragment not in party_marker_observation:
            errors.append(f"s2c-018d observation lost required fact: {fragment}")

    party_marker_layout = capture_layouts["layouts"]["s2c"]["0x018d"]
    party_marker_samples = capture_samples["samples"]["s2c"]["0x018d"]
    retained_samples = party_marker_samples.get("samples", [])
    count_distribution: dict[int, int] = {}
    for sample in retained_samples:
        body = bytes.fromhex(sample["bytes"])
        if len(body) <= 672:
            errors.append("s2c-018d retained sample is too short for the count byte")
            continue
        count = body[672]
        count_distribution[count] = count_distribution.get(count, 0) + 1
    if party_marker_samples.get("sampleCount") != 60 or len(retained_samples) != 60:
        errors.append("s2c-018d retained sample count drifted from 60")
    if {sample.get("sub_size") for sample in retained_samples} != {696}:
        errors.append("s2c-018d retained subpacket length drifted from 696")
    if count_distribution != {1: 58, 2: 2}:
        errors.append(f"s2c-018d count distribution drifted: {count_distribution}")
    if (
        party_marker_layout.get("sample_count") != 60
        or party_marker_layout.get("sub_size_distribution") != {"696": 60}
        or party_marker_layout.get("body_length") != 680
    ):
        errors.append("s2c-018d pinned layout summary drifted")

    party_marker_entry = next(
        entry
        for entry in entries
        if entry.get("opcodeHex") == "0x018d"
        and entry.get("direction") == "clientbound"
        and entry.get("decompAnchor") == "FUN_00575550"
    )
    party_marker_notes = party_marker_entry.get("notes", "")
    if party_marker_entry.get("name") != "PartyMapMarkerUpdatePacket":
        errors.append("s2c-018d canonical name must reflect the client party-marker path")
    if party_marker_entry.get("implementationAnchor") is not None:
        errors.append("s2c-018d must not retain an unproven server implementation anchor")
    if party_marker_entry.get("confidence") != "decomp_routed":
        errors.append("s2c-018d confidence must remain decomp_routed")
    for fragment in (
        "FUN_00575550",
        "FUN_0055CF70",
        "0x290",
        "0x28-byte",
        "696-byte",
        "observed max=2",
        "client_only=",
        "conflict=implementation anchor lacks a source-owned declaration",
    ):
        if fragment not in party_marker_notes:
            errors.append(f"s2c-018d notes lost required fragment: {fragment}")

    work_state_entry = next(
        entry
        for entry in entries
        if entry.get("opcodeHex") == "0x012f"
        and entry.get("direction") == "serverbound"
        and entry.get("decompAnchor") == "FUN_0075E770"
    )
    work_state_notes = work_state_entry.get("notes", "")
    if work_state_entry.get("name") != "WorkStateUpdatePacket":
        errors.append("c2s-012f canonical name must remain client-derived and tentative")
    if work_state_entry.get("implementationAnchor") is not None:
        errors.append("c2s-012f must not retain an unproven implementation enum anchor")
    if work_state_entry.get("confidence") != "decomp_routed":
        errors.append("c2s-012f confidence must remain decomp_routed")
    for fragment in (
        "_updateWork",
        "record+0x3c",
        "naming=tentative",
        "conflict=ActorWorkUpdatePacket",
        "conflict=ParameterDataRequestPacket",
    ):
        if fragment not in work_state_notes:
            errors.append(f"c2s-012f notes lost required fragment: {fragment}")

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
