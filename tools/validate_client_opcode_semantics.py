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
    "0x00da",
    "0x00e1",
    "0x0143",
    "0x0144",
    "0x0146",
    "0x016d",
    "0x016e",
    "0x017a",
    "0x0179",
    "0x017c",
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
ZONE_DUMMY_CLUSTER_PRIOR = {
    0x01C3: ("StartRecruitingResponse", "MapServerOpcode::StartRecruitingResponse"),
    0x01C4: ("EndRecruitmentPacket", "MapServerOpcode::EndRecruitment"),
    0x01C5: ("RecruiterStatePacket", "MapServerOpcode::RecruiterState"),
    0x01C8: ("CurrentRecruitmentDetailsPacket", "MapServerOpcode::CurrentRecruitmentDetails"),
    0x01C9: ("BlacklistAddedPacket", "MapServerOpcode::BlacklistAdded"),
    0x01CA: ("BlacklistRemovedPacket", "MapServerOpcode::BlacklistRemoved"),
    0x01CB: ("SendBlacklistPacket", "MapServerOpcode::SendBlacklist"),
    0x01CC: ("FriendlistAddedPacket", "MapServerOpcode::FriendlistAdded"),
    0x01CD: ("FriendlistRemovedPacket", "MapServerOpcode::FriendlistRemoved"),
    0x01CE: ("SendFriendlistPacket", "MapServerOpcode::SendFriendlist"),
    0x01CF: ("FriendStatusPacket", "MapServerOpcode::FriendStatus"),
    0x01D0: ("FaqListResponsePacket", "MapServerOpcode::FaqListResponse"),
    0x01D1: ("FaqBodyResponsePacket", "MapServerOpcode::FaqBodyResponse"),
    0x01D2: ("IssueListResponsePacket", "MapServerOpcode::IssueListResponse"),
    0x01D3: ("StartGMTicketPacket", "MapServerOpcode::StartGMTicket"),
    0x01D4: ("GMTicketPacket", "MapServerOpcode::GMTicket"),
    0x01D5: ("GMTicketSentResponsePacket", "MapServerOpcode::GMTicketSentResponse"),
    0x01D6: ("EndGMTicketPacket", "MapServerOpcode::EndGMTicket"),
    0x01D7: ("ItemSearchResultsBeginPacket", "MapServerOpcode::ItemSearchResultsBegin"),
    0x01D8: ("ItemSearchResultsBodyPacket", "MapServerOpcode::ItemSearchResultsBody"),
    0x01D9: ("ItemSearchResultsEndPacket", "MapServerOpcode::ItemSearchResultsEnd"),
    0x01DA: ("RetainerResultEndPacket", "MapServerOpcode::RetainerResultEnd"),
    0x01DB: ("RetainerResultBodyPacket", "MapServerOpcode::RetainerResultBody"),
    0x01DC: ("RetainerResultUpdatePacket", "MapServerOpcode::RetainerResultUpdate"),
    0x01DD: ("RetainerSearchHistoryPacket", "MapServerOpcode::RetainerSearchHistory"),
    0x01DF: ("PlayerSearchInfoResultPacket", "MapServerOpcode::PlayerSearchInfoResult"),
}
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
    "c2s-012d": ("opcode 0x012d", "record size 0xc8", "four u32", "one u8", "FUN_00DAE010", "126 captured 216-byte subpackets", "command.canFire", "100 owner IDs", "88 also join to gameCommand"),
    "c2s-012e": ("opcode 0x012e", "body size 0x68", "sixteen dwords", "FUN_004D6D30", "120-byte total subpacket"),
    "c2s-012f": ("opcode 0x012f", "record size 0x38", "leading dword", "32-byte", "four-byte stack tail", "_updateWork", "FUN_004D6D30", "72-byte subpackets"),
    "c2s-0131": ("opcode 0x0131", "size 0x18", "u32", "u8", "FUN_004D6D30"),
    "c2s-0132": ("opcode 0x0132", "size 0x18", "u32", "u16", "u8", "FUN_004D6D30"),
    "c2s-0134": (
        "MyPlayer slot 103",
        "_setAchievementTitle",
        "PlayerBase+0xE8",
        "opcode 0x0134",
        "body size 0x28",
        "title value at application offset 0",
        "computes CRC32 over a 16-byte generated ASCII buffer",
        "writes it at offset 4",
        "position-specific letters A through O or a through o",
        "position 15 is trailing NUL",
        "offsets 8 through 0x17",
        "two qwords",
        "FUN_004D6D30",
        "No nonce, challenge, authorization-token, acknowledgement, or server-policy meaning is established",
    ),
    "c2s-0135": (
        "opcode 0x0135",
        "body size 0x18",
        "one u32 payload value to application offset 0",
        "FUN_004D6D30",
    ),
}
BARE_FUNCTION = re.compile(r"^FUN_[0-9A-F]{8}$")
SOURCE_REF = re.compile(
    r"^(xivl-client-structs|xivl-client-scripts|xivl-client-data|xivl-captures|xivl-decomp|retail):"
)
EXPECTED_CAPTURE_ROWS = {"c2s-00c9", "c2s-00ce", "c2s-012d", "c2s-012e", "c2s-012f", "s2c-00da", "s2c-00e1", "s2c-0144", "s2c-0179", "s2c-017c", "s2c-017f", "s2c-0183", "s2c-0187", "s2c-018b", "s2c-018d", "s2c-018f", "s2c-0190", "s2c-0191", "s2c-0193", "s2c-0196"}

CLIENT_ONLY_EXPECTATIONS = {
    "s2c-00da": ("0x00da", "clientbound", "FUN_0058CAD0"),
    "s2c-00e1": ("0x00e1", "clientbound", "FUN_0058C690"),
    "c2s-00ce": ("0x00ce", "serverbound", "FUN_00763DC0"),
    "c2s-012d": ("0x012d", "serverbound", "FUN_00776760"),
    "s2c-01cb": ("0x01cb", "clientbound", "FUN_00DB8FA0"),
    "s2c-0196": ("0x0196", "clientbound", "FUN_00576050"),
    "s2c-018a": ("0x018a", "clientbound", "FUN_00576380"),
    "s2c-0193": ("0x0193", "clientbound", "FUN_00578C90"),
    "s2c-018f": ("0x018f", "clientbound", "FUN_00576C60"),
    "s2c-0191": ("0x0191", "clientbound", "FUN_00576D40"),
    "s2c-0190": ("0x0190", "clientbound", "FUN_00576CD0"),
    "s2c-0187": ("0x0187", "clientbound", "FUN_00576390"),
    "s2c-018b": ("0x018b", "clientbound", "FUN_005763A0"),
    "s2c-018d": ("0x018d", "clientbound", "FUN_00575550"),
    "c2s-012f": ("0x012f", "serverbound", "FUN_0075E770"),
    "c2s-0135": ("0x0135", "serverbound", "FUN_0075ECD0"),
}

LAYOUT_SUMMARY_EXPECTATIONS = {
    "s2c-0144": ("0x0144", {"sample_count": 60, "sub_size_distribution": {"40": 60}, "body_length": 24}),
    "s2c-0179": ("0x0179", {"sample_count": 55, "sub_size_distribution": {"72": 55}, "body_length": 56}),
    "s2c-00da": ("0x00da", {"sample_count": 16, "sub_size_distribution": {"40": 16}, "body_length": 24}),
    "s2c-00e1": ("0x00e1", {"sample_count": 3, "sub_size_distribution": {"48": 3}, "body_length": 32}),
    "s2c-0196": ("0x0196", {"sample_count": 11, "sub_size_distribution": {"56": 11}, "body_length": 40}),
    "s2c-0193": ("0x0193", {"sample_count": 9, "sub_size_distribution": {"40": 9}, "body_length": 24}),
    "s2c-018f": ("0x018f", {"sample_count": 15, "sub_size_distribution": {"40": 15}, "body_length": 24}),
    "s2c-0191": ("0x0191", {"sample_count": 15, "sub_size_distribution": {"40": 15}, "body_length": 24}),
    "s2c-0190": ("0x0190", {"sample_count": 32, "sub_size_distribution": {"136": 32}, "body_length": 120}),
    "s2c-0187": ("0x0187", {"sample_count": 33, "sub_size_distribution": {"96": 33}, "body_length": 80}),
    "s2c-018b": ("0x018b", {"sample_count": 31, "sub_size_distribution": {"88": 31}, "body_length": 72}),
    "s2c-018d": ("0x018d", {"sample_count": 60, "sub_size_distribution": {"696": 60}, "body_length": 680}),
}

EXPECTED_0193_SAMPLES = (
    ("gridania_to_coerthas.pcapng", 0x50E0F492, 0x14, 15),
    ("move_out_of_room.pcapng", 0x50E0E9D5, 0x14, 15),
    ("party_battle_leve.pcapng", 0x50E11DE8, 0x14, 2),
    ("return_to_inn.pcapng", 0x50E0EDDB, 0x12, 900),
    ("return_to_inn.pcapng", 0x50E0EDDB, 0x14, 2),
    ("teleport_to_camp_nine_ivies.pcapng", 0x50E0F7F2, 0x14, 2),
    ("teleport_to_camp_tranquil.pcapng", 0x50E0EB11, 0x14, 2),
    ("teleport_to_gridania.pcapng", 0x50E0EC64, 0x14, 2),
    ("war_quest_update2.pcapng", 0x50E15B05, 0x14, 2),
)

CHANT_BOUNDARY_EXPECTATIONS = {
    "s2c-0144": (
        "FUN_0075A9A0 constructs ChangeActorSubStatModeBorderReceiver from application offset 4",
        "FUN_006EECB0 writes only that byte to CharaSubStatStorage+0x18",
        "does not write the status-word bits 8..15",
        "does not establish a chant enum",
    ),
    "s2c-0179": (
        "u16 statusIds[20]",
        "kind 1 selects bits 12..15 with >> 12 & 0xf",
        "kind 2 selects bits 8..11 with >> 8 & 0xf",
        "Zero values and unsupported kind tags return nil",
        "bits 8..11, bits 14..15, and bits 12..13",
        "no client table or branch maps values 1..15 to stable semantic nouns",
    ),
}


def validate_mechanical_expectations(
    errors: list[str], entries: list[dict], capture_layouts: dict
) -> None:
    """Validate repeated client-only anchors and pinned layout summaries."""
    for label, (opcode_hex, direction, anchor) in CLIENT_ONLY_EXPECTATIONS.items():
        matches = [
            entry for entry in entries
            if entry.get("opcodeHex") == opcode_hex and entry.get("direction") == direction
            and entry.get("decompAnchor") == anchor
        ]
        if len(matches) != 1:
            errors.append(f"{label}: expected one {direction} catalog row")
            continue
        entry = matches[0]
        if entry.get("decompAnchor") != anchor:
            errors.append(f"{label}: decompAnchor is not {anchor}")
        if entry.get("implementationAnchor") is not None:
            errors.append(f"{label}: implementationAnchor must remain null")
        if entry.get("confidence") != "decomp_routed":
            errors.append(f"{label}: confidence must remain decomp_routed")

    layouts = capture_layouts.get("layouts", {}).get("s2c", {})
    for label, (opcode_hex, expected) in LAYOUT_SUMMARY_EXPECTATIONS.items():
        layout = layouts.get(opcode_hex, {})
        if any(layout.get(key) != value for key, value in expected.items()):
            errors.append(f"{label} pinned layout summary drifted")


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

    if len(rows) != 44:
        errors.append(f"evidence row count is {len(rows)}, expected 44")
    if {row.get("dependencyOrdinal") for row in rows} != set(range(44)):
        errors.append("dependencyOrdinal values must be exactly 0 through 43")

    inbound = {row.get("opcodeHex") for row in rows if row.get("direction") == "clientbound"}
    outbound = {row.get("opcodeHex") for row in rows if row.get("direction") == "serverbound"}
    if inbound != EXPECTED_INBOUND:
        errors.append("clientbound opcode set does not match the 34-row ledger slice")
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

    rows_by_id = {row.get("id"): row for row in rows}
    for label, fragments in CHANT_BOUNDARY_EXPECTATIONS.items():
        observation = rows_by_id.get(label, {}).get("observation", "")
        for fragment in fragments:
            if fragment not in observation:
                errors.append(f"{label}: chant boundary lacks required fact {fragment!r}")

    anchors = [entry["decompAnchor"] for entry in entries if entry.get("decompAnchor")]
    if len(anchors) != 86:
        errors.append(f"catalog has {len(anchors)} decompAnchor values, expected 86")
    bad_anchors = [anchor for anchor in anchors if not BARE_FUNCTION.fullmatch(anchor)]
    if bad_anchors:
        errors.append(f"non-bare decompAnchor values: {bad_anchors}")

    battle_effect_row = next(row for row in rows if row.get("id") == "s2c-00da")
    battle_effect_observation = battle_effect_row.get("observation", "")
    for fragment in (
        "FUN_004D9910",
        "FUN_0058CAD0",
        "forwards application u32 +0 while forcing both staged source and target "
        "to the resolved CharaElement actor and forcing staged u16 control to zero",
        "0x00e0 calls FUN_0058C690 with the resolved source, application u32 +0 as "
        "selector, application u32 +4 as target, and control zero",
        "0x00e1 calls FUN_0058C690 with the resolved source, application u32 +0 as "
        "selector, application u32 +4 as target, and application u16 +8 as control",
        "FUN_0058C690 fixes row count to one",
        "visual/action type at record +0x04",
        "does not retain the wire opcode",
        "FUN_0058DF90 calls FUN_0058DA10",
        "FUN_004E9700 and FUN_0060C140 to FUN_007C93C0",
        "vtable offset +0x274",
        "FUN_00662D30 case 4 directly calls FUN_00846080",
        "FUN_00845E80",
        "first proven controller presentation operation",
        "CharaActionVisual primary slots +0x54, +0x58, and +0x60 resolve to "
        "FUN_00798BF0, FUN_00799C90, and FUN_00798A40",
        "+0x58 explicitly builds a /client/vfx/ resource path",
        "resource lookup FUN_00D39290 and resource-slot assignment helper FUN_006320C0",
        "queue back-pointer +0x24 call resolves to CharaActionQue slot 9 FUN_00843DE0",
        "RaptureSchEffectController +0x18 call resolves to FUN_0080B6C0, a membership test",
        "concrete slot 10 FUN_007254A0, which returns one",
        "Factory-created action-object calls at +0x2c, +0x34, and related offsets remain "
        "runtime-polymorphic",
        "not an exact animation resource, a named controller state transition, or a "
        "completion callback",
    ):
        if fragment not in battle_effect_observation:
            errors.append(f"s2c-00da observation lost required fact: {fragment}")

    battle_effect_samples = capture_samples["samples"]["s2c"]["0x00da"]
    retained_battle_effects = battle_effect_samples.get("samples", [])
    if battle_effect_samples.get("sampleCount") != 16 or len(retained_battle_effects) != 16:
        errors.append("s2c-00da retained sample count drifted from 16")
    if {sample.get("sub_size") for sample in retained_battle_effects} != {40}:
        errors.append("s2c-00da retained subpacket length drifted from 40")
    if len({sample.get("capture") for sample in retained_battle_effects}) != 7:
        errors.append("s2c-00da retained capture count drifted from 7")
    if any(bytes.fromhex(sample["bytes"])[20:24] != b"\0\0\0\0" for sample in retained_battle_effects):
        errors.append("s2c-00da retained second application u32 is no longer uniformly zero")

    battle_effect_entry = next(
        entry
        for entry in entries
        if entry.get("opcodeHex") == "0x00da"
        and entry.get("direction") == "clientbound"
        and entry.get("decompAnchor") == "FUN_0058CAD0"
    )
    battle_effect_notes = battle_effect_entry.get("notes", "")
    if battle_effect_entry.get("name") != "_0x00DA":
        errors.append("s2c-00da must retain a placeholder packet name")
    if battle_effect_entry.get("implementationAnchor") is not None:
        errors.append("s2c-00da must not retain the imported implementation anchor")
    for fragment in (
        "discriminator=record+0x04 is the derived visual class",
        "producer_difference=0x00DA forces source and target",
        "per_frame=FUN_0058DF90 calls FUN_0058DA10",
        "FUN_007C93C0 resolves the CharaActor",
        "first_controller_edge=CharaActor FUN_00662D30 case 4 directly calls FUN_00846080",
        "FUN_00845E80 allocates a concrete CharaActionQue",
        "local_visual_path=classes 3..0x0b also call FUN_0058CA80",
        "concrete_visual=FUN_00843B50 constructs CharaActionVisual",
        "resource_behavior=the +0x54 and +0x58 paths call FUN_00D39290 and FUN_006320C0",
        "queue_back_pointer=visual +0x24 resolves to CharaActionQue slot 9 FUN_00843DE0",
        "RaptureSchEffectController +0x18 resolves to membership test FUN_0080B6C0",
        "unresolved_virtuals=factory-created action-object +0x2c, +0x34, and related calls "
        "remain runtime-polymorphic",
        "not an exact animation resource, named controller state transition, completion "
        "callback, or restored producer opcode",
        "naming=placeholder retained",
        "prior_label=PlayAnimationOnActorPacket / MapServerOpcode::PlayAnimationOnActor",
        "conflict=imported packet noun and implementation anchor are unsupported",
    ):
        if fragment not in battle_effect_notes:
            errors.append(f"s2c-00da notes lost required fact: {fragment}")

    action_family_row = next(row for row in rows if row.get("id") == "s2c-00e1")
    action_family_observation = action_family_row.get("observation", "")
    for fragment in (
        "0x00e1 case at VA 0x0058D020",
        "application u32 +0, u32 +4, and u16 +8",
        "passes them to FUN_0058C690 as effect-or-action selector, target actor, "
        "and staged control",
        "resolved CharaElement actor becomes the staged source",
        "0x00e0 case at VA 0x0058D00A calls FUN_0058C690 with the same selector "
        "and target fields but control zero",
        "0x00da case at VA 0x0058CFFA enters FUN_0058CAD0, which uses the same "
        "selector but forces target equal to the resolved source and control zero",
        "No producer tag or wire opcode survives",
        "FUN_00662D30 case 4",
        "FUN_00845E80",
        "CharaActionVisual primary slots +0x54, +0x58, and +0x60 resolve to "
        "FUN_00798BF0, FUN_00799C90, and FUN_00798A40",
        "+0x58 explicitly builds a /client/vfx/ resource path",
        "RaptureSchEffectController +0x18 call resolves to FUN_0080B6C0, a membership test",
        "Factory-created action-object calls at +0x2c, +0x34, and related offsets remain "
        "runtime-polymorphic",
        "not an exact animation resource, a named controller state transition, or a "
        "completion callback",
        "shared presentation route cannot restore the lost producer opcode",
        "ActorDoEmotePacket is rejected as unsupported",
    ):
        if fragment not in action_family_observation:
            errors.append(f"s2c-00e1 observation lost required fact: {fragment}")

    action_family_samples = capture_samples["samples"]["s2c"]["0x00e1"]
    retained_action_family = action_family_samples.get("samples", [])
    if action_family_samples.get("sampleCount") != 3 or len(retained_action_family) != 3:
        errors.append("s2c-00e1 retained sample count drifted from 3")
    if {sample.get("sub_size") for sample in retained_action_family} != {48}:
        errors.append("s2c-00e1 retained subpacket length drifted from 48")
    if len({sample.get("capture") for sample in retained_action_family}) != 3:
        errors.append("s2c-00e1 retained capture count drifted from 3")
    action_family_bytes = [bytes.fromhex(sample["bytes"]) for sample in retained_action_family]
    if {int.from_bytes(value[16:20], "little") for value in action_family_bytes} != {
        0x0500B000,
        0x05010000,
        0x05013000,
    }:
        errors.append("s2c-00e1 effect-or-action selector values drifted")
    if {int.from_bytes(value[20:24], "little") for value in action_family_bytes} != {
        0x029B2941,
        0x45606E27,
    }:
        errors.append("s2c-00e1 target actor values drifted")
    if {int.from_bytes(value[24:26], "little") for value in action_family_bytes} != {
        0x526E,
        0x529F,
        0x52BE,
    }:
        errors.append("s2c-00e1 staged control values drifted")
    if any(value[26:32] != bytes(6) for value in action_family_bytes):
        errors.append("s2c-00e1 six-byte tail is no longer uniformly zero")

    action_family_entry = next(
        entry
        for entry in entries
        if entry.get("opcodeHex") == "0x00e1"
        and entry.get("direction") == "clientbound"
        and entry.get("decompAnchor") == "FUN_0058C690"
    )
    if action_family_entry.get("name") != "_0x00E1":
        errors.append("s2c-00e1 must retain a placeholder packet name")
    if action_family_entry.get("implementationAnchor") is not None:
        errors.append("s2c-00e1 must not retain the imported implementation anchor")
    if action_family_entry.get("observedIn") != [
        "emote_dance.pcapng",
        "emote_kneel.pcapng",
        "war_quest_update2.pcapng",
    ]:
        errors.append("s2c-00e1 catalog capture list drifted")
    if action_family_entry.get("payloadLengths") != [48]:
        errors.append("s2c-00e1 catalog payload length drifted")
    for fragment in (
        "case 0x00E1 at VA 0x0058D020",
        "wire_application=effect-or-action selector u32 at +0",
        "staging=resolved actor becomes source, packet +4 becomes target, packet +0 "
        "becomes effect-or-action value, row count is fixed to one",
        "producer_difference=0x00E0 calls FUN_0058C690 with the same packet selector "
        "and target but forces control zero, while 0x00DA forces both source and target to the "
        "resolved actor and forces control zero",
        "producer_identity=wire opcode is dropped",
        "FUN_00845E80 CharaActionQue insertion",
        "concrete_visual=FUN_00843B50 constructs CharaActionVisual",
        "resource_behavior=the +0x54 and +0x58 paths call FUN_00D39290 and FUN_006320C0",
        "controller_targets=slots 2..5 reach visual dispatch and local flags",
        "unresolved_virtuals=factory-created action-object +0x2c, +0x34, and related calls "
        "remain runtime-polymorphic",
        "not an exact animation resource, named controller state transition, completion "
        "callback, or restored producer opcode",
        "naming=placeholder retained",
        "prior_label=ActorDoEmotePacket / MapServerOpcode::ActorDoEmote",
        "capture filenames are not semantic proof",
    ):
        if fragment not in action_family_entry.get("notes", ""):
            errors.append(f"s2c-00e1 notes lost required fact: {fragment}")

    if any(
        entry.get("opcodeHex") == "0x00e0" and entry.get("direction") == "clientbound"
        for entry in entries
    ):
        errors.append("s2c-00e0 must not gain an unobserved catalog row")

    group_expectations = {
        "s2c-017c": {
            "sub_size": 152,
            "body_length": 136,
            "catalog_fragments": (
                "groupTypeId at application offset 0x30",
                "application_payload=0x78 bytes",
                "observed_subpacket=0x98 bytes",
                "10001 x14,10002 x265,30001 x65,30006 x4,50001 x2,80001 x11",
                "30001_scope=65/65 party_battle_leve.pcapng",
                "no group-kind mapping",
                "BCS-Y-0564",
                "director_group_wire_identity.json#layouts.0x017C",
            ),
        },
        "s2c-017f": {
            "sub_size": 440,
            "body_length": 424,
            "catalog_fragments": (
                "application_payload=0x198 bytes",
                "observed_subpacket=0x1b8 bytes",
                "eight 0x30-byte records at application offset 0x10",
                "memberCount=u32 at application offset 0x190",
                "director_group_wire_identity.json#layouts.0x017F",
            ),
        },
        "s2c-0183": {
            "sub_size": 152,
            "body_length": 136,
            "catalog_fragments": (
                "application_payload=0x78 bytes",
                "observed_subpacket=0x98 bytes",
                "eight 0x0c-byte records at application offset 0x10",
                "memberCount=low byte at application offset 0x70",
                "director_group_wire_identity.json#layouts.0x0183",
            ),
        },
    }
    for row_id, expected in group_expectations.items():
        row = next(row for row in rows if row.get("id") == row_id)
        entry = next(
            entry for entry in entries
            if entry.get("opcodeHex") == row["opcodeHex"]
            and entry.get("direction") == "clientbound"
            and entry.get("decompAnchor") == row["function"]
        )
        layout = capture_layouts["layouts"]["s2c"][row["opcodeHex"]]
        if layout.get("common_sub_size") != expected["sub_size"]:
            errors.append(f"{row_id}: pinned subpacket size drifted")
        if layout.get("body_length") != expected["body_length"]:
            errors.append(f"{row_id}: pinned body length drifted")
        notes = entry.get("notes", "")
        for fragment in expected["catalog_fragments"]:
            if fragment not in notes:
                errors.append(f"{row_id}: catalog notes lost required fact {fragment!r}")

    group_header = (REPO_ROOT / "structs" / "map" / "clientbound.h").read_text(encoding="ascii")
    for pattern in (
        r"uint32_t\s+groupTypeId;\s*// application\[\+0x30\]; positional observation",
        r"uint8_t\s+members\[384\];\s*// eight 0x30-byte records at application\[\+0x10\]",
        r"uint32_t\s+memberCount;\s*// application\[\+0x190\]",
        r"uint8_t\s+members\[96\];\s*// eight 0x0c-byte records at application\[\+0x10\]",
        r"uint8_t\s+memberCount;\s*// application\[\+0x70\]",
    ):
        if re.search(pattern, group_header) is None:
            errors.append(f"generated Group-family structs lost pattern {pattern!r}")

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

    event_start_row = next(row for row in rows if row.get("id") == "c2s-012d")
    event_start_observation = event_start_row.get("observation", "")
    for fragment in (
        "FUN_006EE680/FUN_0075E3A0",
        "combat and noncombat scenarios",
        "All 126 captured 216-byte subpackets",
        "100 owner IDs have upper 16 bits 0xa0f0",
        "88 also join to gameCommand",
        "12 are command actors absent from that sheet",
        "61/64 combat-example occurrences",
        "39/62 other occurrences",
        "retained 60-sample cap independently gives 41 staticactor",
        "direct scalar gameCommand propagation",
        "command.canFire",
        "native dynamic dispatch",
    ):
        if fragment not in event_start_observation:
            errors.append(f"c2s-012d observation lost required fact {fragment!r}")
    event_start_entry = next(
        entry
        for entry in entries
        if entry.get("opcodeHex") == "0x012d"
        and entry.get("direction") == "serverbound"
        and entry.get("decompAnchor") == "FUN_00776760"
    )
    event_start_notes = event_start_entry.get("notes", "")
    if event_start_entry.get("name") != "EventStartPacket":
        errors.append("c2s-012d canonical name must remain EventStartPacket")
    if event_start_entry.get("payloadLengths") != [216]:
        errors.append("c2s-012d must retain the observed 216-byte wire length")
    event_start_layout = capture_layouts.get("layouts", {}).get("c2s", {}).get("0x012d", {})
    event_start_samples = capture_samples.get("samples", {}).get("c2s", {}).get("0x012d", {})
    if (
        event_start_layout.get("common_sub_size") != 216
        or event_start_layout.get("sub_size_distribution") != {"216": 60}
        or event_start_layout.get("sample_count") != 60
        or event_start_layout.get("body_length") != 200
    ):
        errors.append("c2s-012d capture layout must remain 60 retained 216-byte samples with a 200-byte body")
    if event_start_samples.get("sampleCount") != 60 or any(
        sample.get("sub_size") != 216 for sample in event_start_samples.get("samples", [])
    ):
        errors.append("c2s-012d retained samples must remain exactly 60 216-byte subpackets")
    for fragment in (
        "client_prechecks=50-byte combined script-string limit",
        "command_id_mapping=resolved for owner ids in the 0xa0f00000 static-actor block",
        "application offset 0x04 low16 joins 100/100 /Command staticactor rows",
        "88/100 gameCommand rows",
        "non_gameCommand_command_actors=12",
        "event_owner_scope=26/126 owners are outside the static block",
        "pattern_scope=general EventStart envelope",
        "retained_sample_cap=41/60 staticactor and 29/60 gameCommand joins",
        "direct_gameCommand_scalar=unproven",
        "prior_label=MapClientOpcode::EventStart",
        "separate_family=0x01c3..0x01df",
    ):
        if fragment not in event_start_notes:
            errors.append(f"c2s-012d notes lost required fact {fragment!r}")

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
    if manager_row.get("supportedLabel") != (
        "0x018a Group-current u32-to-u64 snapshot reconciliation with a "
        "120-byte application payload"
    ):
        errors.append("s2c-018a supported operation label drifted")
    for fragment in (
        "FUN_00576380",
        "FUN_006C82A0",
        "FUN_006C6A70",
        "signed low byte",
        "application offset 0x60",
        "+0x40+4*i",
        "+8*i",
        "FUN_006C58C0",
        "persistent 0x18-byte state object",
        "removes absent keys",
        "Group::SharedWork virtual call",
        "120-byte application payload",
        "20-byte tail",
        "120-byte inner body",
        "104 captured bytes after its 16-byte game-message prefix are zero",
        "FUN_00578970 -> FUN_006CDF20",
        "FUN_006C2200",
        "FUN_00700E70",
        "FUN_00700FF0",
        "_onUpdateGroupCurrent",
        "changed-snapshot key",
        "FUN_00585020",
        "FUN_006C1510",
        "FUN_006D1020",
        "GroupBase-reference identity pair",
        "GroupReferenceRecord",
        "FUN_006BFCD0 initializes both state dwords to zero",
        "matched group-list node offsets +0x10 and +0x14",
        "FUN_006E2240 copies that complete record into a new GroupBase at +0x68",
        "FUN_006C7B80 passes the pair unchanged to FUN_006D5DB0",
        "unsigned high dword first and unsigned low dword second",
        "Zero-zero is the null pair",
        "all ten direct callers of FUN_006C1510",
        "opaque low and high components of the GroupBase-reference identity pair",
        "single 0x0137 -> 0x018a -> 0x0189 chronology does not prove causality",
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
    if manager_entry.get("observedIn") != ["login.pcapng"]:
        errors.append("s2c-018a must retain only the verified login.pcapng observation")
    if manager_entry.get("payloadLengths") != [136]:
        errors.append("s2c-018a must retain only the verified 136-byte subpacket length")
    for fragment in (
        "FUN_00576380",
        "FUN_006C82A0",
        "FUN_006C6A70",
        "application_payload=120 bytes",
        "map_build=u32 keys at +0x40 to u64 values at +0",
        "loop_bound=signed low byte at +0x60",
        "unread_tail=20 bytes at +0x64..+0x77",
        "commit=FUN_006C58C0 reconciles the temporary ordered map",
        "removing absent keys and inserting or replacing changed values",
        "consumer_route=frame FUN_00578970 reaches FUN_006CDF20",
        "change_drain=FUN_006C2200 drains the state +0x0c changed-key list",
        "FUN_00700E70 and FUN_00700FF0 _onUpdateGroupCurrent fire sites",
        "u32_domain=changed snapshot key",
        "FUN_00585020 as a numeric callback argument",
        "u64_domain=GroupBase-reference state-pair key",
        "FUN_006C1510 and FUN_006D1020",
        "GroupReferenceRecord",
        "u64_low_component=opaque first GroupBase-reference identity component",
        "group-list node at +0x10",
        "unsigned secondary ordering component",
        "u64_high_component=opaque second GroupBase-reference identity component",
        "node at +0x14",
        "unsigned primary ordering component",
        "component_boundary=zero-zero is the null pair",
        "preserve both dwords without exposing an independent domain",
        "consumer_boundary=positive callback consumer and field domains",
        "no Group::SharedWork virtual call in the commit body",
        "both u64 components remaining opaque",
        "corpus_aggregate=1 event",
        "retained_payload_evidence=1 136-byte subpacket with a 120-byte inner body",
        "104 captured bytes after the 16-byte game-message prefix are zero",
        "therefore count zero and an empty input snapshot",
        "naming=placeholder retained",
        "candidate_label=SetActiveLinkshellPacket is an imported source-manifest term, not retail-proven",
        "client_only=",
        "conflict=implementation anchor and packet noun lack a source-owned declaration",
        "BCS-Y-0578,BCS-Y-0888,BCS-Y-1632,BCS-Y-1633,BCS-S-0244",
    ):
        if fragment not in manager_notes:
            errors.append(f"s2c-018a notes lost required fragment: {fragment}")

    world_018a = [
        entry
        for entry in catalog["lists"]["WorldClientbound"]
        if entry.get("opcodeHex") == "0x018a"
    ]
    if world_018a:
        errors.append("s2c-018a must not retain a WorldClientbound catalog row")

    control_row = next(row for row in rows if row.get("id") == "s2c-0193")
    if control_row.get("supportedLabel") != (
        "0x0193 multiplexed client timer/config/command dispatcher with an 8-byte application payload"
    ):
        errors.append("s2c-0193 supported structural label drifted")
    control_observation = control_row.get("observation", "")
    for fragment in (
        "FUN_00578C90",
        "packet-header u32 +0x08",
        "application payload is 8 bytes, not 12",
        "header_clock + application_delta",
        "0x00..0x0f",
        "FUN_0075F3E0",
        "runtime dword length",
        "error path still reaches the raw write",
        "FUN_0075F420",
        "FUN_00705450",
        "0x3c-byte member at RaptureElementContainer+0x510",
        "RaptureUserControl object at RaptureElementContainer+0x17758 is a separate member",
        "_getOccupancyContentsTime decrements its Lua argument",
        "Lua arguments 1..16 map exactly to native indices 0..15",
        "sixteen documented client presentation rows",
        "0x10, 0x11, 0x12, and 0x16",
        "+0x10, +0x14, +0x18, and +0x1c",
        "_getNormalBehestTime, _getCompanyBehestTime, _getWarpRecastTime, and _getNMRushUpdateTime respectively",
        "consume stored values as endpoints",
        "places the packet-header clock in the Unix-compatible whole-second domain",
        "application values are offsets in that same integer unit",
        "0x12 value 900 produces a stored endpoint about 900 seconds after frame completion",
        "does not establish authoritative eligibility, reset policy, or server scheduling",
        "ActionCheck field at +0x38",
        "field is not diagnostic-only",
        "interpret it as signed and gate only on greater than zero",
        "actor-key insertion when absent during battle-result record staging",
        "equal-key erasure during queued-record drain",
        "zero and negative values suppress those local ordered-container mutations",
        "selector 0x7c000062",
        "0x10000000..0x10ffffff",
        "0x14000000..0x14ffffff",
        "drain consumer additionally excludes a null route-state pointer at +0x4",
        "insert iterator remains local and unused",
        "erase count is ignored",
        "no packet emission, Lua/N-API result, UI, movement, animation, targeting, or actor-state edge",
        "RaptureUserControl vtable",
        "RaptureCommands callbacks",
        "FUN_00576020",
        "FUN_0075B360",
        "9 retained 40-byte subpackets",
        "8 captures",
        "0x14 x8 or 0x12 x1",
        "0x50e0eddb/900",
        "ordered 0x12 then 0x14 in one frame",
        "0x50e0f15f",
        "does not name the +0x510 state class or ActionCheck ordered container",
        "no stable cross-branch packet noun",
        "no stable cross-branch packet noun, server implementation declaration, server behavior, server policy, server scheduling, or login causality",
    ):
        if fragment not in control_observation:
            errors.append(f"s2c-0193 observation lost required fact: {fragment}")
    required_control_refs = {
        "xivl-decomp:config/s2c_0193_native_state.json#route",
        "xivl-decomp:config/s2c_0193_native_state.json#timerState",
        "xivl-decomp:config/s2c_0193_native_state.json#raptureUserControl",
        "xivl-decomp:config/s2c_0193_native_state.json#actionCheck",
        "xivl-decomp:asm/ffxivgame/00178390_FUN_00578390.s#0x005783BA-0x00578410",
        "xivl-decomp:asm/ffxivgame/001785d0_FUN_005785d0.s#0x005785F7-0x0057864F",
        "xivl-client-scripts:manifests/myplayer_timer_consumers.json#nativeMapping",
        "xivl-client-scripts:manifests/myplayer_timer_consumers.json#occupancyArgumentMap",
        "xivl-client-scripts:manifests/myplayer_timer_consumers.json#scalarConsumerChains",
        "xivl-captures:studies/map-0193-clock-contract/derived/verdicts.md#clock-and-arithmetic-verdict",
    }
    if not required_control_refs.issubset(control_row.get("sourceRefs", [])):
        errors.append("s2c-0193 cross-repository semantic citations drifted")

    control_samples = capture_samples["samples"]["s2c"]["0x0193"]
    retained_control = control_samples.get("samples", [])
    subops: dict[int, int] = {}
    observed_control: list[tuple[str, int, int, int]] = []
    for sample in retained_control:
        body = bytes.fromhex(sample["bytes"])
        header_clock = int.from_bytes(body[8:12], "little")
        payload = body[16:24]
        subop = int.from_bytes(payload[:4], "little")
        application_delta = int.from_bytes(payload[4:8], "little")
        subops[subop] = subops.get(subop, 0) + 1
        observed_control.append(
            (sample.get("capture", ""), header_clock, subop, application_delta)
        )
    if control_samples.get("sampleCount") != 9 or len(retained_control) != 9:
        errors.append("s2c-0193 retained sample count drifted from 9")
    if {sample.get("sub_size") for sample in retained_control} != {40}:
        errors.append("s2c-0193 retained subpacket length drifted from 40")
    if len({sample.get("capture") for sample in retained_control}) != 8:
        errors.append("s2c-0193 retained capture count drifted from 8")
    if subops != {0x14: 8, 0x12: 1}:
        errors.append(f"s2c-0193 retained subopcode distribution drifted: {subops}")
    if tuple(observed_control) != EXPECTED_0193_SAMPLES:
        errors.append("s2c-0193 retained header/subopcode/delta chronology drifted")
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
    for fragment in (
        "FUN_00578C90",
        "application_payload=8 bytes",
        "third_scalar=packet-header u32 +0x08, not application +0x08",
        "route_state=structurally bounded 0x3c-byte RaptureElementContainer+0x510 member",
        "separate_member=0x58-byte RaptureUserControl at RaptureElementContainer+0x17758",
        "0x00..0x0f write a sixteen-entry u32 vector at index subopcode",
        "runtime-length error path still reaches the raw write",
        "paired reader=FUN_0075F420",
        "occupancy_reader=MyPlayer _getOccupancyContentsTime decrements Lua arguments 1..16 to native indices 0..15",
        "sixteen documented client presentation rows",
        "scalar_readers=0x10 _getNormalBehestTime,0x11 _getCompanyBehestTime,0x12 _getWarpRecastTime,0x16 _getNMRushUpdateTime",
        "presentation=Lua timer paths consume stored values as endpoints",
        "clock_contract=the packet-header clock is Unix-compatible whole seconds and application values are offsets in the same integer unit",
        "captured_0x12_delta=900 produces a stored endpoint about 900 seconds after frame completion",
        "timer_boundary=no authoritative eligibility, reset policy, or server scheduling established",
        "actioncheck=0x13 queries on 0xffffffff or writes ActionCheck u32 +0x38",
        "predicate=signed greater than zero",
        "positive_effect=insert absent actor key during battle-result record staging and erase equal actor keys during queued-record drain",
        "suppressed_effect=zero and negative values cause no local container mutation",
        "selector_exclusions=0x7c000062,0x10000000..0x10ffffff,0x14000000..0x14ffffff",
        "null_state_exclusion=queued-record drain also excludes null route state +0x4",
        "result_boundary=insert iterator local and unused, erase count ignored",
        "edge_boundary=no packet emission, Lua/N-API result, UI, movement, animation, targeting, or actor-state edge",
        "0x14 guards zero-to-one around FUN_0075B300",
        "RaptureUserControl targets increment u32 counts +0x18/+0x2c/+0x40/+0x54",
        "0x15 reaches FUN_00576020 and FUN_0075B360",
        "observed=9 retained 40-byte subpackets across 8 captures",
        "retained_subops=0x14 x8, 0x12 x1",
        "50e0eddb/900,50e0eddb/2",
        "retained_order=return_to_inn has 0x12 then 0x14 in one frame",
        "captured_0x12_store=0x50e0f15f",
        "corpus_aggregate=9 events",
        "unresolved=+0x510 state class, computed or dynamic indirect ActionCheck consumers, high-level ActionCheck ordered-container purpose",
        "first_reader_wrappers=FUN_00705450,FUN_007054D0,FUN_00705510,FUN_00705550,FUN_00706A00",
        "naming=placeholder retained",
        "candidate_label=SetControlStatePacket is an imported source-manifest term, not retail-proven",
        "client_only=",
        "does not establish server behavior, server policy, server scheduling, or login causality",
        "conflict=implementation anchor and packet noun lack a source-owned declaration",
        "BCS-Y-0584,BCS-Y-0990,BCS-Y-0991,BCS-Y-0992,BCS-Y-0993,BCS-Y-0996,BCS-Y-0997,BCS-Y-0998",
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

    modifier_samples = capture_samples["samples"]["s2c"]["0x0190"]
    retained_modifiers = modifier_samples.get("samples", [])
    if modifier_samples.get("sampleCount") != 32 or len(retained_modifiers) != 32:
        errors.append("s2c-0190 retained sample count drifted from 32")
    if {sample.get("sub_size") for sample in retained_modifiers} != {136}:
        errors.append("s2c-0190 retained subpacket length drifted from 136")
    if len({sample.get("capture") for sample in retained_modifiers}) != 8:
        errors.append("s2c-0190 retained capture count drifted from 8")
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

    occupancy_samples = capture_samples["samples"]["s2c"]["0x0187"]
    retained_occupancy = occupancy_samples.get("samples", [])
    if occupancy_samples.get("sampleCount") != 33 or len(retained_occupancy) != 33:
        errors.append("s2c-0187 retained sample count drifted from 33")
    if {sample.get("sub_size") for sample in retained_occupancy} != {96}:
        errors.append("s2c-0187 retained subpacket length drifted from 96")
    if len({sample.get("capture") for sample in retained_occupancy}) != 13:
        errors.append("s2c-0187 retained capture count drifted from 13")
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

    group_layout_samples = capture_samples["samples"]["s2c"]["0x018b"]
    retained_group_layout = group_layout_samples.get("samples", [])
    if group_layout_samples.get("sampleCount") != 31 or len(retained_group_layout) != 31:
        errors.append("s2c-018b retained sample count drifted from 31")
    if {sample.get("sub_size") for sample in retained_group_layout} != {88}:
        errors.append("s2c-018b retained subpacket length drifted from 88")
    if len({sample.get("capture") for sample in retained_group_layout}) != 13:
        errors.append("s2c-018b retained capture count drifted from 13")
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
    if party_marker_row.get("supportedLabel") != (
        "_0x018D client route with a fixed 0x298-byte application layout and "
        "native MapScreenControl presentation"
    ):
        errors.append("s2c-018d supported label lost the neutral identity boundary")
    party_marker_observation = party_marker_row.get("observation", "")
    for fragment in (
        "FUN_004DC690",
        "FUN_00575550",
        "FUN_0055CF70",
        "application +0x0c is unread",
        "0x28-byte wire rows begin at application +0x10",
        "count byte at application +0x290",
        "no rejection, clamp, or truncation",
        "592 fixed 696-byte subpackets",
        "415 carried one row and 177 carried two",
        "prior +0x0c and +0x20 claims",
        "unsafe client behavior, not a server implementation prescription",
        "native MapScreenControl UI property presentation",
        "wire +0x14 and +0x1c binary32 values with CVTTSS2SI to X:Int and Z:Int",
        "projected wire +0x18 is not read there",
        "Wire +0x00 is the primary tagged-referent selector",
        "+0x08 is fallback only after signed -1",
        "+0x0c is eligibility-only",
        "The resolved Utf8String minus every literal !!! becomes Text:String",
        "matched referent +0x00 becomes Layout:Int",
        "MapMarkerParty is supplied as a Template:String value",
        "Static marker resources exist, but no runtime edge joins them to 0x018D",
    ):
        if fragment not in party_marker_observation:
            errors.append(f"s2c-018d observation lost required fact: {fragment}")

    party_marker_samples = capture_samples["samples"]["s2c"]["0x018d"]
    retained_samples = party_marker_samples.get("samples", [])
    count_distribution: dict[int, int] = {}
    for sample in retained_samples:
        body = bytes.fromhex(sample["bytes"])
        if len(body) != 680:
            errors.append(f"s2c-018d retained sample body length drifted: {len(body)}")
        if len(body) <= 672:
            continue
        count = body[672]
        count_distribution[count] = count_distribution.get(count, 0) + 1
    if party_marker_samples.get("sampleCount") != 60 or len(retained_samples) != 60:
        errors.append("s2c-018d retained sample count drifted from 60")
    if {sample.get("sub_size") for sample in retained_samples} != {696}:
        errors.append("s2c-018d retained subpacket length drifted from 696")
    if count_distribution != {1: 58, 2: 2}:
        errors.append(f"s2c-018d count distribution drifted: {count_distribution}")
    party_marker_entry = next(
        entry
        for entry in entries
        if entry.get("opcodeHex") == "0x018d"
        and entry.get("direction") == "clientbound"
        and entry.get("decompAnchor") == "FUN_00575550"
    )
    party_marker_notes = party_marker_entry.get("notes", "")
    if party_marker_entry.get("name") != "_0x018D":
        errors.append("s2c-018d canonical name must remain the neutral placeholder")
    for fragment in (
        "wire_layout=data/s2c_018d_wire_layout.json",
        "FUN_00575550",
        "FUN_0055CF70",
        "record_offset=0x10",
        "record_stride=0x28",
        "count_offset=0x290",
        "count_check=none",
        "observed_events=592",
        "first_outward_consumer=native MapScreenControl UI property presentation",
        "presentation_projection=wire +0x14 and +0x1c become X:Int and Z:Int after CVTTSS2SI",
        "middle_projected_float=not read by the presentation consumer",
        "record_lookup=wire +0x00 is the primary tagged-referent selector, +0x08 is fallback only after signed -1, and +0x0c is eligibility-only",
        "helper_outputs=resolved Utf8String minus every literal !!! becomes Text:String, and matched referent +0x00 becomes Layout:Int",
        "template_boundary=MapMarkerParty is a Template:String value, not a packet or native class name",
        "static_resource_boundary=no runtime edge joins marker resources to 0x018D",
        "name_boundary=placeholder retained",
        "client_only=",
    ):
        if fragment not in party_marker_notes:
            errors.append(f"s2c-018d notes lost required fragment: {fragment}")
    required_party_marker_refs = {
        "xivl-client-structs:manifests/s2c_018d_map_marker_presentation.json",
        "xivl-decomp:config/s2c_018d_client_consumer.json",
        "xivl-decomp:docs/net/s2c-018d-client-consumer.md",
        "xivl-captures:studies/party-marker-018d-chronology/derived/field-verdicts.md",
        "xivl-client-data:manifests/map_marker_resources.json",
    }
    if not required_party_marker_refs.issubset(party_marker_row.get("sourceRefs", [])):
        errors.append("s2c-018d lost native presentation source references")

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

    validate_mechanical_expectations(errors, entries, capture_layouts)

    cluster_entries = [
        entry
        for entry in catalog["lists"]["MapClientbound"]
        if entry.get("direction") == "clientbound"
        and 0x01C3 <= entry.get("opcode", -1) <= 0x01DF
    ]
    misplaced_cluster_entries = [
        (bucket, entry.get("opcode"))
        for bucket, bucket_entries in catalog["lists"].items()
        if bucket != "MapClientbound"
        for entry in bucket_entries
        if entry.get("direction") == "clientbound"
        and 0x01C3 <= entry.get("opcode", -1) <= 0x01DF
    ]
    if misplaced_cluster_entries:
        errors.append(
            f"s2c 0x01c3..0x01df rows escaped MapClientbound: {misplaced_cluster_entries}"
        )
    if len(cluster_entries) != 29:
        errors.append(
            f"s2c 0x01c3..0x01df row count is {len(cluster_entries)}, expected 29"
        )
    cluster_by_opcode = {entry.get("opcode"): entry for entry in cluster_entries}
    for opcode in range(0x01C3, 0x01E0):
        entry = cluster_by_opcode.get(opcode)
        if entry is None:
            errors.append(f"s2c 0x{opcode:04x} no-op callback row is missing")
            continue
        expected_function = f"FUN_{0x00DB8F20 + (opcode - 0x01C3) * 0x10:08X}"
        expected_slot = opcode - 0x011E
        notes = entry.get("notes", "")
        if entry.get("name") != f"_0x{opcode:04X}":
            errors.append(f"s2c 0x{opcode:04x} must retain a placeholder name")
        if entry.get("implementationAnchor") is not None:
            errors.append(f"s2c 0x{opcode:04x} retained an imported implementation anchor")
        if entry.get("decompAnchor") != expected_function:
            errors.append(
                f"s2c 0x{opcode:04x} decomp anchor is not {expected_function}"
            )
        if entry.get("confidence") != "decomp_routed":
            errors.append(f"s2c 0x{opcode:04x} confidence must be decomp_routed")
        for fragment in (
            f"callback slot {expected_slot}",
            "callback_body=ret 0xc with no payload reads or state writes",
            "client_re_evidence=xivl-client-structs:manifests/zone_dummy_callback_cluster.json",
            "dependency_status=closed",
        ):
            if fragment not in notes:
                errors.append(
                    f"s2c 0x{opcode:04x} notes lost required fact {fragment!r}"
                )
        prior = ZONE_DUMMY_CLUSTER_PRIOR.get(opcode)
        if prior:
            prior_packet, prior_anchor = prior
            for fragment in (
                f"prior_packet_label={prior_packet}",
                f"prior_label={prior_anchor}",
                "conflict=imported packet noun and implementation anchor are unsupported",
            ):
                if fragment not in notes:
                    errors.append(
                        f"s2c 0x{opcode:04x} lost prior-lineage fact {fragment!r}"
                    )
        expected_observed = {
            0x01CF: (["friendlist_search.pcapng", "invite_join_party.pcapng"], [1640]),
            0x01DF: (["friendlist_search.pcapng"], [968]),
        }.get(opcode, ([], []))
        if entry.get("observedIn") != expected_observed[0]:
            errors.append(f"s2c 0x{opcode:04x} observedIn drifted")
        if entry.get("payloadLengths") != expected_observed[1]:
            errors.append(f"s2c 0x{opcode:04x} payloadLengths drifted")

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
