"""Apply curated overrides and canonicalize both root catalogs."""

import json
import sys
from pathlib import Path

from _json_io import CONSTANTS_PATH, OPCODES_PATH, write_json

EXPECTED_TOP_DESC = "FFXIV 1.23b opcode catalog joined with pcap observations and retail-client analysis. WorldMapBackend holds world<->map backbone packets; both backend directions share opcode integers. WorldMapBackend entries are server-to-server and never cross the client TCP socket, so client-capture pcap evidence is structurally impossible for those wire values. A catalog extension added 4 client-side receiver opcodes (0x018E SetRetainerStar, 0x01A2 JobQuestCompleteTriple, 0x01A6 HamletSupplyRanking, 0x01A8 HamletDefenseScore); evidence is xivl-client-structs client receiver decomp."
REVERIFY_METHOD = "live-validation: verify that the retail 1.23b client accepts the behavior in a live session"
CLIENT_SEMANTICS_PATH = Path(__file__).resolve().parent.parent / "data" / "client_opcode_semantics.json"
LOCAL_DECOMP_ANCHOR_EVIDENCE = {
    "FUN_0075ECD0": "data/client_opcode_semantics.json#c2s-0135",
    "FUN_00576560": "data/vendor/client-structs/bcsy-opcode-bindings.json#BCS-Y-0545",
    "FUN_00576250": "data/vendor/client-structs/bcsy-opcode-bindings.json#BCS-Y-0564",
    "FUN_0089F530": "data/vendor/client-structs/bcsy-opcode-bindings.json#BCS-Y-0029",
    "FUN_0089F430": "data/vendor/client-structs/bcsy-opcode-bindings.json#BCS-Y-0031",
    "FUN_0089D180": "data/vendor/client-structs/bcsy-opcode-bindings.json#BCS-Y-0033",
    "FUN_0089D980": "data/vendor/client-structs/bcsy-opcode-bindings.json#BCS-Y-0734",
}
UNSUPPORTED_NOTE_PREFIXES = (
    "processor_evidence=",
    "case_comment=",
    "dispatch_only_no_packet_class",
)

OVERRIDES = [
    (
        "LobbyClientbound",
        "0x0002",
        "Error",
        "implementationServiceRelabel=same_wire_integer_used_by_World/Map_at_0x0002; no_reference_Lobby_Server_packet_class_at_this_opcode; not_a_parity_discrepancy; no_pcap_evidence",
        "implementationServiceRelabel=same_wire_integer_used_by_World/Map_at_0x0002; no_reference_Lobby_Server_packet_class_at_this_opcode; not_a_parity_discrepancy; no_pcap_evidence",
    ),
    (
        "WorldClientbound",
        "0x0002",
        "_0x2Packet",
        "no_pcap_evidence",
        "no_pcap_evidence; implementationServiceRelabel=LobbyOpcode::Error_at_lobby_clientbound_same_wire_integer; not_a_parity_discrepancy",
    ),
    (
        "MapServerbound",
        "0x0002",
        "_0x0002Handler",
        "no_pcap_evidence",
        "no_pcap_evidence; implementationServiceRelabel=LobbyOpcode::Error_at_lobby_clientbound_same_wire_integer; not_a_parity_discrepancy",
    ),
    (
        "MapClientbound",
        "0x0002",
        "_0x02Packet",
        "no_pcap_evidence",
        "no_pcap_evidence; implementationServiceRelabel=LobbyOpcode::Error_at_lobby_clientbound_same_wire_integer; not_a_parity_discrepancy",
    ),
    (
        "MapClientbound",
        "0x013a",
        "CommandResultX10Packet",
        "packet_size=0xD8; multiplexed_at_runtime=true; payload_variants=CommandResultX10Packet,BattleActionX10Packet; runtime_distinguish=source_actor+per_entry_layout(12B_CommandResult_vs_~16B_BattleAction)",
        "packet_size=0xD8; pcap_shape=sparse_SoA_CommandResultX10; columns=targets@0x28,amounts@0x50,textIds@0x64,effectIds@0x78,params@0xA0,hitNums@0xAA; 66_s2c_main_occurrences_in_6_captures; alternate_name=BattleActionX10Packet",
    ),
    (
        "MapClientbound",
        "0x013b",
        "CommandResultX18Packet",
        "packet_size=0x148; payload_variants=CommandResultX18Packet,BattleActionX18Packet; no_occurrences_in_54_capture_corpus; unresolved_discriminator=retail_0x013B_payload_showing_columnar_CommandResult_or_per_entry_BattleAction_layout",
        "packet_size=0x148; payload_shape=sparse_SoA_CommandResultX18; columns=targets@0x28,amounts@0x70,textIds@0x94,effectIds@0xB8,params@0x100,hitNums@0x112; rows=18x0x14_transposed_by_FUN_005874B0; no_occurrences_in_54_capture_corpus; alternate_name=BattleActionX18Packet",
    ),
    (
        "WorldMapBackend",
        "0x100a",
        "ErrorPacket",
        "backend_direction=world_to_map; no_pcap_evidence; structural_backbone_no_client_pcap_resolution_possible",
        "backend_direction=world_to_map; no_pcap_evidence; structural_backbone_no_client_pcap_resolution_possible",
    ),
    (
        "WorldMapBackend",
        "0x1010",
        "_0x1010",
        "no_retail_evidence; structural_backbone_no_client_pcap_resolution_possible",
        "no_retail_evidence; structural_backbone_no_client_pcap_resolution_possible",
    ),
    (
        "WorldMapBackend",
        "0x1011",
        "_0x1011",
        "no_retail_evidence; structural_backbone_no_client_pcap_resolution_possible",
        "no_retail_evidence; structural_backbone_no_client_pcap_resolution_possible",
    ),
    (
        "WorldMapBackend",
        "0x1020",
        "PartyModifyPacket",
        "backend_direction=map_to_world; no_pcap_evidence; structural_backbone_no_client_pcap_resolution_possible",
        "backend_direction=map_to_world; no_pcap_evidence; structural_backbone_no_client_pcap_resolution_possible",
    ),
    (
        "WorldMapBackend",
        "0x1020",
        "PartySyncPacket",
        "backend_direction=world_to_map; no_pcap_evidence; structural_backbone_no_client_pcap_resolution_possible",
        "backend_direction=world_to_map; no_pcap_evidence; structural_backbone_no_client_pcap_resolution_possible",
    ),
    (
        "WorldMapBackend",
        "0x1025",
        "CreateLinkshellPacket",
        "backend_direction=map_to_world; no_pcap_evidence; structural_backbone_no_client_pcap_resolution_possible",
        "backend_direction=map_to_world; no_pcap_evidence; structural_backbone_no_client_pcap_resolution_possible",
    ),
    (
        "WorldMapBackend",
        "0x1025",
        "LinkshellResultPacket",
        "backend_direction=world_to_map; no_pcap_evidence; structural_backbone_no_client_pcap_resolution_possible",
        "backend_direction=world_to_map; no_pcap_evidence; structural_backbone_no_client_pcap_resolution_possible",
    ),
    (
        "WorldMapBackend",
        "0x1fff",
        "_0x1FFF",
        "no_retail_evidence; structural_backbone_no_client_pcap_resolution_possible",
        "no_retail_evidence; structural_backbone_no_client_pcap_resolution_possible",
    ),
]

OVERRIDE_NAME_ALIASES = {
    ("MapClientbound", "0x013b", "CommandResultX18Packet"): (
        "BattleActionX18Packet",
    ),
}

UNSUPPORTED_IMPLEMENTATION_OVERRIDES = [
    ("WorldMapBackend", "0x1000", "SessionBeginConfirmPacket"),
    ("WorldMapBackend", "0x1000", "SessionBeginPacket"),
    ("WorldMapBackend", "0x1001", "SessionEndConfirmPacket"),
    ("WorldMapBackend", "0x1001", "SessionEndPacket"),
    ("WorldMapBackend", "0x1002", "WorldRequestZoneChangePacket"),
    ("WorldMapBackend", "0x1003", "MapDrainPendingSendsPacket"),
    ("WorldMapBackend", "0x100a", "ErrorPacket"),
    ("WorldMapBackend", "0x1020", "PartyModifyPacket"),
    ("WorldMapBackend", "0x1020", "PartySyncPacket"),
    ("WorldMapBackend", "0x1021", "PartyLeavePacket"),
    ("WorldMapBackend", "0x1022", "PartyInvitePacket"),
    ("WorldMapBackend", "0x1023", "GroupInviteResultPacket"),
    ("WorldMapBackend", "0x1025", "CreateLinkshellPacket"),
    ("WorldMapBackend", "0x1025", "LinkshellResultPacket"),
    ("WorldMapBackend", "0x1026", "ModifyLinkshellPacket"),
    ("WorldMapBackend", "0x1027", "DeleteLinkshellPacket"),
    ("WorldMapBackend", "0x1028", "LinkshellChangePacket"),
    ("WorldMapBackend", "0x1029", "LinkshellInvitePacket"),
    ("WorldMapBackend", "0x1030", "LinkshellInviteCancelPacket"),
    ("WorldMapBackend", "0x1031", "LinkshellLeavePacket"),
    ("WorldMapBackend", "0x1032", "LinkshellRankChangePacket"),
]

REVERIFY_OVERRIDES = [
    ("WorldMapBackend", "0x1010", "_0x1010"),
    ("WorldMapBackend", "0x1011", "_0x1011"),
    ("WorldMapBackend", "0x1fff", "_0x1FFF"),
]


# Name overrides require the prior name and accept the corrected name for idempotent reruns.
NAME_OVERRIDES = [
    (
        "MapClientbound",
        "0x0193",
        "_0x0193",
        "_0x0193",
        None,
    ),
    (
        "MapClientbound",
        "0x018f",
        "_0x018F",
        "_0x018F",
        None,
    ),
    (
        "MapClientbound",
        "0x0191",
        "_0x0191",
        "_0x0191",
        None,
    ),
    (
        "MapClientbound",
        "0x0190",
        "_0x0190",
        "_0x0190",
        None,
    ),
    (
        "MapClientbound",
        "0x018b",
        "_0x018B",
        "SetGroupLayoutIDPacket",
        None,
    ),
    (
        "MapClientbound",
        "0x0187",
        "_0x0187",
        "SetOccupancyGroupPacket",
        None,
    ),
    (
        "MapClientbound",
        "0x018d",
        "_0x018D",
        "PartyMapMarkerUpdatePacket",
        None,
    ),
    (
        "MapClientbound",
        "0x013b",
        "BattleActionX18Packet",
        "CommandResultX18Packet",
        "MapServerOpcode::CommandResultX18",
    ),
    (
        "MapServerbound",
        "0x012f",
        "ActorWorkUpdatePacket",
        "WorkStateUpdatePacket",
        None,
    ),
    (
        "MapServerbound",
        "0x0133",
        "GroupCreatedPacket",
        "GroupWorkUpdatePacket",
        "MapClientOpcode::GroupWorkUpdate",
    ),
    (
        "WorldServerbound",
        "0x0133",
        "GroupCreatedPacket",
        "GroupWorkUpdatePacket",
        "MapClientOpcode::GroupWorkUpdate",
    ),
    (
        "MapServerbound",
        "0x0135",
        "BindingSubscribeRequestPacket",
        "AchievementRateRequestPacket",
        None,
    ),
]

# Accept managed aliases while preserving the pristine-input guard carried by
# NAME_OVERRIDES.
NAME_OVERRIDE_PRIOR_ALIASES = {
    ("MapClientbound", "0x018b", "SetGroupLayoutIDPacket"): (
        "SetGroupLayoutIdPacket",
    ),
    ("MapServerbound", "0x012f", "WorkStateUpdatePacket"): (
        "ParameterDataRequestPacket",
    ),
    ("MapServerbound", "0x0135", "AchievementRateRequestPacket"): (
        "AchievementProgressRequestPacket",
    ),
}


# Pcap joins use (direction, opcode) only; PCAP_AMBIGUOUS marks shared services and
# PCAP_LOBBY_PURGE removes lobby rows that inherited in-world captures.
PCAP_AMBIGUOUS_SERVICES = "world,map"
PCAP_AMBIGUOUS = [
    ("WorldClientbound", "0x017a", "SynchGroupWorkValuesPacket"),
    ("MapClientbound", "0x017a", "SynchGroupWorkValuesPacket"),
    ("WorldClientbound", "0x017c", "GroupHeaderPacket"),
    ("MapClientbound", "0x017c", "GroupHeaderPacket"),
    ("WorldClientbound", "0x017d", "GroupMembersBeginPacket"),
    ("MapClientbound", "0x017d", "GroupMembersBeginPacket"),
    ("WorldClientbound", "0x017e", "GroupMembersEndPacket"),
    ("MapClientbound", "0x017e", "GroupMembersEndPacket"),
    ("WorldClientbound", "0x017f", "GroupMembersX08Packet"),
    ("MapClientbound", "0x017f", "GroupMembersX08Packet"),
    ("WorldServerbound", "0x0133", "GroupWorkUpdatePacket"),
    ("MapServerbound", "0x0133", "GroupWorkUpdatePacket"),
]

LANE_MOVES = {
    "0x0007": ("DeleteAllActorsPacket", 12),
    "0x0008": ("_0x0008", 19),
    "0x0143": ("DeleteGroupPacket", 12),
}
LANE_UNRESOLVED = {"0x0002", "0x0003", "0x0188", "0x0189", "0x018a"}
PCAP_LOBBY_PURGE = [
    ("LobbyServerbound", "0x0003", "_0x0003Handler"),
    ("LobbyClientbound", "0x000c", "AccountListPacket"),
    ("LobbyClientbound", "0x000d", "CharacterListPacket"),
    ("LobbyClientbound", "0x000f", "SelectCharacterConfirmPacket"),
]


CLIENT_SEMANTICS_SPECIAL_NOTES = {
    "s2c-0193": (
        "retail_client_analysis=FUN_00578C90 switches the first application u32; "
        "application_payload=8 bytes; subop_routes=<0x10 to FUN_0075F3E0 indexed "
        "write, 0x10/0x11/0x12/0x16 direct state writes, 0x13 string/config path, "
        "0x14 one-time init gate, 0x15 unresolved FUN_00576020; observed=9 retained "
        "40-byte subpackets across 8 captures; retained_subops=0x14 x8, 0x12 x1; "
        "corpus_aggregate=9 events; unresolved=low-range,0x13 string/config,0x15 helper "
        "semantics; semantic_status=decomp_routed; naming=placeholder retained because "
        "retail does not establish a stable packet noun; candidate_label=SetControlStatePacket "
        "is an imported source-manifest term, not retail-proven; client_only=multiplexed "
        "state/config route does not establish server behavior; "
        "prior_label=MapServerOpcode::SetControlState; "
        "conflict=implementation anchor and packet noun lack a source-owned declaration; "
        "client_evidence=BCS-Y-0584,BCS-Y-0990"
    ),
    "s2c-018f": (
        "retail_client_analysis=FUN_00576C60 forwards opcode 0x018f into "
        "FUN_0076BE30; direct_payload_reads=none in wrapper and worker; "
        "application_payload=8 bytes, zero in all retained samples but semantically "
        "unknown; shared_helper_boundary=FUN_0076B950,FUN_0075F720; "
        "FUN_00759220 only writes a local byte 0xff; observed=15 retained 40-byte "
        "subpackets across 8 captures; corpus_aggregate=28 events; "
        "semantic_status=decomp_routed; naming=placeholder retained because retail "
        "does not establish a stable packet noun; candidate_label=MassSetItemModifierBeginPacket "
        "is an imported source-manifest term, not retail-proven; client_only=route and "
        "payload non-use do not establish server behavior; "
        "prior_label=MapServerOpcode::MassSetItemModifierBegin; "
        "conflict=implementation anchor and packet noun lack a source-owned declaration; "
        "client_evidence=BCS-Y-0581,BCS-Y-0722,BCS-Y-0954"
    ),
    "s2c-0191": (
        "retail_client_analysis=FUN_00576D40 forwards opcode 0x0191 into "
        "FUN_0076BF10; direct_payload_reads=none in wrapper and worker; "
        "application_payload=8 bytes, zero in all retained samples but semantically "
        "unknown; shared_helper_boundary=FUN_0076B950,FUN_0075F910,FUN_0075F7C0,"
        "FUN_0076BA10,FUN_00768B10,FUN_007840D0; observed=15 retained 40-byte "
        "subpackets across 8 captures; corpus_aggregate=28 events; "
        "semantic_status=decomp_routed; naming=placeholder retained because retail "
        "does not establish a stable packet noun; candidate_label=MassSetItemModifierEndPacket "
        "is an imported source-manifest term, not retail-proven; client_only=route and "
        "payload non-use do not establish server behavior; "
        "prior_label=MapServerOpcode::MassSetItemModifierEnd; "
        "conflict=implementation anchor and packet noun lack a source-owned declaration; "
        "client_evidence=BCS-Y-0583,BCS-Y-0723,BCS-Y-0955"
    ),
    "s2c-0190": (
        "retail_client_analysis=FUN_00576CD0 forwards opcode 0x0190 through "
        "FUN_0076BE60 and FUN_00768C40 into the client manager update path; "
        "application_payload=0x68 bytes with neutral header dwords at +0/+4, "
        "words[16] at +0x08..+0x47, and an unread 32-byte tail at "
        "+0x48..+0x67; observed=32 retained 136-byte subpackets across 8 captures; "
        "corpus_aggregate=5569 events; field_semantics=unresolved; "
        "semantic_status=decomp_routed; naming=placeholder retained because retail "
        "does not establish a stable packet noun; candidate_label=MassSetItemModifierPacket "
        "is an imported source-manifest term, not retail-proven; client_only=route and "
        "shape do not establish server behavior; prior_label=MapServerOpcode::MassSetItemModifier; "
        "conflict=implementation anchor and packet noun lack a source-owned declaration; "
        "client_evidence=BCS-Y-0582,BCS-Y-0721,BCS-Y-0951,BCS-Y-0952,BCS-Y-0953"
    ),
    "s2c-018b": (
        "retail_client_analysis=FUN_005763A0 forwards opcode 0x018b through "
        "FUN_006C5DF0 and FUN_006C5240 into the client Group/SharedWork layout "
        "path; application_payload=0x38 bytes with an opaque 8-byte group header, "
        "group-handle u32 at +0x08, localized-name u32 at +0x0c, signed layout-id "
        "dword at +0x10, unresolved layout-kind byte at +0x14, unresolved reserved "
        "byte at +0x15, and layout name char[34] at +0x16; observed=31 retained "
        "88-byte subpackets across 13 captures; semantic_status=decomp_routed; "
        "naming=client-derived from the Group/SharedWork layout path; "
        "client_only=route and shape do not establish server behavior; "
        "alternate_spelling=SetGroupLayoutIdPacket; "
        "prior_label=MapServerOpcode::SetGroupLayoutId; "
        "conflict=implementation anchor lacks a source-owned declaration; "
        "client_evidence=BCS-Y-0579 dispatcher and BCS-Y-0889 GroupSharedWork layout path"
    ),
    "s2c-0187": (
        "retail_client_analysis=FUN_00576390 forwards opcode 0x0187 through "
        "FUN_006C8340 and FUN_006C6B20 into the client Group/SharedWork "
        "property-update path; application_payload=0x40 bytes with an opaque "
        "16-byte group header, occupancy-work u32[2] at +0x10, localized-name "
        "u32 at +0x18, and occupancy name char[36] at +0x1c; observed=33 "
        "retained 96-byte subpackets across 13 captures; "
        "semantic_status=decomp_routed; naming=client-derived from the occupancy "
        "Group/SharedWork path; client_only=route and layout do not establish "
        "server behavior; prior_label=MapServerOpcode::SetOccupancyGroup; "
        "conflict=implementation anchor lacks a source-owned declaration; "
        "client_evidence=BCS-Y-0575 dispatcher and BCS-Y-0885 GroupSharedWork_SetOccupancy"
    ),
    "s2c-018d": (
        "retail_client_analysis=FUN_00575550 gates the central opcode 0x018d route "
        "and FUN_0055CF70 copies three header dwords, reads the u8 count at "
        "application offset 0x290, and transposes count 0x28-byte source rows into "
        "0x78-byte client rows; wire_capacity=16 reserved source rows with no static "
        "compare or clamp; observed=60 696-byte subpackets; observed max=2; "
        "semantic_status=decomp_routed; naming=client-derived from the party map-marker "
        "apply path; client_only=route and layout do not establish server behavior; "
        "prior_label=MapServerOpcode::PartyMapMarkerUpdate; "
        "conflict=implementation anchor lacks a source-owned declaration"
    ),
    "c2s-012f": (
        "retail_client_analysis=FUN_0075E770 writes opcode 0x012f and record size 0x38, "
        "then sends a leading caller dword, a 32-byte zero-initialized staging area "
        "populated by a runtime-length generic range copy, and an unwritten four-byte "
        "stack tail through FUN_004D6D30; client_route=CharaBase and DirectorBase "
        "_updateWork via FUN_00767FC0 and FUN_00767C00; observed=44 72-byte "
        "subpackets; tail_distribution=8 distinct values including zero; "
        "tail=record+0x3c is unwritten by the builder and nonconstant on wire; "
        "semantic_status=decomp_routed; naming=tentative, derived from the client "
        "_updateWork operation; prior_label=ActorWorkUpdatePacket; "
        "conflict=ActorWorkUpdatePacket implementation noun unsupported by retail; "
        "prior_label=ParameterDataRequestPacket; "
        "conflict=ParameterDataRequestPacket server noun unsupported by retail"
    ),
    "c2s-0135": (
        "no_pcap_evidence; semantic_status=decomp_routed; "
        "naming=tentative, derived from the registered client Lua N-API operation; "
        "retail_client_analysis=FUN_00705EB0 is MyPlayer vtable slot 112 and "
        "the _getAchievementRate implementation; FUN_005819A0 returns the "
        "first runtime argument-vector entry +0x8 value on the valid path; "
        "FUN_0075ECD0 emits that achievement-id lookup key as the sole u32 "
        "payload in opcode 0x0135 with packet length 0x18; exact server packet "
        "class and request noun remain unproven; "
        "prior_label=BindingSubscribeRequestPacket; "
        "conflict=prior implementation label unsupported by retail"
    ),
}


def scrub_emulator_notes(notes: str) -> tuple[str, int]:
    """Remove unsupported server-source notes while preserving local evidence tails."""
    cleaned = []
    removed = 0
    for part in (part.strip() for part in notes.split(";") if part.strip()):
        if part.startswith(UNSUPPORTED_NOTE_PREFIXES):
            removed += 1
            _, separator, local_tail = part.partition(" | ")
            if separator and local_tail:
                cleaned.append(local_tail.strip())
            continue
        if part.startswith("reference_doc="):
            removed += 1
            _, separator, local_tail = part.partition(" | ")
            if separator and local_tail:
                cleaned.append(local_tail.strip())
            continue
        cleaned.append(part)
    return "; ".join(cleaned), removed


def localize_decomp_anchor_evidence(entry: dict) -> tuple[bool, bool]:
    """Localize supported anchor citations and remove unsupported external ones."""
    evidence = LOCAL_DECOMP_ANCHOR_EVIDENCE.get(entry.get("decompAnchor"))
    if evidence is None:
        parts = [
            part.strip()
            for part in entry.get("notes", "").split(";")
            if part.strip()
        ]
        retained = [
            part
            for part in parts
            if not (
                part.startswith("decomp_anchor_evidence=")
                and not part.partition("=")[2].startswith("data/")
            )
        ]
        if retained != parts:
            entry["notes"] = "; ".join(retained)
            return False, True
        return False, False

    token = f"decomp_anchor_evidence={evidence}"
    parts = [part.strip() for part in entry.get("notes", "").split(";") if part.strip()]
    replaced = False
    localized = []
    for part in parts:
        if part.startswith("decomp_anchor_evidence="):
            if part != token:
                replaced = True
            if token not in localized:
                localized.append(token)
        else:
            localized.append(part)
    if not any(part.startswith("decomp_anchor_evidence=") for part in parts):
        localized.append(token)
        replaced = True
    if replaced:
        entry["notes"] = "; ".join(localized)
    return replaced, False


def swap_managed_prefix(current: str, expected_old: str, new_notes: str):
    """Replace an owned prefix idempotently while preserving an appended tail."""
    # new_notes may start with expected_old, so test the applied form first.
    if current.startswith(new_notes):
        return current, "skipped"
    if current.startswith(expected_old):
        return new_notes + current[len(expected_old):], "applied"
    return current, "mismatch"


def apply_client_semantics(top: dict) -> tuple[int, int]:
    """Attach the independently reviewed client-body evidence to catalog rows."""
    evidence = json.loads(CLIENT_SEMANTICS_PATH.read_text(encoding="utf-8"))
    applied = 0
    errors = 0

    for row in evidence["rows"]:
        matches = [
            entry
            for entries in top["lists"].values()
            for entry in entries
            if entry["opcodeHex"] == row["opcodeHex"]
            and entry["direction"] == row["direction"]
            and entry.get("decompAnchor") == row["function"]
        ]
        if len(matches) != 1:
            print(
                f"  WARN: client semantics {row['id']} matched {len(matches)} catalog rows"
            )
            errors += 1
            continue

        entry = matches[0]
        if row["id"] in CLIENT_SEMANTICS_SPECIAL_NOTES:
            entry["notes"] = CLIENT_SEMANTICS_SPECIAL_NOTES[row["id"]]

        parts = [part.strip() for part in entry.get("notes", "").split(";") if part.strip()]
        parts = [
            part
            for part in parts
            if not part.startswith("client_semantics_evidence=")
            and not part.startswith("dependency_status=")
        ]
        if row["status"] == "closed":
            parts = [
                part
                for part in parts
                if not part.startswith("decomp_anchor_evidence=")
                and not part.startswith("decomp_anchor_locator=")
            ]
        elif not any(
            part.startswith("decomp_anchor_evidence=") for part in parts
        ):
            local_evidence = LOCAL_DECOMP_ANCHOR_EVIDENCE.get(row["function"])
            if local_evidence is None:
                print(f"  WARN: no local anchor evidence for open row {row['id']}")
                errors += 1
                continue
            parts.extend(
                [
                    f"decomp_anchor_evidence={local_evidence}",
                    f"decomp_anchor_locator={row['function']}",
                ]
            )
        parts.extend(
            [
                f"client_semantics_evidence=data/client_opcode_semantics.json#{row['id']}",
                f"dependency_status={row['status']}",
            ]
        )
        entry["notes"] = "; ".join(parts)
        if row["id"] in {"s2c-0187", "s2c-018b", "s2c-018d", "s2c-018f", "s2c-0190", "s2c-0191", "s2c-0193"}:
            entry["confidence"] = "decomp_routed"
        elif row["id"] == "c2s-012f":
            entry["confidence"] = "decomp_routed"
        elif row["id"] == "c2s-0135":
            entry["confidence"] = "decomp_routed"
        applied += 1

    return applied, errors


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    catalog = json.loads(OPCODES_PATH.read_text(encoding="utf-8"))
    top = catalog[0]

    scrubbed = 0
    localized = 0
    removed_external = 0
    for entries in top["lists"].values():
        for entry in entries:
            notes, removed = scrub_emulator_notes(entry.get("notes", ""))
            if removed:
                entry["notes"] = notes
                scrubbed += removed
            did_localize, did_remove = localize_decomp_anchor_evidence(entry)
            localized += did_localize
            removed_external += did_remove
    print(f"Removed {scrubbed} unsupported emulator note fragments")
    print(f"Localized {localized} decomp-anchor citations")
    print(f"Removed {removed_external} unsupported external decomp-anchor citations")

    warned = 0
    if top["description"] == EXPECTED_TOP_DESC:
        print("Top-level description matches the expected baseline")
    else:
        print("WARN: top-level description drifted from the expected baseline")
        warned += 1

    applied = 0
    skipped = 0
    for bucket, opcode_hex, name, expected_old, new_notes in OVERRIDES:
        found = False
        accepted_names = (name,) + OVERRIDE_NAME_ALIASES.get(
            (bucket, opcode_hex, name), ()
        )
        for e in top["lists"][bucket]:
            if e["opcodeHex"] == opcode_hex and e["name"] in accepted_names:
                found = True
                current = e.get("notes", "")
                e["notes"], status = swap_managed_prefix(current, expected_old, new_notes)
                if status == "applied":
                    applied += 1
                elif status == "skipped":
                    skipped += 1
                else:
                    print(f"  WARN: {bucket} {opcode_hex} {name} notes don't match expected baseline")
                    print(f"    expected: {expected_old[:120]}")
                    print(f"    current:  {current[:120]}")
                    warned += 1
                break
        if not found:
            print(f"  WARN: no entry found for {bucket} {opcode_hex} {name}")
            warned += 1

    print(f"\nApplied {applied} note overrides ({skipped} skipped, {warned} warnings)")

    retired_applied = 0
    retired_skipped = 0
    for bucket, opcode_hex, name in UNSUPPORTED_IMPLEMENTATION_OVERRIDES:
        for e in top["lists"].get(bucket, []):
            if e["opcodeHex"] == opcode_hex and e["name"] == name:
                if (
                    e.get("implementationAnchor") is None
                    and e.get("confidence") == "blocked"
                    and "needsReverify" not in e
                    and "reverifyMethod" not in e
                ):
                    retired_skipped += 1
                else:
                    e["implementationAnchor"] = None
                    e["confidence"] = "blocked"
                    e.pop("needsReverify", None)
                    e.pop("reverifyMethod", None)
                    retired_applied += 1
                break
        else:
            print(f"  WARN: no entry for retired anchor {bucket} {opcode_hex} {name}")
            warned += 1
    print(
        f"Applied {retired_applied} retired implementation overrides "
        f"({retired_skipped} skipped)"
    )

    reverify_applied = 0
    reverify_skipped = 0
    for bucket, opcode_hex, name in REVERIFY_OVERRIDES:
        for e in top["lists"].get(bucket, []):
            if e["opcodeHex"] == opcode_hex and e["name"] == name:
                if e.get("needsReverify") is True and e.get("reverifyMethod") == REVERIFY_METHOD:
                    reverify_skipped += 1
                else:
                    e["needsReverify"] = True
                    e["reverifyMethod"] = REVERIFY_METHOD
                    reverify_applied += 1
                break
        else:
            print(f"  WARN: no entry for reverify mark {bucket} {opcode_hex} {name}")
            warned += 1
    print(f"Applied {reverify_applied} reverify marks ({reverify_skipped} skipped)")

    name_applied = 0
    name_skipped = 0
    for bucket, opcode_hex, prior_name, new_name, new_anchor in NAME_OVERRIDES:
        found = False
        accepted_prior_names = (prior_name,) + NAME_OVERRIDE_PRIOR_ALIASES.get(
            (bucket, opcode_hex, new_name), ()
        )
        for e in top["lists"].get(bucket, []):
            if e["opcodeHex"] == opcode_hex and e.get("name") in (
                *accepted_prior_names,
                new_name,
            ):
                found = True
                if e.get("name") == new_name and e.get("implementationAnchor") == new_anchor:
                    name_skipped += 1
                else:
                    e["name"] = new_name
                    e["implementationAnchor"] = new_anchor
                    name_applied += 1
                break
        if not found:
            print(
                f"  WARN: no entry found for name override {bucket} {opcode_hex} "
                f"prior_name={prior_name}"
            )
            warned += 1
    print(f"Applied {name_applied} name overrides ({name_skipped} skipped)")

    amb_token = f"pcap_service_ambiguous={PCAP_AMBIGUOUS_SERVICES}"
    amb_applied = 0
    amb_skipped = 0
    for bucket, opcode_hex, name in PCAP_AMBIGUOUS:
        for e in top["lists"].get(bucket, []):
            if e["opcodeHex"] == opcode_hex and e["name"] == name:
                notes = e.get("notes", "")
                if amb_token in notes:
                    amb_skipped += 1
                else:
                    e["notes"] = f"{notes}; {amb_token}" if notes else amb_token
                    amb_applied += 1
                break
        else:
            print(f"  WARN: no entry for ambiguity mark {bucket} {opcode_hex} {name}")
            warned += 1
    print(f"Applied {amb_applied} pcap-ambiguity marks ({amb_skipped} skipped)")

    purge_token = "pcap_evidence_dropped=lobby_not_in_capture_corpus"
    purge_applied = 0
    purge_skipped = 0
    for bucket, opcode_hex, name in PCAP_LOBBY_PURGE:
        for e in top["lists"].get(bucket, []):
            if e["opcodeHex"] == opcode_hex and e["name"] == name:
                notes = e.get("notes", "")
                if not e.get("observedIn") and purge_token in notes:
                    purge_skipped += 1
                else:
                    e["observedIn"] = []
                    e["payloadLengths"] = []
                    if purge_token not in notes:
                        e["notes"] = f"{notes}; {purge_token}" if notes else purge_token
                    purge_applied += 1
                break
        else:
            print(f"  WARN: no entry for lobby purge {bucket} {opcode_hex} {name}")
            warned += 1
    print(f"Applied {purge_applied} lobby pcap purges ({purge_skipped} skipped)")

    world = top["lists"]["WorldClientbound"]
    before = len(world)
    top["lists"]["WorldClientbound"] = [
        e for e in world if e["opcodeHex"] not in LANE_MOVES
    ]
    print(f"Removed {before - len(top['lists']['WorldClientbound'])} main-lane world duplicates")

    # These counts are curated input facts, not values derived from git history.
    for bucket_name, entries in top["lists"].items():
        for e in entries:
            opcode_hex = e["opcodeHex"]
            if bucket_name == "MapClientbound" and opcode_hex in LANE_MOVES:
                expected_name, count = LANE_MOVES[opcode_hex]
                if e["name"] != expected_name:
                    continue
                ruling = (f"lane_ruling=moved_from_WorldClientbound; "
                          f"main_lane_count={count}; chat_lane_count=0")
            elif bucket_name == "WorldClientbound" and opcode_hex in LANE_UNRESOLVED:
                ruling = ("lane_ruling=unresolved_no_s2c_observation; "
                          "main_lane_count=0; chat_lane_count=0")
            else:
                continue
            notes = e.get("notes", "")
            if "lane_ruling=" not in notes:
                e["notes"] = f"{notes}; {ruling}" if notes else ruling

    semantics_applied, semantics_errors = apply_client_semantics(top)
    warned += semantics_errors
    print(f"Applied {semantics_applied} client-semantics evidence links")

    if warned:
        print(f"Refusing to write opcodes.json after {warned} warning(s)", file=sys.stderr)
        return 1

    write_json(OPCODES_PATH, catalog)
    print("Canonicalized opcodes.json")

    if not CONSTANTS_PATH.is_file():
        print(f"{CONSTANTS_PATH.name}: file missing", file=sys.stderr)
        return 1
    write_json(
        CONSTANTS_PATH,
        json.loads(CONSTANTS_PATH.read_text(encoding="utf-8")),
    )
    print("Canonicalized constants.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
