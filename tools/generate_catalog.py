"""Apply curated overrides and canonicalize both root catalogs."""

import json
import sys
from pathlib import Path

from _json_io import CONSTANTS_PATH, OPCODES_PATH, write_json

EXPECTED_TOP_DESC = "FFXIV 1.23b opcode catalog joined with pcap observations and retail-client analysis. WorldMapBackend holds world<->map backbone packets; both backend directions share opcode integers. WorldMapBackend entries are server-to-server and never cross the client TCP socket, so client-capture pcap evidence is structurally impossible for those wire values. A catalog extension added 4 client-side receiver opcodes (0x018E SetRetainerStar, 0x01A2 JobQuestCompleteTriple, 0x01A6 HamletSupplyRanking, 0x01A8 HamletDefenseScore); evidence is xivl-client-structs client receiver decomp."
REVERIFY_METHOD = "live-validation: verify that the retail 1.23b client accepts the behavior in a live session"
CLIENT_SEMANTICS_PATH = Path(__file__).resolve().parent.parent / "data" / "client_opcode_semantics.json"
BATTLE_RESULT_SEMANTICS_PATH = Path(__file__).resolve().parent.parent / "data" / "battle_result_semantics.json"
ZONE_DUMMY_CLUSTER_EVIDENCE = "xivl-client-structs:manifests/zone_dummy_callback_cluster.json"
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
        "0x0196",
        "SetSpecialEventWorkPacket",
        "SetSpecialEventWorkPacket",
        None,
    ),
    (
        "MapClientbound",
        "0x018a",
        "_0x018A",
        "_0x018A",
        None,
    ),
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
        "0x01cb",
        "SendBlacklistPacket",
        "_0x01CB",
        None,
    ),
    (
        "MapServerbound",
        "0x00ce",
        "_0x00CEHandler",
        "_0x00CEHandler",
        None,
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

DECOMP_ANCHOR_OVERRIDES = [
    ("MapServerbound", "0x00ce", "_0x00CEHandler", "FUN_00763DC0"),
    ("MapClientbound", "0x01cb", "_0x01CB", "FUN_00DB8FA0"),
]


ZONE_DUMMY_CLUSTER_PRIOR = {
    "0x01c3": ("StartRecruitingResponse", "MapServerOpcode::StartRecruitingResponse"),
    "0x01c4": ("EndRecruitmentPacket", "MapServerOpcode::EndRecruitment"),
    "0x01c5": ("RecruiterStatePacket", "MapServerOpcode::RecruiterState"),
    "0x01c6": (None, None),
    "0x01c7": (None, None),
    "0x01c8": ("CurrentRecruitmentDetailsPacket", "MapServerOpcode::CurrentRecruitmentDetails"),
    "0x01c9": ("BlacklistAddedPacket", "MapServerOpcode::BlacklistAdded"),
    "0x01ca": ("BlacklistRemovedPacket", "MapServerOpcode::BlacklistRemoved"),
    "0x01cb": ("SendBlacklistPacket", "MapServerOpcode::SendBlacklist"),
    "0x01cc": ("FriendlistAddedPacket", "MapServerOpcode::FriendlistAdded"),
    "0x01cd": ("FriendlistRemovedPacket", "MapServerOpcode::FriendlistRemoved"),
    "0x01ce": ("SendFriendlistPacket", "MapServerOpcode::SendFriendlist"),
    "0x01cf": ("FriendStatusPacket", "MapServerOpcode::FriendStatus"),
    "0x01d0": ("FaqListResponsePacket", "MapServerOpcode::FaqListResponse"),
    "0x01d1": ("FaqBodyResponsePacket", "MapServerOpcode::FaqBodyResponse"),
    "0x01d2": ("IssueListResponsePacket", "MapServerOpcode::IssueListResponse"),
    "0x01d3": ("StartGMTicketPacket", "MapServerOpcode::StartGMTicket"),
    "0x01d4": ("GMTicketPacket", "MapServerOpcode::GMTicket"),
    "0x01d5": ("GMTicketSentResponsePacket", "MapServerOpcode::GMTicketSentResponse"),
    "0x01d6": ("EndGMTicketPacket", "MapServerOpcode::EndGMTicket"),
    "0x01d7": ("ItemSearchResultsBeginPacket", "MapServerOpcode::ItemSearchResultsBegin"),
    "0x01d8": ("ItemSearchResultsBodyPacket", "MapServerOpcode::ItemSearchResultsBody"),
    "0x01d9": ("ItemSearchResultsEndPacket", "MapServerOpcode::ItemSearchResultsEnd"),
    "0x01da": ("RetainerResultEndPacket", "MapServerOpcode::RetainerResultEnd"),
    "0x01db": ("RetainerResultBodyPacket", "MapServerOpcode::RetainerResultBody"),
    "0x01dc": ("RetainerResultUpdatePacket", "MapServerOpcode::RetainerResultUpdate"),
    "0x01dd": ("RetainerSearchHistoryPacket", "MapServerOpcode::RetainerSearchHistory"),
    "0x01de": (None, None),
    "0x01df": ("PlayerSearchInfoResultPacket", "MapServerOpcode::PlayerSearchInfoResult"),
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
LOGIN_CAPTURE = "login.pcapng"
LOGIN_CAPTURE_SHA256 = "28e06b54fe559870031f077f8549b9244caafa7e5177dbca08a7feae6c2b1b62"
LOGIN_LANE_EVIDENCE = "xivl-captures:derived/lane_observations.json"
LOGIN_PREZONE_ATTRIBUTIONS = [
    ("MapServerbound", "0x0133", "GroupWorkUpdatePacket", "c2s", 72),
    ("MapServerbound", "0x0006", "LangaugeCodePacket", "c2s", 40),
    ("MapClientbound", "0x0001", "PongPacket", "s2c", 64),
    ("MapClientbound", "0x017a", "SynchGroupWorkValuesPacket", "s2c", 176),
    ("MapClientbound", "0x000c", "SetMusicPacket", "s2c", 40),
    ("MapClientbound", "0x017c", "GroupHeaderPacket", "s2c", 152),
    ("MapClientbound", "0x017d", "GroupMembersBeginPacket", "s2c", 64),
    ("MapClientbound", "0x017e", "GroupMembersEndPacket", "s2c", 56),
    ("MapClientbound", "0x0010", "SetDalamudPacket", "s2c", 40),
    ("MapClientbound", "0x000f", "_0xFPacket", "s2c", 56),
    ("MapClientbound", "0x017f", "GroupMembersX08Packet", "s2c", 440),
    ("MapClientbound", "0x0002", "_0x02Packet", "s2c", 48),
    ("MapClientbound", "0x0003", "SendMessagePacket", "s2c", 584),
    ("MapClientbound", "0x018a", "_0x018A", "s2c", 136),
    ("MapClientbound", "0x0189", "CreateNamedGroupMultiple", "s2c", 552),
]

LANE_MOVES = {
    "0x0007": ("DeleteAllActorsPacket", 12),
    "0x0008": ("_0x0008", 19),
    "0x0143": ("DeleteGroupPacket", 12),
    "0x018a": ("_0x018A", 1),
}
LANE_UNRESOLVED = {"0x0188"}
PCAP_LOBBY_PURGE = [
    ("LobbyServerbound", "0x0003", "_0x0003Handler"),
    ("LobbyClientbound", "0x000c", "AccountListPacket"),
    ("LobbyClientbound", "0x000d", "CharacterListPacket"),
    ("LobbyClientbound", "0x000f", "SelectCharacterConfirmPacket"),
]


CLIENT_SEMANTICS_SPECIAL_NOTES = {
    "s2c-017c": (
        "retail_client_analysis=FUN_00576250 routes the Group header and the client "
        "layout reads positional u32 groupTypeId at application offset 0x30; "
        "application_payload=0x78 bytes; observed_subpacket=0x98 bytes; "
        "observed_groupTypeId=10001 x14,10002 x265,30001 x65,30006 x4,50001 x2,80001 x11 "
        "across 361 headers; 30001_scope=65/65 party_battle_leve.pcapng; "
        "field_semantics=positional observation only, no group-kind mapping; "
        "client_evidence=BCS-Y-0564,xivl-client-structs:manifests/director_group_wire_identity.json#layouts.0x017C; "
        "capture_evidence=xivl-captures:studies/director-wire-identity/derived/accounting.json#group_type_candidate_distribution; "
        "client_only=layout and observed values do not establish server behavior; "
        "pcap_service_ambiguous=world,map"
    ),
    "s2c-017f": (
        "retail_client_analysis=FUN_005762E0 routes the eight-entry Group member update; "
        "application_payload=0x198 bytes; observed_subpacket=0x1b8 bytes; "
        "member_layout=eight 0x30-byte records at application offset 0x10; "
        "memberCount=u32 at application offset 0x190 with observed values 1 x12 and 2 x15; "
        "client_evidence=xivl-client-structs:manifests/director_group_wire_identity.json#layouts.0x017F; "
        "capture_evidence=xivl-captures:studies/director-wire-identity/derived/group-members.csv#opcode=0x017F; "
        "client_only=layout and observed values do not establish server behavior; "
        "pcap_service_ambiguous=world,map"
    ),
    "s2c-0183": (
        "retail_client_analysis=FUN_00576320 routes the compact content-member update; "
        "application_payload=0x78 bytes; observed_subpacket=0x98 bytes; "
        "member_layout=eight 0x0c-byte records at application offset 0x10; "
        "memberCount=low byte at application offset 0x70; "
        "client_evidence=xivl-client-structs:manifests/director_group_wire_identity.json#layouts.0x0183; "
        "capture_evidence=xivl-captures:studies/director-wire-identity/derived/group-members.csv#opcode=0x0183; "
        "client_only=layout and observed values do not establish server behavior"
    ),
    "c2s-012d": (
        "retail_client_analysis=FUN_00776760 writes opcode 0x012d and record size "
        "0xc8 after FUN_006EE680 and FUN_0075E3A0 stage a generic event command; "
        "wire_send_path=FUN_004D6D30->FUN_004E0240->FUN_00DAE010; observed=126 "
        "total 216-byte subpackets across combat and noncombat scenarios; "
        "client_prechecks=50-byte combined script-string limit, command burst "
        "blocker, _canExecuteCommand, and dynamic command.canFire; "
        "command_id_mapping=resolved for owner ids in the 0xa0f00000 static-actor "
        "block: application offset 0x04 low16 joins 100/100 /Command staticactor "
        "rows and 88/100 gameCommand rows; non_gameCommand_command_actors=12; "
        "event_owner_scope=26/126 owners are outside the static block and are not "
        "masked; pattern_scope=general EventStart envelope, with static owners in "
        "61/64 combat-example and 39/62 other occurrences; retained_sample_cap="
        "41/60 staticactor and 29/60 gameCommand joins; direct_gameCommand_scalar="
        "unproven; "
        "semantic_status=decomp_routed; "
        "prior_label=MapClientOpcode::EventStart; conflict=implementation anchor "
        "lacks a source-owned declaration; client_only=route, pre-checks, and "
        "payload shape do not establish server behavior; separate_family="
        "0x01c3..0x01df social/mail/search emitters excluded"
    ),
    "c2s-00ce": (
        "retail_client_analysis=FUN_00763DC0 and FUN_0076D610 each build opcode "
        "0x00ce with record size 0x38 and call FUN_004D6D10; wire_send_path="
        "FUN_004D6D10->FUN_004E0240->FUN_00DAE010; observed=2 retained "
        "72-byte subpackets in cutscene_book.pcapng; application_payload=40 bytes; "
        "semantic_status=decomp_routed; naming=placeholder retained because retail "
        "does not establish a stable operation noun; prior_label="
        "MapClientOpcode::Opaque0xCE; conflict=implementation anchor lacks a "
        "source-owned declaration; client_only=builder route and shape do not "
        "establish server behavior"
    ),
    "s2c-01cb": (
        "retail_client_analysis=opcode 0x01cb routes through ZoneProtoDown callback "
        "slot 173 to FUN_00DB8FA0; callback_body=ret 0xc with no payload reads or "
        "state writes; semantic_status=decomp_routed; naming=placeholder retained "
        "because retail does not establish a clientbound packet noun; "
        "prior_label=MapServerOpcode::SendBlacklist; conflict=implementation anchor "
        "and packet noun lack a source-owned declaration; separate_direction=c2s "
        "FUN_004CA100 emits opcode 0x01cb through the zone send path, which does not "
        "supply clientbound semantics; client_only=no-op callback routing does not "
        "establish server behavior"
    ),
    "s2c-0196": (
        "retail_client_analysis=FUN_00576050 expands application byte +1 into eight "
        "flags and reads eight u16 values at +2..+0x10; state_writer=FUN_0075D2D0 "
        "writes flags at +0x84..+0x8b and u16 values at +0x8c..+0x9a; "
        "client_api=WorldMaster._getSpecialEventWork reads the same arrays through "
        "FUN_0075D390 and FUN_0075D3A0; application_payload=24 bytes with a six-byte "
        "tail; observed=11 retained 56-byte subpackets across 8 captures; "
        "retained_values=flags zero,eventWork6 one,other eventWork values zero,tail zero; "
        "corpus_aggregate=12 events; semantic_status=decomp_routed; naming=client-derived "
        "from the WorldMaster SpecialEventWork API and matching state arrays; "
        "client_only=operation and field layout do not establish server behavior; "
        "prior_label=MapServerOpcode::SetSpecialEventWork; "
        "conflict=implementation anchor lacks a source-owned declaration; "
        "client_evidence=BCS-Y-0585,BCS-Y-0226"
    ),
    "s2c-018a": (
        "retail_client_analysis=FUN_00576380 forwards application payload through "
        "FUN_006C82A0 to FUN_006C6A70; application_payload=120 bytes; "
        "map_build=u32 keys at +0x40 to u64 values at +0; loop_bound=signed low byte "
        "at +0x60; unread_tail=20 bytes at +0x64..+0x77; "
        "commit=FUN_006C58C0 reconciles the temporary ordered map into the persistent "
        "child +0x10 state by removing absent keys and inserting or replacing changed values; "
        "consumer_route=frame FUN_00578970 reaches FUN_006CDF20, which passes child +0x10 state "
        "to FUN_006C2200; change_drain=FUN_006C2200 drains the state +0x0c changed-key list and "
        "reaches non-mutating FUN_00700E70 and FUN_00700FF0 _onUpdateGroupCurrent fire sites; "
        "u32_domain=changed snapshot key marshaled by FUN_00585020 as a numeric callback argument; "
        "u64_domain=GroupBase-reference state-pair key looked up by FUN_006C1510 and FUN_006D1020 "
        "and copied with the resolved GroupBase pointer into a GroupReferenceRecord; "
        "consumer_boundary=positive callback consumer and field domains, with no Group::SharedWork "
        "virtual call in the commit body and both u64 component meanings unresolved; "
        "corpus_aggregate=1 event; retained_payload_evidence=1 136-byte subpacket with a 120-byte "
        "inner body in login.pcapng, whose 104 captured bytes after the 16-byte game-message prefix "
        "are zero, therefore count zero and an empty input snapshot; "
        "semantic_status=decomp_routed; naming=placeholder retained because callback identity "
        "does not establish a stable packet noun; candidate_label=SetActiveLinkshellPacket "
        "is an imported source-manifest term, not retail-proven; client_only=ordered-map "
        "reconciliation and Lua callback routing do not establish server behavior; "
        "prior_label=MapServerOpcode::SetActiveLinkshell; "
        "conflict=implementation anchor and packet noun lack a source-owned declaration; "
        "client_evidence=BCS-Y-0578,BCS-Y-0888,BCS-Y-1632,BCS-Y-1633,BCS-S-0244"
    ),
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
    # Pcap reconciliation removes this leading evidence token after overrides.
    if new_notes.startswith(expected_old + ";") and current.startswith(
        new_notes[len(expected_old) + 1 :].lstrip()
    ):
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
            login_parts = [
                part.strip()
                for part in entry.get("notes", "").split(";")
                if part.strip().startswith("login_")
            ]
            entry["notes"] = "; ".join(
                [CLIENT_SEMANTICS_SPECIAL_NOTES[row["id"]], *login_parts]
            )

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
        if row["id"] in {"s2c-0187", "s2c-018a", "s2c-018b", "s2c-018d", "s2c-018f", "s2c-0190", "s2c-0191", "s2c-0193", "s2c-0196", "s2c-01cb", "c2s-00ce", "c2s-012d"}:
            entry["confidence"] = "decomp_routed"
        elif row["id"] == "c2s-012f":
            entry["confidence"] = "decomp_routed"
        elif row["id"] == "c2s-0135":
            entry["confidence"] = "decomp_routed"
        if row["id"] == "c2s-012d":
            entry["implementationAnchor"] = None
        applied += 1

    return applied, errors


def apply_battle_result_semantics(top: dict) -> tuple[int, int]:
    """Apply the reviewed battle-result route and field contract."""
    evidence = json.loads(BATTLE_RESULT_SEMANTICS_PATH.read_text(encoding="utf-8"))
    applied = 0
    errors = 0

    for row in evidence["rows"]:
        matches = [
            entry
            for entry in top["lists"]["MapClientbound"]
            if entry["opcodeHex"] == row["opcodeHex"]
        ]
        if len(matches) != 1:
            print(
                f"  WARN: battle-result row {row['opcodeHex']} matched {len(matches)} catalog rows"
            )
            errors += 1
            continue

        entry = matches[0]
        entry["name"] = row["name"]
        entry["implementationAnchor"] = None
        entry["decompAnchor"] = row["function"]
        entry["confidence"] = "decomp_routed"
        aliases = ",".join(row["alternateNames"]) if row["alternateNames"] else "none"
        entry["notes"] = "; ".join(
            [
                "battle_result_semantics=data/battle_result_semantics.json",
                f"shape={row['shape']}",
                f"row_capacity={row['rowCapacity']}",
                f"status={row['status']}",
                f"observed_occurrences={row['observedOccurrences']}",
                f"capture_count={row['captureCount']}",
                f"retained_samples={row['retainedSamples']}",
                f"alternate_names={aliases}",
                "normalized_queue=0x1a0_bytes; header=0x38_bytes; rows=18x0x14",
                "prior_implementation_anchor_conflict=MapServerOpcode_label_is_not_retail_client_implementation_evidence",
                "client_data_boundary=row_identity_only_no_behavior_or_scaling_claim",
            ]
        )
        applied += 1

    return applied, errors


def apply_zone_dummy_cluster(top: dict) -> tuple[int, int]:
    """Replace imported 0x01c3..0x01df s2c nouns with retail no-op routes."""
    entries = top["lists"]["MapClientbound"]
    applied = 0
    inserted = 0
    for opcode in range(0x01C3, 0x01E0):
        opcode_hex = f"0x{opcode:04x}"
        prior_name, prior_anchor = ZONE_DUMMY_CLUSTER_PRIOR[opcode_hex]
        matches = [entry for entry in entries if entry["opcodeHex"] == opcode_hex]
        if len(matches) > 1:
            raise ValueError(f"duplicate MapClientbound row for {opcode_hex}")
        if matches:
            entry = matches[0]
        else:
            entry = {
                "name": f"_0x{opcode:04X}",
                "opcode": opcode,
                "opcodeHex": opcode_hex,
                "service": "map",
                "direction": "clientbound",
                "implementationAnchor": None,
                "decompAnchor": None,
                "observedIn": [],
                "payloadLengths": [],
                "confidence": "decomp_routed",
                "notes": "",
            }
            entries.append(entry)
            inserted += 1

        slot = opcode - 0x011E
        callback_va = 0x00DB8F20 + (opcode - 0x01C3) * 0x10
        function = f"FUN_{callback_va:08X}"
        parts = [
            f"retail_client_analysis=ZoneProtoDown opcode {opcode_hex} case {slot - 2} routes callback slot {slot} to {function}",
            "callback_body=ret 0xc with no payload reads or state writes",
            "semantic_status=decomp_routed",
            "naming=placeholder retained because retail establishes no clientbound packet noun",
        ]
        if prior_name:
            parts.append(f"prior_packet_label={prior_name}")
        if prior_anchor:
            parts.append(f"prior_label={prior_anchor}")
        if prior_name or prior_anchor:
            parts.append("conflict=imported packet noun and implementation anchor are unsupported by the retail no-op callback")
        parts.extend(
            [
                (
                    "separate_direction=c2s FUN_004CA100 emits opcode 0x01cb through the zone send path, which does not supply clientbound semantics"
                    if opcode == 0x01CB
                    else "separate_direction=the same opcode integer has independent serverbound emitter semantics that do not transfer to this row"
                ),
                "client_only=no-op callback routing does not establish server behavior",
                f"client_re_evidence={ZONE_DUMMY_CLUSTER_EVIDENCE}#s2c-{opcode:04x}",
                "dependency_status=closed",
            ]
        )
        if opcode == 0x01CB:
            parts.append("client_semantics_evidence=data/client_opcode_semantics.json#s2c-01cb")
        entry["name"] = f"_0x{opcode:04X}"
        entry["implementationAnchor"] = None
        entry["decompAnchor"] = function
        entry["confidence"] = "decomp_routed"
        entry["notes"] = "; ".join(parts)
        applied += 1

    entries.sort(key=lambda entry: (entry["opcode"], entry["name"]))
    return applied, inserted


def remove_note_token(notes: str, token: str) -> tuple[str, bool]:
    if notes == token:
        return "", True
    prefix = token + ";"
    if notes.startswith(prefix):
        return notes[len(prefix):].lstrip(), True
    for marker in ("; " + token,):
        start = notes.find(marker)
        if start < 0:
            continue
        end = start + len(marker)
        if end == len(notes) or notes[end] == ";":
            return notes[:start] + notes[end:], True
    return notes, False


def append_note_token(notes: str, token: str) -> str:
    if token in notes:
        return notes
    return f"{notes}; {token}" if notes else token


def apply_login_prezone_attributions(top: dict) -> tuple[int, int, int]:
    """Assign login.pcapng observations to the captured main Map/Zone lane."""
    applied = 0
    skipped = 0
    errors = 0
    stale_lane_tokens = (
        "lane_ruling=unresolved_no_s2c_observation",
        "main_lane_count=0",
        "chat_lane_count=0",
    )

    for bucket, opcode_hex, name, wire_direction, payload_length in LOGIN_PREZONE_ATTRIBUTIONS:
        selected = None
        for entry in top["lists"].get(bucket, []):
            if entry["opcodeHex"] == opcode_hex and entry["name"] == name:
                selected = entry
                break
        if selected is None:
            print(f"  WARN: no entry for login attribution {bucket} {opcode_hex} {name}")
            errors += 1
            continue

        evidence = f"{LOGIN_LANE_EVIDENCE}#lanes/main/{wire_direction}/{opcode_hex}"
        attribution = "login_service_attribution=map_main_lane"
        evidence_token = f"login_evidence={evidence}"
        identity_token = f"login_capture_sha256={LOGIN_CAPTURE_SHA256}"
        before = (
            list(selected.get("observedIn", [])),
            list(selected.get("payloadLengths", [])),
            selected.get("notes", ""),
        )
        selected["observedIn"] = sorted(
            set(selected.get("observedIn", [])) | {LOGIN_CAPTURE}
        )
        selected["payloadLengths"] = sorted(
            set(selected.get("payloadLengths", [])) | {payload_length}
        )
        notes = selected.get("notes", "")
        for token in (attribution, evidence_token, identity_token):
            notes = append_note_token(notes, token)
        selected["notes"] = notes

        for entries in top["lists"].values():
            for entry in entries:
                if (
                    entry is selected
                    or entry.get("direction") != selected.get("direction")
                    or entry.get("opcode") != selected.get("opcode")
                    or entry.get("service") == selected.get("service")
                ):
                    continue
                competitor_had_capture = LOGIN_CAPTURE in entry.get("observedIn", [])
                if competitor_had_capture:
                    entry["observedIn"] = sorted(
                        set(entry.get("observedIn", [])) - {LOGIN_CAPTURE}
                    )
                    if not entry["observedIn"]:
                        entry["payloadLengths"] = []
                competitor_notes = entry.get("notes", "")
                for token in stale_lane_tokens:
                    competitor_notes, _ = remove_note_token(competitor_notes, token)
                if entry.get("service") != "lobby":
                    competitor_notes = append_note_token(
                        competitor_notes, "login_service_exclusion=map_main_lane"
                    )
                    competitor_notes = append_note_token(competitor_notes, evidence_token)
                    competitor_notes = append_note_token(competitor_notes, identity_token)
                entry["notes"] = competitor_notes

        after = (
            selected.get("observedIn", []),
            selected.get("payloadLengths", []),
            selected.get("notes", ""),
        )
        if before == after:
            skipped += 1
        else:
            applied += 1

    return applied, skipped, errors


def reconcile_pcap_notes(top: dict) -> tuple[int, int, int]:
    """Keep pcap notes aligned with the observedIn evidence they describe."""
    stale_removed = 0
    ambiguity_added = 0
    ambiguity_removed = 0
    stale_tokens = ("no_pcap_evidence", "inferred_not_observed_in_corpus")
    ambiguity_token = f"pcap_service_ambiguous={PCAP_AMBIGUOUS_SERVICES}"
    login_keys = {
        ("serverbound" if wire_direction == "c2s" else "clientbound", int(opcode_hex, 16))
        for _bucket, opcode_hex, _name, wire_direction, _length
        in LOGIN_PREZONE_ATTRIBUTIONS
    }

    non_lobby_rows = []
    for entries in top["lists"].values():
        for entry in entries:
            if entry.get("service") == "lobby":
                continue
            non_lobby_rows.append(entry)
            if not entry.get("observedIn"):
                continue
            notes = entry.get("notes", "")
            for token in stale_tokens:
                notes, removed = remove_note_token(notes, token)
                if removed:
                    stale_removed += 1
            entry["notes"] = notes

    by_key: dict[tuple[str, int], list[dict]] = {}
    for entry in non_lobby_rows:
        key = (entry.get("direction"), entry.get("opcode"))
        by_key.setdefault(key, []).append(entry)
    for key, rows in by_key.items():
        observed_rows = [entry for entry in rows if entry.get("observedIn")]
        services = {entry.get("service") for entry in observed_rows}
        for entry in rows:
            notes = entry.get("notes", "")
            if services == {"map", "world"} and entry in observed_rows:
                if ambiguity_token not in notes:
                    entry["notes"] = append_note_token(notes, ambiguity_token)
                    ambiguity_added += 1
            elif key in login_keys:
                entry["notes"], removed = remove_note_token(notes, ambiguity_token)
                if removed:
                    ambiguity_removed += 1

    return stale_removed, ambiguity_added, ambiguity_removed


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
        for e in top["lists"][bucket]:
            if e["opcodeHex"] == opcode_hex and e["name"] == name:
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

    decomp_anchor_applied = 0
    decomp_anchor_skipped = 0
    for bucket, opcode_hex, name, decomp_anchor in DECOMP_ANCHOR_OVERRIDES:
        for e in top["lists"].get(bucket, []):
            if e["opcodeHex"] == opcode_hex and e.get("name") == name:
                if e.get("decompAnchor") == decomp_anchor:
                    decomp_anchor_skipped += 1
                else:
                    e["decompAnchor"] = decomp_anchor
                    decomp_anchor_applied += 1
                break
        else:
            print(
                f"  WARN: no entry found for decomp-anchor override {bucket} "
                f"{opcode_hex} name={name}"
            )
            warned += 1
    print(
        f"Applied {decomp_anchor_applied} decomp-anchor overrides "
        f"({decomp_anchor_skipped} skipped)"
    )

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

    battle_applied, battle_errors = apply_battle_result_semantics(top)
    warned += battle_errors
    print(f"Applied {battle_applied} battle-result semantic routes")

    cluster_applied, cluster_inserted = apply_zone_dummy_cluster(top)
    print(
        f"Applied {cluster_applied} Zone dummy-callback routes "
        f"({cluster_inserted} inserted catalog rows)"
    )

    observation_applied, observation_skipped, observation_errors = (
        apply_login_prezone_attributions(top)
    )
    warned += observation_errors
    print(
        f"Applied {observation_applied} login pre-zone attributions "
        f"({observation_skipped} skipped)"
    )

    stale_removed, ambiguity_added, ambiguity_removed = reconcile_pcap_notes(top)
    print(f"Removed {stale_removed} stale no-pcap note tokens")
    print(f"Added {ambiguity_added} pcap-ambiguity note tokens")
    print(f"Removed {ambiguity_removed} stale pcap-ambiguity note tokens")

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
