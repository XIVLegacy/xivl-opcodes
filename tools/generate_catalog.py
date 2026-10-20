"""Apply curated overrides and canonicalize both root catalogs."""

import json
import sys
from pathlib import Path

from _json_io import CONSTANTS_PATH, OPCODES_PATH, write_json

EXPECTED_TOP_DESC = "FFXIV 1.23b opcode catalog joined with pcap observations and retail-client analysis. WorldMapBackend holds world<->map backbone packets; both backend directions share opcode integers. WorldMapBackend entries are server-to-server and never cross the client TCP socket, so client-capture pcap evidence is structurally impossible for those wire values. The catalog includes 4 client-side receiver opcodes (0x018E SetRetainerStar, 0x01A2 JobQuestCompleteTriple, 0x01A6 HamletSupplyRanking, 0x01A8 HamletDefenseScore); evidence is xivl-client-structs client receiver decomp."
REVERIFY_METHOD = "live-validation: verify that the retail 1.23b client accepts the behavior in a live session"
CLIENT_SEMANTICS_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "client_opcode_semantics.json"
)
ZONE_DISPATCH_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "zone_dispatch_map.json"
)
DECOMP_OPCODES_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "decomp_opcodes.json"
)
BATTLE_RESULT_SEMANTICS_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "battle_result_semantics.json"
)
ACHIEVEMENT_LIFECYCLE_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "achievement_lifecycle.json"
)
ZONE_DUMMY_CLUSTER_EVIDENCE = (
    "xivl-client-structs:manifests/zone_dummy_callback_cluster.json"
)
MAP_SOCIAL_NEIGHBORHOOD = {
    "0x01c9": {
        "names": ("AddRemoveSocialPacket", "_0x01C9Handler"),
        "name": "_0x01C9Handler",
        "function": "FUN_004C9DA0",
        "confidence": "decomp_routed",
        "notes": (
            "no_pcap_evidence; retail_client_analysis=FUN_004C9DA0 builds a 0x30-byte "
            "inner record for opcode 0x01c9 and routes it through FUN_004E0240 to the Zone "
            "forwarder FUN_00DAE010; application_size=32; builder_fields=linked-list iteration "
            "with four qwords copied from param_2; semantic_boundary=Mail/Letter UI caller "
            "context supports the subsystem but not an add/remove-social noun or server policy; "
            "prior_packet_label=AddRemoveSocialPacket; prior_label=MapClientOpcode::AddBlacklist; "
            "conflict=inherited social noun and implementation anchor disagree with Mail/Letter client evidence; "
            "naming=placeholder retained; client_only=producer construction does not establish "
            "server behavior; client_re_evidence=xivl-client-structs:manifests/c2s_emit_sites.json#byOpcode.0x01C9; "
            "client_role_evidence=xivl-client-structs:manifests/cluster_refinements_unobserved.json#0x01c9"
        ),
    },
    "0x01ca": {
        "names": ("AddRemoveSocialPacket", "_0x01CAHandler"),
        "name": "_0x01CAHandler",
        "function": "FUN_004B7D70",
        "confidence": "decomp_routed",
        "notes": (
            "no_pcap_evidence; retail_client_analysis=FUN_004B7D70 builds a 0x30-byte "
            "inner record for opcode 0x01ca and routes it through FUN_004E0240 to the Zone "
            "forwarder FUN_00DAE010; application_size=32; builder_fields=four qwords copied "
            "from param_2; semantic_boundary=Mail/Letter UI caller context supports an "
            "attribute-update role but not remove-blacklist or server policy; "
            "prior_packet_label=AddRemoveSocialPacket; prior_label=MapClientOpcode::RemoveBlacklist; "
            "conflict=inherited social noun and implementation anchor disagree with Mail/Letter client evidence; "
            "naming=placeholder retained; client_only=producer construction does not establish "
            "server behavior; client_re_evidence=xivl-client-structs:manifests/c2s_emit_sites.json#byOpcode.0x01CA; "
            "client_role_evidence=xivl-client-structs:manifests/cluster_refinements_unobserved.json#0x01ca"
        ),
    },
    "0x01cb": {
        "names": ("_0x01CBHandler",),
        "name": "_0x01CBHandler",
        "function": "FUN_004CA100",
        "confidence": "decomp_routed",
        "notes": (
            "no_pcap_evidence; retail_client_analysis=FUN_004CA100 builds a 0x18-byte inner "
            "record for opcode 0x01cb and routes it through FUN_004E0240 to the Zone forwarder "
            "FUN_00DAE010; application_size=8; builder_fields=one state field copied from "
            "object offset 0xc40 with remaining application bytes unresolved; producer_behavior=state "
            "gates and self-actor/login callers establish a startup state-machine step; "
            "prior_label=MapClientOpcode::BlacklistRequest; conflict=inherited implementation anchor is not independent retail evidence; "
            "semantic_boundary=the specific blacklist noun depends on inherited catalog vocabulary, "
            "not an independently decoded payload; naming=placeholder retained; client_only=producer "
            "state transitions do not establish server policy; client_re_evidence=xivl-client-structs:manifests/symbols.json#BCS-Y-1071"
        ),
    },
    "0x01cc": {
        "names": ("AddRemoveSocialPacket", "_0x01CCHandler"),
        "name": "_0x01CCHandler",
        "function": "FUN_004CA1B0",
        "confidence": "decomp_routed",
        "notes": (
            "no_pcap_evidence; retail_client_analysis=FUN_004CA1B0 builds a 0x30-byte "
            "inner record for opcode 0x01cc and routes it through FUN_004E0240 to the Zone "
            "forwarder FUN_00DAE010; application_size=32; builder_fields=linked-list iteration "
            "with four qwords; "
            "prior_packet_label=AddRemoveSocialPacket; prior_label=MapClientOpcode::AddFriendlist; "
            "conflict=inherited social noun and implementation anchor disagree with Mail/Letter client evidence; "
            "semantic_boundary=Mail/Letter caller clustering is supported, but the caller has no "
            "distinguishing strings and does not establish add-friend or "
            "server policy; naming=placeholder retained; client_only=producer construction does "
            "not establish server behavior; client_re_evidence=xivl-client-structs:manifests/c2s_emit_sites.json#byOpcode.0x01CC; "
            "client_role_evidence=xivl-client-structs:manifests/cluster_refinements_unobserved.json#0x01cc"
        ),
    },
    "0x01cd": {
        "names": ("AddRemoveSocialPacket", "_0x01CDHandler"),
        "name": "_0x01CDHandler",
        "function": "FUN_004B7E30",
        "confidence": "blocked",
        "notes": (
            "no_pcap_evidence; retail_client_analysis=FUN_004B7E30 contains a 0x30-byte "
            "inner-record builder for opcode 0x01cd and a route through FUN_004E0240 to the Zone "
            "forwarder FUN_00DAE010; application_size=32; builder_fields=four qwords; "
            "evidence_conflict=c2s_emit_sites records a caller while the later exhaustive "
            "reference and byte-pattern pass reports no instruction or function-pointer references; "
            "prior_packet_label=AddRemoveSocialPacket; prior_label=MapClientOpcode::RemoveFriendlist; "
            "conflict=inherited social noun and implementation anchor are unsupported by the reachability evidence; "
            "semantic_boundary=compiled builder only, with runtime production and remove-friend "
            "semantics unresolved; naming=placeholder retained; client_only=dead-or-unreachable "
            "client code does not establish server behavior; client_re_evidence=xivl-client-structs:manifests/c2s_emit_sites.json#byOpcode.0x01CD; "
            "client_conflict_evidence=xivl-client-structs:manifests/cluster_refinements_unresolved.json#0x01cd"
        ),
    },
    "0x01ce": {
        "names": ("_0x01CEHandler",),
        "name": "_0x01CEHandler",
        "function": "FUN_004CA730",
        "confidence": "decomp_routed",
        "notes": (
            "no_pcap_evidence; retail_client_analysis=FUN_004CA730 builds a 0x18-byte inner "
            "record for opcode 0x01ce and routes it through FUN_004E0240 to the Zone forwarder "
            "FUN_00DAE010; application_size=8; builder_fields=one state field copied from object "
            "offset 0xcb0 with remaining application bytes unresolved; producer_behavior=state gate "
            "and login/UI callers establish a startup or social state-machine step; "
            "prior_label=MapClientOpcode::FriendlistRequest; conflict=inherited implementation anchor is not independent retail evidence; "
            "semantic_boundary=the specific friendlist noun is not independently decoded from the "
            "payload; naming=placeholder retained; client_only=producer state transitions do not "
            "establish server policy; client_re_evidence=xivl-client-structs:manifests/symbols.json#BCS-Y-1072"
        ),
    },
    "0x01cf": {
        "names": ("_0x01CFHandler",),
        "name": "_0x01CFHandler",
        "function": "FUN_004B7EF0",
        "confidence": "decomp_routed",
        "notes": (
            "retail_client_analysis=FUN_004B7EF0 builds a 0x18-byte inner record for opcode "
            "0x01cf and routes it through FUN_004E0240 to the Zone forwarder FUN_00DAE010; "
            "application_size=8; builder_fields=one state field copied from object offset 0xcb0 "
            "with remaining application bytes unresolved; producer_behavior=state gate and two UI "
            "callers establish a social/party initiation boundary; "
            "prior_label=MapClientOpcode::FriendStatusRequest; conflict=inherited implementation anchor is not independent retail evidence; "
            "semantic_boundary=observations in friend-search and party-invite scenarios do not "
            "distinguish a friend-status noun, "
            "causality, or server policy; naming=placeholder retained; client_only=producer state "
            "transitions do not establish server behavior; client_re_evidence=xivl-client-structs:manifests/symbols.json#BCS-Y-1073; "
            "capture_layout_evidence=xivl-captures:derived/payload_layouts.json#layouts.c2s.0x01cf"
        ),
    },
}
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
        "MapServerbound",
        "0x0001",
        "PingPacket",
        "corpus request_response_pairs.json: 3329 c2s 0x0001 firings; top responses s2c "
        "0x0190 (1288 pairs, 38%), 0x0137 (423/12%), 0x00d0 (242/7%). Likely "
        "heartbeat/keepalive with paired periodic updates. | "
        "decomp_source=tierc_outbound_scan; bcsy_ref=BCS-Y-0314; evidence=FUN_004E20A0 "
        "(Zone tick handler) emits opcode 0x0001 size 0x28 via thunk_FUN_004E0240 -> "
        "FUN_004E0240 (BCS-Y-0312, Tier-C wrapper) -> FUN_00DAE010 (BCS-Y-0304, Zone "
        "generic forwarder). The stack record at the thunk call site has local_1160 = 1 "
        "(opcode) and local_115c = 0x28 (size). This is an INDIRECT Tier-D binding via the "
        "Tier-C wrapper path - the previously-named PingPacket entry is confirmed at the "
        "emission site here.; likely_role=Map channel keepalive / ping (c2s, in tick loop) "
        "| pcap_observations merged from xivl-client-structs pcap_opcode_evidence.json.",
        "retail_client_analysis=FUN_004E20A0 periodic construction sends through 0x004E24E7"
        " -> FUN_004DD660 -> FUN_004E0240 -> FUN_00DAE010; application_extent=24 bytes "
        "after the 16-byte game-message prefix, within a 56-byte subpacket; field_map=u32 "
        "timeGetTime result at application+0 followed by 20 explicitly zeroed bytes at "
        "application+4; producer_evidence=xivl-decomp:docs/net/periodic-map-0001.md; "
        "clock_boundary=the __time64-based send trigger is separate from the four-byte wire"
        " clock; trigger_boundary=the path follows the queue drain and does not require "
        "that no inbound packet was processed earlier in the invocation; "
        "retained_correlation=xivl-captures:derived/request_response_pairs.json reports "
        "3371 numeric c2s 0x0001 events and a 200ms window, with 1288 pairs with s2c 0x0190"
        " (38%), 423 with s2c 0x0137 (13%) and 242 with s2c 0x00d0 (7%); "
        "semantic_boundary=overlapping timing correlations do not establish a causal reply,"
        " ping/pong identity, server echo, sequence meaning, cadence policy or guaranteed "
        "delivery; naming=PingPacket retained as a lookup label without retail semantic "
        "confirmation; pcap_observations merged from xivl-client-structs "
        "pcap_opcode_evidence.json.",
    ),
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
        "no_pcap_evidence; "
        "implementationServiceRelabel=LobbyOpcode::Error_at_lobby_clientbound_same_wire_integer;"
        " not_a_parity_discrepancy; native_record_candidate=FUN_004E3910 writes record "
        "value 2 and size 0x28, one caller u32 and two qwords totaling 16 supplied bytes; "
        "copy_boundary=the published forwarder implies a 24-byte region whose final four "
        "bytes are not written by this builder; initialization_boundary=caller "
        "initialization and the selected input values remain unknown; "
        "wire_binding_boundary=record value 2 is not independent proof of serialized Map "
        "opcode 0x0002 or a login/handshake identity; "
        "native_record_evidence=xivl-decomp:docs/net/zone-value-two-record.md; "
        "next_static_edge=the builder value through finalization to the serialized header",
        "no_pcap_evidence; "
        "implementationServiceRelabel=LobbyOpcode::Error_at_lobby_clientbound_same_wire_integer;"
        " not_a_parity_discrepancy; native_record_producer=FUN_004E3910 writes record "
        "value 2 and size 0x28; header_binding=Zone constructors store that value at "
        "builder+0x1c and vtable slot2 FUN_00DC1BE0 writes its low16 to game-header+2 "
        "with tag 0x0014; finalization=slot3 FUN_00DC1C10 and its two no-store helpers "
        "preserve the opcode through FUN_00DB06A0 submission to FUN_00DAF920; "
        "application_extent=24 bytes within a statically implied 56-byte subpacket; "
        "builder_fields=one caller u32 and two qwords totaling 16 supplied bytes; "
        "tail_boundary=the final application u32 is not written by this builder and "
        "its caller initialization and selected value remain unknown; "
        "semantic_boundary=the native Map serverbound 0x0002 route is bound, while a "
        "login/handshake name, final-u32 selector meaning, response policy, delivery "
        "and client acceptance remain unproved; naming=placeholder retained; "
        "native_record_evidence=xivl-decomp:docs/net/zone-value-two-record.md; "
        "header_binding_evidence=xivl-decomp:docs/net/zone-outbound-header.md; "
        "next_static_edge=the specific caller input values and final-u32 initialization",
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
    (
        "MapClientbound",
        "0x0147",
        "_0x0147",
        "",
        "historical_interpretation=InventorySetEndPacket; "
        "historical_implementation_anchor=MapServerOpcode::InventorySetEnd; "
        "historical_status=unverified prior catalog association, retained as provenance only; "
        "naming=placeholder retained because packet identity is unconfirmed; "
        "capture_layout_evidence=data/vendor/captures/payload_layouts.json#layouts.s2c.0x0147; "
        "capture_sample_evidence=data/vendor/captures/payload_samples.json#samples.s2c.0x0147; "
        "retail_dispatch_evidence=data/zone_dispatch_map.json#cases.65 (case 65 routes to slot 67); "
        "default_callback_evidence=xivl-decomp:config/ffxivgame.vtable_slots.jsonl#83702 "
        "(ZoneProtoDownDummyCallback slot 67); "
        "default_callback_body=xivl-decomp:asm/ffxivgame/009b8900_FUN_00db8900.s#1-6 (RET 0xc); "
        "runtime_callback_boundary=xivl-decomp:asm/ffxivgame/009ae520_FUN_00dae520.s#26 selects "
        "DummyCallback for one dispatcher call; other runtime callback selection remains unresolved",
    ),
    (
        "MapServerbound",
        "0x0003",
        "ChatMessagePacket",
        "decomp_source=tierc_outbound_scan; bcsy_ref=BCS-Y-0313; evidence=FUN_004E0320 emits opcode "
        "0x0003 size 0x230 (560 bytes, the largest single-opcode emitter on the direct FUN_00DAE010 "
        "path). 438-byte function at VA 0x004E0320 with sole caller FUN_004D8160. Stack record: "
        "local_ac0=3 (opcode), local_abc=0x230 (size). Body block of 0x200 bytes loaded from "
        "FUN_00445210/FUN_004451F0 (string-pool source) via _memset + _memcpy.; likely_role=Map state "
        "push (large 512-byte body block)",
        "decomp_source=tierc_outbound_scan; bcsy_ref=BCS-Y-0313; evidence=FUN_004E0320 emits opcode "
        "0x0003 internal builder-record size 0x230 (560 bytes, the largest single-opcode emitter on the"
        " direct FUN_00DAE010 path). 438-byte function at VA 0x004E0320 with sole caller FUN_004D8160. "
        "Stack record: local_ac0=3 (opcode), local_abc=0x230 (size). Body block of 0x200 bytes loaded "
        "from FUN_00445210/FUN_004451F0 (string-pool source) via _memset + _memcpy. Retail Map-main c2s"
        " specimens in "
        "xivl-captures:studies/m9-corpus-research/derived/verdicts.md#map-main-client-to-server-0x0003 "
        "retain selector u32 1 (Say) or 2 (Shout), text[512], and an opaque prefix/tail in 576-byte "
        "subevents. Their 552-byte normalized body retains the final eight bytes of the 16-byte game "
        "header; the internal builder-record size is a different extent.; likely_role=Map Say/Shout "
        "chat request (retained selectors 1 and 2)",
    ),
    (
        "WorldServerbound",
        "0x00c9",
        "SelectedGroupChatMessagePacket",
        "pcap_observations merged from xivl-client-structs pcap_opcode_evidence.json.; "
        "bcsy_ref=BCS-Y-0309; exact 0x228 subpacket and 0x210 application: selector u32 10 at +0x00, "
        "zero u32 at +0x04, selected Group entry token u32 at +0x08, NUL-terminated UTF-8 message[512] "
        "at +0x0c, and opaque tail[4] at +0x20c; FUN_006C0590 selects the token from a Group-owned "
        "entry table and FUN_006C13D0 matches it in a Group-record vector; FUN_006CBDD0 constructs the "
        "same +0x70 token vector for ordinary and linkshell-specific EntryBuilder paths, proving "
        "mechanism compatibility but not a player-linkshell chat route; the token is not proven to be "
        "an actor, party, linkshell, or sender identifier; an empty message reaches emission because "
        "FUN_00C99B80 accepts an initial NUL and no later nonempty check exists",
        "pcap_observations merged from xivl-client-structs pcap_opcode_evidence.json.; "
        "bcsy_ref=BCS-Y-0309; exact 0x228 subpacket and 0x210 application: selector u32 10 at +0x00, "
        "zero u32 at +0x04, selected Group entry token u32 at +0x08, NUL-terminated UTF-8 message[512] "
        "at +0x0c, and opaque tail[4] at +0x20c; FUN_006C0590 selects the token from a Group-owned "
        "entry table and FUN_006C13D0 matches it in a Group-record vector; FUN_006CBDD0 constructs the "
        "same +0x70 token vector for ordinary and linkshell-specific EntryBuilder paths; DesktopWidget "
        "chatDirect mode 5 supplies MyPlayer:getCommunityGroupCurrent(20002) and index 1 to "
        "MyPlayer:_chat; mode 4 supplies the party Group and index 1. "
        "CharaBaseClass:getCommunityGroupCurrent calls _getExtendedTemporaryGroupCurrent, whose native "
        "binding and MyPlayer slot 38 resolve the current Group through FUN_006C20C0. FUN_006E91F0 "
        "retrieves ExecuteParameters selectors 2 and 3, decrements the one-based index, and reads the "
        "supplied Group token through FUN_006C0590. This joins the active player-linkshell state to the"
        " same 0x00c9 emitter, without a retained retail linkshell specimen or recovered server routing"
        " policy. "
        "producer_evidence=xivl-decomp@553b27eff1e9c661c731b982691ead59b556a8e9:docs/net/wire-protocol.md#world-chat-selected-group-route;"
        " the token is not proven to be an actor, party, linkshell, or sender identifier; an empty "
        "message reaches emission because FUN_00C99B80 accepts an initial NUL and no later nonempty "
        "check exists; application_basis=normalized body retains final eight bytes of the 16-byte "
        "game-message header; "
        "capture_contract=xivl-captures:studies/world-party-chat-00c9-contract/derived/field-matrix.csv",
    ),
    (
        "WorldClientbound",
        "0x00c9",
        "SelectedGroupChatMessagePacket",
        "World Chat s2c 0x00c9 relay, observed 26 times across party_battle_leve.pcapng and "
        "war_quest_update2.pcapng. Exact 0x248 subpacket and 0x230 application: selector u32 10 at "
        "+0x00, zero u32 at +0x04, selected Group entry token u32 at +0x08, senderName[32] at +0x0c, "
        "message[512] at +0x2c, and zero tail[4] at +0x22c. FUN_004D8D10 case VA 0x004D8E7B passes the "
        "full token to FUN_005754E0 -> FUN_006C7B80 and drops the message when lookup returns zero. "
        "FUN_006C13D0 matches it in a Group-record u32 vector at +0x74; the match index selects a u16 "
        "presentation value from a secondary node range at +0x28. FUN_006CBDD0 constructs that token "
        "vector for both ordinary and linkshell-specific EntryBuilder paths. This proves linkshell "
        "mechanism compatibility and a selected Group entry-token lookup, not an actor, party, "
        "linkshell, or sender identifier or the presentation enum values. Player-linkshell chat remains"
        " an unresolved static candidate: the Group ExecuteParameters producer has not been joined to "
        "active-linkshell state, and no retained retail linkshell specimen exists. Server recipient "
        "selection, presence, echo, offline behavior, and cross-zone behavior remain unknown.",
        "World Chat s2c 0x00c9 relay, observed 26 times across party_battle_leve.pcapng and "
        "war_quest_update2.pcapng. Exact 0x248 subpacket and 0x230 application: selector u32 10 at "
        "+0x00, zero u32 at +0x04, selected Group entry token u32 at +0x08, senderName[32] at +0x0c, "
        "message[512] at +0x2c, and zero tail[4] at +0x22c. FUN_004D8D10 case VA 0x004D8E7B passes the "
        "full token to FUN_005754E0 -> FUN_006C7B80 and drops the message when lookup returns zero. "
        "FUN_006C13D0 matches it in a Group-record u32 vector at +0x74; the match index selects a u16 "
        "presentation value from a secondary node range at +0x28. FUN_006CBDD0 constructs that token "
        "vector for both ordinary and linkshell-specific EntryBuilder paths. This proves linkshell "
        "mechanism compatibility and a selected Group entry-token lookup, not an actor, party, "
        "linkshell, or sender identifier or the presentation enum values. DesktopWidget chatDirect mode"
        " 5 supplies MyPlayer:getCommunityGroupCurrent(20002) and index 1 to MyPlayer:_chat; mode 4 "
        "supplies the party Group and index 1. CharaBaseClass:getCommunityGroupCurrent calls "
        "_getExtendedTemporaryGroupCurrent, whose native binding and MyPlayer slot 38 resolve the "
        "current Group through FUN_006C20C0. FUN_006E91F0 retrieves ExecuteParameters selectors 2 and "
        "3, decrements the one-based index, and reads the supplied Group token through FUN_006C0590. "
        "This joins the active player-linkshell state to the same 0x00c9 emitter, without a retained "
        "retail linkshell specimen or recovered server routing policy. Producer evidence: "
        "xivl-decomp@553b27eff1e9c661c731b982691ead59b556a8e9:docs/net/wire-protocol.md#world-chat-selected-group-route."
        " Server recipient selection, presence, echo, offline behavior, and cross-zone behavior remain "
        "unknown. Application offsets use the normalized body that retains the final eight bytes of the"
        " 16-byte game-message header; the direction-specific matrix is "
        "xivl-captures:studies/world-party-chat-00c9-contract/derived/field-matrix.csv.",
    ),
    (
        "MapServerbound",
        "0x00ca",
        "UpdatePlayerPositionPacket",
        "decomp_source=tierd_outbound_scan; bcsy_ref=BCS-Y-0321 + BCS-Y-0324 summary; "
        "evidence=Tier-D emitter FUN_004DC690 (3364-byte host function, sole caller "
        "FUN_004E20A0 = BCS-Y-0314) emits opcode 0x00CA via record-builder FUN_004dd620: "
        "`uVar6 = FUN_004dd620((int)_Var13, &local_9f4); FUN_004E0240(uVar6, 0xCA, 0)`. "
        "Size determined by FUN_004dd620 (not hardcoded at caller). NOTE this is OUTSIDE "
        "the 0x01C3..0x01DF cluster - separate lower-range opcode.; likely_role=Map "
        "position update through the helper-built production path | "
        "decomp_source=final_gap_outbound_scan; bcsy_ref=BCS-Y-0328 + BCS-Y-0321; "
        "evidence=Cross-confirmation (second emission site): BCS-Y-0321 documented "
        "FUN_004DC690 (3364B helper-built path via FUN_004dd620); BCS-Y-0328 confirms "
        "FUN_00589030 (stack-record path via FUN_004D6D10 thunk) emits the same opcode "
        "0x00CA size 0x30. The same opcode has two distinct production paths in the binary "
        "- normal stack-record (FUN_00589030) and large-context helper-built (FUN_004DC690 "
        "from tick handler FUN_004E20A0 / BCS-Y-0314).; likely_role=Map position update "
        "(internal record size 0x30, two production paths) | pcap_observations merged from "
        "xivl-client-structs pcap_opcode_evidence.json.; "
        "field_contract=xivl-client-structs:manifests/c2s_payload_decoding.json#payloadStructs.c2s_0x00ca;"
        " application_extent=32 bytes after the 16-byte game-message prefix; "
        "selected_builder_fields=FUN_004DD620 exposes an eight-byte time container at +0, "
        "float x/y/z/rotation at +8/+12/+16/+20, u16 state at +24, and six uninterpreted "
        "bytes at +26; time_boundary=the retained low-dword __time64 write does not "
        "establish additional precision; semantic_boundary=movement enums, units and "
        "cadence policy are not established by this field geometry",
        "client_context=Position producer geometry; producer=Published production sites are"
        " FUN_00589030, the FUN_004DC690 case-7 path using FUN_004DD620, and FUN_0058E0C0 "
        "case 0x51. The dispatcher is a host of one embedded emit, not a standalone "
        "position emitter.; field_geometry=IPC 48 bytes; application 32 bytes: eight-byte "
        "time container at +0, floats at +8/+12/+16/+20, u16 state at +24, six unresolved "
        "bytes at +26.; "
        "client_contract=xivl-client-structs:manifests/c2s_payload_decoding.json#payloadStructs.c2s_0x00ca;"
        " "
        "framing_contract=xivl-client-structs:docs/search-recruitment-wire-contract.md#outbound-framing;"
        " semantic_boundary=The documented low-dword __time64 write does not establish "
        "additional precision. Movement enums, units and cadence policy remain unresolved.;"
        " confidence_boundary=the native emitter anchor does not confirm the retained "
        "packet name, implementation label, server policy or acceptance; "
        "decomp_source=tierd_outbound_scan; bcsy_ref=BCS-Y-0321 + BCS-Y-0324 summary; "
        "decomp_source=final_gap_outbound_scan; bcsy_ref=BCS-Y-0328 + BCS-Y-0321; "
        "pcap_observations merged from xivl-client-structs pcap_opcode_evidence.json.; "
        "related_catalog_refs=BCS-Y-0314",
    ),
    (
        "MapServerbound",
        "0x0133",
        "GroupWorkUpdatePacket",
        "role=client-to-server actor/group work update; the client sends one when it first observes a "
        "group or actor and asks the server to register that actor's event handlers. Same wire integer "
        "as the outbound generic-data opcode, disambiguated by direction. Observed across 16 captures, "
        "72-byte packet; corpus request_response_pairs.json: 268 total c2s 0x0133 firings paired with "
        "s2c responses within 200ms; top response is s2c 0x0137 SetActorProperty (180 pairs, 67% "
        "c2sShare = action command reliably triggers property update). Also reliably triggers s2c "
        "0x00CC (161 pairs, 60%) and 0x0134 (161 pairs, 60%) - composite 5+ packet response. | "
        "pcap_observations merged from xivl-client-structs pcap_opcode_evidence.json.",
        "role=client-side Group work emission with unresolved caller-word semantics; "
        "producer=FUN_0075E950 copies two supplied u32 values followed by 32 staged bytes and sends "
        "through FUN_004D6D30->FUN_004E0240; application_extent=40 bytes after the 16-byte game-message"
        " prefix, within a 72-byte subpacket; "
        "producer_evidence=xivl-client-structs:manifests/op0133_groupcreated_emitter.json; "
        "bounded_caller=a Group ring-drain ADD route reaches the builder through "
        "FUN_006C8CF0/FUN_006C72E0; "
        "caller_evidence=xivl-client-structs:docs/client-architecture.md#zone-actor-binding-and-lua-class-readiness;"
        " field_boundary=the two caller dwords and copied buffer do not establish a universal actor ID,"
        " sequence, timestamp, transition mode or property path; "
        "retained_correlation=xivl-captures:derived/request_response_pairs.json reports 270 numeric "
        "c2s 0x0133 events and a 200ms window, with 180 pairs with s2c 0x0137 (67%), 161 with s2c "
        "0x00cc (60%) and 161 with s2c 0x0134 (60%); causality_boundary=these overlapping timing "
        "correlations do not prove that this packet requests handler registration or triggers the "
        "later packets; scope_boundary=the cited Group-ADD route bounds one client "
        "producer example, while the numeric-c2s correlation product does not independently prove "
        "Map attribution for every event; existing World/Map capture-attribution qualifications "
        "remain; pcap_observations merged from xivl-client-structs pcap_opcode_evidence.json.",
    ),
    (
        "MapServerbound",
        "0x0007",
        "ZoneInCompletePacket",
        "| decomp_source=final_gap_outbound_scan; bcsy_ref=BCS-Y-0330; evidence=Dual-site "
        "Tier-D emission: FUN_00586F40 (gated on DAT_01338D28 == 0, initial-once with "
        "timestamp via __time64) and FUN_00586FB0 (unconditional fallback) both build stack"
        " record `local_8b0=7, local_8ac=0x18, local_898=timestamp, "
        "local_894=param/0xFFFFFFFF` and call FUN_004D6CF0 (BCS-Y-0323 gating thunk) -> "
        "FUN_004E0240 (BCS-Y-0312) -> FUN_00DAE010 (BCS-Y-0304, Zone Tier-B). Pattern "
        "suggests keepalive/connection-state ping.; likely_role=Map channel "
        "connection-state ping / keepalive (c2s, dual emission with retry fallback) | "
        "pcap_observations merged from xivl-client-structs pcap_opcode_evidence.json.",
        "client_context=Dual timestamp/caller-word emission; producer=FUN_00586F40 is gated"
        " on DAT_01338D28 == 0; FUN_00586FB0 supplies the fallback. Both reach FUN_004D6CF0"
        " -> FUN_004E0240 -> FUN_00DAE010.; field_geometry=IPC 24 bytes; application 8 "
        "bytes: __time64-derived u32 at +0 and caller u32 or 0xFFFFFFFF at +4.; "
        "client_contract=xivl-client-structs:manifests/structs.json#BCS-S-0028; "
        "framing_contract=xivl-client-structs:docs/search-recruitment-wire-contract.md#outbound-framing;"
        " semantic_boundary=Keepalive, zone-completion effects, seed meanings and higher "
        "time precision are not established.; confidence_boundary=the native emitter anchor"
        " does not confirm the retained packet name, implementation label, server policy or"
        " acceptance; decomp_source=final_gap_outbound_scan; bcsy_ref=BCS-Y-0330; "
        "pcap_observations merged from xivl-client-structs pcap_opcode_evidence.json.; "
        "related_catalog_refs=BCS-Y-0304,BCS-Y-0312,BCS-Y-0323",
    ),
    (
        "MapServerbound",
        "0x00cc",
        "LockTargetPacket",
        "corpus request_response_pairs.json: 66 c2s 0x00CC LockTarget firings; top "
        "responses s2c 0x0190 (116/175% c2sShare indicating multi-response), 0x0001 "
        "(23/34%), 0x00d3 (21/31%). LockTarget triggers actor-state + heartbeat + "
        "target-time update.",
        "client_context=Target-control producer with unresolved tail; producer=Both "
        "retained FUN_00561BB0 branches build 0x00CC and reach FUN_004D6D10 -> "
        "FUN_004E0240; one writes 0xC0000000 and the other an object-ID-style word.; "
        "field_geometry=IPC 24 bytes; application 8 bytes: actor-ID-style u32 at +0 and "
        "four unresolved bytes at +4.; "
        "client_contract=xivl-client-structs:manifests/c2s_payload_decoding.json#payloadStructs.c2s_0x00cc;"
        " "
        "framing_contract=xivl-client-structs:docs/search-recruitment-wire-contract.md#outbound-framing;"
        " semantic_boundary=The selected pass did not find an explicit trailing-word write;"
        " universal noninitialization and a lock-kind enum are unproved. Numeric timing "
        "correlations do not prove a causal response.; confidence_boundary=the native "
        "emitter anchor does not confirm the retained packet name, implementation label, "
        "server policy or acceptance",
    ),
    (
        "MapServerbound",
        "0x00cd",
        "SetTargetPacket",
        "",
        "client_context=Two-word target-control producer; producer=FUN_0075EB30 and "
        "FUN_00562D30 write the same two-dword application. The former reaches FUN_004D6D10"
        " -> FUN_004E0240.; field_geometry=IPC 24 bytes; application 8 bytes: "
        "object-ID-style u32 at +0 and a second target-control u32 at +4.; "
        "client_contract=xivl-client-structs:manifests/c2s_payload_decoding.json#payloadStructs.c2s_0x00cd;"
        " "
        "framing_contract=xivl-client-structs:docs/search-recruitment-wire-contract.md#outbound-framing;"
        " semantic_boundary=No target-kind enum or complete value domain is established.; "
        "confidence_boundary=the native emitter anchor does not confirm the retained packet"
        " name, implementation label, server policy or acceptance",
    ),
    (
        "MapServerbound",
        "0x0130",
        "UpdateGroupPacket",
        "decomp_source=final_gap_outbound_scan; bcsy_ref=BCS-Y-0329; evidence=FUN_0075E8D0 "
        "builds stack record `local_8b0=0x130, local_8ac=0x20` then calls FUN_004D6D30 "
        "(BCS-Y-0323 gating thunk, sole caller of that thunk) with `(&local_8b0, 0, 0)`. "
        "Routes thunk -> FUN_004E0240 -> FUN_00DAE010. Opcode 0x0130 = decimal 304, sits "
        "OUTSIDE the 0x01C3-0x01DF action cluster.; likely_role=Map channel mid-range "
        "opcode (separate from action cluster); lua_binding=CharaBase._updateGroup -> "
        "0x0130 via FUN_0075E860 (confirmed_direct_emit, BCS-Y-0380); "
        "lua_binding=GroupBase._updateMemberAndInformation -> 0x0130 via 0x0075E8D0 "
        "(confirmed_direct_emit, BCS-Y-0382, recovered via reverse-BFS from send-helper "
        "caller lists); naming_upgrade=_0x0130 -> UpdateGroupPacket based on the two "
        "confirmed Lua triggers _updateGroup and _updateMemberAndInformation both emitting "
        "this opcode with size 0x20, matching the convention of neighbor 0x0131 "
        "UpdateItemPackagePacket (Lua trigger _updateItemPackage)",
        "client_context=Group update producer variants; producer=CharaBase._updateGroup "
        "reaches FUN_0075E860; GroupBase._updateMemberAndInformation reaches FUN_0075E8D0. "
        "Both use FUN_004D6D30 -> FUN_004E0240 -> FUN_00DAE010.; field_geometry=IPC 32 "
        "bytes; application 16 bytes in four unnamed u32 fields. FUN_0075E860 zeros the "
        "last two; FUN_0075E8D0 fills all four.; "
        "client_contract=xivl-client-structs:manifests/c2s_payload_decoding.json#payloadStructs.c2s_0x0130;"
        " "
        "framing_contract=xivl-client-structs:docs/search-recruitment-wire-contract.md#outbound-framing;"
        " semantic_boundary=Group policy and field nouns remain unresolved. The retained "
        "catalog length 32 is the legacy builder totalSize; the selected native framing "
        "implies a 48-byte subevent, not a new capture observation.; "
        "confidence_boundary=the native emitter anchor does not confirm the retained packet"
        " name, implementation label, server policy or acceptance; "
        "decomp_source=final_gap_outbound_scan; bcsy_ref=BCS-Y-0329; "
        "related_catalog_refs=BCS-Y-0323,BCS-Y-0380,BCS-Y-0382",
    ),
    (
        "MapServerbound",
        "0x01c3",
        "StartRecruitingRequestPacket",
        "no_pcap_evidence; decomp_source=tierd_outbound_scan; bcsy_ref=BCS-Y-0318 + "
        "BCS-Y-0324 summary; evidence=Tier-D emitter 0x004B7A20 builds record via helper "
        "`uVar = FUN_004cfd10(...)` then calls FUN_004E0240(uVar, 0x01C3, 0). Size "
        "determined by FUN_004cfd10 (not hardcoded at caller). Routed through Tier-C "
        "wrapper FUN_004E0240 (BCS-Y-0312) -> Tier-B FUN_00DAE010 (BCS-Y-0304).; "
        "likely_role=Map action-system request (0x01C3-0x01DF cluster: combat/skill/action "
        "use; specific role TBD via pcap correlation)",
        "no_pcap_evidence; client_context=Bounded recruitment listing post/start context; "
        "producer=FUN_004B7A20 sends the helper-built record from FUN_004CFD10 through "
        "FUN_004E0240.; field_geometry=IPC 464 bytes (0x1D0); application 448 bytes "
        "(0x1C0): three leading u32 values, four three-dword groups, a 96-dword block, and "
        "four unresolved bytes at +0x1BC.; "
        "client_contract=xivl-client-structs:manifests/structs.json#BCS-S-0356; "
        "framing_contract=xivl-client-structs:docs/search-recruitment-wire-contract.md#outbound-framing;"
        " semantic_boundary=Individual field meanings, server listing policy and client "
        "acceptance remain unresolved.; confidence_boundary=the native emitter anchor does "
        "not confirm the retained packet name, implementation label, server policy or "
        "acceptance; decomp_source=tierd_outbound_scan; bcsy_ref=BCS-Y-0318 + BCS-Y-0324 "
        "summary; related_catalog_refs=BCS-Y-0304,BCS-Y-0312",
    ),
    (
        "MapServerbound",
        "0x01c4",
        "_0x01C4Handler",
        "no_pcap_evidence; | decomp_source=tierd_outbound_scan; bcsy_ref=BCS-Y-0324; "
        "per-opcode binding in operation_opcode_map_outbound.json tierDSweep.bindings "
        "table; evidence=Tier-D emitter 0x004B7AD0 sets stack record `local_8b0 = 0x01C4 "
        "(opcode); local_8ac = 0x18 (size); [body fields]` then calls "
        "FUN_004E0240(&local_8b0, 0x01C4, 0). Routed through Tier-C wrapper FUN_004E0240 "
        "(BCS-Y-0312) -> Tier-B Zone forwarder FUN_00DAE010 (BCS-Y-0304). Member of the "
        "24-emitter 0x01C3..0x01DF action-system traffic cluster.; likely_role=Map "
        "action-system request (0x01C3-0x01DF cluster: combat/skill/action use; specific "
        "role TBD via pcap correlation)",
        "no_pcap_evidence; client_context=Bounded recruitment listing-view/browse context; "
        "producer=FUN_004B7AD0 constructs 0x01C4 and reaches FUN_004E0240.; "
        "field_geometry=IPC 24 bytes; application 8 bytes: explicitly zero u32 at +0 and "
        "four bytes with no documented write at +4.; "
        "client_contract=xivl-client-structs:manifests/structs.json#BCS-S-0359; "
        "framing_contract=xivl-client-structs:docs/search-recruitment-wire-contract.md#outbound-framing;"
        " semantic_boundary=The zero has no established enum meaning; the retained "
        "EndRecruitingRequest implementation label is not retail identity.; "
        "confidence_boundary=the native emitter anchor does not confirm the retained packet"
        " name, implementation label, server policy or acceptance; "
        "decomp_source=tierd_outbound_scan; bcsy_ref=BCS-Y-0324; "
        "related_catalog_refs=BCS-Y-0304,BCS-Y-0312",
    ),
    (
        "MapServerbound",
        "0x01c5",
        "_0x01C5Handler",
        "no_pcap_evidence; | decomp_source=tierd_outbound_scan; bcsy_ref=BCS-Y-0324; "
        "per-opcode binding in operation_opcode_map_outbound.json tierDSweep.bindings "
        "table; evidence=Tier-D emitter 0x004B7990 sets stack record `local_8b0 = 0x01C5 "
        "(opcode); local_8ac = 0x18 (size); [body fields]` then calls "
        "FUN_004E0240(&local_8b0, 0x01C5, 0). Routed through Tier-C wrapper FUN_004E0240 "
        "(BCS-Y-0312) -> Tier-B Zone forwarder FUN_00DAE010 (BCS-Y-0304). Member of the "
        "24-emitter 0x01C3..0x01DF action-system traffic cluster.; likely_role=Map "
        "action-system request (0x01C3-0x01DF cluster: combat/skill/action use; specific "
        "role TBD via pcap correlation)",
        "no_pcap_evidence; client_context=Bounded recruitment edit-mode toggle context; "
        "producer=FUN_004B7990 constructs 0x01C5 and reaches FUN_004E0240.; "
        "field_geometry=IPC 24 bytes; application 8 bytes: explicitly zero u32 at +0 and "
        "four unresolved bytes at +4.; "
        "client_contract=xivl-client-structs:manifests/structs.json#BCS-S-0360; "
        "framing_contract=xivl-client-structs:docs/search-recruitment-wire-contract.md#outbound-framing;"
        " semantic_boundary=The complete edit operation, zero meaning and server policy are"
        " unresolved; no new packet name is established.; confidence_boundary=the native "
        "emitter anchor does not confirm the retained packet name, implementation label, "
        "server policy or acceptance; decomp_source=tierd_outbound_scan; "
        "bcsy_ref=BCS-Y-0324; related_catalog_refs=BCS-Y-0304,BCS-Y-0312",
    ),
    (
        "MapServerbound",
        "0x01c8",
        "RecruitmentDetailsRequestPacket",
        "no_pcap_evidence; | decomp_source=tierd_outbound_scan; bcsy_ref=BCS-Y-0324; "
        "per-opcode binding in operation_opcode_map_outbound.json tierDSweep.bindings "
        "table; evidence=Tier-D emitter 0x004B7B60 sets stack record `local_8b0 = 0x01C8 "
        "(opcode); local_8ac = 0x18 (size); [body fields]` then calls "
        "FUN_004E0240(&local_8b0, 0x01C8, 0). Routed through Tier-C wrapper FUN_004E0240 "
        "(BCS-Y-0312) -> Tier-B Zone forwarder FUN_00DAE010 (BCS-Y-0304). Member of the "
        "24-emitter 0x01C3..0x01DF action-system traffic cluster.; likely_role=Map "
        "action-system request (0x01C3-0x01DF cluster: combat/skill/action use; specific "
        "role TBD via pcap correlation)",
        "no_pcap_evidence; client_context=Neutral recruitment-context emission; "
        "producer=FUN_004B7B60 constructs 0x01C8 from two caller words and reaches "
        "FUN_004E0240.; field_geometry=IPC 24 bytes; application 8 bytes in two "
        "caller-supplied u32 values.; "
        "client_contract=xivl-client-structs:manifests/c2s_emit_sites.json#emit_sites_table;"
        " "
        "framing_contract=xivl-client-structs:docs/search-recruitment-wire-contract.md#outbound-framing;"
        " semantic_boundary=Retained detailed sources disagree between recruitment-details "
        "and cancellation/leave/withdraw roles. The current structs "
        "method.c463Limits/c467Limits defers a detailed model. Caller action, argument "
        "identities and the exact operation remain unresolved.; confidence_boundary=the "
        "native emitter anchor does not confirm the retained packet name, implementation "
        "label, server policy or acceptance; decomp_source=tierd_outbound_scan; "
        "bcsy_ref=BCS-Y-0324; related_catalog_refs=BCS-Y-0304,BCS-Y-0312",
    ),
    (
        "MapServerbound",
        "0x01d0",
        "FaqListRequestPacket",
        "no_pcap_evidence; decomp_source=tierd_outbound_scan; bcsy_ref=BCS-Y-0324; "
        "per-opcode binding in operation_opcode_map_outbound.json tierDSweep.bindings "
        "table; evidence=Tier-D emitter 0x004B7F90 sets stack record `local_8b0 = 0x01D0 "
        "(opcode); local_8ac = 0x18 (size); [body fields]` then calls "
        "FUN_004E0240(&local_8b0, 0x01D0, 0). Routed through Tier-C wrapper FUN_004E0240 "
        "(BCS-Y-0312) -> Tier-B Zone forwarder FUN_00DAE010 (BCS-Y-0304). Member of the "
        "24-emitter 0x01C3..0x01DF action-system traffic cluster.; likely_role=Map "
        "action-system request (0x01C3-0x01DF cluster: combat/skill/action use; specific "
        "role TBD via pcap correlation)",
        "no_pcap_evidence; client_context=Bounded Topic/bulletin-board list context; "
        "producer=FUN_004B7F90 constructs 0x01D0 and reaches FUN_004E0240; the first word "
        "comes from provider virtual +0x18.; field_geometry=IPC 24 bytes; application 8 "
        "bytes: provider-result u32 at +0 and four unresolved bytes at +4.; "
        "client_contract=xivl-client-structs:manifests/structs.json#BCS-S-0351; "
        "framing_contract=xivl-client-structs:docs/search-recruitment-wire-contract.md#outbound-framing;"
        " semantic_boundary=Provider identity and token meaning remain unresolved. The "
        "retained FAQ label is implementation provenance.; confidence_boundary=the native "
        "emitter anchor does not confirm the retained packet name, implementation label, "
        "server policy or acceptance; decomp_source=tierd_outbound_scan; "
        "bcsy_ref=BCS-Y-0324; related_catalog_refs=BCS-Y-0304,BCS-Y-0312",
    ),
    (
        "MapServerbound",
        "0x01d1",
        "FaqBodyRequestPacket",
        "no_pcap_evidence; | decomp_source=tierd_outbound_scan; bcsy_ref=BCS-Y-0324; "
        "per-opcode binding in operation_opcode_map_outbound.json tierDSweep.bindings "
        "table; evidence=Tier-D emitter 0x004B8030 sets stack record `local_8b0 = 0x01D1 "
        "(opcode); local_8ac = 0x18 (size); [body fields]` then calls "
        "FUN_004E0240(&local_8b0, 0x01D1, 0). Routed through Tier-C wrapper FUN_004E0240 "
        "(BCS-Y-0312) -> Tier-B Zone forwarder FUN_00DAE010 (BCS-Y-0304). Member of the "
        "24-emitter 0x01C3..0x01DF action-system traffic cluster.; likely_role=Map "
        "action-system request (0x01C3-0x01DF cluster: combat/skill/action use; specific "
        "role TBD via pcap correlation)",
        "no_pcap_evidence; client_context=Bounded Call/help request context; "
        "producer=FUN_004B8030 constructs 0x01D1 and reaches FUN_004E0240.; "
        "field_geometry=IPC 24 bytes; application 8 bytes: explicit caller u32 at +0 and "
        "provider virtual +0x18 result u32 at +4.; "
        "client_contract=xivl-client-structs:manifests/structs.json#BCS-S-0352; "
        "framing_contract=xivl-client-structs:docs/search-recruitment-wire-contract.md#outbound-framing;"
        " semantic_boundary=Voice-call versus help-call semantics and both value domains "
        "remain unresolved; the FAQ label is implementation provenance.; "
        "confidence_boundary=the native emitter anchor does not confirm the retained packet"
        " name, implementation label, server policy or acceptance; "
        "decomp_source=tierd_outbound_scan; bcsy_ref=BCS-Y-0324; "
        "related_catalog_refs=BCS-Y-0304,BCS-Y-0312",
    ),
    (
        "MapServerbound",
        "0x01d2",
        "GMTicketIssuesRequestPacket",
        "no_pcap_evidence; | decomp_source=tierd_outbound_scan; bcsy_ref=BCS-Y-0324; "
        "per-opcode binding in operation_opcode_map_outbound.json tierDSweep.bindings "
        "table; evidence=Tier-D emitter 0x004B80E0 sets stack record `local_8b0 = 0x01D2 "
        "(opcode); local_8ac = 0x18 (size); [body fields]` then calls "
        "FUN_004E0240(&local_8b0, 0x01D2, 0). Routed through Tier-C wrapper FUN_004E0240 "
        "(BCS-Y-0312) -> Tier-B Zone forwarder FUN_00DAE010 (BCS-Y-0304). Member of the "
        "24-emitter 0x01C3..0x01DF action-system traffic cluster.; likely_role=Map "
        "action-system request (0x01C3-0x01DF cluster: combat/skill/action use; specific "
        "role TBD via pcap correlation)",
        "no_pcap_evidence; client_context=Bounded mail-compose send context; "
        "producer=FUN_004B80E0 constructs 0x01D2 and reaches FUN_004E0240.; "
        "field_geometry=IPC 24 bytes; application 8 bytes: provider-result u32 at +0 and "
        "four unresolved bytes at +4.; "
        "client_contract=xivl-client-structs:manifests/structs.json#BCS-S-0353; "
        "framing_contract=xivl-client-structs:docs/search-recruitment-wire-contract.md#outbound-framing;"
        " semantic_boundary=The context-token domain and mail delivery policy are "
        "unresolved; the GM-ticket label is implementation provenance.; "
        "confidence_boundary=the native emitter anchor does not confirm the retained packet"
        " name, implementation label, server policy or acceptance; "
        "decomp_source=tierd_outbound_scan; bcsy_ref=BCS-Y-0324; "
        "related_catalog_refs=BCS-Y-0304,BCS-Y-0312",
    ),
    (
        "MapServerbound",
        "0x01d3",
        "_0x01D3Handler",
        "no_pcap_evidence; | decomp_source=tierd_outbound_scan; bcsy_ref=BCS-Y-0324; "
        "per-opcode binding in operation_opcode_map_outbound.json tierDSweep.bindings "
        "table; evidence=Tier-D emitter 0x004B8180 sets stack record `local_8b0 = 0x01D3 "
        "(opcode); local_8ac = 0x18 (size); [body fields]` then calls "
        "FUN_004E0240(&local_8b0, 0x01D3, 0). Routed through Tier-C wrapper FUN_004E0240 "
        "(BCS-Y-0312) -> Tier-B Zone forwarder FUN_00DAE010 (BCS-Y-0304). Member of the "
        "24-emitter 0x01C3..0x01DF action-system traffic cluster.; likely_role=Map "
        "action-system request (0x01C3-0x01DF cluster: combat/skill/action use; specific "
        "role TBD via pcap correlation)",
        "no_pcap_evidence; client_context=State-gated neutral emission; "
        "producer=FUN_004B8180 requires owner+0x10 == 0 and owner+0x15 != 0, calls a "
        "pre-emit helper, constructs 0x01D3 and reaches FUN_004E0240. Success writes owner "
        "state.; field_geometry=IPC 24 bytes; application 8 bytes: explicit zero u32 at +0,"
        " with remaining initialization unresolved.; "
        "client_contract=xivl-client-structs:manifests/symbols.json#BCS-Y-1074; "
        "framing_contract=xivl-client-structs:docs/search-recruitment-wire-contract.md#outbound-framing;"
        " semantic_boundary=Owner-byte permission/GM-rank meaning and complete operation "
        "identity are unproved. No login witness or completely zero body is added.; "
        "confidence_boundary=the native emitter anchor does not confirm the retained packet"
        " name, implementation label, server policy or acceptance; "
        "decomp_source=tierd_outbound_scan; bcsy_ref=BCS-Y-0324; "
        "related_catalog_refs=BCS-Y-0304,BCS-Y-0312",
    ),
    (
        "MapServerbound",
        "0x01d4",
        "_0x01D4Handler",
        "no_pcap_evidence; | decomp_source=tierd_outbound_scan; bcsy_ref=BCS-Y-0324; "
        "per-opcode binding in operation_opcode_map_outbound.json tierDSweep.bindings "
        "table; evidence=Tier-D emitter 0x004B8210 sets stack record `local_8b0 = 0x01D4 "
        "(opcode); local_8ac = 0x18 (size); [body fields]` then calls "
        "FUN_004E0240(&local_8b0, 0x01D4, 0). Routed through Tier-C wrapper FUN_004E0240 "
        "(BCS-Y-0312) -> Tier-B Zone forwarder FUN_00DAE010 (BCS-Y-0304). Member of the "
        "24-emitter 0x01C3..0x01DF action-system traffic cluster.; likely_role=Map "
        "action-system request (0x01C3-0x01DF cluster: combat/skill/action use; specific "
        "role TBD via pcap correlation)",
        "no_pcap_evidence; client_context=Bounded Topic submit/update context; "
        "producer=FUN_004B8210 constructs 0x01D4 and reaches FUN_004E0240.; "
        "field_geometry=IPC 24 bytes; application 8 bytes: explicit zero u32 at +0 and four"
        " unresolved bytes at +4.; "
        "client_contract=xivl-client-structs:manifests/structs.json#BCS-S-0354; "
        "framing_contract=xivl-client-structs:docs/search-recruitment-wire-contract.md#outbound-framing;"
        " semantic_boundary=The exact Topic operation and value meaning remain unresolved; "
        "the GM-ticket label is implementation provenance.; confidence_boundary=the native "
        "emitter anchor does not confirm the retained packet name, implementation label, "
        "server policy or acceptance; decomp_source=tierd_outbound_scan; "
        "bcsy_ref=BCS-Y-0324; related_catalog_refs=BCS-Y-0304,BCS-Y-0312",
    ),
    (
        "MapServerbound",
        "0x01d5",
        "GMSupportTicketPacket",
        "no_pcap_evidence; | decomp_source=tierd_outbound_scan; bcsy_ref=BCS-Y-0324; "
        "per-opcode binding in operation_opcode_map_outbound.json tierDSweep.bindings "
        "table; evidence=Tier-D emitter 0x004B82A0 sets stack record `local_8b0 = 0x01D5 "
        "(opcode); local_8ac = 0x898 (size); [body fields]` then calls "
        "FUN_004E0240(&local_8b0, 0x01D5, 0). Routed through Tier-C wrapper FUN_004E0240 "
        "(BCS-Y-0312) -> Tier-B Zone forwarder FUN_00DAE010 (BCS-Y-0304). Member of the "
        "24-emitter 0x01C3..0x01DF action-system traffic cluster.; likely_role=Map "
        "action-system request (0x01C3-0x01DF cluster: combat/skill/action use; specific "
        "role TBD via pcap correlation)",
        "no_pcap_evidence; client_context=Bounded mail-compose field-update context; "
        "producer=FUN_004B82A0 constructs 0x01D5 and reaches FUN_004E0240.; "
        "field_geometry=IPC 2200 bytes (0x898); application 2184 bytes (0x888): two leading"
        " dwords, a 32-dword block at +8, and a 512-dword block at +0x88.; "
        "client_contract=xivl-client-structs:manifests/structs.json#BCS-S-0350; "
        "framing_contract=xivl-client-structs:docs/search-recruitment-wire-contract.md#outbound-framing;"
        " semantic_boundary=Individual field meanings and mail transaction policy remain "
        "unresolved. IPC 2200 is not a 2200-byte application, and the final block is not "
        "513 dwords; the GM-support label is implementation provenance.; "
        "confidence_boundary=the native emitter anchor does not confirm the retained packet"
        " name, implementation label, server policy or acceptance; "
        "decomp_source=tierd_outbound_scan; bcsy_ref=BCS-Y-0324; "
        "related_catalog_refs=BCS-Y-0304,BCS-Y-0312",
    ),
    (
        "MapServerbound",
        "0x01d6",
        "_0x01D6Handler",
        "no_pcap_evidence; | decomp_source=tierd_outbound_scan; bcsy_ref=BCS-Y-0324; "
        "per-opcode binding in operation_opcode_map_outbound.json tierDSweep.bindings "
        "table; evidence=Tier-D emitter 0x004B8370 sets stack record `local_8b0 = 0x01D6 "
        "(opcode); local_8ac = 0x18 (size); [body fields]` then calls "
        "FUN_004E0240(&local_8b0, 0x01D6, 0). Routed through Tier-C wrapper FUN_004E0240 "
        "(BCS-Y-0312) -> Tier-B Zone forwarder FUN_00DAE010 (BCS-Y-0304). Member of the "
        "24-emitter 0x01C3..0x01DF action-system traffic cluster.; likely_role=Map "
        "action-system request (0x01C3-0x01DF cluster: combat/skill/action use; specific "
        "role TBD via pcap correlation)",
        "no_pcap_evidence; client_context=Bounded Call acknowledgement/status context; "
        "producer=FUN_004B8370 constructs 0x01D6 and reaches FUN_004E0240.; "
        "field_geometry=IPC 24 bytes; application 8 bytes: explicit zero u32 at +0 and four"
        " unresolved bytes at +4.; "
        "client_contract=xivl-client-structs:manifests/structs.json#BCS-S-0355; "
        "framing_contract=xivl-client-structs:docs/search-recruitment-wire-contract.md#outbound-framing;"
        " semantic_boundary=The complete Call lifecycle and server policy remain "
        "unresolved; the GM-ticket label is implementation provenance.; "
        "confidence_boundary=the native emitter anchor does not confirm the retained packet"
        " name, implementation label, server policy or acceptance; "
        "decomp_source=tierd_outbound_scan; bcsy_ref=BCS-Y-0324; "
        "related_catalog_refs=BCS-Y-0304,BCS-Y-0312",
    ),
    (
        "MapServerbound",
        "0x01db",
        "_0x01DB",
        "decomp_source=final_gap_outbound_scan; bcsy_ref=BCS-Y-0327; evidence=FUN_004C73D0 "
        "sets stack record `local_8b0=0x1DB (opcode), local_8ac=0x18 (size)` then calls "
        "FUN_004C7150 (BCS-Y-0322 passthrough relay). Passthrough reads *record and "
        "forwards to FUN_004E0240 -> FUN_00DAE010. Fills one of the 3 cluster gaps left "
        "unbound in 0x01C3..0x01DF.; likely_role=Map action-system request (cluster member,"
        " size 0x18 single-record)",
        "client_context=Neutral ItemSearch marketplace context; producer=FUN_004C73D0 "
        "constructs 0x01DB and reaches FUN_004C7150 -> FUN_004E0240 -> FUN_00DAE010.; "
        "field_geometry=IPC 24 bytes; application 8 bytes: explicit zero u32 at +0 and four"
        " unresolved bytes at +4.; "
        "client_contract=xivl-client-structs:manifests/structs.json#BCS-S-0367; "
        "framing_contract=xivl-client-structs:docs/search-recruitment-wire-contract.md#outbound-framing;"
        " semantic_boundary=The detailed ItemSearch operation remains unresolved. Selected "
        "native framing implies a 40-byte subevent; the retained catalog length 24 has no "
        "joined capture witness and is not validated by this static construction.; "
        "confidence_boundary=the native emitter anchor does not confirm the retained packet"
        " name, implementation label, server policy or acceptance; "
        "decomp_source=final_gap_outbound_scan; bcsy_ref=BCS-Y-0327; "
        "related_catalog_refs=BCS-Y-0322",
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
        "0x00e1",
        "ActorDoEmotePacket",
        "_0x00E1",
        None,
    ),
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
        "0x0147",
        "InventorySetEndPacket",
        "_0x0147",
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
        "_0x018D",
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
    ("MapClientbound", "0x0147", "_0x0147"): ("InventorySetEndPacket",),
    ("MapClientbound", "0x018b", "SetGroupLayoutIDPacket"): ("SetGroupLayoutIdPacket",),
    ("MapServerbound", "0x012f", "WorkStateUpdatePacket"): (
        "ParameterDataRequestPacket",
    ),
    ("MapServerbound", "0x0135", "AchievementRateRequestPacket"): (
        "AchievementProgressRequestPacket",
    ),
}

CONFIDENCE_OVERRIDES = [
    ("MapClientbound", "0x0147", "_0x0147", "implemented", "pcap_observed"),
    ("MapServerbound", "0x0002", "_0x0002Handler", "implemented", "decomp_routed"),
]

DECOMP_ANCHOR_OVERRIDES = [
    ("MapServerbound", "0x0002", "_0x0002Handler", "FUN_004E3910"),
    ("MapServerbound", "0x0007", "ZoneInCompletePacket", "FUN_00586F40"),
    ("MapServerbound", "0x00ca", "UpdatePlayerPositionPacket", "FUN_00589030"),
    ("MapServerbound", "0x00cc", "LockTargetPacket", "FUN_00561BB0"),
    ("MapServerbound", "0x00cd", "SetTargetPacket", "FUN_0075EB30"),
    ("MapServerbound", "0x0130", "UpdateGroupPacket", "FUN_0075E8D0"),
    ("MapServerbound", "0x01c3", "StartRecruitingRequestPacket", "FUN_004B7A20"),
    ("MapServerbound", "0x01c4", "_0x01C4Handler", "FUN_004B7AD0"),
    ("MapServerbound", "0x01c5", "_0x01C5Handler", "FUN_004B7990"),
    ("MapServerbound", "0x01c8", "RecruitmentDetailsRequestPacket", "FUN_004B7B60"),
    ("MapServerbound", "0x01d0", "FaqListRequestPacket", "FUN_004B7F90"),
    ("MapServerbound", "0x01d1", "FaqBodyRequestPacket", "FUN_004B8030"),
    ("MapServerbound", "0x01d2", "GMTicketIssuesRequestPacket", "FUN_004B80E0"),
    ("MapServerbound", "0x01d3", "_0x01D3Handler", "FUN_004B8180"),
    ("MapServerbound", "0x01d4", "_0x01D4Handler", "FUN_004B8210"),
    ("MapServerbound", "0x01d5", "GMSupportTicketPacket", "FUN_004B82A0"),
    ("MapServerbound", "0x01d6", "_0x01D6Handler", "FUN_004B8370"),
    ("MapServerbound", "0x01db", "_0x01DB", "FUN_004C73D0"),
    ("MapServerbound", "0x0001", "PingPacket", "FUN_004E20A0"),
    ("MapClientbound", "0x00e1", "_0x00E1", "FUN_0058C690"),
    ("MapClientbound", "0x0144", "SetActorSubStatePacket", "FUN_008A32C0"),
    ("MapClientbound", "0x0179", "SetActorStatusAllPacket", "FUN_008A3630"),
    ("MapServerbound", "0x00ce", "_0x00CEHandler", "FUN_00763DC0"),
    ("MapClientbound", "0x01cb", "_0x01CB", "FUN_00DB8FA0"),
]


ZONE_DUMMY_CLUSTER_PRIOR = {
    "0x01c3": ("StartRecruitingResponse", "MapServerOpcode::StartRecruitingResponse"),
    "0x01c4": ("EndRecruitmentPacket", "MapServerOpcode::EndRecruitment"),
    "0x01c5": ("RecruiterStatePacket", "MapServerOpcode::RecruiterState"),
    "0x01c6": (None, None),
    "0x01c7": (None, None),
    "0x01c8": (
        "CurrentRecruitmentDetailsPacket",
        "MapServerOpcode::CurrentRecruitmentDetails",
    ),
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
    "0x01d7": (
        "ItemSearchResultsBeginPacket",
        "MapServerOpcode::ItemSearchResultsBegin",
    ),
    "0x01d8": ("ItemSearchResultsBodyPacket", "MapServerOpcode::ItemSearchResultsBody"),
    "0x01d9": ("ItemSearchResultsEndPacket", "MapServerOpcode::ItemSearchResultsEnd"),
    "0x01da": ("RetainerResultEndPacket", "MapServerOpcode::RetainerResultEnd"),
    "0x01db": ("RetainerResultBodyPacket", "MapServerOpcode::RetainerResultBody"),
    "0x01dc": ("RetainerResultUpdatePacket", "MapServerOpcode::RetainerResultUpdate"),
    "0x01dd": ("RetainerSearchHistoryPacket", "MapServerOpcode::RetainerSearchHistory"),
    "0x01de": (None, None),
    "0x01df": (
        "PlayerSearchInfoResultPacket",
        "MapServerOpcode::PlayerSearchInfoResult",
    ),
}


# Pcap joins use (direction, opcode) only; PCAP_AMBIGUOUS marks shared services.
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
LOGIN_CAPTURE_SHA256 = (
    "28e06b54fe559870031f077f8549b9244caafa7e5177dbca08a7feae6c2b1b62"
)
LOGIN_LANE_EVIDENCE = "xivl-captures:derived/lane_observations.json"
LOGIN_OBSERVATION_EVIDENCE = "xivl-captures:derived/observations.json"
LOGIN_PREZONE_ATTRIBUTIONS = [
    ("MapServerbound", "0x0133", "GroupWorkUpdatePacket", "c2s", 72),
    ("MapServerbound", "0x0006", "LangaugeCodePacket", "c2s", 40),
    ("MapServerbound", "0x01cb", "_0x01CBHandler", "c2s", 40),
    ("MapServerbound", "0x01ce", "_0x01CEHandler", "c2s", 40),
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
    ("MapClientbound", "0x0134", "SetActorStatePacket", "s2c", 40),
    ("MapClientbound", "0x019d", "SetPlayerTitlePacket", "s2c", 40),
    ("MapClientbound", "0x01cb", "_0x01CB", "s2c", 680),
    ("MapClientbound", "0x01ce", "_0x01CE", "s2c", 840),
]
LOBBY_CENSUS_COMMIT = "458115d9682a76d4540392ba224d30ba17722b1f"
LOBBY_CENSUS_EVIDENCE = (
    f"xivl-captures@{LOBBY_CENSUS_COMMIT}:"
    "studies/lobby-handshake-triage/derived/record-census.md"
    "#client-dispatch-correspondence"
)
LOBBY_CENSUS_ATTRIBUTIONS = [
    ("LobbyServerbound", "0x0003", "_0x0003Handler", 48),
    ("LobbyServerbound", "0x0004", "SelectCharacterPacket", 56),
    ("LobbyServerbound", "0x0005", "SessionPacket", 176),
    ("LobbyClientbound", "0x000c", "AccountListPacket", 624),
    ("LobbyClientbound", "0x000d", "CharacterListPacket", 976),
    ("LobbyClientbound", "0x000f", "SelectCharacterConfirmPacket", 184),
    ("LobbyClientbound", "0x0015", "WorldListPacket", 528),
    ("LobbyClientbound", "0x0016", "ImportListPacket", 528),
    ("LobbyClientbound", "0x0017", "RetainerListPacket", 496),
]

LANE_MOVES = {
    "0x0007": ("DeleteAllActorsPacket", 12),
    "0x0008": ("_0x0008", 19),
    "0x0143": ("DeleteGroupPacket", 12),
    "0x018a": ("_0x018A", 1),
}
LANE_UNRESOLVED = {"0x0188"}


CLIENT_SEMANTICS_SPECIAL_NOTES = {
    "s2c-0144": (
        "retail_client_analysis=the 8-byte application payload retains structural byte labels, "
        "but FUN_0075A9A0 constructs ChangeActorSubStatModeBorderReceiver from application "
        "offset 4 and FUN_008A32C0 applies only that byte through FUN_006EECB0 to "
        "CharaSubStatStorage+0x18; callback=FUN_008A3310->FUN_007084E0 fires "
        "_onChangeSubStatMode for a changed byte; chant_boundary=application offset 1 has the "
        "historical chantId layout label but this retained route does not copy it into the "
        "status-word bits 8..15 or establish a chant enum; observed=60 retained 40-byte "
        "subpackets with 8 application bytes; client_only=layout, store, and callback do not "
        "establish server behavior or packet ordering"
    ),
    "s2c-0179": (
        "retail_client_analysis=the 40-byte application payload is u16 statusIds[20]; "
        "FUN_008A3350 maps each nonzero identifier through the client status-data table, "
        "retains its resolved handle and slot byte, and FUN_008A3630 passes them through "
        "FUN_007084B0 to FUN_00707D60; storage=FUN_00707D60 replaces one full u32 status "
        "reference and _onChangeSubStatStatus receives one-based slot plus whole new and old references; "
        "chant_reader=FUN_006F9EC0 kind 1 selects bits 12..15 with >> 12 & 0xf, kind 2 "
        "selects bits 8..11 with >> 8 & 0xf, and zero or unsupported kinds return nil; "
        "overlap=FUN_006F9F70 also reads bits 8..11,14..15,12..13 as an object descriptor; "
        "naming=the two nibble domains remain numeric because no table or branch maps values "
        "1..15 to stable semantic nouns; observed=55 retained 72-byte subpackets with 40 "
        "application bytes and only one nonzero retained status identifier; client_only=lookup, "
        "storage, and reader projections do not establish server behavior or packet ordering"
    ),
    "s2c-00e1": (
        "retail_client_analysis=FUN_004DC690 case 12 resolves the packet actor through "
        "FUN_004D9910 and calls CharaElement slot 9 FUN_0058CCA0; case 0x00E1 at "
        "VA 0x0058D020 reads application u32 +0, u32 +4, and u16 +8 before calling "
        "FUN_0058C690; wire_application=effect-or-action selector u32 at +0, target actor "
        "u32 at +4, staged control u16 at +8, and six unread trailing bytes; "
        "staging=resolved actor becomes source, packet +4 becomes target, packet +0 becomes "
        "effect-or-action value, row count is fixed to one, and FUN_00585800 derives the "
        "record+0x04 visual/action type; producer_difference=0x00E0 calls FUN_0058C690 "
        "with the same packet selector and target but forces control zero, while 0x00DA "
        "forces both source and target to the resolved actor and forces control zero; "
        "retained_fields=record+0x04 "
        "visual/action type,+0x0c source,+0x10 effect-or-action,+0x30 row count,+0x32 "
        "control,+0x38 first target; producer_identity=wire opcode is dropped, so an 0x00E1 "
        "record with zero control cannot be distinguished from a matching 0x00E0 record, "
        "and a matching self-target zero-control record cannot be distinguished from 0x00DA; "
        "presentation=FUN_005901D0 queue -> FUN_0058DA10 -> Scene op 4 -> FUN_00662D30 "
        "case 4 -> FUN_00846080 -> FUN_00845E80 CharaActionQue insertion; observed=3 "
        "retained 48-byte subpackets across 3 captures with 16 application bytes and a zero "
        "six-byte tail; naming=placeholder retained because the generic action-family route "
        "does not establish an emote operation and capture filenames are not semantic proof; "
        "prior_label=ActorDoEmotePacket / MapServerOpcode::ActorDoEmote; conflict=imported "
        "packet noun and implementation anchor are unsupported by retail client semantics; "
        "client_only=queue and presentation routing do not establish server behavior"
    ),
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
        "u64_low_component=opaque first GroupBase-reference identity component copied from a matched "
        "group-list node at +0x10 and used as the unsigned secondary ordering component; "
        "u64_high_component=opaque second GroupBase-reference identity component copied from the same "
        "node at +0x14 and used as the unsigned primary ordering component; "
        "component_boundary=zero-zero is the null pair, but all construction, writer, comparator, reader, "
        "direct-caller, and callback-preparation paths preserve both dwords without exposing an independent "
        "domain for either component; "
        "consumer_boundary=positive callback consumer and field domains, with no Group::SharedWork "
        "virtual call in the commit body and both u64 components remaining opaque; "
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
        "retail_client_analysis=FUN_00578C90 switches application u32 +0x00; "
        "application_payload=8 bytes; third_scalar=packet-header u32 +0x08, not application +0x08; "
        "derived_value=zero when application +0x04 is 0xffffffff, otherwise header_clock plus application_delta; "
        "route_state=structurally bounded 0x3c-byte RaptureElementContainer+0x510 member; "
        "separate_member=0x58-byte RaptureUserControl at RaptureElementContainer+0x17758; "
        "subop_routes=0x00..0x0f write a sixteen-entry u32 vector at index subopcode through FUN_0075F3E0; "
        "the runtime-length error path still reaches the raw write; paired reader=FUN_0075F420; "
        "occupancy_reader=MyPlayer _getOccupancyContentsTime decrements Lua arguments 1..16 to native "
        "indices 0..15, deterministically matching sixteen documented client presentation rows; "
        "scalar_readers=0x10 _getNormalBehestTime,0x11 _getCompanyBehestTime,0x12 _getWarpRecastTime,"
        "0x16 _getNMRushUpdateTime from same-owner slots +0x10/+0x14/+0x18/+0x1c; "
        "presentation=Lua timer paths consume stored values as endpoints; clock_contract=the packet-header "
        "clock is Unix-compatible whole seconds and application values are offsets in the same integer unit; "
        "captured_0x12_delta=900 produces a stored endpoint about 900 seconds after frame completion; "
        "timer_boundary=no authoritative eligibility, reset policy, or server scheduling established; "
        "actioncheck=0x13 queries on 0xffffffff or writes ActionCheck u32 +0x38; predicate=signed greater than zero; "
        "positive_effect=insert absent actor key during battle-result record staging and erase equal actor keys "
        "during queued-record drain; suppressed_effect=zero and negative values cause no local container mutation; "
        "selector_exclusions=0x7c000062,0x10000000..0x10ffffff,0x14000000..0x14ffffff; "
        "null_state_exclusion=queued-record drain also excludes null route state +0x4; "
        "result_boundary=insert iterator local and unused, erase count ignored; "
        "edge_boundary=no packet emission, Lua/N-API result, UI, movement, animation, targeting, or actor-state edge; "
        "0x14 guards zero-to-one around FUN_0075B300 setup slots +0x04/+0x10/+0x1c/+0x28, "
        "whose resolved RaptureUserControl targets increment u32 counts +0x18/+0x2c/+0x40/+0x54 "
        "and register RaptureCommands callbacks where applicable; 0x15 reaches FUN_00576020 and "
        "FUN_0075B360 for inverse count-tested decrements and guard clear; observed=9 retained "
        "40-byte subpackets across 8 captures; "
        "retained_subops=0x14 x8, 0x12 x1; retained_values=header/app_delta pairs "
        "50e0f492/15,50e0e9d5/15,50e11de8/2,50e0eddb/900,50e0eddb/2,"
        "50e0f7f2/2,50e0eb11/2,50e0ec64/2,50e15b05/2; retained_order=return_to_inn "
        "has 0x12 then 0x14 in one frame; captured_0x12_store=0x50e0f15f; "
        "corpus_aggregate=9 events; unresolved=+0x510 state class, computed or dynamic "
        "indirect ActionCheck consumers, high-level ActionCheck ordered-container purpose; "
        "first_reader_wrappers=FUN_00705450,FUN_007054D0,"
        "FUN_00705510,FUN_00705550,FUN_00706A00; "
        "semantic_status=decomp_routed; naming=placeholder retained because "
        "retail does not establish a stable packet noun; candidate_label=SetControlStatePacket "
        "is an imported source-manifest term, not retail-proven; client_only=multiplexed "
        "timer/config/command route does not establish server behavior, server policy, server scheduling, "
        "or login causality; "
        "prior_label=MapServerOpcode::SetControlState; "
        "conflict=implementation anchor and packet noun lack a source-owned declaration; "
        "client_evidence=BCS-Y-0584,BCS-Y-0990,BCS-Y-0991,BCS-Y-0992,BCS-Y-0993,"
        "BCS-Y-0996,BCS-Y-0997,BCS-Y-0998"
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
        "retail_client_analysis=FUN_004DC690 case 0x018d calls FUN_00575550 and "
        "FUN_0055CF70; wire_layout=data/s2c_018d_wire_layout.json; "
        "subpacket_size=0x2b8; application_size=0x298; application_header=0x10; "
        "record_offset=0x10; record_stride=0x28; wire_capacity=16; "
        "count_offset=0x290; count_width=1; count_load=MOVSX; count_check=none; "
        "storage_record_offset=0x18; storage_record_stride=0x78; "
        "observed_events=592; observed_counts=1x415,2x177; "
        "first_outward_consumer=native MapScreenControl UI property presentation; "
        "presentation_projection=wire +0x14 and +0x1c become X:Int and Z:Int after "
        "CVTTSS2SI; middle_projected_float=not read by the presentation consumer; "
        "record_lookup=wire +0x00 is the primary tagged-referent selector, +0x08 "
        "is fallback only after signed -1, and +0x0c is eligibility-only; "
        "helper_outputs=resolved Utf8String minus every literal !!! becomes Text:String, "
        "and matched referent +0x00 becomes Layout:Int; "
        "template_boundary=MapMarkerParty is a Template:String value, not a packet "
        "or native class name; "
        "static_resource_boundary=no runtime edge joins marker resources to 0x018D; "
        "semantic_status=decomp_routed; name_boundary=placeholder retained; "
        "client_only=route, layout, and presentation do not establish wire field "
        "nouns or server behavior"
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

BATTLE_EFFECT_PRESENTATION_NOTES = (
    "concrete_visual=FUN_00843B50 constructs CharaActionVisual, whose primary slots +0x54, "
    "+0x58, and +0x60 resolve to FUN_00798BF0, FUN_00799C90, and FUN_00798A40; "
    "resource_behavior=the +0x54 and +0x58 paths call FUN_00D39290 and "
    "FUN_006320C0 for resource lookup and slot assignment, +0x58 explicitly builds a "
    "/client/vfx/ path, and +0x60 only dispatches bounded category names; "
    "queue_back_pointer=visual +0x24 resolves to CharaActionQue slot 9 FUN_00843DE0 "
    "and visual +0x1c resolves to slot 7 FUN_00844660; "
    "controller_targets=slots 2..5 reach visual dispatch and local flags, "
    "RaptureSchEffectController +0x18 resolves to membership test FUN_0080B6C0, slot 11 "
    "reaches FUN_00846220 then constant-one slot 10 FUN_007254A0, and slot 12 reaches "
    "FUN_00843E20 then visual record accessor FUN_00799FE0; "
    "unresolved_virtuals=factory-created action-object +0x2c, +0x34, and related calls "
    "remain runtime-polymorphic; presentation_boundary=the concrete route proves "
    "category-specific visual/VFX resource lookup and load-assignment attempts plus local "
    "queue flag updates, not an exact animation resource, named controller state "
    "transition, completion callback, or restored producer opcode"
)


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
            part.strip() for part in entry.get("notes", "").split(";") if part.strip()
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
    # An empty expected prefix is only valid for a pristine empty field.  Do
    # not treat it as a wildcard, or an unrelated note would be overwritten
    # and a rerun could duplicate the managed block.
    if not expected_old:
        if not current:
            return new_notes, "applied"
        return current, "mismatch"
    # Pcap reconciliation removes this leading evidence token after overrides.
    if new_notes.startswith(expected_old + ";") and current.startswith(
        new_notes[len(expected_old) + 1 :].lstrip()
    ):
        return current, "skipped"
    if current.startswith(expected_old):
        return new_notes + current[len(expected_old) :], "applied"
    return current, "mismatch"


def apply_client_semantics(top: dict) -> tuple[int, int]:
    """Attach the client-body evidence to catalog rows."""
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

        parts = [
            part.strip() for part in entry.get("notes", "").split(";") if part.strip()
        ]
        parts = [
            part
            for part in parts
            if not part.startswith("client_semantics_evidence=")
            and not part.startswith("dependency_status=")
        ]
        if row["id"] in {"s2c-00da", "s2c-00e1"}:
            presentation_keys = (
                "concrete_visual=",
                "resource_behavior=",
                "queue_back_pointer=",
                "controller_targets=",
                "unresolved_virtuals=",
                "presentation_boundary=",
            )
            parts = [part for part in parts if not part.startswith(presentation_keys)]
            parts.extend(
                part.strip()
                for part in BATTLE_EFFECT_PRESENTATION_NOTES.split(";")
                if part.strip()
            )
        if row["status"] == "closed":
            parts = [
                part
                for part in parts
                if not part.startswith("decomp_anchor_evidence=")
                and not part.startswith("decomp_anchor_locator=")
            ]
        elif not any(part.startswith("decomp_anchor_evidence=") for part in parts):
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
        if row["id"] in {
            "s2c-00da",
            "s2c-00e1",
            "s2c-0187",
            "s2c-018a",
            "s2c-018b",
            "s2c-018d",
            "s2c-018f",
            "s2c-0190",
            "s2c-0191",
            "s2c-0193",
            "s2c-0196",
            "s2c-01cb",
            "c2s-00ce",
            "c2s-012d",
        }:
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
    """Apply the battle-result route and field contract."""
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


def apply_achievement_lifecycle(top: dict) -> tuple[int, int]:
    """Apply the bounded achievement request and update routes."""
    evidence = json.loads(ACHIEVEMENT_LIFECYCLE_PATH.read_text(encoding="utf-8"))
    applied = 0
    errors = 0

    for row in evidence["rows"]:
        matches = [
            entry
            for entries in top["lists"].values()
            for entry in entries
            if entry["opcodeHex"].lower() == row["opcodeHex"].lower()
            and entry["direction"] == row["direction"]
            and entry.get("service") == "map"
        ]
        if len(matches) != 1:
            print(
                f"  WARN: achievement row {row['id']} matched {len(matches)} catalog rows"
            )
            errors += 1
            continue

        entry = matches[0]
        entry["name"] = row["name"]
        entry["decompAnchor"] = row["function"]
        entry["confidence"] = (
            "confirmed" if row["nameConfidence"] == "confirmed" else "decomp_routed"
        )
        if row["direction"] == "serverbound":
            entry["observedIn"] = []
            entry["payloadLengths"] = []

        observed = row["observedOccurrences"]
        captures = row["captureCount"]
        samples = row["retainedSamples"]
        parts = [
            f"achievement_lifecycle=data/achievement_lifecycle.json#{row['id']}",
            f"retail_client_analysis={row['flow']}",
            f"wire_application={row['fields']}",
            f"application_size={row['applicationSize']}",
            f"observed_occurrences={observed}",
            f"capture_count={captures}",
            f"retained_samples={samples}",
        ]
        if "builderRecordSize" in row:
            parts.append(f"builder_record_size={row['builderRecordSize']}")
        if "observedSubpacketSize" in row:
            parts.append(f"observed_subpacket_size={row['observedSubpacketSize']}")
        if observed == 0:
            parts.append("no_pcap_evidence")
        if row["direction"] == "serverbound":
            semantic_id = f"c2s-{row['opcodeHex'][2:]}"
            parts.extend(
                [
                    f"client_semantics_evidence=data/client_opcode_semantics.json#{semantic_id}",
                    "dependency_status=closed",
                ]
            )
        if row["nameConfidence"] == "tentative_client_operation":
            parts.extend(
                [
                    "naming=tentative, derived from the registered client Lua N-API operation",
                    "exact server method and request policy remain unproven",
                ]
            )
        if row["id"] == "c2s-0135-achievement-rate-request":
            parts.extend(
                [
                    "prior_label=BindingSubscribeRequestPacket",
                    "conflict=prior implementation label unsupported by retail",
                ]
            )
        entry["notes"] = "; ".join(parts)
        applied += 1

    return applied, errors


def apply_dispatch_catalog_completion(top: dict) -> int:
    """Insert missing structural routes without replacing existing evidence."""
    inserted = 0
    evidence = json.loads(ZONE_DISPATCH_PATH.read_text(encoding="utf-8"))
    entries = top["lists"]["MapClientbound"]
    for case in evidence["cases"]:
        if case["is_catchall"]:
            continue
        for opcode_hex in case["opcodes"]:
            if opcode_hex in evidence.get("catalog_exclusions", {}):
                continue
            opcode = int(opcode_hex, 16)
            if any(entry["opcode"] == opcode for entry in entries):
                continue
            entries.append(
                {
                    "name": f"_0x{opcode:04X}",
                    "opcode": opcode,
                    "opcodeHex": f"0x{opcode:04x}",
                    "service": "map",
                    "direction": "clientbound",
                    "implementationAnchor": None,
                    "decompAnchor": None,
                    "observedIn": [],
                    "payloadLengths": [],
                    "confidence": "decomp_routed",
                    "notes": (
                        f"dispatch_slot_evidence=data/zone_dispatch_map.json#cases.{case['case']}; "
                        f"retail_client_analysis=ZoneProtoDown FUN_00DBFD10 opcode {opcode_hex} "
                        f"selects case {case['case']} and callback slot {case['vtable_slot']}; "
                        "naming=placeholder retained; dispatch_boundary=structural callback slot "
                        "does not identify an application handler, payload layout, packet meaning "
                        "or server behavior; no_pcap_evidence"
                    ),
                }
            )
            inserted += 1

    curated = json.loads(DECOMP_OPCODES_PATH.read_text(encoding="utf-8"))
    for row in curated:
        if row.get("source") != "clientbound_dispatch_completion":
            continue
        bucket = {"world": "WorldClientbound"}[row["service"]]
        entries = top["lists"][bucket]
        if any(entry["opcode"] == row["opcode"] for entry in entries):
            continue
        entries.append(
            {
                "name": row["name"],
                "opcode": row["opcode"],
                "opcodeHex": row["opcodeHex"].lower(),
                "service": row["service"],
                "direction": row["direction"],
                "implementationAnchor": None,
                "decompAnchor": None,
                "observedIn": [],
                "payloadLengths": [],
                "confidence": "decomp_routed",
                "notes": "dispatch_slot_evidence=data/decomp_opcodes.json#world.clientbound.0x0001; "
                + row["evidence"]
                + "; no_pcap_evidence",
            }
        )
        inserted += 1
    for bucket in ("MapClientbound", "WorldClientbound"):
        top["lists"][bucket].sort(key=lambda entry: (entry["opcode"], entry["name"]))
    return inserted


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
            "naming=placeholder retained because no retail packet class name is established",
        ]
        if prior_name:
            parts.append(f"prior_packet_label={prior_name}")
        if prior_anchor:
            parts.append(f"prior_label={prior_anchor}")
        if prior_name or prior_anchor:
            parts.append(
                "conflict=imported packet noun and implementation anchor are unsupported by the retail no-op callback"
            )
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
            parts.append(
                "client_semantics_evidence=data/client_opcode_semantics.json#s2c-01cb"
            )
        if opcode == 0x01CF:
            parts.append(
                "capture_layout_evidence=xivl-captures:derived/payload_layouts.json#layouts.s2c.0x01cf"
            )
        entry["name"] = f"_0x{opcode:04X}"
        entry["implementationAnchor"] = None
        entry["decompAnchor"] = function
        entry["confidence"] = "decomp_routed"
        entry["notes"] = "; ".join(parts)
        applied += 1

    entries.sort(key=lambda entry: (entry["opcode"], entry["name"]))
    return applied, inserted


def apply_low_pair_staging_contract(top: dict) -> int:
    """Apply the bounded low-opcode array and range-erase findings."""
    evidence = "xivl-decomp:docs/net/low-opcode-pair-staging.md"
    contracts = {
        0x0006: (
            "FUN_0081EB90",
            "case_0006=FUN_004DC690 at 0x004DC7D6 passes case-entry EDI+0x17810 to FUN_0081EB90; "
            "range_effect=FUN_00440940 erases the valid full staged range by setting end to begin; "
            "no_per_entry_visitor; application_reads=none in the checked case and erase path",
        ),
        0x0008: (
            "FUN_004DC690",
            "case_0008=0x004DC7E6; application_count=u8 at +0; "
            "application_values=u32 at +4+4*i; application_flags=u8 at +0x24+i; "
            "count_reloaded_after_each_call; no_local_packet_length_or_8_or_11_entry_clamp; "
            "retained_samples=19 with count 1..8, eight zero flag bytes and 48 application bytes; "
            "framing=80-byte subevent,64-byte game message,48-byte application; "
            "lane_ruling=moved_from_WorldClientbound; main_lane_count=19; chat_lane_count=0",
        ),
        0x0009: (
            "FUN_004DC690",
            "case_0009=0x004DC82D; fixed_count=16; application_values=u32 at +4*i; "
            "application_flags=u8 at +0x40+i; minimum_application_read=80; no_local_packet_length_check",
        ),
        0x000A: (
            "FUN_004DC690",
            "case_000a=0x004DC869; fixed_count=32; application_values=u32 at +4*i; "
            "application_flags=u8 at +0x80+i; minimum_application_read=160; "
            "body_contract=reused from xivl-client-structs:manifests/low_switch_remaining_cases.json#case_table",
        ),
        0x000B: (
            "FUN_004DC690",
            "case_000b=0x004DC89D; fixed_count=64; application_values=u32 at +4*i; "
            "application_flags=u8 at +0x100+i; minimum_application_read=320; "
            "no_local_packet_length_check; native_read_extent_is_not_an_observed_packet_size",
        ),
    }
    prior_notes = {
        0x0006: (
            "pcap_only_no_reference_match; service_inferred=map_default_guess; "
            "role=server-to-client mass actor-deletion start marker; opens a delete sequence "
            "whose body packets list actors to exempt and whose end marker (0x0007) commits it. "
            "8-byte body. Same wire integer as the serverbound language-code opcode, "
            "disambiguated by direction. Observed across 9 captures."
        ),
        0x0008: (
            "role=server-to-client mass actor-deletion body (variable-count), game-message opcode"
            " 0x0008. Same numeric value as the transport pong subpacket, but at a different "
            "layer: the transport pong subpacket is the **subpacket type** (raw transport ping, "
            "used in `SubPacket::new_with_flag(false, ...)`), whereas this mass-delete game "
            "message is the **game-message opcode** field inside a type-3 (game-message) "
            "subpacket. The dispatcher routes subpacket-type=8 to `handle_ping` and "
            "subpacket-type=3 + game-message-opcode=0x0008 to the Mass Delete Actor body path. "
            "Despite an x1 (8-byte, single u32 actor) label, retail captures "
            "(`ffxiv_traces/*.pcapng` 0x0008 OUT records) confirm the actual on-the-wire shape is"
            " a **variable-count** list with capacity 11: `u32 count + u32[count] actor_ids + "
            "zero pad to 48-byte body` Body is always 48 bytes (SubPacket size 0x50). `count` is "
            "1..=11 across the surveyed captures. Retail uses this 19x - far more than "
            '0x0009/0x000A/0x000B combined - making it the de-facto "standard" Mass Delete Body '
            "opcode for typical zone-transition exempt lists. The fixed-slot _X16/_X32/_X64 "
            "variants are reserved for batches that exceed 11 actors.; "
            "lane_ruling=moved_from_WorldClientbound; main_lane_count=19; chat_lane_count=0"
        ),
        0x0009: (
            "pcap_only_no_reference_match; service_inferred=map_default_guess; "
            "role=server-to-client mass actor-deletion body carrying up to 16 actor ids (0x10 "
            "hex); 80-byte body (16 x u32 id + 16 pad). Observed 2x during large zone "
            "transitions."
        ),
        0x000A: (
            "pcap_only_no_reference_match; service_inferred=map_default_guess; "
            "role=server-to-client mass actor-deletion body carrying up to 32 actor ids (0x20 "
            "hex); 160-byte body (32 x u32 id + 32 pad). Observed 2x."
        ),
        0x000B: (
            "role=server-to-client mass actor-deletion body carrying up to 64 actor ids (0x40 "
            "hex); 320-byte body (64 x u32 id + 64 pad) by symmetry with the x16 and x32 "
            "variants. inferred_not_observed_in_corpus."
        ),
    }
    for opcode, (function, contract) in contracts.items():
        rows = [r for r in top["lists"]["MapClientbound"] if r["opcode"] == opcode]
        if len(rows) != 1:
            raise ValueError(
                f"low pair staging requires one Map clientbound 0x{opcode:04x}"
            )
        row = rows[0]
        row["decompAnchor"] = function
        row["confidence"] = "decomp_routed"
        managed_notes = (
            "retail_client_analysis="
            + contract
            + "; staging=local u32/u8 pair supplied to FUN_0081F090; "
            "queue_owner=case-entry EDI+0x17810, absolute owner binding unproved; "
            "construction_and_growth_helpers=uninspected; pair_meanings_and_actor_effects=unproved; "
            "sequence_0007=outside this proof; client_contract=" + evidence
        )
        row["notes"], status = swap_managed_prefix(
            row.get("notes", ""), prior_notes[opcode], managed_notes
        )
        if status == "mismatch":
            raise ValueError(
                f"low pair staging notes do not match the managed prefix for 0x{opcode:04x}"
            )
    samples_path = OPCODES_PATH.parent / "data/vendor/captures/payload_samples.json"
    samples = json.loads(samples_path.read_text(encoding="utf-8"))["samples"]["s2c"][
        "0x0008"
    ]
    if samples["sampleCount"] != 19 or len(samples["samples"]) != 19:
        raise ValueError(
            "low pair staging requires the pinned 19-record 0x0008 product"
        )
    row = next(r for r in top["lists"]["MapClientbound"] if r["opcode"] == 8)
    row["observedIn"] = sorted({s["capture"] for s in samples["samples"]})
    row["payloadLengths"] = sorted({s["sub_size"] for s in samples["samples"]})
    return len(contracts)


def apply_e2_selector_contract(top: dict) -> int:
    """Attach the selected E2 branch contract while preserving later evidence."""
    rows = [r for r in top["lists"]["MapClientbound"] if r["opcode"] == 0xE2]
    if len(rows) != 1:
        raise ValueError("E2 selector contract requires one Map clientbound row")
    row = rows[0]
    managed_notes = (
        "retail_client_analysis=CharaElement slot 9 FUN_0058CCA0 case 0x0058CD81; "
        "application_selector=u32le at +0, read only for the local actor; "
        "local_0x15=FUN_00574ED0(receiver=[Chara+0x80],arg=0x15), then exit before state writes; "
        "local_0x16=FUN_00574EE0(receiver=[Chara+0x80],arg=0x16), then exit before state writes; "
        "local_other=OR bit0 at Chara+0x26D, call FUN_00586F40(parent,0x4FE); "
        "nonlocal=skip selector and local writes; "
        "final_state=byte1 at [parent+0x4E0]+0xBC only for local_other or nonlocal after normal returns; "
        "retained_samples=8 with selectors 0x02 x6 and 0x0F x2; "
        "framing=40-byte subevent,24-byte game message,8-byte application; "
        "dynamic_bridge_effects_state_meanings_and_complete_warp=unproved; "
        "client_contract=xivl-decomp:docs/net/e2-selector-state.md"
    )
    row["notes"], status = swap_managed_prefix(row.get("notes", ""), "", managed_notes)
    if status == "mismatch":
        raise ValueError("E2 selector notes do not match the managed prefix")
    row["decompAnchor"] = "FUN_0058CCA0"
    row["confidence"] = "decomp_routed"
    return 1


def apply_e3_state_index_contract(top: dict) -> int:
    """Retain the E3 input, changed-state and separate table-field contracts."""
    rows = [r for r in top["lists"]["MapClientbound"] if r["opcode"] == 0xE3]
    if len(rows) != 1:
        raise ValueError("E3 state contract requires one Map clientbound row")
    row = rows[0]
    managed_notes = (
        "retail_client_analysis=CharaElement case 0xE3 calls FUN_00588A20; "
        "application_index=u32le at +0; admitted_index=unsigned 0..5; "
        "unchanged_index=no writes or helper calls; packed_state=Chara+0x270,mask0x7C0,shift6; "
        "scene_record=0x14 with two bytes {1,table_flag}, not the incoming index; "
        "table_flags=1,0,1,0,1,1; "
        "table_values=FFFFFFFF,FFFFFFFF,00000204,FFFFFFFF,00000215,FFFFFFFF; "
        "zero_flag_path=FUN_004D7310(parent), then nonnull receiver FUN_00563920(arg=Chara); "
        "tail_dispatch=slot7 with receiver Chara+0xBA0 and table_value as the stack argument; "
        "retained_samples=12 with index0 x3 and index2 x9 across seven captures; "
        "framing=40-byte subevent,24-byte game message,8-byte application; "
        "name_boundary=retained label, index status and forwarded resource meanings unproved; "
        "client_contract=xivl-decomp:docs/net/e3-state-index.md"
    )
    row["notes"], status = swap_managed_prefix(row.get("notes", ""), "", managed_notes)
    if status == "mismatch":
        raise ValueError("E3 state notes do not match the managed prefix")
    row["decompAnchor"] = "FUN_00588A20"
    row["confidence"] = "decomp_routed"
    return 1


def apply_e5_field_staging_contract(top: dict) -> int:
    """Keep the native E5 read extent separate from an observed packet length."""
    rows = [r for r in top["lists"]["MapClientbound"] if r["opcode"] == 0xE5]
    if len(rows) != 1:
        raise ValueError("E5 field staging requires one Map clientbound row")
    row = rows[0]
    managed_notes = (
        "retail_client_analysis=CharaElement FUN_0058CCA0 case 0x0058D246; "
        "application_fields=u8 at +0, u32 words at +8/+0xC, copied bytes at +0x18 with width32; "
        "native_min_application_read=56, game_message_read=72; native_extent_is_not_observed_size; "
        "string_length_word=FFFFFFFF at 0x00F67298, retained value selects strlen in FUN_00447260 BCS-Y-0311; "
        "string_termination=no local NUL or 32-byte scan bound proved; "
        "forwarded_arg0=only low8 bits established, upper24 unproved; "
        "forwarded_words=arg0,word_at_app8,word_at_appC,local_string_pointer; "
        "next_consumer=FUN_0058EB80 forwards unchanged words to FUN_00797C80 with receiver Chara+0xE60; "
        "consumer_time_units_presentation_and_raid_carrier=unproved; "
        "client_contract=xivl-decomp:docs/net/e5-field-staging.md; no_pcap_evidence"
    )
    row["notes"], status = swap_managed_prefix(
        row.get("notes", ""), "no_pcap_evidence", managed_notes
    )
    if status == "mismatch":
        raise ValueError("E5 staging notes do not match the managed prefix")
    row["decompAnchor"] = "FUN_0058CCA0"
    row["confidence"] = "decomp_routed"
    return 1


def apply_shadow_flag_contract(top: dict) -> int:
    """Retain the consumed byte despite zero-valued capture samples."""
    rows = [r for r in top["lists"]["MapClientbound"] if r["opcode"] == 0x17B]
    if len(rows) != 1:
        raise ValueError("Shadow flag contract requires one Map clientbound row")
    row = rows[0]
    managed_notes = (
        "native_route=FUN_004D8860 case0x17B reads game+0x10 then FUN_005752B0 slot89/+0x164; "
        "route_conditions=dispatcher entry gate, nonnull receiver+0x80 and matching LuaActorImpl implementation; "
        "retail_client_analysis=ChangeShadowActorFlagReceiver FUN_0089CC70 BCS-Y-0944 "
        "forwards to FUN_006DBE50 BCS-Y-1814; "
        "application_flag=u8 at +0, not unused padding or a proved boolean-only field; "
        "target_store=full byte at target+0x5D, including an equal value; "
        "changed_value=target virtual slot31 at +0x7C only when old!=new; "
        "pre_post_warp_slots=41/42 at +0xA4/+0xA8 are separate; "
        "remaining_application_bytes=7 with unproved meaning or required value; "
        "retained_samples=55 across16captures with zero application bytes; "
        "framing=40-byte subevent,24-byte game message,8-byte application; "
        "dynamic_callback_visible_effect_and_historical_sender_policy=unproved; "
        "client_contract=xivl-decomp:docs/net/shadow-flag-state.md"
    )
    row["notes"], status = swap_managed_prefix(row.get("notes", ""), "", managed_notes)
    if status == "mismatch":
        raise ValueError("Shadow flag notes do not match the managed prefix")
    row["decompAnchor"] = "FUN_0089CC70"
    row["confidence"] = "decomp_routed"
    return 1


def apply_retained_contracts(top: dict) -> int:
    """Attach bounded retail contracts without treating native sizes as captures."""
    structures = "xivl-client-structs:manifests/"
    search = structures + "search_recruitment_wire_contract.json"
    study = "xivl-captures:studies/group-combat-wire-contracts/README.md"
    outbound = {
        0x01C6: (
            "FUN_004B7CC0",
            40,
            24,
            "recruitment acceptance key; application+0x0c has no established write",
        ),
        0x01C7: (
            "FUN_004B7C10",
            72,
            56,
            "recruitment search controls through FUN_004CFDA0",
        ),
        0x01DC: (
            "FUN_004C7490",
            568,
            552,
            "PcSearch profile update through FUN_00693290 and FUN_00874570",
        ),
        0x01DD: (
            "FUN_004C7300",
            280,
            264,
            "PcSearch tagged filters through FUN_00693650 and FUN_008746E0; name-prefix and paging fields unproved",
        ),
        0x01DE: ("FUN_0085E1B0", 80, 64, "ItemSearchDirectPurchaseWidget request"),
        0x01DF: (
            "FUN_0051A970",
            296,
            280,
            "ItemSearchListWidget request; distinct from clientbound player-search results",
        ),
    }
    outbound_refs = {
        0x01C6: "BCS-Y-0324",
        0x01C7: "BCS-Y-0319",
        0x01DC: "BCS-Y-0326",
        0x01DD: "BCS-Y-0325",
        0x01DE: "BCS-Y-0320",
        0x01DF: "BCS-Y-0693",
    }
    inbound = {
        0x01C6: (
            "FUN_004C9D60",
            "first application byte is acceptance answer; zero emits text 0x0b8d; operation state becomes 12; full extent unknown",
        ),
        0x01C7: (
            "FUN_004B5F50",
            "30 rows of stride 80; count at application+0x960; total at +0x964; minimum read extent 2408, not an observed size",
        ),
        0x01C8: ("FUN_004C9BB0", "dispatch binding only; field layout unresolved"),
        0x01DA: (
            "FUN_004B6250",
            "dispatch binding only; commerce field semantics unresolved",
        ),
        0x01DB: (
            "FUN_004B6270",
            "dispatch binding only; commerce field semantics unresolved",
        ),
        0x01DC: (
            "FUN_004B6290",
            "dispatch binding only; commerce field semantics unresolved",
        ),
        0x01DD: (
            "FUN_004B62C0",
            "dispatch binding only; commerce field semantics unresolved",
        ),
        0x01DF: (
            "FUN_004C77B0",
            "12-byte header and 92-byte player rows; captured application extent 936; no native capacity clamp",
        ),
        0x01E0: (
            "FUN_004C78A0",
            "indexed comments with big-endian u16 lengths; flag 2 completes request; partial-record continuation unproved",
        ),
    }
    additions = {
        ("MapServerbound", 0x012D): (
            "direct_fallback=both _callServerOnCommand and _doServerOnCommand construct this opcode; "
            "direct_fields=+04 command binding reference,+08 self actor+14; event wrappers have a different +08 source; "
            "typed_tail=scalar 00, nil 05, control 06, item 07, adjacent-item group 08, item metadata 09, terminator 0f; "
            "native_boundary=selected runtime descriptor; named_definitions=s2c 0x0132; server_boundary=consumption of queued record; "
            "wire_contract=" + structures + "player_command_wire_contract.json"
        ),
        ("MapClientbound", 0x0132): (
            "application_layout=priority input u8 at +00,selector u8 at +01,name[32] at +02,unresolved tail[6] at +22; "
            "record_producer=NullActorImpl slot49 FUN_0076CA90; "
            "constructor=selector equals runtime byte[0134c3fe] chooses CommandBlock,otherwise CommandNonBlock; "
            "boundary=receipt does not prove the later selected descriptor; "
            "wire_contract=" + structures + "command_descriptor_registration.json; "
            "capture_study=xivl-captures:studies/command-registration/README.md"
        ),
        ("MapClientbound", 0x00D7): (
            "record_layout=application+0, stride 8, u32 value+0 and u8 index+4; count u8 at application+0x80; "
            "setter=FUN_00586870 accepts index below 28; full packet extent and server semantics unresolved; "
            "wire_contract=" + structures + "appearance_record_wire_contract.json"
        ),
        ("MapClientbound", 0x01A6): (
            "native_copy_extent=1520 application bytes; 20 rows of stride 76; first dword zero skips row; "
            "consumer=AreaBase ranking cache; no captured packet length; wire_contract="
            + structures
            + "hamlet_wire_contract.json"
        ),
        ("MapClientbound", 0x01A8): (
            "native_copy_extent=264 application bytes; selectors and factors drive client score lookup; "
            "totals_getter=consumes and frees player score cache; no captured packet length or server scoring policy; "
            "wire_contract=" + structures + "hamlet_wire_contract.json"
        ),
        ("MapClientbound", 0x017A): (
            "retained_corpus=275 packets,338 typed properties; application size 144, stream capacity 135; "
            "max_observed_stream=47 bytes and 6 properties; no type-20002 player-linkshell header or capacity split witnessed; "
            "capture_study=" + study
        ),
        ("MapClientbound", 0x0187): (
            "full_corpus=44 packets across 14 captures; prior 33-packet count describes the retained sample subset; "
            "sequence=occupancy precedes first damage result in selected combat examples; five same-group deletions in party example; "
            "boundary=no disengagement trigger or server ownership policy proved; capture_study="
            + study
        ),
        ("MapClientbound", 0x0195): (
            "retained_corpus=149 packets; application fields are u32 target and u16 indicator with zero u16 tail; "
            "combat_examples=100,100,65535,65535; intermediate damage results lack indicator packets; "
            "boundary=no percentage,rank,formula,per-hit cadence or sentinel meaning proved; capture_study="
            + study
        ),
    }

    def select(bucket: str, opcode: int) -> dict:
        rows = [row for row in top["lists"][bucket] if row["opcode"] == opcode]
        if len(rows) != 1:
            raise ValueError(
                f"retained contract requires one {bucket} 0x{opcode:04x} row"
            )
        return rows[0]

    for opcode, (function, ipc, application, role) in outbound.items():
        row = select("MapServerbound", opcode)
        row["implementationAnchor"] = None
        row["decompAnchor"] = function
        row["confidence"] = "decomp_routed"
        if not row["observedIn"]:
            row["payloadLengths"] = []
        row["notes"] = (
            f"retail_client_analysis={role}; native_ipc_size={ipc}; native_application_size={application}; "
            f"framing=observed subevent adds 16 bytes to IPC size; wire_contract={search}; "
            f"bcsy_ref={outbound_refs[opcode]}; "
            "client_only=construction does not establish server acceptance or policy"
        )
        if not row["observedIn"]:
            row["notes"] += "; no_pcap_evidence"
    for opcode, (function, role) in inbound.items():
        row = select("MapClientbound", opcode)
        if opcode == 0x01E0:
            row["name"] = "_0x01E0"
            row["implementationAnchor"] = None
            row["decompAnchor"] = function
            row["confidence"] = "decomp_routed"
            row["notes"] = "ZoneProtoDown_callback=FUN_00DB90F0 ret 0xc"
        additions[("MapClientbound", opcode)] = (
            f"application_consumer={function} through FUN_004CE190; {role}; "
            "dispatch_order=relative to ZoneProtoDown unestablished; "
            f"wire_contract={search}; server_behavior=unproved"
        )
    registration = select("MapClientbound", 0x0132)
    registration["notes"] = (
        "bcsy_ref=BCS-Y-0594,BCS-Y-0162,BCS-Y-1118,BCS-Y-0280,BCS-Y-0540; "
        "dispatch=FUN_004DC690 -> CharaElement slot9 FUN_0058CCA0 -> FUN_004D8860 case0132 -> "
        "FUN_00574FC0 -> NullActorImpl slot49 FUN_0076CA90; "
        "framing=72-byte subevent,56-byte game message,40-byte application; "
        "direction_asymmetry=c2s 0132 is distinct ItemWorkUpdatePacket via FUN_0075EAC0"
    )
    for (bucket, opcode), note in additions.items():
        row = select(bucket, opcode)
        # Replace the owned suffix so repeated generation is byte-stable.
        prefix = row.get("notes", "").split("; retained_contract=", 1)[0]
        row["notes"] = prefix + "; retained_contract=" + note
    return len(outbound) + len(additions)


def apply_map_social_neighborhood(top: dict) -> tuple[int, int]:
    """Replace inherited 0x01c9..0x01cf c2s nouns with bounded client evidence."""
    entries = top["lists"]["MapServerbound"]
    applied = 0
    errors = 0

    for opcode_hex, ruling in MAP_SOCIAL_NEIGHBORHOOD.items():
        matches = [entry for entry in entries if entry["opcodeHex"] == opcode_hex]
        if len(matches) != 1:
            print(
                f"  WARN: social neighborhood {opcode_hex} matched {len(matches)} rows"
            )
            errors += 1
            continue

        entry = matches[0]
        if entry.get("name") not in ruling["names"]:
            print(
                f"  WARN: social neighborhood {opcode_hex} has unexpected name "
                f"{entry.get('name')}"
            )
            errors += 1
            continue

        entry["name"] = ruling["name"]
        entry["implementationAnchor"] = None
        entry["decompAnchor"] = ruling["function"]
        entry["confidence"] = ruling["confidence"]
        entry["notes"] = ruling["notes"]
        applied += 1

    return applied, errors


def remove_note_token(notes: str, token: str) -> tuple[str, bool]:
    if notes == token:
        return "", True
    prefix = token + ";"
    if notes.startswith(prefix):
        return notes[len(prefix) :].lstrip(), True
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

    for (
        bucket,
        opcode_hex,
        name,
        wire_direction,
        payload_length,
    ) in LOGIN_PREZONE_ATTRIBUTIONS:
        selected = None
        for entry in top["lists"].get(bucket, []):
            if entry["opcodeHex"] == opcode_hex and entry["name"] == name:
                selected = entry
                break
        if selected is None:
            print(
                f"  WARN: no entry for login attribution {bucket} {opcode_hex} {name}"
            )
            errors += 1
            continue

        evidence = f"{LOGIN_LANE_EVIDENCE}#lanes/main/{wire_direction}/{opcode_hex}"
        observation_evidence = (
            f"{LOGIN_OBSERVATION_EVIDENCE}#inner_opcodes.{wire_direction}.{opcode_hex}"
        )
        attribution = "login_service_attribution=map_main_lane"
        evidence_token = f"login_evidence={evidence}"
        observation_token = f"login_payload_evidence={observation_evidence}"
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
        tokens = [attribution, evidence_token, identity_token]
        if opcode_hex in {"0x01cb", "0x01ce"}:
            tokens.append(observation_token)
        if bucket == "MapClientbound" and opcode_hex == "0x0003":
            tokens.append("wire_layout=data/s2c_0003_wire_layout.json")
        for token in tokens:
            notes = append_note_token(notes, token)
        selected["notes"] = notes

        for entries in top["lists"].values():
            for entry in entries:
                if (
                    entry is selected
                    or entry.get("direction") != selected.get("direction")
                    or entry.get("opcode") != selected.get("opcode")
                    or entry.get("service") == selected.get("service")
                    or entry.get("service") == "lobby"
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
                    competitor_notes = append_note_token(
                        competitor_notes, evidence_token
                    )
                    competitor_notes = append_note_token(
                        competitor_notes, identity_token
                    )
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


def apply_lobby_census_attributions(top: dict) -> tuple[int, int, int]:
    """Apply the sanitized port-54994 inner-route census."""
    applied = 0
    skipped = 0
    errors = 0
    evidence_token = f"lobby_census_evidence={LOBBY_CENSUS_EVIDENCE}"
    identity_token = f"login_capture_sha256={LOGIN_CAPTURE_SHA256}"
    stale_tokens = (
        "no_pcap_evidence",
        "pcap_evidence_dropped=lobby_not_in_capture_corpus",
    )

    for bucket, opcode_hex, name, payload_length in LOBBY_CENSUS_ATTRIBUTIONS:
        selected = next(
            (
                entry
                for entry in top["lists"].get(bucket, [])
                if entry["opcodeHex"] == opcode_hex and entry["name"] == name
            ),
            None,
        )
        if selected is None:
            print(f"  WARN: no entry for lobby census {bucket} {opcode_hex} {name}")
            errors += 1
            continue

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
        for token in stale_tokens:
            notes, _ = remove_note_token(notes, token)
        for token in (evidence_token, identity_token):
            notes = append_note_token(notes, token)
        selected["notes"] = notes

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
        (
            "serverbound" if wire_direction == "c2s" else "clientbound",
            int(opcode_hex, 16),
        )
        for _bucket, opcode_hex, _name, wire_direction, _length in LOGIN_PREZONE_ATTRIBUTIONS
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
            # Remove the generated contract suffix before other producers append
            # their evidence tokens; otherwise the next pass would discard them.
            entry["notes"] = entry.get("notes", "").split("; retained_contract=", 1)[0]
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
        accepted_names = (name,) + NAME_OVERRIDE_PRIOR_ALIASES.get(
            (bucket, opcode_hex, name), ()
        )
        for e in top["lists"][bucket]:
            if e["opcodeHex"] == opcode_hex and e.get("name") in accepted_names:
                found = True
                current = e.get("notes", "")
                e["notes"], status = swap_managed_prefix(
                    current, expected_old, new_notes
                )
                if status == "applied":
                    applied += 1
                elif status == "skipped":
                    skipped += 1
                else:
                    print(
                        f"  WARN: {bucket} {opcode_hex} {name} notes don't match expected baseline"
                    )
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
                if (
                    e.get("needsReverify") is True
                    and e.get("reverifyMethod") == REVERIFY_METHOD
                ):
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
                if (
                    e.get("name") == new_name
                    and e.get("implementationAnchor") == new_anchor
                ):
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

    confidence_applied = 0
    confidence_skipped = 0
    for bucket, opcode_hex, name, expected_old, confidence in CONFIDENCE_OVERRIDES:
        for e in top["lists"].get(bucket, []):
            if e["opcodeHex"] == opcode_hex and e.get("name") == name:
                if e.get("confidence") == confidence:
                    confidence_skipped += 1
                elif e.get("confidence") == expected_old:
                    e["confidence"] = confidence
                    confidence_applied += 1
                else:
                    print(
                        f"  WARN: {bucket} {opcode_hex} {name} confidence "
                        f"{e.get('confidence')} does not match expected baseline "
                        f"{expected_old}"
                    )
                    warned += 1
                break
        else:
            print(
                f"  WARN: no entry found for confidence override "
                f"{bucket} {opcode_hex} {name}"
            )
            warned += 1
    print(
        f"Applied {confidence_applied} confidence overrides "
        f"({confidence_skipped} skipped)"
    )

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

    world = top["lists"]["WorldClientbound"]
    before = len(world)
    top["lists"]["WorldClientbound"] = [
        e for e in world if e["opcodeHex"] not in LANE_MOVES
    ]
    print(
        f"Removed {before - len(top['lists']['WorldClientbound'])} main-lane world duplicates"
    )

    # These counts are curated input facts, not values derived from git history.
    for bucket_name, entries in top["lists"].items():
        for e in entries:
            opcode_hex = e["opcodeHex"]
            if bucket_name == "MapClientbound" and opcode_hex in LANE_MOVES:
                expected_name, count = LANE_MOVES[opcode_hex]
                if e["name"] != expected_name:
                    continue
                ruling = (
                    f"lane_ruling=moved_from_WorldClientbound; "
                    f"main_lane_count={count}; chat_lane_count=0"
                )
            elif bucket_name == "WorldClientbound" and opcode_hex in LANE_UNRESOLVED:
                ruling = (
                    "lane_ruling=unresolved_no_s2c_observation; "
                    "main_lane_count=0; chat_lane_count=0"
                )
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

    achievement_applied, achievement_errors = apply_achievement_lifecycle(top)
    warned += achievement_errors
    print(f"Applied {achievement_applied} achievement lifecycle routes")

    social_applied, social_errors = apply_map_social_neighborhood(top)
    warned += social_errors
    print(f"Applied {social_applied} Map social-neighborhood routes")

    dispatch_inserted = apply_dispatch_catalog_completion(top)
    print(f"Inserted {dispatch_inserted} structural callback catalog routes")

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

    lobby_applied, lobby_skipped, lobby_errors = apply_lobby_census_attributions(top)
    warned += lobby_errors
    print(
        f"Applied {lobby_applied} lobby census attributions ({lobby_skipped} skipped)"
    )

    retained_applied = apply_retained_contracts(top)
    print(f"Applied {retained_applied} retained retail contracts")

    low_pairs_applied = apply_low_pair_staging_contract(top)
    print(f"Applied {low_pairs_applied} low-opcode pair staging contracts")

    e2_applied = apply_e2_selector_contract(top)
    print(f"Applied {e2_applied} E2 selector contract")

    e3_applied = apply_e3_state_index_contract(top)
    print(f"Applied {e3_applied} E3 state index contract")

    e5_applied = apply_e5_field_staging_contract(top)
    print(f"Applied {e5_applied} E5 field staging contract")

    shadow_applied = apply_shadow_flag_contract(top)
    print(f"Applied {shadow_applied} shadow flag contract")

    stale_removed, ambiguity_added, ambiguity_removed = reconcile_pcap_notes(top)
    print(f"Removed {stale_removed} stale no-pcap note tokens")
    print(f"Added {ambiguity_added} pcap-ambiguity note tokens")
    print(f"Removed {ambiguity_removed} stale pcap-ambiguity note tokens")

    if warned:
        print(
            f"Refusing to write opcodes.json after {warned} warning(s)", file=sys.stderr
        )
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
