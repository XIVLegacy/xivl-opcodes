#!/usr/bin/env python3
"""Validate the neutral s2c 0x018D wire-layout contract."""

from __future__ import annotations

import json
import sys

from _json_io import OPCODES_PATH, REPO_ROOT


EVIDENCE_PATH = REPO_ROOT / "data" / "s2c_018d_wire_layout.json"
HEADER_PATH = REPO_ROOT / "structs" / "map" / "clientbound.h"
BCSY_BINDINGS_PATH = (
    REPO_ROOT / "data" / "vendor" / "client-structs" / "bcsy-opcode-bindings.json"
)
EXPECTED_BINARY = {
    "name": "ffxivgame.exe",
    "version": "1.23b",
    "sha256": "9341f2b4567440b310a4d494f5cc5599ca334ba51c8042247317ff466492f2e9",
}
EXPECTED_PROJECTION = (
    (0x00, 0x00, 4, "u32"),
    (0x08, 0x08, 4, "u32"),
    (0x0C, 0x0C, 4, "u32"),
    (0x14, 0x10, 4, "f32"),
    (0x18, 0x14, 4, "f32"),
    (0x1C, 0x18, 4, "f32"),
)
EXPECTED_COUNT_BEHAVIOR = {
    "load": "MOVSX from the raw byte at application+0x290",
    "zero": "No record is copied.",
    "positiveRange": "Raw values 1..127 copy exactly that many records.",
    "highBitRange": (
        "Raw values 128..255 sign-extend to 0xFFFFFF80..0xFFFFFFFF and become "
        "an enormous unsigned loop bound."
    ),
    "maximumAcceptedCount": None,
    "capacityCheck": False,
    "truncation": False,
    "overflow": (
        "A count above 16 reads beyond the reserved wire array and writes beyond "
        "the sixteen-record ClientWorkStorage array; no rejection, clamp, or "
        "recovery is present in the traced case or apply function."
    ),
}
EXPECTED_TAIL_FLAG = (
    "If storage+0x798 is zero, FUN_0055CF70 sets it to one exactly when the "
    "loaded count is greater than one; a preexisting nonzero value is preserved."
)
EXPECTED_PRESENTATION_PROJECTION = (
    (0x14, 0x10, "binary32 CVTTSS2SI", "X", "Int"),
    (0x1C, 0x18, "binary32 CVTTSS2SI", "Z", "Int"),
)
EXPECTED_CONSUMER_REFS = {
    "xivl-client-structs:manifests/s2c_018d_map_marker_presentation.json",
    "xivl-decomp:config/s2c_018d_client_consumer.json",
    "xivl-decomp:docs/net/s2c-018d-client-consumer.md",
    "xivl-captures:studies/party-marker-018d-chronology/derived/field-verdicts.md",
    "xivl-client-data:manifests/map_marker_resources.json",
}
EXPECTED_POINTER_ADJUSTMENTS = [
    "The dispatcher receives the 16-byte game-message header at offset +0x10 from the start of the subpacket.",
    "The case advances that game-message pointer by +0x10 before passing the application pointer to FUN_0055CF70.",
    "The case reads RaptureElementContainer+0x4D8, rejects null, then adds +0x98 to the ClientWorkElement pointee for the ClientWorkStorage this pointer.",
]
EXPECTED_REJECTED_INTERPRETATIONS = [
    "The wire application layout is not the ClientWorkStorage in-memory layout.",
    "The opcode and copied fields do not establish marker nouns, party policy, permissions, server causality, coordinate meanings, or selector creation.",
    "The sixteen reserved wire records are a physical capacity, not a validated runtime limit.",
    "Static marker resources do not establish a runtime edge to 0x018D or assign a wire-field noun.",
]
EXPECTED_REMAINING_BOUNDARY = (
    "The three copied header dwords, the unread application header dword, the "
    "unprojected record spans, key dword domains, coordinate system, marker "
    "identity, server policy, creation trigger, update cadence, and behavior "
    "after the first out-of-bounds access remain semantically unresolved."
)


def fail(message: str) -> None:
    print(f"0x018D wire layout FAILED: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> int:
    evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
    catalog = json.loads(OPCODES_PATH.read_text(encoding="utf-8"))
    header = HEADER_PATH.read_text(encoding="utf-8")
    bindings = json.loads(BCSY_BINDINGS_PATH.read_text(encoding="utf-8"))

    if evidence.get("schemaVersion") != 1 or evidence.get("binary") != EXPECTED_BINARY:
        fail("schema or retail binary identity drifted")
    if (evidence.get("opcodeHex"), evidence.get("direction"), evidence.get("name")) != (
        "0x018d", "clientbound", "_0x018D"
    ):
        fail("opcode identity or neutral name drifted")

    route = evidence["route"]
    if (
        route["dispatcher"], route["caseInstruction"], route["prepareCall"],
        route["apply"], route["applyCall"]
    ) != ("FUN_004DC690", "0x004DD167", "0x004DD195", "FUN_0055CF70", "0x004DD1A9"):
        fail("instruction-level route drifted")
    if route.get("pointerAdjustments") != EXPECTED_POINTER_ADJUSTMENTS:
        fail("game-message, application, or storage pointer adjustment drifted")

    framing = evidence["framing"]
    if tuple(framing[key] for key in (
        "subpacketSize", "subpacketHeaderSize", "gameMessageHeaderSize",
        "applicationOffsetFromSubpacket", "applicationSize"
    )) != (696, 16, 16, 32, 664):
        fail("subpacket or game-message framing drifted")

    application = evidence["application"]
    if tuple(application[key] for key in (
        "headerSize", "unreadHeaderOffset", "unreadHeaderSize", "recordOffset",
        "recordStride", "recordCapacity", "recordExtent", "countOffset",
        "countWidth", "tailOffset", "tailSize"
    )) != (16, 12, 4, 16, 40, 16, 640, 656, 1, 657, 7):
        fail("application dimensions drifted")
    if application.get("consumedHeaderDwordOffsets") != [0, 4, 8]:
        fail("consumed application header fields drifted")
    if application["recordOffset"] + application["recordExtent"] != application["countOffset"]:
        fail("record extent no longer ends at the count byte")
    if application["tailOffset"] + application["tailSize"] != framing["applicationSize"]:
        fail("application tail no longer closes the fixed extent")

    storage = evidence["storage"]
    if tuple(storage[key] for key in (
        "countOffset", "recordOffset", "recordStride", "recordCapacity", "tailFlagOffset"
    )) != (20, 24, 120, 16, 1944):
        fail("ClientWorkStorage dimensions drifted")
    if storage.get("tailFlagBehavior") != EXPECTED_TAIL_FLAG:
        fail("storage tail flag behavior drifted")
    if "FUN_00573FC0" not in storage.get("perRecordHelper", ""):
        fail("storage tail flag or per-record helper behavior drifted")
    projection = tuple(
        (row["wireOffset"], row["storageOffset"], row["width"], row["kind"])
        for row in storage.get("projection", [])
    )
    if projection != EXPECTED_PROJECTION:
        fail(f"wire-to-storage projection is {projection!r}")
    if storage.get("unprojectedWireSpans") != [
        "+0x04..+0x07", "+0x10..+0x13", "+0x20..+0x27"
    ]:
        fail("unprojected wire spans drifted")

    behavior = evidence["countBehavior"]
    if behavior != EXPECTED_COUNT_BEHAVIOR:
        fail("unbounded signed-count behavior drifted")

    consumer = evidence["consumerClassification"]
    if tuple(consumer.get(key) for key in ("class", "function", "kind")) != (
        "Application::Main::SqwtInterface::CustomControl::MapScreenControl",
        "FUN_00671400",
        "native UI property presentation",
    ):
        fail("native presentation consumer classification drifted")
    if consumer.get("scope") != (
        "This is the first outward consumer established by the recorded static route; "
        "computed, indirect, dynamic, and runtime-only consumers remain outside the result."
    ):
        fail("first-outward-consumer scope drifted")
    if not all(
        token in consumer.get("networkBoundary", "")
        for token in ("client-owned projected storage", "not a packet builder", "server")
    ):
        fail("presentation network boundary drifted")
    presentation = tuple(
        (
            row["wireOffset"], row["storageOffset"], row["conversion"],
            row["uiProperty"], row["uiType"],
        )
        for row in consumer.get("presentationProjection", [])
    )
    if presentation != EXPECTED_PRESENTATION_PROJECTION:
        fail(f"presentation projection is {presentation!r}")
    unread = consumer.get("unreadProjectedFloat", {})
    if (
        unread.get("wireOffset"), unread.get("storageOffset"), unread.get("boundary")
    ) != (0x18, 0x14, "The middle projected binary32 value is not read by FUN_00671400."):
        fail("middle projected float boundary drifted")
    template = consumer.get("template", {})
    if tuple(template.get(key) for key in ("property", "type", "value")) != (
        "Template", "String", "MapMarkerParty"
    ) or "not a native class or canonical packet name" not in template.get("boundary", ""):
        fail("MapMarkerParty presentation-value boundary drifted")
    if "do not assign coordinate-system" not in consumer.get("fieldBoundary", ""):
        fail("presentation-to-wire field boundary drifted")
    if not EXPECTED_CONSUMER_REFS.issubset(evidence.get("sourceRefs", [])):
        fail("consumer-classification source references drifted")
    if evidence.get("rejectedInterpretations") != EXPECTED_REJECTED_INTERPRETATIONS:
        fail("rejected interpretations drifted")
    if evidence.get("remainingBoundary") != EXPECTED_REMAINING_BOUNDARY:
        fail("remaining semantic boundary drifted")
    binding_names = {
        row["bcsyId"]: row["name"]
        for row in bindings.get("syncCandidates", [])
        if row.get("bcsyId") in {"BCS-Y-1032", "BCS-Y-1033"}
    }
    if binding_names != {
        "BCS-Y-1032": "FUN_006C1570",
        "BCS-Y-1033": "FUN_00573F10",
    }:
        fail("0x018D vendor binding names lost their neutral address form")

    reconciliation = evidence["offsetReconciliation"]
    if (
        "application+0x0C..+0x0F unread" not in reconciliation.get("applicationPlus0C", "")
        or "not the record base" not in reconciliation.get("applicationPlus0C", "")
        or "application+0x10" not in reconciliation.get("gameMessagePlus20", "")
        or reconciliation.get("resolved") != (
            "The first record starts at application+0x10, game-message+0x20, "
            "and subpacket+0x30."
        )
    ):
        fail("prior offset bases are no longer reconciled")

    captures = evidence["captureReconciliation"]
    if tuple(captures[key] for key in (
        "captures", "events", "subpacketSize", "recordStride", "records",
        "shapeExclusions", "capacityExclusions", "tailExclusions",
        "nonfiniteFloatExclusions"
    )) != (54, 592, 696, 40, 769, 0, 0, 0, 0):
        fail("complete capture reconciliation drifted")
    if captures.get("subpacketSizeDistribution") != {"696": 592}:
        fail("fixed subpacket-size distribution drifted")
    if captures.get("countDistribution") != {"1": 415, "2": 177}:
        fail("one/two-record distribution drifted")

    rows = [
        row for row in catalog[0]["lists"]["MapClientbound"]
        if row.get("opcodeHex") == "0x018d"
    ]
    if len(rows) != 1:
        fail(f"MapClientbound contains {len(rows)} 0x018D rows")
    row = rows[0]
    if (
        row.get("name") != "_0x018D"
        or row.get("decompAnchor") != "FUN_00575550"
        or row.get("implementationAnchor") is not None
        or row.get("confidence") != "decomp_routed"
        or row.get("payloadLengths") != [696]
    ):
        fail("catalog row identity, anchor, confidence, or size drifted")
    notes = row.get("notes", "")
    for token in (
        "wire_layout=data/s2c_018d_wire_layout.json",
        "subpacket_size=0x2b8",
        "application_size=0x298",
        "record_offset=0x10",
        "record_stride=0x28",
        "wire_capacity=16",
        "count_offset=0x290",
        "count_width=1",
        "count_load=MOVSX",
        "count_check=none",
        "storage_record_offset=0x18",
        "storage_record_stride=0x78",
        "observed_events=592",
        "first_outward_consumer=native MapScreenControl UI property presentation",
        "presentation_projection=wire +0x14 and +0x1c become X:Int and Z:Int after CVTTSS2SI",
        "middle_projected_float=not read by the presentation consumer",
        "template_boundary=MapMarkerParty is a Template:String value, not a packet or native class name",
        "static_resource_boundary=no runtime edge joins marker resources to 0x018D",
        "name_boundary=placeholder retained",
    ):
        if token not in notes:
            fail(f"catalog notes lost {token!r}")
    for forbidden in ("PartyMapMarker", "permission", "coordinate", "selector creation"):
        if forbidden in row.get("name", "") or forbidden in notes:
            fail(f"catalog row contains unsupported interpretation {forbidden!r}")

    for token in (
        "struct _0x018DRecord",
        "uint8_t       gameMessagePreamble[8]",
        "_0x018DRecord records[16]",
        "int8_t        recordCount",
        "static_assert(sizeof(_0x018DBody) == 672",
    ):
        if token not in header:
            fail(f"generated header lost {token!r}")

    print("0x018D wire layout OK (592 events, 0x298 application, 0x28 stride).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
