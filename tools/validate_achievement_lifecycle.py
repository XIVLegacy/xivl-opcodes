#!/usr/bin/env python3
"""Validate the bounded achievement request and update lifecycle."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from _json_io import OPCODES_PATH, REPO_ROOT


EVIDENCE_PATH = REPO_ROOT / "data" / "achievement_lifecycle.json"
CAPTURE_LAYOUTS_PATH = REPO_ROOT / "data" / "vendor" / "captures" / "payload_layouts.json"
CAPTURE_SAMPLES_PATH = REPO_ROOT / "data" / "vendor" / "captures" / "payload_samples.json"
EXPECTED_BINARY = {
    "name": "ffxivgame.exe",
    "version": "1.23b",
    "sha256": "9341f2b4567440b310a4d494f5cc5599ca334ba51c8042247317ff466492f2e9",
}
EXPECTED_CORPUS_SNAPSHOTS = {
    "current": {
        "sourceRef": "xivl-captures@db6a3b43a1d6a073f3cc72ade0ec4aebb89cd069",
        "captureCount": 54,
    },
    "pinned": {
        "sourceRef": "data/vendor/captures/PROVENANCE.json",
        "captureCount": 53,
        "payloadSamplesSha256": "3d08a4ed4407738c02ce13b0fe853b6e8dba6340930e59dc94734055f8b8da38",
    },
}
EXPECTED = {
    "c2s-0134-achievement-title-request": (
        "0x0134", "serverbound", "AchievementTitleRequestPacket", "FUN_0075EBA0",
        24, 0, 0, 0, "decomp_routed", 0, [],
    ),
    "s2c-0134-actor-state": (
        "0x0134", "clientbound", "SetActorStatePacket", "FUN_00588BA0",
        8, 912, 20, 60, "confirmed", 20, [40],
    ),
    "s2c-019d-achievement-title-update": (
        "0x019d", "clientbound", "SetPlayerTitlePacket", "FUN_005751E0",
        8, 14, 11, 14, "confirmed", 11, [40],
    ),
    "c2s-0135-achievement-rate-request": (
        "0x0135", "serverbound", "AchievementRateRequestPacket", "FUN_0075ECD0",
        4, 0, 0, 0, "decomp_routed", 0, [],
    ),
    "s2c-019f-achievement-rate-update": (
        "0x019f", "clientbound", "SendAchievementRatePacket", "FUN_00575200",
        16, 0, 0, 0, "decomp_routed", 0, [],
    ),
}
EXPECTED_PINNED = {
    "0x0134": (60, 17, 40, 24),
    "0x019d": (13, 10, 40, 24),
}


def load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def validate() -> list[str]:
    errors: list[str] = []
    evidence = load(EVIDENCE_PATH)
    catalog = load(OPCODES_PATH)
    layouts = load(CAPTURE_LAYOUTS_PATH)["layouts"]
    samples = load(CAPTURE_SAMPLES_PATH)["samples"]

    if evidence.get("schemaVersion") != 1:
        errors.append("schemaVersion must remain 1")
    if evidence.get("binary") != EXPECTED_BINARY:
        errors.append("retail binary identity drifted")
    snapshots = evidence.get("corpusSnapshots", {})
    for name, expected_snapshot in EXPECTED_CORPUS_SNAPSHOTS.items():
        snapshot = snapshots.get(name, {})
        for key, value in expected_snapshot.items():
            if snapshot.get(key) != value:
                errors.append(f"{name} corpus snapshot {key} drifted")
        if not snapshot.get("role"):
            errors.append(f"{name} corpus snapshot lacks its evidence role")

    evidence_rows = evidence.get("rows", [])
    rows = {row.get("id"): row for row in evidence_rows}
    if len(evidence_rows) != len(EXPECTED) or set(rows) != set(EXPECTED):
        errors.append("evidence must contain exactly the five managed direction/opcode rows")
        return errors

    catalog_rows = [
        row
        for bucket in catalog[0]["lists"].values()
        for row in bucket
        if row.get("service") == "map"
        and (row.get("direction"), row.get("opcodeHex", "").lower())
        in {
            (expected[1], expected[0])
            for expected in EXPECTED.values()
        }
    ]
    keyed_catalog = {
        (row["direction"], row["opcodeHex"].lower()): row
        for row in catalog_rows
    }
    if len(catalog_rows) != len(EXPECTED) or len(keyed_catalog) != len(EXPECTED):
        errors.append("catalog must contain exactly the five managed Map rows")
        return errors

    for row_id, expected in EXPECTED.items():
        (
            opcode, direction, name, function, application_size, occurrences,
            captures, retained, confidence, catalog_captures, payload_lengths,
        ) = expected
        row = rows[row_id]
        actual = (
            row.get("opcodeHex", "").lower(), row.get("direction"), row.get("name"),
            row.get("function"), row.get("applicationSize"),
            row.get("observedOccurrences"), row.get("captureCount"),
            row.get("retainedSamples"),
        )
        if actual != expected[:8]:
            errors.append(f"{row_id} evidence tuple drifted: {actual!r}")
        if not row.get("sourceRefs") or not all(":" in ref for ref in row["sourceRefs"]):
            errors.append(f"{row_id} sourceRefs are missing or malformed")

        catalog_row = keyed_catalog[(direction, opcode)]
        if catalog_row.get("name") != name:
            errors.append(f"{row_id} catalog name drifted")
        if catalog_row.get("decompAnchor") != function:
            errors.append(f"{row_id} catalog route anchor drifted")
        if catalog_row.get("confidence") != confidence:
            errors.append(f"{row_id} catalog confidence drifted")
        if len(catalog_row.get("observedIn", [])) != catalog_captures:
            errors.append(f"{row_id} catalog capture count drifted")
        if catalog_row.get("payloadLengths") != payload_lengths:
            errors.append(f"{row_id} catalog payloadLengths drifted")
        notes = catalog_row.get("notes", "")
        for token in (
            f"achievement_lifecycle=data/achievement_lifecycle.json#{row_id}",
            f"application_size={application_size}",
            f"observed_occurrences={occurrences}",
            f"capture_count={captures}",
            f"retained_samples={retained}",
        ):
            if token not in notes:
                errors.append(f"{row_id} catalog notes lost {token!r}")

    title_request = rows["c2s-0134-achievement-title-request"]
    for token in (
        "title_value:u32@+0x00",
        "generated_ascii_crc32:u32@+0x04",
        "generated_ascii[16]@+0x08",
    ):
        if token not in title_request["fields"]:
            errors.append(f"c2s 0x0134 fields lost {token!r}")
    for token in (
        "writes the full value to PlayerBase+0xE8",
        "position-specific A..O or a..o",
        "leaves byte 15 NUL",
        "computes CRC32 over all 16 bytes",
    ):
        if token not in title_request["flow"]:
            errors.append(f"c2s 0x0134 flow lost {token!r}")

    actor_state = rows["s2c-0134-actor-state"]
    for token in ("main_state:u8@+0x00", "discarded_byte:u8@+0x01", "unknown[6]@+0x02"):
        if token not in actor_state["fields"]:
            errors.append(f"s2c 0x0134 fields lost {token!r}")
    for token in ("CharaElement+0xF4", "conditionally +0xF0", "does not construct or invoke AchievementTitleReceiver"):
        if token not in actor_state["flow"]:
            errors.append(f"s2c 0x0134 route lost {token!r}")

    title_update = rows["s2c-019d-achievement-title-update"]
    for token in ("LuaActorImpl slot 75", "AchievementTitleReceiver", "PlayerBase+0xE8", "adjacent three overwritten bytes remain unresolved"):
        if token not in title_update["flow"]:
            errors.append(f"s2c 0x019D route lost {token!r}")

    rate_request = rows["c2s-0135-achievement-rate-request"]
    if rate_request["fields"] != "achievement_id:u32@+0x00":
        errors.append("c2s 0x0135 must retain one u32 achievement-id field")
    rate_update = rows["s2c-019f-achievement-rate-update"]
    for token in ("achievement_id:u32@+0x00", "progress_count:u32@+0x04", "progress_flags:u32@+0x08", "unknown:u32@+0x0C"):
        if token not in rate_update["fields"]:
            errors.append(f"s2c 0x019F fields lost {token!r}")
    for token in ("LuaActorImpl slot 77", "_onReceiveAchievementRate", "closing dword is not copied", "No persistent client-state write"):
        if token not in rate_update["flow"]:
            errors.append(f"s2c 0x019F route lost {token!r}")

    relationships = evidence.get("relationships", {})
    if "Same-number reuse is not an acknowledgement relationship" not in relationships.get("sameNumberBoundary", ""):
        errors.append("same-number direction boundary drifted")
    if "s2c 0x019D, not s2c 0x0134" not in relationships.get("titleLifecycle", ""):
        errors.append("actual AchievementTitleReceiver opcode boundary drifted")
    if "does not establish that 0x019F acknowledges or responds to 0x0135" not in relationships.get("rateLifecycle", ""):
        errors.append("rate acknowledgement boundary drifted")
    chronology = relationships.get("chronology", "")
    for token in ("zero c2s 0x0134", "zero c2s 0x0135", "zero s2c 0x019F", "912 s2c 0x0134", "14 s2c 0x019D", "no causal edge"):
        if token not in chronology:
            errors.append(f"retained-corpus chronology lost {token!r}")

    unresolved = " ".join(evidence.get("unresolvedBoundaries", []))
    for token in ("nonce, challenge, or authorization token", "progress_flags bits", "+0xE9..+0xEB"):
        if token not in unresolved:
            errors.append(f"unresolved boundary lost {token!r}")

    for opcode, (sample_count, capture_count, sub_size, body_length) in EXPECTED_PINNED.items():
        layout = layouts["s2c"][opcode]
        retained_samples = samples["s2c"][opcode]["samples"]
        actual = (
            layout["sample_count"], len({sample["capture"] for sample in retained_samples}),
            layout["common_sub_size"], layout["body_length"],
        )
        if actual != (sample_count, capture_count, sub_size, body_length):
            errors.append(f"pinned s2c {opcode} capture fixture drifted: {actual!r}")
        row_id = "s2c-0134-actor-state" if opcode == "0x0134" else "s2c-019d-achievement-title-update"
        if rows[row_id].get("pinnedRetainedSamples") != sample_count:
            errors.append(f"{row_id} pinned sample count drifted")
        if rows[row_id].get("pinnedSampleCaptureCount") != capture_count:
            errors.append(f"{row_id} pinned sample capture count drifted")

    title_samples = samples["s2c"]["0x019d"]["samples"]
    title_values = {int.from_bytes(bytes.fromhex(sample["bytes"])[16:20], "little") for sample in title_samples}
    if title_values != {0, 810}:
        errors.append(f"pinned s2c 0x019D title values drifted: {sorted(title_values)}")
    if any(bytes.fromhex(sample["bytes"])[20:24] != b"\0" * 4 for sample in title_samples):
        errors.append("pinned s2c 0x019D unknown tail is no longer all zero")

    for direction, opcode in (("c2s", "0x0134"), ("c2s", "0x0135"), ("s2c", "0x019f")):
        if opcode in samples.get(direction, {}) or opcode in layouts.get(direction, {}):
            errors.append(f"pinned captures unexpectedly contain {direction} {opcode}")

    return errors


def main() -> int:
    errors = validate()
    if errors:
        print(f"Achievement lifecycle FAILED ({len(errors)} problem(s)):", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    print("Achievement lifecycle OK (5 routes, title correction, no causal overclaim).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
