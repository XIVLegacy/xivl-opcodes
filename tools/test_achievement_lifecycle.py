#!/usr/bin/env python3
"""Focused mutation tests for the achievement lifecycle contract."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate_achievement_lifecycle as validator  # noqa: E402


REPO = Path(__file__).resolve().parents[1]
EVIDENCE = REPO / "data" / "achievement_lifecycle.json"
CATALOG = REPO / "opcodes.json"
LAYOUTS = REPO / "data" / "vendor" / "captures" / "payload_layouts.json"
SAMPLES = REPO / "data" / "vendor" / "captures" / "payload_samples.json"
MUTATION_COUNT = 20


def load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, document: object) -> Path:
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path


def run_validator(
    directory: Path,
    *,
    evidence: dict | None = None,
    catalog: list | None = None,
    layouts: dict | None = None,
    samples: dict | None = None,
) -> bool:
    evidence_path = write(directory / "evidence.json", load(EVIDENCE) if evidence is None else evidence)
    catalog_path = write(directory / "catalog.json", load(CATALOG) if catalog is None else catalog)
    layouts_path = write(directory / "layouts.json", load(LAYOUTS) if layouts is None else layouts)
    samples_path = write(directory / "samples.json", load(SAMPLES) if samples is None else samples)
    with (
        mock.patch.object(validator, "EVIDENCE_PATH", evidence_path),
        mock.patch.object(validator, "OPCODES_PATH", catalog_path),
        mock.patch.object(validator, "CAPTURE_LAYOUTS_PATH", layouts_path),
        mock.patch.object(validator, "CAPTURE_SAMPLES_PATH", samples_path),
    ):
        return not validator.validate()


def row(document: dict, row_id: str) -> dict:
    return next(item for item in document["rows"] if item["id"] == row_id)


def catalog_row(document: list, direction: str, opcode: str) -> dict:
    return next(
        item
        for rows in document[0]["lists"].values()
        for item in rows
        if item.get("service") == "map"
        and item.get("direction") == direction
        and item.get("opcodeHex", "").lower() == opcode
    )


def main() -> int:
    failures: list[str] = []

    def reject(label: str, **kwargs: object) -> None:
        if run_validator(directory, **kwargs):
            failures.append(label)

    with tempfile.TemporaryDirectory(prefix="achievement-lifecycle-test-") as raw:
        directory = Path(raw)
        if not run_validator(directory):
            failures.append("baseline must pass")

        evidence = copy.deepcopy(load(EVIDENCE))
        row(evidence, "c2s-0134-achievement-title-request")["name"] = "_0x0134"
        reject("title-request placeholder mutation must fail", evidence=evidence)

        evidence = copy.deepcopy(load(EVIDENCE))
        item = row(evidence, "c2s-0134-achievement-title-request")
        item["fields"] = item["fields"].replace("generated_ascii_crc32", "token")
        reject("CRC32 field mutation must fail", evidence=evidence)

        evidence = copy.deepcopy(load(EVIDENCE))
        item = row(evidence, "c2s-0134-achievement-title-request")
        item["flow"] = item["flow"].replace("position-specific A..O or a..o", "random ASCII")
        reject("generated-letter domain mutation must fail", evidence=evidence)

        evidence = copy.deepcopy(load(EVIDENCE))
        evidence["unresolvedBoundaries"][1] = "The generated buffer is a nonce."
        reject("nonce overclaim mutation must fail", evidence=evidence)

        evidence = copy.deepcopy(load(EVIDENCE))
        row(evidence, "s2c-0134-actor-state")["function"] = "FUN_005751E0"
        reject("s2c 0x0134 route mutation must fail", evidence=evidence)

        evidence = copy.deepcopy(load(EVIDENCE))
        item = row(evidence, "s2c-0134-actor-state")
        item["flow"] = item["flow"].replace("does not construct or invoke", "constructs and invokes")
        reject("s2c 0x0134 receiver-association mutation must fail", evidence=evidence)

        evidence = copy.deepcopy(load(EVIDENCE))
        evidence["relationships"]["titleLifecycle"] = "s2c 0x0134 applies AchievementTitleReceiver."
        reject("actual title-update opcode mutation must fail", evidence=evidence)

        evidence = copy.deepcopy(load(EVIDENCE))
        item = row(evidence, "s2c-019d-achievement-title-update")
        item["flow"] = item["flow"].replace("PlayerBase+0xE8", "PlayerBase+0xEC")
        reject("title state-write mutation must fail", evidence=evidence)

        evidence = copy.deepcopy(load(EVIDENCE))
        row(evidence, "c2s-0135-achievement-rate-request")["fields"] = "achievement_id:u16@+0x00"
        reject("achievement-id width mutation must fail", evidence=evidence)

        evidence = copy.deepcopy(load(EVIDENCE))
        item = row(evidence, "s2c-019f-achievement-rate-update")
        item["fields"] = item["fields"].replace("progress_flags:u32@+0x08", "progress_flags:u16@+0x08")
        reject("progress-flags width mutation must fail", evidence=evidence)

        evidence = copy.deepcopy(load(EVIDENCE))
        item = row(evidence, "s2c-019f-achievement-rate-update")
        item["flow"] = item["flow"].replace("No persistent client-state write", "A persistent client-state write")
        reject("rate persistent-state mutation must fail", evidence=evidence)

        evidence = copy.deepcopy(load(EVIDENCE))
        evidence["relationships"]["rateLifecycle"] = "s2c 0x019F acknowledges c2s 0x0135."
        reject("rate acknowledgement mutation must fail", evidence=evidence)

        evidence = copy.deepcopy(load(EVIDENCE))
        evidence["relationships"]["chronology"] = "The rate request precedes its response."
        reject("retained chronology mutation must fail", evidence=evidence)

        evidence = copy.deepcopy(load(EVIDENCE))
        row(evidence, "s2c-019f-achievement-rate-update")["sourceRefs"] = []
        reject("source reference mutation must fail", evidence=evidence)

        catalog = copy.deepcopy(load(CATALOG))
        catalog_row(catalog, "serverbound", "0x0134")["name"] = "_0x0134"
        reject("catalog title-request name mutation must fail", catalog=catalog)

        catalog = copy.deepcopy(load(CATALOG))
        catalog_row(catalog, "serverbound", "0x0134")["payloadLengths"] = [40]
        reject("unobserved c2s payload-length mutation must fail", catalog=catalog)

        catalog = copy.deepcopy(load(CATALOG))
        catalog_row(catalog, "clientbound", "0x0134")["decompAnchor"] = "FUN_005751E0"
        reject("catalog actor-state route mutation must fail", catalog=catalog)

        samples = copy.deepcopy(load(SAMPLES))
        payload = bytearray.fromhex(samples["samples"]["s2c"]["0x019d"]["samples"][0]["bytes"])
        payload[16] = 1
        samples["samples"]["s2c"]["0x019d"]["samples"][0]["bytes"] = payload.hex()
        reject("pinned title-value mutation must fail", samples=samples)

        samples = copy.deepcopy(load(SAMPLES))
        samples["samples"]["c2s"]["0x0135"] = {"opcode": 309, "sampleCount": 0, "samples": []}
        reject("unexpected retained c2s request mutation must fail", samples=samples)

        layouts = copy.deepcopy(load(LAYOUTS))
        layouts["layouts"]["s2c"]["0x019d"]["sample_count"] = 14
        reject("pinned title sample-count mutation must fail", layouts=layouts)

    if failures:
        print(f"Achievement lifecycle mutation tests FAILED ({len(failures)}):", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(f"Achievement lifecycle mutation tests OK ({MUTATION_COUNT} mutations rejected).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
