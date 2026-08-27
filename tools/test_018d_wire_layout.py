#!/usr/bin/env python3
"""Focused mutation tests for the neutral s2c 0x018D wire layout."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import tempfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate_018d_wire_layout as validator  # noqa: E402


REPO = Path(__file__).resolve().parents[1]
EVIDENCE = REPO / "data" / "s2c_018d_wire_layout.json"
CATALOG = REPO / "opcodes.json"
HEADER = REPO / "structs" / "map" / "clientbound.h"
BINDINGS = REPO / "data" / "vendor" / "client-structs" / "bcsy-opcode-bindings.json"


def load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, document: object) -> Path:
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path


def run_validator(
    directory: Path,
    evidence: dict,
    catalog: list | None = None,
    header: str | None = None,
    bindings: dict | None = None,
) -> int:
    evidence_path = write(directory / "evidence.json", evidence)
    catalog_path = write(directory / "catalog.json", load(CATALOG) if catalog is None else catalog)
    header_path = directory / "clientbound.h"
    header_path.write_text(HEADER.read_text(encoding="utf-8") if header is None else header, encoding="utf-8")
    bindings_path = write(
        directory / "bindings.json", load(BINDINGS) if bindings is None else bindings
    )
    with (
        mock.patch.object(validator, "EVIDENCE_PATH", evidence_path),
        mock.patch.object(validator, "OPCODES_PATH", catalog_path),
        mock.patch.object(validator, "HEADER_PATH", header_path),
        mock.patch.object(validator, "BCSY_BINDINGS_PATH", bindings_path),
        contextlib.redirect_stdout(io.StringIO()),
        contextlib.redirect_stderr(io.StringIO()),
    ):
        try:
            return validator.main()
        except SystemExit as exc:
            return int(exc.code or 0)


def catalog_row(document: list) -> dict:
    return next(
        row for row in document[0]["lists"]["MapClientbound"]
        if row.get("opcodeHex") == "0x018d"
    )


def main() -> int:
    failures: list[str] = []
    baseline = load(EVIDENCE)
    with tempfile.TemporaryDirectory(prefix="wire-018d-test-") as raw:
        directory = Path(raw)
        if run_validator(directory, baseline) != 0:
            failures.append("baseline must pass")

        mutations = (
            ("record start", lambda row: row["application"].__setitem__("recordOffset", 12)),
            ("record stride", lambda row: row["application"].__setitem__("recordStride", 44)),
            ("count offset", lambda row: row["application"].__setitem__("countOffset", 655)),
            ("count clamp", lambda row: row["countBehavior"].__setitem__("capacityCheck", True)),
            ("count load", lambda row: row["countBehavior"].__setitem__("load", "MOVZX")),
            ("high-bit behavior", lambda row: row["countBehavior"].__setitem__("highBitRange", "stops")),
            ("high-bit inversion", lambda row: row["countBehavior"].__setitem__("highBitRange", "Raw values 128..255 stop safely instead of forming an unsigned loop bound.")),
            ("tail latch", lambda row: row["storage"].__setitem__("tailFlagBehavior", "unknown")),
            ("tail-latch inversion", lambda row: row["storage"].__setitem__("tailFlagBehavior", "If the count is greater than one, storage+0x798 remains zero.")),
            ("capture count", lambda row: row["captureReconciliation"].__setitem__("events", 591)),
            ("capture distribution", lambda row: row["captureReconciliation"].__setitem__("countDistribution", {"1": 416, "2": 176})),
            ("projection", lambda row: row["storage"]["projection"][3].__setitem__("wireOffset", 32)),
            ("offset basis", lambda row: row["offsetReconciliation"].__setitem__("resolved", "application+0x0C")),
            ("pointer adjustment", lambda row: row["route"]["pointerAdjustments"].__setitem__(0, "subpacket+0x10 is application")),
            ("unprojected spans", lambda row: row["storage"].__setitem__("unprojectedWireSpans", [])),
            ("consumer class", lambda row: row["consumerClassification"].__setitem__("class", "MapMarkerParty")),
            ("consumer kind", lambda row: row["consumerClassification"].__setitem__("kind", "packet handler")),
            ("consumer scope", lambda row: row["consumerClassification"].__setitem__("scope", "all consumers")),
            ("X projection", lambda row: row["consumerClassification"]["presentationProjection"][0].__setitem__("wireOffset", 24)),
            ("float conversion", lambda row: row["consumerClassification"]["presentationProjection"][0].__setitem__("conversion", "round")),
            ("middle float", lambda row: row["consumerClassification"]["unreadProjectedFloat"].__setitem__("wireOffset", 20)),
            ("template identity", lambda row: row["consumerClassification"]["template"].__setitem__("boundary", "canonical packet name")),
            ("consumer citation", lambda row: row.__setitem__("sourceRefs", [ref for ref in row["sourceRefs"] if "s2c_018d_map_marker_presentation" not in ref])),
            ("rejected boundary", lambda row: row.__setitem__("rejectedInterpretations", [])),
            ("remaining boundary", lambda row: row.__setitem__("remainingBoundary", "resolved")),
            ("primary selector", lambda row: row["recordLookupSemantics"]["primary"].__setitem__("role", "actor ID")),
            ("fallback sentinel", lambda row: row["recordLookupSemantics"]["fallback"].__setitem__("condition", "zero")),
            ("eligibility selector", lambda row: row["recordLookupSemantics"]["eligibilityOnly"].__setitem__("role", "lookup key")),
            ("helper text", lambda row: row["recordLookupSemantics"]["helperOutputs"].__setitem__("text", "label")),
            ("helper layout", lambda row: row["recordLookupSemantics"]["helperOutputs"].__setitem__("layout", "layout ID")),
        )
        for label, mutate in mutations:
            document = copy.deepcopy(baseline)
            mutate(document)
            if run_validator(directory, document) == 0:
                failures.append(f"{label} mutation must fail")

        catalog = copy.deepcopy(load(CATALOG))
        catalog_row(catalog)["name"] = "PartyMapMarkerUpdatePacket"
        if run_validator(directory, baseline, catalog) == 0:
            failures.append("inferred noun mutation must fail")

        header = HEADER.read_text(encoding="utf-8").replace(
            "gameMessagePreamble[8]", "gameMessagePreamble[4]"
        )
        if run_validator(directory, baseline, header=header) == 0:
            failures.append("generated preamble mutation must fail")

        bindings = copy.deepcopy(load(BINDINGS))
        next(
            row for row in bindings["syncCandidates"]
            if row.get("bcsyId") == "BCS-Y-1032"
        )["name"] = "PartySubsystem_CrossOpcodeUpdateGateway_FUN_006C1570"
        if run_validator(directory, baseline, bindings=bindings) == 0:
            failures.append("unsupported vendor binding noun mutation must fail")

    if failures:
        print(f"0x018D wire mutation tests FAILED ({len(failures)}):", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("0x018D wire mutation tests OK (33 mutations rejected).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
