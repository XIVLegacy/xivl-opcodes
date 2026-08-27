#!/usr/bin/env python3
"""Focused mutation tests for the retained 0x0193 route evidence."""

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

import validate_client_opcode_semantics as validator  # noqa: E402


REPO = Path(__file__).resolve().parents[1]
SEMANTICS = REPO / "data" / "client_opcode_semantics.json"
LAYOUTS = REPO / "data" / "vendor" / "captures" / "payload_layouts.json"
SAMPLES = REPO / "data" / "vendor" / "captures" / "payload_samples.json"
CATALOG = REPO / "opcodes.json"


def load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, document: object) -> Path:
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path


def run_validator(
    directory: Path,
    *,
    semantics: dict | None = None,
    samples: dict | None = None,
    catalog: list | None = None,
) -> int:
    semantics_path = write(
        directory / "semantics.json", load(SEMANTICS) if semantics is None else semantics
    )
    layouts_path = write(directory / "layouts.json", load(LAYOUTS))
    samples_path = write(
        directory / "samples.json", load(SAMPLES) if samples is None else samples
    )
    catalog_path = write(
        directory / "catalog.json", load(CATALOG) if catalog is None else catalog
    )
    with (
        mock.patch.object(validator, "EVIDENCE_PATH", semantics_path),
        mock.patch.object(validator, "CAPTURE_LAYOUTS_PATH", layouts_path),
        mock.patch.object(validator, "CAPTURE_SAMPLES_PATH", samples_path),
        mock.patch.object(validator, "OPCODES_PATH", catalog_path),
        contextlib.redirect_stdout(io.StringIO()),
        contextlib.redirect_stderr(io.StringIO()),
    ):
        return validator.main()


def semantic_row(document: dict) -> dict:
    return next(row for row in document["rows"] if row.get("id") == "s2c-0193")


def retained_samples(document: dict) -> list[dict]:
    return document["samples"]["s2c"]["0x0193"]["samples"]


def catalog_row(document: list) -> dict:
    return next(
        row
        for row in document[0]["lists"]["MapClientbound"]
        if row.get("opcodeHex") == "0x0193"
    )


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="route-0193-test-") as raw:
        directory = Path(raw)
        if run_validator(directory) != 0:
            failures.append("baseline must pass")

        semantics = copy.deepcopy(load(SEMANTICS))
        semantic_row(semantics)["supportedLabel"] = "SetControlStatePacket"
        if run_validator(directory, semantics=semantics) == 0:
            failures.append("imported noun mutation must fail")

        samples = copy.deepcopy(load(SAMPLES))
        body = bytearray.fromhex(retained_samples(samples)[0]["bytes"])
        body[8] ^= 1
        retained_samples(samples)[0]["bytes"] = body.hex()
        if run_validator(directory, samples=samples) == 0:
            failures.append("header clock mutation must fail")

        samples = copy.deepcopy(load(SAMPLES))
        body = bytearray.fromhex(retained_samples(samples)[3]["bytes"])
        body[20] ^= 1
        retained_samples(samples)[3]["bytes"] = body.hex()
        if run_validator(directory, samples=samples) == 0:
            failures.append("application delta mutation must fail")

        samples = copy.deepcopy(load(SAMPLES))
        retained_samples(samples)[3:5] = reversed(retained_samples(samples)[3:5])
        if run_validator(directory, samples=samples) == 0:
            failures.append("same-frame chronology mutation must fail")

        catalog = copy.deepcopy(load(CATALOG))
        catalog_row(catalog)["name"] = "SetControlStatePacket"
        if run_validator(directory, catalog=catalog) == 0:
            failures.append("catalog noun mutation must fail")

    if failures:
        print(f"0x0193 route mutation tests FAILED ({len(failures)}):", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("0x0193 route mutation tests OK (5 mutations rejected).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
