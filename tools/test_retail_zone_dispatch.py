#!/usr/bin/env python3
"""Asset-free mutation tests for the retail zone-dispatch contract."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _schema_check  # noqa: E402
import verify_retail_zone_dispatch as verifier  # noqa: E402


REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "tools" / "fixtures" / "retail_zone_dispatch_observations.json"
CHECK = REPO / "data" / "retail_zone_dispatch_check.json"
RETAIL_INPUTS = REPO / "data" / "retail_inputs.json"
ZONE_MAP = REPO / "data" / "zone_dispatch_map.json"
SEMANTICS = REPO / "data" / "client_opcode_semantics.json"
CATALOG = REPO / "opcodes.json"
SCHEMA = REPO / "schemas" / "retail-evidence-attestation.schema.json"
VERIFY = REPO / "tools" / "verify_retail_zone_dispatch.py"
EXPORTER = REPO / "tools" / "ghidra_scripts" / "ExportZoneDispatchRoute.java"
WORKFLOW = REPO / ".github" / "workflows" / "retail-checks.yml"
PASSED: list[str] = []
FAILED: list[str] = []


def check(name: str, condition: bool) -> None:
    (PASSED if condition else FAILED).append(name)


def _load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, document: object) -> Path:
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path


def _write_observation(path: Path, document: object) -> Path:
    serialized = json.dumps(
        document, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ) + "\n"
    path.write_bytes(serialized.encode("ascii"))
    return path


def _fails(
    directory: Path,
    observation: dict | None = None,
    expected: dict | None = None,
    retail_inputs: dict | None = None,
    zone_map: dict | None = None,
    semantics: dict | None = None,
    catalog: list | None = None,
) -> bool:
    observation_path = _write_observation(
        directory / "observations.json",
        _load(FIXTURE) if observation is None else observation,
    )
    expected_path = _write(
        directory / "expected.json", _load(CHECK) if expected is None else expected
    )
    retail_path = _write(
        directory / "retail-inputs.json",
        _load(RETAIL_INPUTS) if retail_inputs is None else retail_inputs,
    )
    zone_path = _write(
        directory / "zone-map.json", _load(ZONE_MAP) if zone_map is None else zone_map
    )
    semantics_path = _write(
        directory / "semantics.json",
        _load(SEMANTICS) if semantics is None else semantics,
    )
    catalog_path = _write(
        directory / "catalog.json", _load(CATALOG) if catalog is None else catalog
    )
    try:
        return bool(verifier.verify(
            observation_path,
            expected_path,
            retail_path,
            zone_path,
            semantics_path,
            catalog_path,
        ))
    except (OSError, KeyError, TypeError, ValueError, verifier.VerificationError):
        return True


def _run_cli(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VERIFY), "--input", str(path)],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )


def _semantic_row(document: dict) -> dict:
    return next(row for row in document["rows"] if row.get("id") == "s2c-018d")


def _catalog_row(document: list) -> dict:
    return next(
        row for row in document[0]["lists"]["MapClientbound"]
        if row.get("opcodeHex") == "0x018d"
    )


def main() -> int:
    baseline = _load(FIXTURE)
    check_doc = _load(CHECK)
    with tempfile.TemporaryDirectory(prefix="retail-zone-dispatch-test-") as raw:
        directory = Path(raw)
        check("canonical fixture passes", not _fails(directory, baseline))

        for field, replacement in (
            ("schema_version", 2),
            ("check_id", "wrong-check"),
            ("input_id", "wrong-input"),
            ("dispatcher_va", "0xdeadbeef"),
            ("opcode", "0x018e"),
            ("byte_table_va", "0xdeadbeef"),
            ("dword_table_va", "0xdeadbeef"),
            ("byte_table_entry_va", "0xdeadbeef"),
            ("case_index", 135),
            ("vtable_slot", 137),
        ):
            mutated = copy.deepcopy(baseline)
            mutated[field] = replacement
            check(f"observation {field} drift fails", _fails(directory, mutated))

        mutated = copy.deepcopy(baseline)
        del mutated["opcode"]
        check("missing observation field fails", _fails(directory, mutated))
        mutated = copy.deepcopy(baseline)
        mutated["extra"] = True
        check("extra observation field fails", _fails(directory, mutated))
        mutated = copy.deepcopy(baseline)
        mutated["case_index"] = "134"
        check("malformed observation scalar fails", _fails(directory, mutated))
        mutated = copy.deepcopy(baseline)
        mutated["dispatcher_va"] = "0x00DBFD10"
        check("incorrectly cased observation address fails", _fails(directory, mutated))
        mutated = copy.deepcopy(baseline)
        mutated["vtable_slot"] = True
        check("wrong-type observation field fails", _fails(directory, mutated))
        mutated = copy.deepcopy(baseline)
        mutated["schema_version"] = True
        check("boolean observation schema version fails", _fails(directory, mutated))

        unsorted_path = directory / "unsorted-observation.json"
        unsorted = json.dumps(
                dict(reversed(list(baseline.items()))),
                ensure_ascii=True,
                separators=(",", ":"),
            ) + "\n"
        unsorted_path.write_bytes(unsorted.encode("ascii"))
        try:
            verifier.verify(unsorted_path, CHECK, RETAIL_INPUTS, ZONE_MAP, SEMANTICS, CATALOG)
        except verifier.VerificationError:
            check("unsorted observation fields fail", True)
        else:
            check("unsorted observation fields fail", False)

        duplicate_path = directory / "duplicate-observation.json"
        canonical = FIXTURE.read_text(encoding="ascii").rstrip("\n")
        duplicate_path.write_bytes(
            (canonical[:-1] + ',"vtable_slot":136}\n').encode("ascii")
        )
        try:
            verifier.verify(duplicate_path, CHECK, RETAIL_INPUTS, ZONE_MAP, SEMANTICS, CATALOG)
        except verifier.VerificationError:
            check("duplicated observation field fails", True)
        else:
            check("duplicated observation field fails", False)

        for field, replacement in (
            ("schema_version", 2),
            ("input_id", "other-input"),
        ):
            mutated = copy.deepcopy(check_doc)
            mutated[field] = replacement
            check(f"check {field} drift fails", _fails(directory, expected=mutated))
        for field, replacement in (
            ("dispatcher_va", "0xdeadbeef"),
            ("opcode", "0x018e"),
            ("byte_table_va", "0xdeadbeef"),
            ("dword_table_va", "0xdeadbeef"),
        ):
            mutated = copy.deepcopy(check_doc)
            mutated["locator"][field] = replacement
            check(f"check locator {field} drift fails", _fails(directory, expected=mutated))
        for field, replacement in (
            ("byte_table_entry_va", "0xdeadbeef"),
            ("case_index", 135),
            ("vtable_slot", 137),
        ):
            mutated = copy.deepcopy(check_doc)
            mutated["expected"][field] = replacement
            check(f"check expected {field} drift fails", _fails(directory, expected=mutated))
        mutated = copy.deepcopy(check_doc)
        mutated["extra"] = True
        check("extra check field fails", _fails(directory, expected=mutated))
        mutated = copy.deepcopy(check_doc)
        mutated["check"]["version"] = True
        check("boolean check version fails", _fails(directory, expected=mutated))

        for field, replacement in (
            ("schema_version", 2),
            ("filename", "other.exe"),
            ("size", verifier.INPUT_SIZE + 1),
            ("sha256", "0" * 64),
            ("id", "other-input"),
        ):
            mutated = _load(RETAIL_INPUTS)
            mutated["schema_version"] = 2 if field == "schema_version" else mutated["schema_version"]
            if field != "schema_version":
                mutated["inputs"][0][field] = replacement
            check(f"retail input {field} drift fails", _fails(directory, retail_inputs=mutated))
        for field, replacement in (
            ("repository", "other/repository"),
            ("commit", "0" * 40),
            ("path", "other.exe"),
        ):
            mutated = _load(RETAIL_INPUTS)
            mutated["inputs"][0]["source"][field] = replacement
            check(f"private source {field} drift fails", _fails(directory, retail_inputs=mutated))
        mutated = _load(RETAIL_INPUTS)
        mutated["inputs"][0]["allowed_checks"].append("other-check")
        check("allowed-check expansion fails", _fails(directory, retail_inputs=mutated))
        mutated = _load(RETAIL_INPUTS)
        mutated["inputs"].append(copy.deepcopy(mutated["inputs"][0]))
        check("extra private input fails", _fails(directory, retail_inputs=mutated))
        mutated = _load(RETAIL_INPUTS)
        mutated["schema_version"] = True
        check("boolean retail schema version fails", _fails(directory, retail_inputs=mutated))

        zone = _load(ZONE_MAP)
        target = next(row for row in zone["cases"] if "0x018d" in row["opcodes"])
        for field, replacement in (
            ("case", 135), ("vtable_slot", 137), ("is_catchall", True),
        ):
            mutated = _load(ZONE_MAP)
            next(row for row in mutated["cases"] if "0x018d" in row["opcodes"])[field] = replacement
            check(f"dispatch source {field} drift fails", _fails(directory, zone_map=mutated))
        mutated = _load(ZONE_MAP)
        mutated["cases"].append(copy.deepcopy(target))
        check("duplicate dispatch source row fails", _fails(directory, zone_map=mutated))
        mutated = _load(ZONE_MAP)
        mutated["cases"] = [row for row in mutated["cases"] if "0x018d" not in row["opcodes"]]
        check("missing dispatch source row fails", _fails(directory, zone_map=mutated))

        for field, replacement in (
            ("opcodeHex", "0x018e"),
            ("direction", "serverbound"),
            ("status", "open"),
            ("function", "FUN_00000000"),
        ):
            mutated = _load(SEMANTICS)
            _semantic_row(mutated)[field] = replacement
            check(f"semantic source {field} drift fails", _fails(directory, semantics=mutated))
        mutated = _load(SEMANTICS)
        mutated["rows"].append(copy.deepcopy(_semantic_row(mutated)))
        check("duplicate semantic source row fails", _fails(directory, semantics=mutated))
        mutated = _load(SEMANTICS)
        mutated["rows"] = [row for row in mutated["rows"] if row.get("id") != "s2c-018d"]
        check("missing semantic source row fails", _fails(directory, semantics=mutated))

        for field, replacement in (
            ("direction", "serverbound"),
            ("confidence", "speculative"),
            ("decompAnchor", "FUN_00000000"),
            ("implementationAnchor", "MapOpcode::Wrong"),
        ):
            mutated = _load(CATALOG)
            _catalog_row(mutated)[field] = replacement
            check(f"catalog source {field} drift fails", _fails(directory, catalog=mutated))
        mutated = _load(CATALOG)
        mutated[0]["lists"]["MapClientbound"].append(copy.deepcopy(_catalog_row(mutated)))
        check("duplicate catalog source row fails", _fails(directory, catalog=mutated))
        mutated = _load(CATALOG)
        mutated[0]["lists"]["MapClientbound"] = [
            row for row in mutated[0]["lists"]["MapClientbound"]
            if row.get("opcodeHex") != "0x018d"
        ]
        check("missing catalog source row fails", _fails(directory, catalog=mutated))

        if EXPORTER.exists():
            exporter = EXPORTER.read_text(encoding="utf-8")
            check("canonical exporter contract passes",
                  not verifier.exporter_source_errors(exporter))
            for snippet, label in (
                ("validateDispatcherPacketPath(dispatcher, opcodeLoad)", "packet-to-opcode flow"),
                ("\"EAX\".equalsIgnoreCase(((Register) object).getName())", "opcode base-register flow"),
                ("validateByteTableLoad(byteLoad, byteTableVa)", "byte-table flow"),
                ("long dwordEntryVa = dwordTableVa + ((long) caseIndex * 4L)", "case selection flow"),
                ("validateCallbackLoad(body[3])", "callback load flow"),
                ("validateIndirectCall(body[7], \"EAX\")", "callback call flow"),
            ):
                check(f"exporter {label} mismatch fails",
                      bool(verifier.exporter_source_errors(exporter.replace(snippet, "removed", 1))))
            check("exporter expected case literal fails",
                  bool(verifier.exporter_source_errors(exporter + "\nint seeded = 134;\n")))
            check("exporter expected slot literal fails",
                  bool(verifier.exporter_source_errors(exporter + "\nint seeded = 0x88;\n")))

        workflow = WORKFLOW.read_text(encoding="utf-8")
        shared_actions = [
            line.strip().removeprefix("uses: ")
            for line in workflow.splitlines()
            if line.strip().startswith(
                "uses: XIVLegacy/xivl-tools/.github/actions/"
            )
        ]
        shared_revisions = {
            action.rsplit("@", 1)[-1] for action in shared_actions
        }
        shared_revision = next(iter(shared_revisions), "")
        check("workflow is manual only",
              "  workflow_dispatch:\n" in workflow
              and "pull_request:" not in workflow and "push:" not in workflow)
        check("workflow guards protected main",
              "python tools/verify_retail_zone_dispatch.py --check-dispatch" in workflow
              and "if: github.event_name == 'workflow_dispatch'" not in workflow)
        check("shared retail actions use one immutable pin",
              len(shared_actions) == 3 and len(shared_revisions) == 1
              and len(shared_revision) == 40
              and all(char in "0123456789abcdef" for char in shared_revision)
              and sum("/fetch-retail-input@" in action
                      for action in shared_actions) == 1
              and sum("/setup-retail-toolchain@" in action
                      for action in shared_actions) == 1
              and sum("/finalize-retail-attestation@" in action
                      for action in shared_actions) == 1)
        check("local grant passes the token to the shared fetch action",
              "token: ${{ secrets.RETAIL_INPUTS_TOKEN }}" in workflow
              and "commit: aeb52f6dbde95a793ee6d52be28de9f28a885b15" in workflow
              and "path: ffxivgame.exe" in workflow
              and 'size: "15996808"' in workflow
              and "sha256: 9341f2b4567440b310a4d494f5cc5599ca334ba51c8042247317ff466492f2e9" in workflow)
        check("shared fetch action owns input identity",
              "RETAIL_INPUTS_REPOSITORY" not in workflow
              and "name: Verify private input identity" not in workflow)
        check("toolchain explicitly enables Ghidra",
              'include-ghidra: "true"' in workflow)
        check("analysis requires fetch and toolchain",
              "if: steps.fetch.outcome == 'success' && steps.toolchain.outcome == 'success'" in workflow)
        check("finalize precedes the local retained verifier",
              workflow.index("id: finalize") < workflow.index("id: retained")
              and "if: always() && !cancelled() && steps.finalize.outcome == 'success'" in workflow
              and "hashFiles" not in workflow)
        check("artifact upload follows finalize and retained validation",
              "always() && !cancelled() && steps.finalize.outcome == 'success' && steps.retained.outcome == 'success'" in workflow)
        check("failed evidence result requires every evidence stage",
              "steps.fetch.outcome != 'success' || steps.toolchain.outcome != 'success' || steps.analysis.outcome != 'success' || steps.finalize.outcome != 'success' || steps.retained.outcome != 'success'" in workflow)
        check("upload keeps only name and path",
              "if-no-files-found: error" in workflow
              and "retention-days: 30" in workflow
              and "compression-level:" not in workflow
              and "overwrite:" not in workflow
              and "include-hidden-files:" not in workflow)
        check("lane verifier remains local",
              "python tools/verify_retail_zone_dispatch.py --input" in workflow
              and "python tools/verify_retail_zone_dispatch.py --validate-retained-output _retail-staging" in workflow)

        schema = _schema_check.load_schema(SCHEMA)
        attestation = verifier.build_attestation("pass", "1" * 40)
        check("passing attestation satisfies schema", not _schema_check.validate(attestation, schema))
        check("const false is treated as data",
              not _schema_check.validate(False, {"const": False})
              and bool(_schema_check.validate(True, {"const": False})))
        check("enum values are treated as data",
              not _schema_check.validate({"ok": False}, {"enum": [{"ok": False}]})
              and bool(_schema_check.validate({"ok": True}, {"enum": [{"ok": False}]})))
        try:
            _schema_check.validate("value", {"minLength": 1})
        except _schema_check.SchemaError:
            unsupported_keyword_fails_closed = True
        else:
            unsupported_keyword_fails_closed = False
        check("unsupported schema keyword fails closed", unsupported_keyword_fails_closed)
        mutated = copy.deepcopy(attestation)
        mutated["schemaVersion"] = True
        check("boolean attestation schema version fails",
              bool(_schema_check.validate(mutated, schema)))
        mutated = copy.deepcopy(attestation)
        mutated["check"]["version"] = True
        check("boolean attestation check version fails",
              bool(_schema_check.validate(mutated, schema)))
        for mutation, label in (
            (lambda value: value.update(extra=True), "additional field"),
            (lambda value: value["toolVersions"].update(ghidra="latest"), "unpinned tool version"),
            (lambda value: value.update(approvedInputSha256="0" * 63), "malformed input hash"),
            (lambda value: value.update(publicRepositoryCommit="0" * 39 + "G"), "malformed public commit"),
            (lambda value: value["result"].update(status="unknown"), "invalid status"),
        ):
            mutated = copy.deepcopy(attestation)
            mutation(mutated)
            check(f"attestation {label} fails", bool(_schema_check.validate(mutated, schema)))
        try:
            verifier.build_attestation("unknown", "1" * 40)
        except ValueError:
            check("invalid build status fails", True)
        else:
            check("invalid build status fails", False)
        try:
            verifier.build_attestation("pass", "0" * 40)
        except ValueError:
            check("all-zero public commit fails closed", True)
        else:
            check("all-zero public commit fails closed", False)

        safe = directory / "safe"
        safe.mkdir()
        attestation_path = safe / verifier.ATTESTATION_FILENAME
        attestation_path.write_text(
            json.dumps(attestation, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
            encoding="ascii",
        )
        check("single sanitized retained file passes", not verifier.retained_output_errors(safe))
        check("missing retained output root fails",
              bool(verifier.retained_output_errors(directory / "missing-safe")))
        (safe / "extra.log").write_text("unsafe\n", encoding="ascii")
        check("extra retained file fails", bool(verifier.retained_output_errors(safe)))
        (safe / "extra.log").unlink()
        (safe / "nested").mkdir()
        check("nested retained output fails", bool(verifier.retained_output_errors(safe)))
        (safe / "nested").rmdir()
        attestation_path.write_bytes(b"{" + b"a" * 4097 + b"}")
        check("oversized retained output fails", bool(verifier.retained_output_errors(safe)))
        attestation_path.write_text("not-json\n", encoding="ascii")
        check("malformed retained output fails", bool(verifier.retained_output_errors(safe)))
        attestation_path.write_text(json.dumps({"status": "pass"}), encoding="ascii")
        check("schema-invalid retained output fails", bool(verifier.retained_output_errors(safe)))
        attestation_path.write_text(
            json.dumps(attestation, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
            encoding="ascii",
        )
        link_target = directory / "link-target.json"
        link_target.write_text("{}\n", encoding="ascii")
        link = safe / "link"
        try:
            link.symlink_to(link_target)
        except OSError:
            check("retained symlink test is available", os.name == "nt")
        else:
            check("retained symlink fails", bool(verifier.retained_output_errors(safe)))
            link.unlink()

        sha = "1" * 40
        check("main dispatch passes", not verifier.dispatch_errors(
            "workflow_dispatch", "refs/heads/main", sha, sha
        ))
        for event, ref, dispatch_sha, head, label in (
            ("push", "refs/heads/main", sha, sha, "event"),
            ("workflow_dispatch", "refs/heads/feature", sha, sha, "branch"),
            ("workflow_dispatch", "refs/tags/v1", sha, sha, "tag"),
            ("workflow_dispatch", "refs/heads/main", "1" * 39, sha, "abbreviated SHA"),
            ("workflow_dispatch", "refs/heads/main", sha, "2" * 40, "SHA mismatch"),
            ("workflow_dispatch", "refs/heads/main", sha, None, "git resolution"),
        ):
            check(f"unauthorized dispatch {label} fails", bool(verifier.dispatch_errors(
                event, ref, dispatch_sha, head
            )))
        with mock.patch.object(verifier.subprocess, "run", side_effect=OSError("missing git")):
            try:
                verifier._git_commit()
            except verifier.VerificationError:
                check("git command failure fails closed", True)
            else:
                check("git command failure fails closed", False)

        failed = copy.deepcopy(baseline)
        failed["vtable_slot"] = 135
        failed_path = _write_observation(directory / "failed.json", failed)
        result = _run_cli(failed_path)
        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError:
            output = {}
        check("failure invocation exits nonzero", result.returncode != 0)
        check("failure output is sanitized", set(output) == {
            "schemaVersion", "publicRepositoryCommit", "approvedInputSha256",
            "toolVersions", "check", "result",
        } and output.get("result", {}).get("status") == "fail"
              and "vtable_slot" not in result.stdout
              and "vtable_slot" not in result.stderr)

        first = _run_cli(FIXTURE)
        second = _run_cli(FIXTURE)
        check("repeated passing output is byte-identical",
              first.returncode == second.returncode == 0
              and first.stdout.encode() == second.stdout.encode())

        raw_output = subprocess.run(
            [sys.executable, str(VERIFY), "--input", str(FIXTURE)],
            cwd=REPO,
            capture_output=True,
            check=False,
        )
        check("attestation output uses canonical LF bytes",
              raw_output.returncode == 0
              and raw_output.stdout.endswith(b"\n")
              and b"\r" not in raw_output.stdout)

    if FAILED:
        print("FAIL: " + "; ".join(FAILED))
        return 1
    print(f"PASS: {len(PASSED)} zone-dispatch verification checks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
