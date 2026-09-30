#!/usr/bin/env python3
"""Compiler-backed negative controls for generated payload headers."""

from __future__ import annotations

import argparse
import contextlib
import io
import re
import sys
import tempfile
from pathlib import Path

import validate_generated_headers as validator


def run(directory: Path, compiler: str) -> tuple[int, str]:
    output = io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
        status = validator.main(
            ["--headers-dir", str(directory), "--compiler", compiler]
        )
    return status, output.getvalue()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", default="clang++")
    args = parser.parse_args(argv)
    status, output = run(validator.DEFAULT_HEADERS, args.compiler)
    if status:
        print(output, file=sys.stderr)
        return status

    source = (validator.DEFAULT_HEADERS / "world" / "serverbound.h").read_text(
        encoding="ascii"
    )
    wrong_size, replacements = re.subn(
        r"(static_assert\(sizeof\(\w+\) == )(\d+)",
        lambda match: match[1] + str(int(match[2]) + 1),
        source,
        count=1,
    )
    if (
        replacements != 1
        or source.count("#pragma pack(pop)") != 1
        or source.count("#include <cstdint>") != 1
    ):
        print("FAIL: negative-control source contract changed", file=sys.stderr)
        return 1
    failures: list[str] = []
    checks = 1
    with tempfile.TemporaryDirectory(prefix="generated-header-test-") as raw:
        root = Path(raw)
        missing = str(root / "missing-compiler")
        status, _output = run(validator.DEFAULT_HEADERS, missing)
        checks += 1
        if status != 2:
            failures.append("missing explicit compiler did not report setup failure")
        status, _output = run(root, args.compiler)
        checks += 1
        if status != 2:
            failures.append("empty header set did not report setup failure")

        header = root / "serverbound.h"
        for label, mutated, diagnostic in (
            (
                "self-containment",
                source.replace("#include <cstdint>", ""),
                "error:",
            ),
            ("syntax", source + "invalid C++ syntax;\n", "error:"),
            ("size", wrong_size, "size mismatch"),
            (
                "packing",
                source.replace("#pragma pack(pop)", ""),
                "caller packing",
            ),
        ):
            header.write_text(mutated, encoding="ascii")
            status, output = run(root, args.compiler)
            checks += 1
            if status != 1 or diagnostic not in output:
                failures.append(f"{label} defect was not rejected by compilation")

        collision = "\nstruct GeneratedHeaderCollision {};\n"
        header.write_text(source + collision, encoding="ascii")
        other = root / "clientbound.h"
        other.write_text(
            (validator.DEFAULT_HEADERS / "world" / "clientbound.h").read_text(
                encoding="ascii"
            )
            + collision,
            encoding="ascii",
        )
        errors = validator.compile_headers([header, other], args.compiler)
        checks += 1
        if (
            len(errors) != 2
            or any(not error.startswith("all headers together") for error in errors)
            or any("redefinition" not in error for error in errors)
        ):
            failures.append("combined-only declaration collision was not rejected")

    if failures:
        print("FAIL: " + "; ".join(failures), file=sys.stderr)
        return 1
    print(f"PASS: {checks} generated-header compilation checks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
