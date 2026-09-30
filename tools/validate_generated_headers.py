#!/usr/bin/env python3
"""Compile generated payload headers and check caller packing in C++17."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from _json_io import REPO_ROOT


DEFAULT_HEADERS = REPO_ROOT / "structs"


def header_paths(directory: Path) -> list[Path]:
    """Find every header without traversing links or junctions."""
    if directory.is_symlink() or getattr(directory, "is_junction", lambda: False)():
        raise ValueError(f"header root is a link or junction: {directory}")
    if not directory.is_dir():
        raise ValueError(f"header directory is missing: {directory}")
    headers: list[Path] = []
    for root, directories, files in os.walk(directory, followlinks=False):
        base = Path(root)
        for path in [base, *(base / name for name in directories + files)]:
            if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
                raise ValueError(f"header tree contains a link or junction: {path}")
        headers.extend(base / name for name in files if name.endswith(".h"))
    if not headers:
        raise ValueError(f"no generated headers found in {directory}")
    return sorted(path.resolve() for path in headers)


def translation_unit(headers: list[Path], packed: bool) -> str:
    """Compare layout before and after includes and after the caller's pop."""
    lines = [
        "struct NaturalPacking { char lead; unsigned int word; };",
        "#pragma pack(push, 2)" if packed else "#pragma pack(push)",
        "struct CallerPacking { char lead; unsigned int word; };",
    ]
    for index, header in enumerate(headers):
        lines.append(f'#include "{header.as_posix()}"')
        name = f"AfterHeader{index}"
        lines.append(f"struct {name} {{ char lead; unsigned int word; }};")
        lines.extend(_packing_assertions(name, "CallerPacking"))
    lines.extend(
        [
            "#pragma pack(pop)",
            "struct ReturnedPacking { char lead; unsigned int word; };",
            *_packing_assertions("ReturnedPacking", "NaturalPacking"),
        ]
    )
    return "\n".join(lines) + "\n"


def _packing_assertions(actual: str, expected: str) -> list[str]:
    return [
        f'static_assert(sizeof({actual}) == sizeof({expected}), "caller packing size changed");',
        f'static_assert(alignof({actual}) == alignof({expected}), "caller packing alignment changed");',
        f'static_assert(__builtin_offsetof({actual}, word) == __builtin_offsetof({expected}, word), "caller packing offset changed");',
    ]


def compile_headers(headers: list[Path], compiler: str) -> list[str]:
    """Return compilation failures from standalone and combined includes."""
    executable = shutil.which(compiler)
    if executable is None:
        raise ValueError(
            f"C++ compiler not found: {compiler}; select clang++ or g++ with --compiler"
        )
    command = [
        executable,
        "-std=c++17",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-fsyntax-only",
        "-x",
        "c++",
        "-",
    ]
    groups = [(str(header), [header]) for header in headers]
    groups.append(("all headers together", headers))
    errors: list[str] = []
    for label, group in groups:
        for packed in (False, True):
            result = subprocess.run(
                command,
                cwd=REPO_ROOT,
                input=translation_unit(group, packed),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            if result.returncode:
                mode = "pack(2)" if packed else "default packing"
                detail = result.stderr.strip() or result.stdout.strip()
                errors.append(
                    f"{label}, {mode}: compiler exited {result.returncode}\n{detail}"
                )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--compiler",
        default="clang++",
        help="Clang/GCC C++ driver name or executable path",
    )
    parser.add_argument(
        "--headers-dir",
        type=Path,
        default=DEFAULT_HEADERS,
        help="Generated header root",
    )
    args = parser.parse_args(argv)
    try:
        headers = header_paths(args.headers_dir)
        errors = compile_headers(headers, args.compiler)
    except (OSError, ValueError) as exc:
        print(f"Generated headers C++ could not run: {exc}", file=sys.stderr)
        return 2
    if errors:
        print("Generated headers C++ FAILED:", file=sys.stderr)
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(
        f"Generated headers C++ OK ({len(headers)} headers individually and together; "
        f"default packing and pack(2); compiler: {args.compiler})."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
