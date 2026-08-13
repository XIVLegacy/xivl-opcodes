"""Generate packed per-opcode C++ payload headers from layout digestion.

Each struct omits the 8-byte inner header and locks the observed body size.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import struct
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

from _json_io import DATA_DIR, OPCODES_PATH, REPO_ROOT

# Layouts and samples are pcap-derived fixtures pinned by data/vendor/captures/PROVENANCE.json;
# --digest is an explicit research override.
_DIGEST = DATA_DIR / "vendor" / "captures"
LAYOUTS_IN = _DIGEST / "payload_layouts.json"
SAMPLES_IN = _DIGEST / "payload_samples.json"
OPCODES_IN = OPCODES_PATH
DEFAULT_OUT_DIR = REPO_ROOT / "structs"

INNER_HEADER_LEN = 8

BUCKET_LAYOUT = {
    "LobbyServerbound": ("lobby", "serverbound"),
    "LobbyClientbound": ("lobby", "clientbound"),
    "WorldServerbound": ("world", "serverbound"),
    "WorldClientbound": ("world", "clientbound"),
    "MapServerbound": ("map", "serverbound"),
    "MapClientbound": ("map", "clientbound"),
    "WorldMapBackend": ("worldmap", "backend"),
}

# WorldMapBackend is checked first; ambiguous client directions prefer Map buckets.
DIRECTION_TO_PREFERRED_BUCKETS = {
    "c2s": ["WorldMapBackend", "MapServerbound", "WorldServerbound", "LobbyServerbound"],
    "s2c": ["WorldMapBackend", "MapClientbound", "WorldClientbound", "LobbyClientbound"],
}

# Stable, source-backed semantic comments keyed by generated bucket, opcode,
# and rebased application-payload offset. Generated fields remain generic
# unless a row has a reviewed semantic label here.
FIELD_COMMENT_OVERRIDES = {
    ("MapClientbound", "0x017f", 408):
        "memberCount low byte at payload+0x190; not isOnline",
}

NAME_SUFFIX_STRIP = re.compile(r"(Packet|Handler)$")
NAME_BAD_CHARS = re.compile(r"[^A-Za-z0-9_]")


def sanitize_struct_name(catalog_name: str) -> str:
    """Return a valid C++ Body identifier derived from a catalog name."""
    base = NAME_SUFFIX_STRIP.sub("", catalog_name)
    base = NAME_BAD_CHARS.sub("_", base)
    if not base:
        base = "Unknown"
    if base[0].isdigit():
        base = f"_{base}"
    return f"{base}Body"


def resolve_bucket(catalog: dict, direction: str, opcode_hex: str) -> tuple[str, str] | None:
    """Return the preferred bucket/name for a direction and opcode, or None."""
    for bucket in DIRECTION_TO_PREFERRED_BUCKETS[direction]:
        for entry in catalog["lists"].get(bucket, []):
            if entry["opcodeHex"].lower() == opcode_hex.lower():
                # Backend rows share opcodes across directions; pcap supplies wire direction only.
                if bucket == "WorldMapBackend":
                    return bucket, entry["name"]
                if (direction == "c2s" and bucket.endswith("Serverbound")) or (
                    direction == "s2c" and bucket.endswith("Clientbound")
                ):
                    return bucket, entry["name"]
    return None


def detect_f32(samples: list[dict], body_offset: int) -> bool:
    """Classify a 4-byte field as float-like only with varied, bounded samples."""
    wire_offset = body_offset + INNER_HEADER_LEN
    finite = 0
    total = 0
    seen_magnitudes: set[int] = set()
    for s in samples:
        raw = bytes.fromhex(s["bytes"])
        if wire_offset + 4 > len(raw):
            continue
        word = raw[wire_offset : wire_offset + 4]
        try:
            u32 = struct.unpack("<I", word)[0]
        except struct.error:
            continue
        total += 1
        exp = (u32 >> 23) & 0xFF
        if exp == 0 or exp == 0xFF:
            continue
        val = struct.unpack("<f", word)[0]
        if not math.isfinite(val):
            continue
        if not (1.0e-4 <= abs(val) <= 1.0e6):
            continue
        finite += 1
        # Exponent bins distinguish coordinate variation from random noise.
        seen_magnitudes.add(exp)
    if total == 0:
        return False
    if len(seen_magnitudes) < 2 and total > 4:
        return False
    return (finite / total) >= 0.80


def detect_f32_array(samples: list[dict], body_offset: int, width: int) -> bool:
    if width < 4 or width % 4 != 0:
        return False
    for chunk in range(0, width, 4):
        if not detect_f32(samples, body_offset + chunk):
            return False
    return True


def trim_to_body(fields: list[dict]) -> list[dict]:
    """Drop inner-header bytes and rebase remaining offsets to the body."""
    out: list[dict] = []
    for f in fields:
        end = f["offset"] + f["width"]
        if end <= INNER_HEADER_LEN:
            continue
        if f["offset"] < INNER_HEADER_LEN:
            new_offset = 0
            new_width = end - INNER_HEADER_LEN
            if new_width <= 0:
                continue
            out.append({**f, "offset": new_offset, "width": new_width})
        else:
            out.append({**f, "offset": f["offset"] - INNER_HEADER_LEN})
    return out


def emit_field(field: dict, index: int, samples: list[dict]) -> tuple[str, int]:
    """Emit one C++ field declaration. Returns (line, bytes_consumed)."""
    role = field["role"]
    width = field["width"]
    off = field["offset"]
    end = off + width - 1

    if role == "zero_pad":
        if width == 1:
            return (f"    uint8_t _pad{index};  // body[+{off}] zero", width)
        return (
            f"    uint8_t _pad{index}[{width}];  // body[+{off}..+{end}] zero",
            width,
        )

    if role == "constant":
        value = field["value"]
        if width == 1:
            return (
                f"    uint8_t _const{index};  // body[+{off}] = 0x{value:02x}",
                width,
            )
        return (
            f"    uint8_t _const{index}[{width}];"
            f"  // body[+{off}..+{end}] each byte = 0x{value:02x}",
            width,
        )

    distinct = field.get("distinct", "?")
    if width == 1:
        return (
            f"    uint8_t field{index};  // body[+{off}] u8 ({distinct} distinct)",
            width,
        )
    if width == 2:
        return (
            f"    uint16_t field{index};  // body[+{off}..+{end}] u16 ({distinct} distinct)",
            width,
        )
    if width == 4:
        is_float = detect_f32(samples, off) if samples else False
        c_type = "float" if is_float else "uint32_t"
        kind = "f32" if is_float else "u32"
        return (
            f"    {c_type} field{index};  // body[+{off}..+{end}] {kind} ({distinct} distinct)",
            width,
        )
    if width == 8:
        if samples and detect_f32_array(samples, off, 8):
            return (
                f"    float field{index}[2];  // body[+{off}..+{end}] 2x f32 ({distinct} distinct)",
                width,
            )
        return (
            f"    uint64_t field{index};  // body[+{off}..+{end}] u64 ({distinct} distinct)",
            width,
        )
    if width >= 4 and width % 4 == 0 and samples and detect_f32_array(samples, off, width):
        count = width // 4
        return (
            f"    float field{index}[{count}];  // body[+{off}..+{end}] {count}x f32 ({distinct} distinct)",
            width,
        )
    return (
        f"    uint8_t field{index}[{width}];  // body[+{off}..+{end}] {width}B ({distinct} distinct)",
        width,
    )


def emit_struct(
    bucket: str,
    struct_name: str,
    opcode_hex: str,
    layout: dict,
    samples: list[dict],
) -> tuple[str, int, int]:
    """Build the full struct text. Returns (text, fields_size, body_size).

    fields_size is the sum of declared field widths; body_size is the
    declared payload length after the inner header. They should match.
    """
    body_length_full = layout["body_length"]
    body_size = max(0, body_length_full - INNER_HEADER_LEN)
    fields = trim_to_body(layout["fields"])

    lines = [
        f"// 0x{opcode_hex[2:].lower()} (opcode {layout['opcode']}) - sub_size={layout['common_sub_size']}B"
        f" body={body_size}B samples={layout['sample_count']}",
        f"struct {struct_name} {{",
    ]
    if body_size == 0:
        lines.append("    // no payload after inner header")
        lines.append("};")
        return "\n".join(lines), 0, 0

    bytes_emitted = 0
    for i, f in enumerate(fields):
        line, w = emit_field(f, i, samples)
        semantic_comment = FIELD_COMMENT_OVERRIDES.get(
            (bucket, opcode_hex.lower(), f["offset"])
        )
        if semantic_comment:
            line = f"{line}; {semantic_comment}"
        lines.append(line)
        bytes_emitted += w
    lines.append("};")
    # Assert the observed body size, not the field sum, so underfilled layouts fail validation.
    lines.append(
        f"static_assert(sizeof({struct_name}) == {body_size},"
        f" \"{struct_name} size mismatch\");"
    )
    return "\n".join(lines), bytes_emitted, body_size


def validate_field_comment_overrides(
    by_bucket: dict[str, list[tuple[str, str, dict, list[dict]]]]
) -> None:
    """Reject semantic comments whose keyed layout row is no longer emitted."""
    available = {
        (bucket, opcode_hex.lower(), field["offset"])
        for bucket, entries in by_bucket.items()
        for opcode_hex, _struct_name, layout, _samples in entries
        for field in trim_to_body(layout["fields"])
    }
    missing = [key for key in FIELD_COMMENT_OVERRIDES if key not in available]
    if missing:
        raise ValueError(f"field comment override has no emitted layout row: {missing}")


def build_header(bucket: str, entries: list[tuple[str, str, dict, list[dict]]]) -> str:
    """Compose and format a single header file for one bucket."""
    subdir, leaf = BUCKET_LAYOUT[bucket]
    out: list[str] = [
        "// Auto-generated by tools/generate_structs.py from the"
        " pinned packet-observation payload layouts.",
        f"// Bucket: {bucket}. Do not edit by hand; re-run the generator.",
        "#pragma once",
        "",
        "#include <cstdint>",
        "",
        "#pragma pack(push, 1)",
        "",
        f"namespace bahamut::opcodes::{subdir} {{",
        f"namespace {leaf} {{",
        "",
    ]
    for opcode_hex, struct_name, layout, samples in sorted(entries, key=lambda t: t[0]):
        text, fields_size, body_size = emit_struct(
            bucket, struct_name, opcode_hex, layout, samples
        )
        if fields_size != body_size and body_size > 0:
            text += (
                f"\n// NOTE: emitted {fields_size}B but layout declares {body_size}B"
                f" for {struct_name}; check the pinned payload-layout grouping"
            )
        out.append(text)
        out.append("")
    out.append(f"}}  // namespace {leaf}")
    out.append(f"}}  // namespace bahamut::opcodes::{subdir}")
    out.append("")
    out.append("#pragma pack(pop)")
    out.append("")
    source = "\n".join(out)
    try:
        result = subprocess.run(
            [
                "clang-format",
                "--style=file",
                f"--assume-filename={REPO_ROOT / 'structs' / 'generated.h'}",
            ],
            cwd=REPO_ROOT,
            input=source,
            capture_output=True,
            text=True,
            encoding="ascii",
            check=False,
        )
    except FileNotFoundError as exc:
        raise SystemExit(
            "error: clang-format 22 is required; install tools/requirements.txt"
        ) from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit code {result.returncode}"
        raise SystemExit(f"error: clang-format failed: {detail}")
    return result.stdout


DECL_RE = re.compile(
    r"^\s*(uint8_t|uint16_t|uint32_t|uint64_t|float)\s+([A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\[(\d+)\])?\s*;"
)
STATIC_ASSERT_RE = re.compile(
    r"^static_assert\(\s*sizeof\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*==\s*(\d+)"
)
STRUCT_DECL_RE = re.compile(r"^struct\s+([A-Za-z_][A-Za-z0-9_]*)\s*(\{)?\s*$")
STRUCT_CLOSE_RE = re.compile(r"^\};\s*$")
TYPE_WIDTHS = {
    "uint8_t": 1,
    "uint16_t": 2,
    "uint32_t": 4,
    "uint64_t": 8,
    "float": 4,
}


def validate_header(path: Path) -> tuple[int, int]:
    text = path.read_text(encoding="ascii")
    current_struct: str | None = None
    pending_struct: str | None = None
    accum: int = 0
    sizes: dict[str, int] = {}
    errors = 0
    structs = 0
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        m = STRUCT_DECL_RE.match(stripped)
        if m:
            if current_struct is not None or pending_struct is not None:
                owner = current_struct or pending_struct
                print(f"{path}:{lineno}: nested struct open inside {owner}")
                errors += 1
            if m.group(2):
                current_struct = m.group(1)
                accum = 0
            else:
                pending_struct = m.group(1)
            continue
        if pending_struct is not None:
            if stripped != "{":
                print(f"{path}:{lineno}: expected opening brace for {pending_struct}")
                errors += 1
                pending_struct = None
            else:
                current_struct = pending_struct
                pending_struct = None
                accum = 0
                continue
        if STRUCT_CLOSE_RE.match(stripped):
            if current_struct is None:
                print(f"{path}:{lineno}: close without open")
                errors += 1
            else:
                sizes[current_struct] = accum
                structs += 1
                current_struct = None
            continue
        m = DECL_RE.match(raw_line)
        if m and current_struct is not None:
            t, _name, count = m.groups()
            accum += TYPE_WIDTHS[t] * (int(count) if count else 1)
            continue
        m = STATIC_ASSERT_RE.match(stripped)
        if m:
            sname, expected = m.group(1), int(m.group(2))
            actual = sizes.get(sname)
            if actual is None:
                print(f"{path}:{lineno}: static_assert references unknown struct {sname}")
                errors += 1
            elif actual != expected:
                print(
                    f"{path}:{lineno}: {sname} size mismatch: static_assert={expected}"
                    f" vs sum-of-fields={actual}"
                )
                errors += 1
    if current_struct is not None:
        print(f"{path}: unclosed struct {current_struct}")
        errors += 1
    if pending_struct is not None:
        print(f"{path}: missing opening brace for {pending_struct}")
        errors += 1
    return errors, structs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR))
    ap.add_argument(
        "--digest",
        default=None,
        help="Directory holding payload_layouts.json/payload_samples.json"
        " (default: vendored copy in data/vendor/captures). Point this at a"
        " packet-observation source checkout for a research rerun with fresher"
        " digestion.",
    )
    ap.add_argument("--layouts", default=None, help="Overrides --digest for payload_layouts.json")
    ap.add_argument("--samples", default=None, help="Overrides --digest for payload_samples.json")
    ap.add_argument("--catalog", default=str(OPCODES_IN))
    ap.add_argument(
        "--validate",
        action="store_true",
        help="Run Python-side syntax sanity check after writing",
    )
    args = ap.parse_args()

    digest_dir = Path(args.digest) if args.digest else _DIGEST
    layouts_path = Path(args.layouts) if args.layouts else digest_dir / "payload_layouts.json"
    samples_path = Path(args.samples) if args.samples else digest_dir / "payload_samples.json"

    layouts_doc = json.loads(layouts_path.read_text(encoding="utf-8"))
    samples_doc = json.loads(samples_path.read_text(encoding="utf-8"))
    catalog_wrapper = json.loads(Path(args.catalog).read_text(encoding="utf-8"))
    if (
        not isinstance(catalog_wrapper, list)
        or len(catalog_wrapper) != 1
        or not isinstance(catalog_wrapper[0], dict)
    ):
        print("error: catalog root must contain exactly one object", file=sys.stderr)
        return 1
    catalog = catalog_wrapper[0]

    sample_index: dict[tuple[str, str], list[dict]] = {}
    for direction in ("c2s", "s2c"):
        for hex_key, bundle in samples_doc["samples"].get(direction, {}).items():
            sample_index[(direction, hex_key)] = bundle.get("samples", [])

    by_bucket: dict[str, list[tuple[str, str, dict, list[dict]]]] = defaultdict(list)
    skipped: list[str] = []

    for direction in ("c2s", "s2c"):
        for hex_key, layout in layouts_doc["layouts"][direction].items():
            resolved = resolve_bucket(catalog, direction, hex_key)
            if resolved is None:
                skipped.append(f"{direction} {hex_key}: no matching catalog entry")
                continue
            bucket, name = resolved
            struct_name = sanitize_struct_name(name)
            samples = sample_index.get((direction, hex_key), [])
            by_bucket[bucket].append((hex_key, struct_name, layout, samples))

    validate_field_comment_overrides(by_bucket)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    files_written: list[Path] = []

    for bucket in sorted(by_bucket.keys()):
        entries = by_bucket[bucket]
        subdir, leaf = BUCKET_LAYOUT[bucket]
        bucket_dir = out_dir / subdir
        bucket_dir.mkdir(parents=True, exist_ok=True)
        header_path = bucket_dir / f"{leaf}.h"
        header_path.write_text(build_header(bucket, entries), encoding="ascii")
        files_written.append(header_path)
        print(f"wrote {header_path.relative_to(Path(args.out_dir).parent)}  ({len(entries)} structs)")

    print()
    print(f"summary: {len(files_written)} headers across {len(by_bucket)} buckets")
    if skipped:
        print(f"skipped {len(skipped)} layouts (no catalog match):")
        for s in skipped[:20]:
            print(f"  {s}")

    if args.validate:
        total_errors = 0
        total_structs = 0
        for p in files_written:
            errs, structs = validate_header(p)
            total_errors += errs
            total_structs += structs
        print()
        if total_errors:
            print(f"validation: {total_errors} errors across {len(files_written)} headers")
            return 1
        print(
            f"validation: OK ({total_structs} structs across {len(files_written)} headers)"
            f"  [python-side; no C++ compiler on PATH]"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
