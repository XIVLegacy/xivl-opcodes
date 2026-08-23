#!/usr/bin/env python3
"""Refresh data/vendor fixtures from explicitly named sources and update provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from audit_payload_framing import MANIFESTS, load_schema_lengths_with_sources
from validate_corpus import BCSY_RE

REPO = Path(__file__).resolve().parents[1]
VENDOR = REPO / "data" / "vendor"
HEX40 = re.compile(r"[0-9a-f]{40}")


class RefreshError(Exception):
    """A refresh cannot be completed safely."""


def git(checkout: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(checkout), *args], capture_output=True, check=False
    )
    if result.returncode != 0:
        raise RefreshError(
            f"git {' '.join(args)} failed in {checkout}: "
            f"{result.stderr.decode('utf-8', 'replace').strip()}"
        )
    return result.stdout


def dump(document: object) -> bytes:
    """Return canonical UTF-8 JSON bytes for a derived fixture."""
    return (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def derive_captures_index(checkout: Path, commit: str, source_path: str) -> bytes:
    """Build the complete capture-name fixture used to validate observedIn."""
    listing = git(checkout, "ls-tree", "--name-only", commit, f"{source_path.rstrip('/')}/")
    names = sorted(
        Path(line).name
        for line in listing.decode("utf-8").splitlines()
        if line.endswith(".pcapng")
    )
    if not names:
        raise RefreshError(f"{commit}:{source_path} lists no .pcapng files")
    return dump({"captureNames": names})


def derive_bcsy_ids(checkout: Path, commit: str, source_path: str) -> bytes:
    """Build the BCS-Y id fixture from the cited symbols manifest."""
    text = git(checkout, "show", f"{commit}:{source_path}").decode("utf-8")
    ids = sorted(set(BCSY_RE.findall(text)))
    if not ids:
        raise RefreshError(f"{commit}:{source_path} mentions no BCS-Y ids")
    return dump({"bcsyIds": ids})


def derive_bcsy_opcode_bindings(checkout: Path, commit: str, source_path: str) -> bytes:
    """Build sync candidates from structured BCS-Y-to-opcode IR relationships."""
    document = json.loads(git(checkout, "show", f"{commit}:{source_path}").decode("utf-8"))
    symbols = {
        entry["id"]: {"name": entry["name"], "kind": entry["kind"]}
        for entry in document.get("symbols", [])
        if BCSY_RE.fullmatch(entry.get("id", ""))
    }
    bindings: dict[str, set[tuple[str, str]]] = {}
    relationships = document.get("relationships", {}).get("opcodes", [])
    for opcode in relationships:
        direction = opcode.get("direction")
        opcode_hex = opcode.get("hex")
        if direction not in {"c2s", "s2c"} or not isinstance(opcode_hex, str):
            raise RefreshError(f"{commit}:{source_path} has a malformed opcode relationship")
        for symbol_id in opcode.get("symbols", []):
            if symbol_id not in symbols:
                raise RefreshError(
                    f"{commit}:{source_path} opcode relationship names unknown symbol {symbol_id!r}"
                )
            bindings.setdefault(symbol_id, set()).add((direction, opcode_hex))

    if not bindings:
        raise RefreshError(f"{commit}:{source_path} has no BCS-Y opcode bindings")
    candidates = []
    for symbol_id in sorted(bindings):
        symbol = symbols[symbol_id]
        candidates.append({
            "bcsyId": symbol_id,
            "name": symbol["name"],
            "kind": symbol["kind"],
            "opcodeBindings": [
                {"direction": direction, "opcodeHex": opcode_hex}
                for direction, opcode_hex in sorted(bindings[symbol_id])
            ],
        })
    return dump({"syncCandidates": candidates})


def derive_payload_inner_lengths(checkout: Path, commit: str, source_path: str) -> bytes:
    """Build inner payload lengths through the framing audit's merge rule."""
    base = source_path.rstrip("/")
    with tempfile.TemporaryDirectory() as raw:
        staged = Path(raw)
        for filename, _collection_key, _direction in MANIFESTS:
            (staged / filename).write_bytes(git(checkout, "show", f"{commit}:{base}/{filename}"))
        merged = load_schema_lengths_with_sources(staged)
    return dump({
        "innerLengths": [
            {"direction": direction, "opcode": opcode, "innerLen": inner_len, "source": source}
            for (direction, opcode), (inner_len, source) in sorted(merged.items())
        ]
    })


DERIVERS = {
    "captures-index": derive_captures_index,
    "bcsy-ids": derive_bcsy_ids,
    "bcsy-opcode-bindings": derive_bcsy_opcode_bindings,
    "payload-inner-lengths": derive_payload_inner_lengths,
}


def load_provenance(path: Path) -> dict:
    provenance = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(provenance, dict) or not isinstance(provenance.get("files"), list):
        raise RefreshError(f"{path}: files must be an array")
    return provenance


def write_provenance(path: Path, provenance: dict) -> None:
    path.write_text(
        json.dumps(provenance, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8", newline="\n",
    )


def refresh_entry(entry: dict, directory: Path, checkouts: dict[str, Path], args) -> str:
    name = entry["file"]
    fixture = directory / name
    source_repo = entry["sourceRepo"]

    checkout = checkouts.get(source_repo)
    if checkout is None:
        raise RefreshError(
            f"missing --repo {source_repo}=PATH for the requested fixture"
        )

    commit = args.commit
    if not HEX40.fullmatch(commit):
        raise RefreshError(f"--commit must be a full 40-hex lowercase hash naming the source revision to fetch, got {commit!r}")
    source_path = args.source_path or entry["sourcePath"]

    mode = entry.get("refreshMode")
    if mode == "copy":
        payload = git(checkout, "show", f"{commit}:{source_path}")
    elif mode == "derive":
        deriver = DERIVERS.get(entry.get("deriver"))
        if deriver is None:
            raise RefreshError(f"{name}: unknown deriver {entry.get('deriver')!r}")
        payload = deriver(checkout, commit, source_path)
    else:
        raise RefreshError(f"{name}: unknown refreshMode {mode!r}")

    # Require promoted evidence to be valid JSON before writing it.
    json.loads(payload.decode("utf-8"))

    was_drifted = not fixture.is_file() or fixture.read_bytes() != payload
    fixture.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    entry["sourcePath"] = source_path
    entry["sha256"] = digest

    verb = "re-pinned" if was_drifted else "unchanged"
    return f"{verb} {fixture.relative_to(REPO)} (fetched from {source_repo} at the given --commit; sha256 {digest[:12]})"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "--repo", action="append", default=[], metavar="NAME=PATH",
        help="source checkout for a sourceRepo named in PROVENANCE; repeatable",
    )
    ap.add_argument("--only", default=None, help="single fixture to re-pin, such as data/vendor/captures/payload_samples.json")
    ap.add_argument("--commit", default=None, help="full 40-hex source commit to fetch from (required)")
    ap.add_argument("--source-path", default=None, help="path inside the source repository, overriding the stored sourcePath")
    args = ap.parse_args()

    if not args.only or not args.commit:
        print("error: refreshing a fixture requires both --only and --commit", file=sys.stderr)
        return 2

    checkouts: dict[str, Path] = {}
    for spec in args.repo:
        name, _, raw = spec.partition("=")
        path = Path(raw)
        if not name or not raw or not (path / ".git").exists():
            print(f"error: --repo {spec} must be NAME=PATH pointing at a git checkout", file=sys.stderr)
            return 2
        checkouts[name] = path

    only = (REPO / args.only).resolve() if args.only else None

    exit_code = 0
    touched = 0
    for provenance_path in sorted(VENDOR.glob("*/PROVENANCE.json")):
        directory = provenance_path.parent
        if only.parent != directory:
            continue
        try:
            provenance = load_provenance(provenance_path)
        except (OSError, json.JSONDecodeError, RefreshError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        dirty = False
        for entry in provenance["files"]:
            if only is not None and entry.get("file") != only.name:
                continue
            try:
                print(refresh_entry(entry, directory, checkouts, args))
            except (RefreshError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                print(f"error: {entry.get('file')}: {exc}", file=sys.stderr)
                exit_code = 1
                continue
            dirty = True
            touched += 1
        if dirty:
            write_provenance(provenance_path, provenance)

    if touched == 0 and exit_code == 0:
        print(f"error: no PROVENANCE entry for {args.only}", file=sys.stderr)
        return 2
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
