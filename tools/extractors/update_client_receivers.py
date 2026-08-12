#!/usr/bin/env python3
"""Update client receivers from one explicit client-evidence catalog."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _json_io import DATA_DIR, write_json  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8")

RECEIVERS_PATH = DATA_DIR / "client_receivers.json"


def load_receivers() -> tuple[dict, dict[str, dict]]:
    with RECEIVERS_PATH.open(encoding="utf-8") as f:
        receivers = json.load(f)
    by_name = {receiver["name"]: receiver for receiver in receivers["receivers"]}
    return receivers, by_name


def write_receivers(receivers: dict) -> None:
    write_json(RECEIVERS_PATH, receivers)
    print(f"wrote {RECEIVERS_PATH}")


def update_apply_chain(firers_path: Path) -> int:
    if not firers_path.is_file():
        print(f"error: --firers not found: {firers_path}", file=sys.stderr)
        return 1

    with firers_path.open(encoding="utf-8") as f:
        firers = json.load(f)
    recvs, by_name = load_receivers()

    added_per_receiver: dict[str, list[dict]] = {}
    for fr in firers.get("firers", []):
        recv_name = fr.get("receiverClass")
        if not recv_name or recv_name not in by_name:
            print(f"  warning: receiver {recv_name} not in client_receivers.json")
            continue
        entry = {
            "luaName": fr["luaName"],
            "opcode": fr["opcodeHex"],
            "applyHelperVa": fr.get("applyHelperVa"),
            "fireSite": fr.get("fireSite"),
            "evidenceBcsy": fr.get("evidenceBcsy"),
            "mechanism": "apply_chain",
            "bindingFlavor": fr.get("bindingFlavor", "direct"),
        }
        added_per_receiver.setdefault(recv_name, []).append(entry)

    affected = 0
    for recv_name, readers in added_per_receiver.items():
        receiver = by_name[recv_name]
        existing = receiver.get("apply_chain_lua_readers", [])
        existing_keys = {(entry["luaName"], entry["opcode"]) for entry in existing}
        new = [
            entry
            for entry in readers
            if (entry["luaName"], entry["opcode"]) not in existing_keys
        ]
        if new:
            receiver["apply_chain_lua_readers"] = existing + new
            affected += 1

    recvs["apply_chain_note"] = (
        "xivl-client-structs (BCS-Y-0351) added the apply_chain "
        "binding mechanism: a Lua-name fired from the receiver's apply helper "
        "(depth >= 2 of the apply chain) rather than from a LuaActorImpl::"
        "vftable slot dispatcher. For each receiver whose apply chain fires "
        "named Lua callbacks via FUN_00447260 + FUN_00CC7A90, an "
        "apply_chain_lua_readers entry records the {luaName, opcode, "
        "applyHelperVa, fireSite, evidenceBcsy} link. This sits parallel to "
        "lua_actor_impl_slot (direct slot dispatch) and indirect_lua_readers "
        "(data-dependency via shared field) as the third bridge mechanism."
    )

    write_receivers(recvs)
    print(f"  receivers updated with apply_chain_lua_readers: {affected}")
    for recv_name, readers in sorted(added_per_receiver.items()):
        for entry in readers:
            print(
                f"    {recv_name:35s} <- {entry['luaName']:30s} "
                f"({entry['opcode']})  helper={entry['applyHelperVa']}"
            )
    return 0


def update_indirect(catalog_path: Path) -> int:
    if not catalog_path.is_file():
        print(f"error: --catalog not found: {catalog_path}", file=sys.stderr)
        return 1

    with catalog_path.open(encoding="utf-8") as f:
        dependency_catalog = json.load(f)
    recvs, by_name = load_receivers()

    added_per_receiver: dict[str, list[dict]] = {}
    for binding in dependency_catalog.get("confirmedIndirectBindings", []):
        lua_name = binding.get("luaName")
        if not lua_name:
            continue
        receivers = binding.get("writingReceivers") or [binding.get("writingReceiver")]
        opcodes = binding.get("writingOpcodes") or [binding.get("writingOpcode")]
        receivers = [receiver for receiver in receivers if receiver]
        opcodes = [opcode for opcode in opcodes if opcode]
        for recv_name, _opcode in zip(receivers, opcodes):
            if recv_name not in by_name:
                print(f"  warning: receiver {recv_name} not in client_receivers.json")
                continue
            entry = {
                "luaName": lua_name,
                "luaApiClass": binding.get("luaNameClass"),
                "luaApiImplVa": binding.get("luaApiImplVa")
                or binding.get("luaApiRegistrationVa"),
                "sharedField": {
                    "actorClass": binding.get("readActorClass"),
                    "offsets": binding.get("readsOffsets", []),
                },
                "writerBcsy": binding.get("writingReceiverBcsy"),
                "luaApiBcsy": binding.get("luaApiBcsy"),
                "confidence": binding.get("confidence", "confirmed"),
                "mechanism": "data_dependency",
            }
            added_per_receiver.setdefault(recv_name, []).append(entry)

    affected = 0
    for recv_name, readers in added_per_receiver.items():
        receiver = by_name[recv_name]
        existing = receiver.get("indirect_lua_readers", [])
        existing_keys = {entry["luaName"] for entry in existing}
        new = [entry for entry in readers if entry["luaName"] not in existing_keys]
        if new:
            receiver["indirect_lua_readers"] = existing + new
            affected += 1

    recvs["indirect_lua_readers_note"] = (
        "xivl-client-structs (BCS-Y-0338/0341/0342/0343) added "
        "indirect-binding evidence: for each receiver that writes an actor-state "
        "field also read by a Lua API, an indirect_lua_readers entry records the "
        "{luaName, sharedField, luaApiImplVa, bcsRefs} link. This sits parallel "
        "to lua_actor_impl_slot (which records direct _onXxx callback firing) "
        "and captures the data-dependency mechanism for receivers whose state "
        "mutation surfaces to Lua via field-sharing rather than callback fire."
    )

    write_receivers(recvs)
    print(f"  receivers updated with indirect_lua_readers: {affected}")
    for recv_name, readers in sorted(added_per_receiver.items()):
        for entry in readers:
            class_name = entry.get("luaApiClass") or "?"
            field = entry["sharedField"]
            field_text = f"{field.get('actorClass')}+{','.join(field.get('offsets', []))}"
            print(
                f"    {recv_name:35s} <- {class_name}::"
                f"{entry['luaName']:30s} via {field_text}"
            )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)

    apply_chain = modes.add_parser(
        "apply-chain",
        help="import apply-chain Lua readers from an explicit firers catalog",
    )
    apply_chain.add_argument(
        "--firers",
        required=True,
        type=Path,
        help="explicit lua_apply_chain_firers.json input",
    )

    indirect = modes.add_parser(
        "indirect",
        help="import indirect Lua readers from an explicit binding catalog",
    )
    indirect.add_argument(
        "--catalog",
        required=True,
        type=Path,
        help="explicit data_dependency_catalog.json input",
    )

    args = parser.parse_args()
    if args.mode == "apply-chain":
        return update_apply_chain(args.firers)
    return update_indirect(args.catalog)


if __name__ == "__main__":
    raise SystemExit(main())
