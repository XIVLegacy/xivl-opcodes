# Repository guide

This page maps the curator-only data files and the top-level repository tree.
See the [catalog reference](catalog-reference.md) for the consumer contract,
evidence and confidence rules, pinned mirrors, and validation commands.

## Curator data inventory

`data/` contains research inputs, promoted evidence, extractor products, and
maintainer reports. These files support catalog curation. They are not
additional consumer catalog outputs.

| File | Contents |
|---|---|
| `data/decomp_opcodes.json` | Curated catalog inputs. |
| `data/client_receivers.json` | RTTI inventory of client receivers, including slot RVA, namespace, and mapping target. |
| `data/npc_log_evidence.json` | NPC-capture opcode enrichment evidence against a baseline capture set. |
| `data/zone_dispatch_map.json` | Decompiled universal server-to-client inner-packet dispatcher map. |
| `data/zone_handoff_evidence.json` | World-to-map handoff timing evidence derived from capture edge windows. |
| `data/client_opcode_semantics.json` | Retail-client body and consumer evidence for direction-qualified opcode rows. |
| `data/s2c_018d_wire_layout.json` | Neutral `0x018D` application layout, storage projection, unsafe client count behavior, and native presentation classification. |
| `data/lua_actor_impl_slot_lua_bindings.json` | LuaActorImpl vftable slot-to-Lua-callback binding map. |
| `data/sibling_sync_expected_gaps.json` | Expected xivl-client-structs BCS-Y opcode-binding candidates not yet cited by either root catalog. |
| `data/retail_inputs.json` | Exact private-input identity and one-check grant for the manual retail-input workflow. |
| `data/retail_zone_dispatch_check.json` | Fixed locators and expected derived values for the `0x018d` dispatch route. |

## Repository layout

| Path | Role |
|---|---|
| `opcodes.json` | Canonical opcode catalog output. |
| `constants.json` | Canonical services, directions, and confidence metadata. |
| `data/` | Curator inputs, promoted evidence, and maintainer products. |
| `data/vendor/` | Hash-pinned evidence mirrors described in the [catalog reference](catalog-reference.md#pinned-evidence-mirrors). |
| `schemas/` | JSON schemas used by validation. |
| `structs/` | Generated packed C++ payload headers; see the [header guide](../structs/README.md). |
| `docs/` | Consumer and contribution documentation. |
| `tools/` | Catalog curation, generation, and validation tools; see the [tool reference](../tools/README.md). |
