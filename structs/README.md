# structs/

`structs/` contains generated C++ packet-payload headers organized by service
bucket. Each header declares packed payload structs in the namespace
`bahamut::opcodes::<bucket>::<direction>`.

## Consumer contract

The generator owns every header under this directory. Never hand-edit a
generated file. Change the local catalog or pinned layout evidence, then run
the generator so the output and its size assertions are reproducible.

Each emitted struct:

- includes only the standard integer types it needs;
- uses `#pragma pack(push, 1)` and `#pragma pack(pop)`;
- represents the payload after the 8-byte inner packet header, not the whole
  wire frame; and
- ends with a `static_assert` that locks the emitted struct size.

Field names and types describe the evidence-shaped bytes emitted by the
generator. Consumers may rely on the packed byte layout and size assertion;
they should not treat an inferred field label as a stronger semantic claim
than the catalog evidence supports.

## Emission policy

The generator drops the 8-byte inner header before rebasing fields to the
payload body. `zero_pad` fields become byte padding, `constant` fields become
byte arrays annotated with their observed value, and variable fields use the
smallest matching integer width. Four-byte and repeated four-byte fields become
`float` only when samples pass the bounded, finite, varied-value heuristic;
otherwise they remain unsigned integers or byte arrays.

When a wire direction and opcode match multiple catalog buckets, backend rows
are considered first. For `c2s`, the remaining order is map, world, then lobby;
for `s2c`, it is map, world, then lobby. `WorldMapBackend` accepts either wire
direction because observations do not identify its backend service. This
resolves an evidence limitation: packet observations provide wire direction but
do not always identify the service. The Python-side validator checks balanced
structs, recognized declarations, and size assertions; it is not a C++ compiler
or a semantic field validator.

## Bucket paths

The generator maps catalog buckets to these output paths:

| Catalog bucket | Generated path |
|---|---|
| `MapServerbound` | `map/serverbound.h` |
| `MapClientbound` | `map/clientbound.h` |
| `LobbyServerbound` | `lobby/serverbound.h` |
| `LobbyClientbound` | `lobby/clientbound.h` |
| `WorldServerbound` | `world/serverbound.h` |
| `WorldClientbound` | `world/clientbound.h` |
| `WorldMapBackend` | `worldmap/backend.h` |

A header is emitted when the pinned layout digest contains a matching layout
for a catalog bucket. Do not create a hand-maintained substitute for a bucket
without generated evidence.

## Generation

The bare-checkout command is:

```powershell
python -m pip install -r tools\requirements.txt
python tools\generate_structs.py --validate
```

The default inputs are the pinned payload-layout and payload-sample files in
`data/vendor/captures/` plus the root `opcodes.json`. The generator accepts
explicit digest or catalog paths only for non-gating research runs. The
`--validate` option performs Python-side sanity checks for balanced struct
blocks, recognized declarations, and matching size assertions.
The generator runs the pinned Clang Format 22 release before writing each
header, using the repository's `.clang-format` configuration.

The payload digest is owned by packet-observation research and the catalog is
owned by this repository. The generated headers are this repository's output;
there is no external build or runtime dependency implied by them.
