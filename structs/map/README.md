# structs/map/

Generated C++ packet-payload headers for the map service buckets.

## Files

- `clientbound.h`: `MapClientbound` payload struct definitions.
- `serverbound.h`: `MapServerbound` payload struct definitions.

Both headers use `#pragma pack(push, 1)` and declare structs in the
`bahamut::opcodes::map::{clientbound,serverbound}` namespaces. Each emitted
struct has a `static_assert(sizeof(StructName) == N, ...)` size check.

## Inputs and generation

`tools/generate_structs.py` joins these local inputs:

- `data/vendor/captures/payload_layouts.json` for field offsets, widths, and
  evidence roles;
- `data/vendor/captures/payload_samples.json` for observed payload bytes;
- root `opcodes.json` for bucket and opcode assignment.

The first two files are pinned packet-observation evidence declared by
`data/vendor/captures/PROVENANCE.json`. They are local consumer mirrors, not
live source paths.

Regenerate and run the generator sanity checks with:

```powershell
python tools\generate_structs.py --validate
```

Do not hand-edit `clientbound.h` or `serverbound.h`; the generator owns both
files and overwrites them on regeneration.

## Payload scope

These headers describe opcode-bound wire payload bytes after the 8-byte inner
packet header. They are not a general client object model and do not describe
the outer wire framing. Consumers should use the root catalog for opcode
identity and the generated size assertions for the emitted byte layout.
