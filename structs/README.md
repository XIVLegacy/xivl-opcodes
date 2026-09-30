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
  wire frame;
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
resolves an evidence limitation: packet observations provide wire direction;
they do not always identify the service. Validation checks the emitted layout;
it does not establish field semantics.

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
`data/vendor/captures/` plus the root `opcodes.json`. Explicit digest or catalog
paths are available only to research runs and are excluded from repository
validation. The `--validate` option recognizes declarations, verifies balanced
struct blocks, and checks matching size assertions.
The generator runs the pinned Clang Format 22 release before writing each
header, using the repository's `.clang-format` configuration.

## C++ validation

The repository gate compiles every generated header individually and all
headers together as C++17, exercising their payload-size assertions. The
individual checks provide no preceding includes, so each header must supply
its own dependencies. Probes check size, alignment, and field offsets
under default packing and `#pragma pack(push, 2)`, then verifies packing after
the caller's pop. Compilation uses syntax-only translation units and creates
no object files or executables.

Run the complete gate or just the compilation check with a Clang/GCC C++ driver:

```powershell
python tools\validate_repository.py --compiler clang++
python tools\validate_generated_headers.py --compiler clang++
python tools\test_generated_headers.py --compiler clang++
```

`--compiler` accepts an executable name or path and defaults to `clang++`.
The compiler and its C++ standard-library headers must be installed separately.
Compiler flags use the Clang/GCC driver interface; `cl` and `clang-cl` are not
supported. A missing compiler or header set is a setup failure (exit 2), never
a successful check. Compilation errors exit 1; successful compilation exits 0.
The Catalog Checks CI job requires this check and its negative controls.

The payload digest is owned by packet-observation research and the catalog is
owned by this repository. The generated headers are this repository's output;
there is no external build or runtime dependency implied by them.
