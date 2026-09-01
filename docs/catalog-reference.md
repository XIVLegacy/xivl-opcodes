# Catalog reference

This consumer contract defines the 1.23b catalog scope, fields, evidence
classes, confidence labels, and generated products.

## Product and covered scope

The catalog product has one canonical generated home at the repository root:
`opcodes.json` and `constants.json`. There is no catalog mirror under
`data/`.

`opcodes.json` is an array containing one catalog object. The object has a
`version`, a `region`, and a `lists` object. The `lists` object declares these
buckets, each containing an array of opcode entries:

- `LobbyServerbound`
- `LobbyClientbound`
- `WorldServerbound`
- `WorldClientbound`
- `WorldMapBackend`
- `MapServerbound`
- `MapClientbound`

`WorldMapBackend` is the world-to-map backend bucket. Its backend
directions share one list and are distinguished by the entry's `notes` and
direction metadata where applicable. An opcode integer is not globally
unique: consumers must use the service and direction fields with it.

`constants.json` is a map from region key to catalog metadata. Each metadata
object carries `Version`, `Services`, `Directions`, and `ConfidenceLabels`.
The root files validate against `schemas/opcodes.schema.json` and
`schemas/constants.schema.json`. Opcode entries use a closed schema, so an
entry cannot add undeclared fields.

## Entry fields

| Field | Consumer meaning |
|---|---|
| `name` | Stable catalog packet name. A placeholder such as `_0xNNNN` remains a valid name when later evidence adds anchors. |
| `opcode` | Wire opcode as a decimal integer. |
| `opcodeHex` | The same opcode as four-digit `0xNNNN` text. |
| `service` | One of `lobby`, `world`, `map`, or `world_map_backend`. |
| `direction` | One of `serverbound`, `clientbound`, or `backend`. |
| `implementationAnchor` | An implementation enum or member anchor when the implementation declares the opcode; otherwise null. |
| `decompAnchor` | A retail client `FUN_` or RTTI identifier; null when client analysis supplies none. |
| `observedIn` | Capture filenames whose packet observation contains the entry's wire direction and opcode. |
| `payloadLengths` | Observed subpacket sizes in bytes, including the 16-byte subpacket header; this is not an IPC body size. |
| `confidence` | Exactly one of the six labels in the confidence table below. |
| `notes` | Evidence citations, decoded layout or role notes, ambiguity tags, and conflict records. |
| `retail_class_name` | The retail client receiver class for the packet, when the client evidence identifies one. |
| `needsReverify` | Present and true when a retained binding needs retail-client verification after its prior corroboration was retired. |
| `reverifyMethod` | The required verification action for an entry marked `needsReverify`. |

The `notes` field is part of the evidence record. Consumers should preserve
its citations and identifiers when carrying an entry into another product.

## Evidence classes

The catalog accepts these evidence classes. A claim may use more than one.
The class does not by itself prove a packet identity.

| Evidence class | What it can establish | Usual catalog fields |
|---|---|---|
| Retail packet observation | Wire opcode, direction, observed length, or stream phase. | `observedIn`, `payloadLengths`, `notes` |
| Retail client-file analysis | Client routing, receiver identity, ABI relationship, or expected payload shape. | `decompAnchor`, `retail_class_name`, `notes` |
| Live validation | Verification against the retail 1.23b client in a live session. The client's acceptance of the behavior is the evidence. The implementation that drives the session is only the instrument. | `implementationAnchor`, `notes` |

Evidence identifiers and provenance metadata remain verbatim in the catalog
and relevant provenance manifest. Capture and upstream version dates are
source metadata; do not normalize or remove them when promoting evidence.

## Confidence labels

Every entry carries exactly one of these labels:

| Label | Meaning |
|---|---|
| `pcap_observed` | The opcode, length, direction, or stream phase appears in packet observations, but no packet name is confirmed. |
| `live_validated` | The retail 1.23b client accepted the behavior in a live session. Client acceptance is the evidence, and the implementation that drives the session is only the instrument. |
| `decomp_routed` | Client dispatch or structure evidence identifies the route or expected payload shape. |
| `implemented` | The implementation supplies a class, handler, or test for the mapped packet; this state does not by itself prove retail behavior. |
| `confirmed` | Retail packet observation and client-file analysis agree enough to treat the mapping as settled. |
| `blocked` | Evidence conflicts or the packet boundary cannot be decoded. |

Use the lowest label supported by the evidence record. Use `blocked` when
evidence conflicts or the packet boundary cannot be decoded. Do not infer a
name or layout.

## Reading packet observations

The packet digest keys an observation on `(direction, opcode)` because the wire
does not carry a service tag. A shared capture list therefore supports the
wire pair, not exclusive service ownership. Entries with an ambiguous service
are tagged `pcap_service_ambiguous` in `notes`. One example is
`pcap_service_ambiguous=world,map`.

Lane-preserving evidence can narrow one capture witness when the retail
connection class is independently established. The clear 54992 game traffic
in `login.pcapng` is retained on its Map rows because every relevant pair is
on the main Map/Zone lane; competing World rows carry a capture-specific
exclusion note. This does not resolve service ambiguity for other captures
whose evidence remains merged.

The observation set represents game-protocol traffic. Lobby protocol traffic
uses a separate connection and is not represented by a non-empty `observedIn`;
the 54992 game lanes in `login.pcapng` are not lobby protocol. World-to-map
backend rows are server-to-server and do not cross the client socket, so they
do not carry packet observations.

Opcode integers may also be reused across directions. For example, `0x00ca`
is both a serverbound position update and a clientbound actor spawn broadcast
in the catalog. Direction is mandatory for disambiguation.

## Generated payload headers

`structs/` contains generator-owned C++ headers for payloads with evidence in
the pinned packet digest. A generated struct is named from its catalog entry,
with a trailing `Packet` or `Handler` removed and `Body` appended where that
rule applies. Headers use `#pragma pack(push, 1)` and a `static_assert` for
the emitted size.

The struct represents bytes after the 8-byte inner packet header, not the
whole wire frame. Headers are generated products: consumers may rely on the
declared namespace, packed layout, field widths, and size assertion, but must
not hand-edit a header. Regenerate from the local pinned inputs with:

```powershell
python tools\generate_structs.py --validate
```

See [../structs/README.md](../structs/README.md) for bucket paths and the
generator boundary.

## Pinned evidence mirrors

`data/vendor/` is the boundary between local validation and evidence owned by
another research role. The mirrors are pinned consumer copies or derived
indexes. They are not live sources and do not promise freshness.

| Mirror | What the local file provides | Original owner |
|---|---|---|
| `data/vendor/captures/` | Byte-identical payload layout and payload sample digests used for struct generation. | xivl-captures |
| `data/vendor/captures-index/` | A derived list of capture filenames used to resolve `observedIn`. | xivl-captures |
| `data/vendor/client-structs/` | Derived BCS-Y identifiers, opcode-binding sync candidates, and inner payload lengths used for referential, reverse-sync, and framing checks. | xivl-client-structs |

Each mirror's `PROVENANCE.json` is authoritative for its `sourceRepo`,
`sourcePath`, `sha256`, `evidenceTier`, `refreshMode`, and `transformation`.
The `sha256` anchors byte identity. Source commit hashes are excluded because
source histories are rewritten for publication. The manifest identifiers are
the provenance record. Prose does not repeat repository names, machine paths,
or live checkout locations.

`validate_vendor.py` verifies every declared hash. `refresh_vendor.py` is the
only writer and takes explicit `--repo NAME=PATH` mappings and an explicit
`--commit` for each re-pin.

## Regenerating and validating

Use the [tool reference](../tools/README.md) for generator and validation
commands.

## AI-assisted contributions

AI-assisted work follows the same catalog and evidence rules as
any other contribution. Start with the
[AI-assisted contribution policy](ai_agents/README.md).
