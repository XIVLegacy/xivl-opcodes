# Tools

This repository's tools curate the root opcode catalog, maintain local
evidence, generate payload headers, and run validation in this repository.
The root `opcodes.json` and `constants.json` files are the single catalog
output home. `data/` is the curator and evidence area, not a second catalog
copy.

## Boundaries

Normal tool execution reads and writes only this checkout. The supported
inputs are the root catalog, JSON under `data/`, schemas, and pinned evidence
under `data/vendor/`. Explicit external paths accepted by research overrides
are optional, non-gating inputs; they have no workspace-layout default. The
per-file `data/` inventory lives in the
[repository guide](../docs/repository-guide.md).

Each vendor subdirectory declares its files in `PROVENANCE.json`. The
manifest preserves the exact source repository identity, source path,
sha256, evidence tier, refresh mode, and transformation. The
packet-observation mirrors provide payload layouts, payload samples, and a
capture-name index; their original owner is the capture-research sibling. The
client-ABI mirror provides BCS-Y identifiers, structured opcode-binding sync
candidates, and inner payload lengths; its original owner is the
client-structure research sibling. Those owners remain responsible for their
source products; this repo owns the pinned copies used by its checks.

`validate_vendor.py` verifies the pins. `refresh_vendor.py` is the only writer
for a refresh or re-pin and requires explicit `--repo NAME=PATH` mappings. A
promoted mirror is not a live synchronization edge.

Every refresh targets one fixture and one full lowercase 40-hex source commit:

```powershell
$sourceCommit = git -C PATH rev-parse HEAD
python tools\refresh_vendor.py --repo NAME=PATH --only data/vendor/ROLE/FILE.json --commit $sourceCommit
```

Confirm that `$sourceCommit` is the intended source revision before running the
writer. Abbreviated, uppercase, or omitted hashes are rejected.

## Tool index

- `generate_catalog.py` reapplies curated catalog notes, ambiguity tags,
  capture-specific lane attributions, and other fields no extractor can derive.
  It then rewrites root `opcodes.json` and `constants.json` with the house JSON
  writer.
- `_json_io.py` owns the repo paths and the shared UTF-8, LF, two-space JSON
  writer. `OPCODES_PATH` and `CONSTANTS_PATH` are the single catalog paths.
- `validate_repository.py` is the complete human and CI check. It parses every
  repository JSON file, then runs the vendor, corpus, client-opcode-semantic,
  docs-index, and payload-framing validators in order.
- `validate_client_opcode_semantics.py` checks the 37-row retail-client body
  evidence ledger, catalog evidence links, open/closed dispositions, and the
  bare `decompAnchor` contract.
- `generate_structs.py` emits packed C++ payload headers under `structs/` from
  the pinned packet-observation layouts and samples plus the root catalog.
  `--digest`, `--layouts`, and `--samples` are explicit research overrides.
- `validate_corpus.py` validates schemas, catalog enums, opcode relationships,
  capture references, and BCS-Y references against the pinned local indexes.
  It also reports opcode-bound sibling BCS-Y candidates absent from the root
  catalogs and gates changes against the explicit expected-gap baseline. Its
  `--captures-dir`, `--symbols`, and `--expected-sibling-gaps` options are
  explicit research or fault-injection overrides. `--json` includes the full
  sibling-sync report with the exit code unchanged.
- `validate_vendor.py` rejects a missing, undeclared, or hash-drifted vendor
  file and rejects a vendor directory without its provenance manifest.
- `refresh_vendor.py` restores or re-pins a declared mirror from an explicitly
  named source checkout. It supports copy and derived refresh modes declared
  in the manifest.
- `validate_docs_index.py` checks every tracked Markdown directory under
  `docs/` against its local README index in both directions. The root index
  must also link each nested section index. Only tracked documentation is
  included in the check.
- `audit_payload_framing.py` checks catalog wire lengths against the pinned
  inner-payload-length fixture and its allow-list. The equation, exception,
  and exit-code contract is in `docs/ai_agents/verification.md`;
  `--manifests` is an explicit research override.
- `verify_retail_zone_dispatch.py` validates the fixed retail-input grant,
  expected `0x018d` dispatch route, private structured observation, tracked
  source rows, and sanitized attestation contract. It also owns dispatch-ref and
  retained-output validation for the manual workflow.
- `test_retail_zone_dispatch.py` runs the credential-free mutation suite for
  the retail dispatch contract. It needs no executable, private repository,
  token, Ghidra installation, or sibling checkout.
- `ghidra_scripts/ExportZoneDispatchRoute.java` verifies the fixed dispatcher
  data flow in a fresh analyzed program and emits one private structured
  observation. It emits no disassembly, bytes, paths, names, or expected
  case/slot values.
- `extractors/update_client_receivers.py` updates `data/client_receivers.json`
  in either `apply-chain` or `indirect` mode from an explicit evidence input.
  Re-run a mode only when its named evidence input changes.

`data/client_receivers.json` is an accumulated curator artifact, not a fully
generated file. The updater owns only additive imports into
`apply_chain_lua_readers` and `indirect_lua_readers` plus their top-level notes.
It must preserve every existing receiver, record, and field, including records
whose import key already exists. No `--check` mode exists for this artifact, so
import drift detection remains a known tooling gap.

## Catalog generation

The [checks workflow](../.github/workflows/checks.yml) is the authoritative
list of CI-covered checks. The [verification guide](../docs/ai_agents/verification.md)
provides the minimal bare-checkout entry point, payload-framing contract, and
claim limits.

`generate_catalog.py` reapplies the curated fields that extraction cannot derive
while canonicalizing the existing root catalog files in place. It does not
mirror a catalog from `data/`. The shared writer keeps the output UTF-8 without a BOM,
two-space indented, LF-terminated, and array-wrapped where the schema requires
it. The root files remain the only consumer catalog home.

When payload evidence or catalog bucket assignment changes, regenerate the
headers separately:

```powershell
python tools\generate_structs.py --validate
```

## Evidence and generated-output boundary

Curator inputs and promoted non-pcap evidence live under `data/`. Maintainer
extractors and reports may also write products there, but those files are
evidence or diagnostics rather than consumer catalog output. Root
`opcodes.json` and `constants.json` are the canonical generated outputs.
Generated C++ payload headers under `structs/` are a separate output family
owned by `generate_structs.py` and must not be hand-edited.

## Framing audit

For each entry with `payloadLengths` and a matching inner-payload schema, the
framing audit asserts that the observed wire length equals the inner body plus
the 16-byte sub-packet header and 16-byte game-message header. If the local
fixture under `data/vendor/client-structs/` is missing or framing mismatches,
validation fails. Any exception is a one-line, in-tool allow-list reason.

## Retail dispatch validation

Run the asset-free contract with the normal repository checks:

```powershell
python tools\test_retail_zone_dispatch.py
python tools\verify_retail_zone_dispatch.py
python tools\validate_repository.py
```

The binary-backed rehearsal is deliberately separate from normal validation.
For each rehearsal, create a new empty Ghidra project, import the approved
`ffxivgame.exe` as `x86:LE:32:default` with the Windows compiler
specification, complete standard analysis, and then run
`ExportZoneDispatchRoute.java` read-only with these environment values:

```text
XIVL_RETAIL_DISPATCHER_VA=0x00dbfd10
XIVL_RETAIL_OPCODE=0x018d
XIVL_RETAIL_BYTE_TABLE_VA=0x00dc1274
XIVL_RETAIL_DWORD_TABLE_VA=0x00dc0f5c
XIVL_RETAIL_OBSERVATIONS_OUT=<private output path>
```

Pass the private output to `verify_retail_zone_dispatch.py --input`. Two
separate full imports must produce byte-identical observation and attestation
files. Keep the executable, projects, logs, observations, and diagnostics only
under an ignored private scratch root. Delete that root after recording the safe
timing, footprint, sanitized hash, and verdict. The exact workflow and claim
boundary are documented in [`retail-input-validation.md`](../docs/ai_agents/retail-input-validation.md).
