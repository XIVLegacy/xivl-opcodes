# Tools

This repository's tools curate the root opcode catalog, maintain local
evidence, generate payload headers, and run the validation gate in this repository.
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
source products; this repo owns the pinned copies used by its gate.

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

- `generate_catalog.py` reapplies curated catalog notes, ambiguity tags, and
  other fields no extractor can derive, then rewrites root `opcodes.json` and
  `constants.json` with the house JSON writer.
- `_json_io.py` owns the repo paths and the shared UTF-8, LF, two-space JSON
  writer. `OPCODES_PATH` and `CONSTANTS_PATH` are the single catalog paths.
- `validate_repository.py` is the complete human and CI gate. It parses every
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
  must also link each nested section index; the ignored maintainer island is
  outside the check.
- `audit_payload_framing.py` checks catalog wire lengths against the pinned
  inner-payload-length fixture and its allow-list. The equation, exception,
  and exit-code contract is in `docs/ai_agents/verification.md`;
  `--manifests` is an explicit research override.
- `extractors/update_client_receivers.py` updates `data/client_receivers.json`
  in either `apply-chain` or `indirect` mode from an explicit evidence input.
  Re-run a mode only when its named evidence input changes.

`data/client_receivers.json` is an accumulated curator artifact, not a fully
generated file. The updater owns only additive imports into
`apply_chain_lua_readers` and `indirect_lua_readers` plus their top-level notes;
it must preserve every existing receiver, record, and field, including records
whose import key already exists. No `--check` mode exists for this artifact, so
import drift detection remains a known tooling gap.

## Catalog generation

The [checks workflow](../.github/workflows/checks.yml) is the authoritative
list of CI-covered checks. The
[verification guide](../docs/ai_agents/verification.md) provides the minimal
bare-checkout entry point, payload-framing contract, and claim limits.

`generate_catalog.py` reapplies the curated fields that extraction cannot
derive and canonicalizes the existing root catalog files in place. It does not
mirror a catalog from `data/`. The shared writer keeps the output UTF-8 without
a BOM, two-space indented, LF-terminated, and array-wrapped where the schema
requires it. The root files remain the only consumer catalog home.

When payload evidence or catalog bucket assignment changes, regenerate the
headers separately:

```powershell
python tools\generate_structs.py --validate
```

## Evidence and generated-output boundary

Curator inputs and promoted non-pcap evidence live under `data/`. Extractors
and reports may also write maintainer products there, but those files are
evidence or diagnostics rather than consumer catalog output. Root
`opcodes.json` and `constants.json` are the canonical generated outputs.
Generated C++ payload headers under `structs/` are a separate output family
owned by `generate_structs.py` and must not be hand-edited.

## Framing audit

For each entry with `payloadLengths` and a matching inner-payload schema, the
framing audit asserts that the observed wire length equals the inner body plus
the 16-byte sub-packet header and 16-byte game-message header. The local
fixture under `data/vendor/client-structs/` is required; a missing fixture or
framing mismatch fails the gate. Any exception is a one-line, in-tool
allow-list reason.
