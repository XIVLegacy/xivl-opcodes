# Test authoring

Add a test for an intended catalog or tool behavior, a demonstrated defect, or
a supported failure boundary. Name the defect it detects and check whether an
existing validator or fixture already covers it. Extra cases need a distinct
input, assertion, or failure mode.

Use the [tool guide](../../tools/README.md) for commands and the
[catalog reference](../catalog-reference.md) for consumer contracts. Follow
[evidence and claims](evidence-and-claims.md) when choosing expected values.

## Choose the smallest useful check

- Use a small public fixture for schema, relationship, route, and evidence
  boundary checks. Keep expected opcodes, offsets, lengths, and slots literal
  and independently grounded rather than deriving them with the code under test.
- Test the CLI when argument selection, exit status, compiler setup, or file
  handling is the behavior. Exercise pure transformations directly when process
  startup adds no coverage.
- Reuse the pinned vendor inputs for catalog integration. Normal checks must
  not depend on a sibling checkout or an unreviewed vendor refresh.
- Use compiler-backed cases for generated-header self-containment, syntax,
  size, packing, and combined-include behavior. A text comparison alone cannot
  prove these contracts.

Keep helpers local and small. Share fixture construction when it removes real
duplication, while keeping each mutation and expected result visible. Do not
introduce a generic test framework for a few related cases.

## Preserve distinct coverage

Catalog identity is `(service, direction, opcode)`. A wire opcode alone cannot
distinguish services. Preserve checks for service ambiguity, neutral identities,
source provenance, and unsupported semantic claims. `payloadLengths` includes
the 16-byte subpacket header; it is not the IPC body length.

Keep independent mutations for wrong route relationships, evidence locators,
layout bounds, and provenance. A second assertion against a different boundary
is useful even when the fixture resembles another case. Preserve negative
controls that prove a validator rejects malformed inputs.

For generated headers, retain both individual compilation and combined includes,
including checks that caller packing survives the include. Keep missing-compiler
and empty-input setup failures distinct from invalid-header failures. Exercise
mutations in temporary inputs; generated headers remain generator-owned.

Retain complete repository integrity sweeps for schemas, catalog relationships,
vendor hashes, and generated products. Representative fixtures can reduce a
repeated integration setup without replacing required all-record validation.
Before sampling a matrix, identify the exact input and assertion combinations
that would disappear and justify that tradeoff in review.

Before deduplicating cases, compare the actual mutated inputs and assertions.
Skip unchanged replacements, and consolidate only cases with equivalent behavior
and failure detection. A similar test name or shared fixture is not proof.

## Public and retail checks

Public fixtures and credential-free mutation tests belong in normal checks.
Keep them independently runnable without a retail client executable, private
checkout, credential, or Ghidra analysis. Put source-dependent checks behind only the
source boundary they require; do not skip a mixed group of public checks.

Follow [retail input validation](retail-input-validation.md) for the separate
manual check and its retained attestation. A passing synthetic mutation suite or
header compile proves the repository contract, not live client behavior or a
new retail observation. Preserve input identity, cleanup, allowlist, and
failure-attestation checks when changing the private workflow contract.

## Verification and cost

Run the focused check while editing, then the required repository checks for
the changed behavior. Use the tool guide's existing commands. A prose-only
policy edit needs source and link verification plus the documentation-index
check; it does not need a compiler or a retail-input run.

For a change that adds material cost, identify the expensive operation and
record representative measurements under comparable conditions. Reuse parsing
or setup only when test isolation and failure detection remain intact. Do not
set arbitrary test-count limits or require a benchmark for every small test.
