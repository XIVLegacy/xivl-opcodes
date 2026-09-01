# Retail input validation

The normal asset-free repository checks remain the merge requirement. The additional
manual retail-input workflow asks one narrow question: does a fresh Ghidra
analysis of the exact approved FINAL FANTASY XIV 1.23b executable reproduce the
already tracked route from clientbound opcode `0x018d` to callback-interface
vtable slot 136?

## Workflow contract

| Contract | Value |
|---|---|
| Public repository | `XIVLegacy/xivl-opcodes` |
| Workflow | `.github/workflows/retail-checks.yml` |
| Check | `zone-dispatch-0x018d-slot-v1` |
| Input declaration | `data/retail_inputs.json` |
| Expected result | `data/retail_zone_dispatch_check.json` |
| Attestation schema | `schemas/retail-evidence-attestation.schema.json` |
| Protected environment | `retail-evidence` |
| Private input repository | `XIVLegacy/xivl-private-assets` |

The approved input is only `ffxivgame-1.23b`: repository-relative private path
`ffxivgame.exe` at immutable private commit
`aeb52f6dbde95a793ee6d52be28de9f28a885b15`, size `15996808`, and SHA-256
`9341f2b4567440b310a4d494f5cc5599ca334ba51c8042247317ff466492f2e9`.
The workflow passes this local grant to the shared `fetch-retail-input` action
at an immutable `XIVLegacy/xivl-tools` commit. That action requires the commit
to remain an ancestor of private `main`, requires an untruncated tree response
with the authorized executable entry at that path and its expected blob type,
mode, size, and hash, and verifies size and SHA-256 before analysis. Sibling
entries are outside this check's claim.

## Exact assertion

The exporter starts at the tracked dispatcher and table locators. It verifies
one opcode-to-table data-flow sequence, derives the selected case from the
executable, follows that case body, and derives the callback slot from the
indirect-call sequence. The verifier compares that private observation with
the fixed check and the existing unique rows in `data/zone_dispatch_map.json`,
`data/client_opcode_semantics.json`, and `opcodes.json`.

The passing result proves only that opcode `0x018d` selects case 134 and that
the selected case calls callback-interface vtable slot 136. It does not prove
the packet name, handler identity, payload size or layout, capture counts,
server behavior, runtime behavior, or live client acceptance.

## Credential and execution boundary

Execution is manual `workflow_dispatch` from the reviewed revision on protected
`main`. A credential-free preflight rejects every other event, ref, or checkout
SHA before the environment-bearing job is eligible. The workflow has only
`contents: read`, and checkout credentials are not persisted.

Environment secret `RETAIL_INPUTS_TOKEN` is a fine-grained token selected only
for the private input repository, with Contents read-only and metadata read.
The workflow passes it only to the shared fetch action; the fixed repository
name and transport checks live in that action. The token may be shared with
another explicitly granted retail-input workflow using the same repository and
scope, but each workflow stores it in its own protected environment. Rotation
or revocation must update every sharing environment before another retail run.

The shared action keeps the bearer value out of process arguments and rejects
unsafe API responses before writing the validated input below `RUNNER_TEMP`.
API responses, curl logs, the credential, input, toolchain, project, and raw
observations never enter the checkout. The local workflow retains the input
grant and check-specific verifier; the shared action does not decide the
zone-dispatch assertion.

## Toolchain and retained output

The hosted job invokes the shared `setup-retail-toolchain` action with
`include-ghidra: true`. That
action checksum-pins the Ghidra 12.1.3 archive
`ghidra_12.1.3_PUBLIC_20260817.zip` at SHA-256
`93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54`
and Temurin JDK 21.0.12.1+1 Linux archive
`OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz` at SHA-256
`ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94`.
The local analysis uses the action's `analyze-headless` output with a new empty
PE32 project, standard analysis, and a read-only structured export. No cache or
previously named project is allowed.

On every outcome, the shared `finalize-retail-attestation` action deletes the
entire private root and checks the one-file staging envelope before the local
retained verifier runs.
The retained allowlist is exactly one regular non-link file named
`retail-evidence-attestation.json`, no larger than 4096 bytes. Its strict
schema contains only the public repository commit, approved input hash, pinned
tool versions, check ID and version, and pass or fail status. The sanitized
artifact is retained for 30 days.

## Verification and publication

Run the credential-independent contract and normal repository checks locally:

```powershell
python tools\test_retail_zone_dispatch.py
python tools\verify_retail_zone_dispatch.py
python tools\validate_repository.py
```

Each local rehearsal uses a new empty project and the approved executable.
Two complete imports must produce byte-identical observations and attestations,
and a mutated observation must fail with only a schema-valid fail attestation.
Local Windows runs record their actual JDK 21 build privately; only the hosted
Ubuntu run may attest the checksum-pinned Linux JDK build above.

After reviewed code reaches protected `main`, configure the environment and
run the manual workflow from that exact SHA. Review its logs and downloaded
artifact for leakage. Only after a complete hosted pass may the byte-identical
pass attestation be added under `data/retail_evidence/` with its public run
record. A failure attestation is never tracked.

## Reproduced result

[Retail Checks run 32492349689](https://github.com/XIVLegacy/xivl-opcodes/actions/runs/32492349689)
passed on 2026-08-21 for public commit
`3afad7544a49028de25ea59d001bd4cdc3fb3b73`. Its evidence job completed in
14 minutes 37 seconds. The downloaded pass attestation was byte-identical to a
local regeneration for the same commit and is tracked as
[`zone-dispatch-0x018d-slot.json`](../../data/retail_evidence/zone-dispatch-0x018d-slot.json).
The retained file has SHA-256
`ca867f06d2672ed1b00bd54c6f67cad9cab441bbb5cc4d86463a1e53fe324772`.
Artifact allowlist, schema, cleanup, negative-control, and public-log leakage
reviews passed.

Stop on input, tree, toolchain, analysis, data-flow, case, slot, determinism,
cleanup, allowlist, protected-ref, or normal-CI drift. On suspected credential
or byte exposure, cancel the run, delete unsafe artifacts, disable the
workflow, revoke and remove the token, inspect audit logs, and rotate only
after fixing the cause.
