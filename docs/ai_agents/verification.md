# Verification

`.github/workflows/checks.yml` is the authoritative list of CI-covered checks,
and CI runs them on every pull request and push to `main`. CI covers the full
repository checks and the generated C++ header formatting check.

## Bare checkout

Install the validator dependencies, then run the single ordered repository
validation entry point:

```powershell
python -m pip install -r tools\requirements.txt
python tools\test_retail_zone_dispatch.py
python tools\test_0193_route.py
python tools\validate_repository.py
$headers = git ls-files -- '*.h' '*.hh' '*.hpp' '*.hxx'
clang-format --dry-run --Werror $headers
```

In a bare checkout, referential checks still run when optional dependencies are
absent. CI fails closed if `jsonschema` is unavailable, so hosted validation never
silently skips schema validation.

## Manual retail-input workflow

The manual [retail input validation](retail-input-validation.md) workflow can
reproduce one already tracked static dispatch route from the exact approved
retail executable. Its asset-free mutation suite is part of normal CI and does
not require the executable, a credential, or a sibling checkout. The
environment-bearing job is manual and is not required for merge.

## Payload framing audit

`audit_payload_framing.py` compares catalog `payloadLengths`, which are full
wire subpacket lengths, with the pinned fixture of inner payload lengths under
`data/vendor/client-structs/`. A reconciled entry contains the inner body length
plus 16 bytes for the subpacket header and 16 bytes for the game message header.
The fixture is required for normal validation; `--manifests` is an explicit
research override and is not part of canonical validation.

The tool's allow-list records one-line reasons for known exceptions.
`--no-allowlist` exposes every mismatch. Exit code 0 means the audit passed, 1
means findings were reported, and 2 means a fatal input or setup error. The
vendor refresh deriver uses the same manifest merge rule as this audit.

## Claim limits

A successful run proves that the tracked catalogs parse, pass schema validation,
remain internally consistent and referentially closed, match pinned vendor
provenance, and agree with the pinned framing evidence and docs indexes.

It does not prove retail behavior, a live client session, an external source's
current state, or freshness beyond pinned provenance. Report any unverified
edge and do not replace an absent check with agent output or an unrelated
passing validator.

A passing retail-input attestation additionally proves only the named static
route described in the retail validation contract. It does not promote a
packet name, payload claim, runtime behavior, server behavior, or live-client
result.
