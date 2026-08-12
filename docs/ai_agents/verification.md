# Verification

`.github/workflows/checks.yml` is the authoritative list of CI-covered checks,
and CI runs them on every pull request and push to `main`. CI covers the full
repository gate and the generated C++ header formatting check.

## Bare checkout

Install the validator dependencies, then run the single ordered repository
gate entry point:

```powershell
python -m pip install -r tools\requirements.txt
python tools\validate_repository.py
$headers = git ls-files -- '*.h' '*.hh' '*.hpp' '*.hxx'
clang-format --dry-run --Werror $headers
```

The gate can report schema validity only when the dependencies are available.

## Payload framing audit

`audit_payload_framing.py` compares catalog `payloadLengths`, which are full
wire subpacket lengths, with the pinned fixture of inner payload lengths under
`data/vendor/client-structs/`. A reconciled entry contains the inner body length
plus 16 bytes for the subpacket header and 16 bytes for the game message header.
The fixture is required for the normal gate; `--manifests` is an explicit
research override and is not part of canonical validation.

The tool's allow-list records one-line reasons for known exceptions.
`--no-allowlist` exposes every mismatch. Exit code 0 means the audit passed, 1
means findings were reported, and 2 means a fatal input or setup error. The
vendor refresh deriver uses the same manifest merge rule as this audit.

## Claim limits

A green gate proves that the tracked catalogs parse, pass schema validation,
remain internally consistent and referentially closed, match pinned vendor
provenance, and agree with the pinned framing evidence and docs indexes.

It does not prove retail behavior, a live client session, an external source's
current state, or freshness beyond pinned provenance. Report any unverified
edge and do not replace an absent check with agent output or an unrelated
passing validator.
