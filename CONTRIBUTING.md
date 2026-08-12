# Contributing

Contributions are focused pull requests against `main`. Catalog changes must
be reviewable from their evidence through their generated outputs.

## Before contributing

Read the [catalog reference](docs/catalog-reference.md) and the
[evidence doctrine](docs/ai_agents/evidence-and-claims.md) before changing an
opcode, packet name, direction, layout, or confidence label.

Do not submit retail client binaries or assets, packet captures, decompiler
project files, credentials, or private working material. Evidence strings and
generated headers must not contain player names or chat text.

AI-assisted work has the same evidence and review burden as any other work.
Do not open a contribution if you could not explain every part of its diff,
why it belongs, and how it was verified.

## Code and documentation

The doctrine pages under `docs/ai_agents/` are authoritative:

| Subject | Authority |
|---|---|
| Evidence, claims, and citations | [Evidence doctrine](docs/ai_agents/evidence-and-claims.md) |
| Prose and comments | [Comments and prose](docs/ai_agents/comments-and-prose.md) |
| AI-assisted contributions | [AI policy](docs/ai_agents/README.md) |
| Required checks and claims about verification | [Verification doctrine](docs/ai_agents/verification.md) |

Every opcode entry change must cite the evidence that supports it: a pcap
observation, a client decompilation anchor, a catalog cross-reference, or a
recorded live-validation result. State or preserve the supported confidence
tier. An unsourced opcode claim is unreviewable and will be closed. The
[RE-finding form](.github/ISSUE_TEMPLATE/re-finding.yml) collects these fields
before a claim becomes a pull request.

Edit canonical curator inputs and the owning tools, then regenerate. Use
`tools/generate_catalog.py` as the catalog generation entry point and
`tools/generate_structs.py` for payload headers. Never hand-edit generated
catalogs or headers.

## Verification

The [checks workflow](.github/workflows/checks.yml) is the authoritative list
of CI-covered checks. The
[verification doctrine](docs/ai_agents/verification.md) provides the local
entry point, payload-framing contract, and limits on what the gate proves. Run
the checks that cover the change and report any unverified edge plainly. CI
runs the repository gate on every pull request, and the gate must be green
before merge.

## Pull requests

Fork the repository and open a pull request onto `main`. Keep each pull request
small and focused on one catalog claim, evidence batch, documentation change,
or tool change. Use a draft pull request for work in progress.

Complete the pull request template with the evidence, confidence effect, and
verification a reviewer needs. Keep follow-up changes within the same focused
scope. Do not merge while CI is failing.

## Issues and community

Join the [project Discord](https://discord.gg/PxK5RJYQjm) for questions and
community support.
Use [Issues](https://github.com/XIVLegacy/xivl-opcodes/issues) for bugs and
research findings that need a durable record. Use the bug form for a
reproducible repository defect and the RE-finding form for an opcode claim or
evidence lead.

Report security problems through private vulnerability reporting under the
repository Security tab. Do not open a public issue containing credentials or
private data.
