# Evidence and claims

The [catalog reference](../catalog-reference.md) is canonical for entry fields,
confidence labels, and how observations are interpreted. This page defines
how an agent or contributor may turn a source artifact into a catalog claim.

## What counts

An identified artifact counts as evidence only when it fits one of the
approved classes and directly supports the claim. The class does not by itself
prove a packet identity.

| Evidence class | What it can establish |
|---|---|
| Retail packet observation | Wire opcode, direction, observed length, or stream phase. |
| Retail client-file analysis | Client routing, receiver identity, ABI relationship, or expected payload shape. |
| Live validation | Verification against the retail 1.23b client in a live session. The client's acceptance of the behavior is the evidence. The implementation that drives the session is only the instrument. |

Repository code, tests, and generated headers establish implementation or
layout contracts. They do not prove retail behavior by themselves. Agent
output, summaries, search snippets, and unattributed statements are leads, not
evidence. Inspect the underlying artifact before promoting a fact.

## Promotion matrix

Use the narrowest durable claim supported by the artifact family:

| Artifact family | Claim boundary |
|---|---|
| Retail packet observation digest or capture name index | Wire opcode, direction, observed length, or stream phase. It is not a specific service when services share a wire integer. |
| Retail client decompilation, receiver, or ABI record | Client routing, receiver identity, or expected payload shape; not server behavior. |
| Recorded live-validation result | Verification that the retail 1.23b client accepted the behavior in a live session. Client acceptance is the evidence, and the implementation that drives the session is only the instrument. |

Promotion needs a source citation and its row or symbol locator. Preserve a
placeholder name when the artifact does not support a stable identity. When
approved classes conflict, keep the competing interpretations in `notes` and
use `blocked` until a narrower claim can be defended; do not resolve the
conflict by choosing the most familiar name.

## Claims and names

Make the narrowest claim the evidence supports. State uncertainty when a name,
service, direction, version, region, or layout interpretation is unresolved.
Do not merge conflicting candidates into one assertion.

Use the confidence label that the evidence supports. `pcap_observed` does not
name a packet. `live_validated` records verification against the retail 1.23b
client in a live session: the client's acceptance of the behavior is the
evidence, and the implementation that drives the session is only the instrument.
`decomp_routed` describes client routing or structure evidence.
`implemented` describes an implementation anchor. `confirmed` requires
the record to agree across the relevant evidence. `blocked` records a conflict
or undecodable boundary. See the catalog reference for the complete field
contract.

Keep a placeholder packet name when later evidence adds an anchor. Do not
rename an entry merely to make a later source look primary. Preserve the
alternative name or interpretation in `notes` when it is part of the evidence
record.

`observedIn` supports a direction-and-opcode observation. It is not proof of a
specific service when services share a wire integer. The capture index and
catalog notes carry that ambiguity. Lobby rows and world-to-map backend rows
have no client-capture observation by construction.

## Numbers in prose

Every figure in authored prose must carry its sentence's claim.

Essential figures stay verbatim. Row counts, coverage ratios, per-file byte
sizes and hashes, offsets, and extraction diffs are the claim itself - the
sentence exists to state them. Removing one changes the evidence.

Omit an incidental figure when the sentence's claim survives without it.

Do not qualify a figure with "approximately", "roughly", "about", or a
leading "~". Make it exact or remove it. When an exact source exists, cite
that source instead of restating its number.

This rule applies to authored prose. A figure inside a quoted or transcribed
source stays verbatim, including an approximation.

## Citations

A promoted fact from another repository uses this form:

```text
repository-name:path/to/file
```

Keep the repository identity, source path, and row or symbol locator
verbatim. Commit hashes and date pins are not citations:
repository histories are rewritten before publication, and dated "as of"
claims rot. Vendor mirrors record byte identity in
`data/vendor/*/PROVENANCE.json` via the sha256, together with the evidence
tier, refresh mode, and transformation.

Branch names, working tree paths, absolute machine paths, and unpinned links
are not durable citations. A research override may accept an explicit source
path, but normal validation and catalog regeneration must use inputs from this
repository and its pinned mirrors.
