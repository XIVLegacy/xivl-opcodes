# Comments and prose

Delete explanatory comments unless they meet the keep criteria. Deletion is
the default.

Keep a comment only when it records one of these:

- a current catalog or tool invariant
- a client or wire fact
- an evidence or provenance citation
- a safety constraint
- a non-inferable command, flag, or API contract
- ownership of generated output when the code cannot make it clear

Keep source and evidence identifiers verbatim. Preserve a date when it belongs
to an identifier or external source metadata.

Compress other survivors to about one line at the use site. Move a longer
contract to a public policy or tool page and leave a short pointer. Remove
explanations tied to temporary branch state before merge.

Python docstrings and command help are runtime text. Treat them as public
contracts. Tighten them instead of deleting them when they explain a supported
command, input, output, or failure mode. Keep the source or symbol they mirror
when that pointer is part of the contract.

PowerShell and workflow comments follow the same burden. Keep a validation order,
repository boundary, or safety condition that is not obvious from the command.
Remove comments that repeat the step name or narrate the next line.

JSON has no ordinary comment syntax. A schema description or `$comment` value
is contract metadata, not a disposable source comment. Change it only when
the schema contract is intentionally changing, and run the validation checks.

Generated C++ comments are generator output. Preserve them exactly or change
the owning generator and regenerate. Never hand-edit a generated header.

When unsure, keep one line and flag it in review notes.

## Examples

Keep a wire fact:

```python
# Capture joins use direction and opcode because the wire has no service tag.
```

Keep a safety constraint:

```powershell
# Verify vendor hashes before validation consumes the promoted fixtures.
```

Move a longer contract to the policy page:

```python
# See docs/ai_agents/evidence-and-claims.md for citation rules.
```

Delete narration that repeats the code:

```python
# Increment the index.
index += 1
```

## Authored public prose

Public prose includes the README, the docs index, and any page a stranger
reads. Use a plain, direct register.

- Avoid over-hyphenation and invented compound modifiers. Established
  technical terms keep their hyphens.
- Use semicolons sparingly, preferring periods, commas, or short lists.
- Cut parenthetical asides. If the aside matters, make it a short sentence
  of its own. If it does not, delete it.
- Short declarative sentences, one idea each. A rule gets one line of
  practical justification, then stops.
- "Footgun" and "load-bearing" never ship in docs or comments. Name the
  actual hazard or dependency.

Every tracked authored prose or structured description contains current
evidence or contracts. It does not contain prompts, assignments, review
summaries, checkout state, internal milestones, or work-session plans. These
rules govern the public tier.

Internal working docs are out of scope.
