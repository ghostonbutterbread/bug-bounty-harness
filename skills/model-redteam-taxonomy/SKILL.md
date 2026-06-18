---
name: model-redteam-taxonomy
description: "Select safe model red-team technique families such as reframing, decomposition, multilingual, format pressure, and multi-turn probes."
---
# Model Red-Team Taxonomy

Use to choose technique families and evaluator design for authorized model/app testing. This is a taxonomy and mutation-planning lane, not a raw jailbreak payload bank.

## Invocation

```text
/model-redteam-taxonomy <program-or-lab> <model-or-feature> [--goal <boundary>] [--artifact <path>]
```

## Load Order

1. `$HARNESS_ROOT/prompts/model-redteam-taxonomy-playbook.md`
2. `$HARNESS_ROOT/prompts/prompt-injection-playbook.md` for app-boundary work
3. `/liberate-fren` for authorized local/cloud model behavior research

## Technique Families

- reframing
- decomposition
- multilingual and encoding transformations
- format pressure
- multi-turn escalation
- instruction-hierarchy confusion
- role/task inversion
- persistence and memory poisoning

## Output

Produce candidate probe families, safety limits, scoring criteria, and a route to the smallest applicable skill. Avoid copying large public jailbreak strings into artifacts unless the exact text is needed as evidence and is stored in a controlled research artifact.
