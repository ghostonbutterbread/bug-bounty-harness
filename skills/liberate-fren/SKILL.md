---
name: liberate-fren
description: "Authorized local or cloud model behavior research for jailbreak taxonomy, refusal behavior, and abliteration-style lab studies."
---
# Liberate Fren

Use for model-behavior research on local open-weight models or explicitly approved cloud-model test environments. Keep this separate from live bounty prompt-injection unless a target program explicitly allows model-behavior testing.

## Invocation

```text
/liberate-fren <lab-or-provider> <model> [--mode taxonomy|eval|abliteration-study|compare] [--artifact <path>]
```

## Load Order

1. `$HARNESS_ROOT/prompts/liberate-fren-playbook.md`
2. `$HARNESS_ROOT/prompts/model-redteam-taxonomy-playbook.md`
3. Provider or lab rules, model terms, approval notes, and local safety constraints

## Boundaries

- Local open-weight models are preferred for invasive research such as representation/refusal studies.
- Cloud models are allowed only when Ryushe or the provider terms authorize the evaluation.
- Do not use this lane to generate harmful instructions, steal secrets, bypass third-party access controls, or attack unrelated systems.
- Store datasets, prompts, outputs, and model notes under research artifacts; do not mix them into bounty reports unless they prove an app trust-boundary issue.

## Output

Record model/provider, test authorization, technique family, refusal or compliance behavior, scoring rubric, observed failure mode, and defensive lesson for `/prompt-injection` or app-agent testing.
