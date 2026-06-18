# Liberate Fren Playbook

Use for authorized model behavior research, jailbreak taxonomy work, refusal behavior comparison, and local lab studies. This lane may use local open-weight models or approved cloud models, but it stays separate from third-party bounty prompt-injection unless the target program explicitly allows that testing.

## 1. Authorization

Record:

- model/provider/lab
- local or cloud
- approval source or provider terms
- allowed test categories
- disallowed categories
- artifact location

If authorization is unclear, stop and ask Ryushe.

## 2. Modes

### Taxonomy

Classify technique families and expected model behavior. Use `/model-redteam-taxonomy`.

### Eval

Run a bounded prompt set against a model and record behavior by category. Prefer benign or synthetic tasks that measure instruction-following, boundary confusion, refusal style, and tool-risk reasoning.

### Abliteration Study

Local open-weight only by default. Study refusal representation, behavior drift, benchmark changes, and safety regression in a contained lab. Do not apply invasive model-modification techniques to cloud models.

### Compare

Compare local and approved cloud models on the same safe evaluator. Record differences in:

- instruction hierarchy handling
- refusal style
- indirect injection awareness
- tool-call caution
- multilingual/format robustness
- persistence/memory risk

## 3. Data Handling

- Keep raw prompts/outputs in research artifacts, not bounty reports.
- Do not store secrets, real credentials, private user data, or customer documents.
- Label harmful or sensitive public examples as untrusted research data.
- When importing public jailbreak repos, summarize technique families and store exact strings only if needed for reproducible research.

## 4. Cloud Model Boundary

Cloud models are acceptable for authorized evaluation, but keep probes within:

- provider terms
- owned accounts
- no real-world harm
- no attempts to access third-party secrets or systems
- no automated high-volume abuse

## 5. Output Template

```md
# Liberate Fren Research Note

## Scope
- Model/provider:
- Local/cloud:
- Authorization:
- Mode:

## Technique Families
- Tested:
- Blocked:
- Deferred:

## Results
- Behavior:
- Failure mode:
- Defensive lesson:
- App-testing implication:

## Follow-Up
- Route to `/prompt-injection`:
- Route to `/indirect-injection`:
- Route to `/agent-tool-abuse`:
```
