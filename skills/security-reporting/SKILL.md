---
name: security-reporting
description: Use when writing, revising, reviewing, or packaging a BBH finding's Evidence Report, triager submission, and PoC.
version: 1.0.0
---

# BBH Security Reporting

This is the canonical BBH report-writing skill. Use it for a verified, reportable finding; it does not decide whether an unproven candidate is reportable. Apply program-specific rules and the relevant live-testing policy separately. `poc-tooling-policy` owns creation versus live execution; `triager-first-poc-authoring` owns the executable reviewer artifact. A report package is not an external submission.

## Artifacts and identity

Use one stable finding ID across the package:

1. **Evidence Report:** complete internal source of truth, with claim-to-evidence pointers, prerequisites, sanitized request/response observations, root cause, controls, negatives, variants, limits, corrections, PoC pointer, and cleanup state. Preserve detail and uncertainty; do not put raw credentials, cookies, tokens, or unapproved private content in it.
2. **Submission Report:** concise, triager-facing derivative. It may compress or clarify the Evidence Report but must not introduce claims from memory, prior reports, or intuition. State material prerequisites and limitations rather than hiding them.
3. **PoC:** a small, executable walkthrough of the actual boundary break, with visible attacker/victim actions, decisive evidence, verification, and cleanup. Finalize it alongside the submission; do not ship the research harness merely because it worked.
4. **Judge Receipt:** separate result (`PASS`, `REVISE`, or `BLOCKED`), claim-to-evidence coverage, program-overlay checks, required revisions, and residual gaps. Do not overwrite either report with the receipt.

BBH's generated per-FID finding packet (`REPORT.md` and its navigation, written by `bounty_core.reports`) is a ledger-derived record, **not** automatically the Evidence Report or final submission. Preserve hand-edited records and the selected canonical report in place. When an existing artifact is named, edit that artifact directly; do not create parallel versioned drafts or mirror an exported report without direction. `FINALIZED.md` is not evidence of external submission. Only record a platform submission after Ryushe confirms it through the owning `manual-hunter` flow.

## Evidence-first sequence

Record the protected capability and the observation that proves it before claiming impact. Write or reconcile the Evidence Report first with a checkable minimum structure:

```markdown
# <finding-id> — <precise title>

## Claim and status
## Attacker model and prerequisites
## Evidence index
## Complete reproduction record
## Root cause and supporting implementation facts
## Demonstrated impact and negative boundaries
## Reproduction variants, controls, and failed attempts
## PoC and artifact references
## Remediation candidates
## Open questions / dated corrections
```

Within that structure distinguish attacker/victim roles and access, controlled fixtures, expected versus actual behavior, sanitized request/response and independent effect verification, source facts, side effects/cleanup, and uncertainty. Map each load-bearing claim to a PoC run, sanitized transcript/screenshot, source fact, or documented negative. Distinguish an owned fictional fixture from retrieved customer data. A status code or reflected input alone proves only the narrower observation. Preserve exact technical context, including failed paths and why they are outside the claim, without putting raw credentials or unrelated private content in the report.

Fact-check each material claim against its evidence pointer and PoC. Remove stale facts, secrets, researcher-local paths, unsupported scale or escalation, and misleading negatives. Use the same finding ID in the submission and judge receipt. If proof or an owned prerequisite is missing, name the gap rather than inventing a result. An independent judge compares the submission to the Evidence Report, final PoC, and program overlay; revise or leave a precise blocker.

## Submission structure

Use the program form when it mandates different labels; otherwise:

```markdown
# <specific vulnerability> allows <security-relevant outcome>

## Summary
<one compact paragraph: affected location, failed control, demonstrated attacker outcome and company/user consequence>

## Technical details
<brief root cause: attacker-controlled action/input, missing or incorrect control, causal link to result>

## How to reproduce
**Prerequisites:** <roles, controlled accounts/resources, feature state and human-only setup>

**PoC:** `<command>` — <one or two sentences on what this run proves>
- `<flag>`: <required input and where to obtain it>

**Manual replay:**
1. <setup action and relevant request>
2. <malicious request with portable placeholders>
3. <decisive observed response and independent verification>

## Impact
- **<company consequence>:** <proven capability → attacker action → business/user harm>

## Remediation
<durable fix of the demonstrated root cause and, when needed, independent material exploit-stage control>
```

Do not invent flags when the default PoC takes none. Give necessary nontrivial external setup (create/configure/activate an integration and locate its ID) only if the PoC cannot provision it. In the report, explain what the PoC does in a sentence or two; let its run walk the reviewer through provisioning, exploit, verification, and cleanup. Do not narrate its guided output again.

For request-based findings, make manual replay a short chronological setup → malicious request → decisive result. Show the **actual relevant requests**, especially the malicious one, and the observed response body or verified state change beside it. Include method, path, necessary headers/body and stable application fields; replace only triager-supplied values with clear placeholders. Omit incidental client headers, auth material, unrelated response fields, and raw private data. An HTTP success status alone is not proof of the claimed effect. For purely UI/browser findings, include request-level replay when it helps understand the proof; a minimal inline payload may itself be the clearest proof. Keep complete sanitized traces and variants in the Evidence Report.

Use neutral imperative steps, not a first-person research diary. Define attacker and victim accurately; do not imply a separate victim was tested when only an owned attacker browser was used. State expected secure versus actual behavior where it clarifies the flaw. Each prose paragraph and list item is one unbroken Markdown source line; do not hard-wrap or insert manual `<br>` spacing. Keep technical details causal rather than a source walkthrough, Impact about production consequences rather than test actions, and Remediation limited to the demonstrated path.

Never cite, link, name, or refer a triager to another one of our reports. Private prior reports may inform internal drafting only when Ryushe requests a comparison; every submission stands on its own prerequisites, malicious request, observed result, and evidence. The paired Evidence Report validates the submission internally, not as a cross-report dependency for the triager.

## Claim and program boundaries

For multi-organisation access, state the proven membership and role-permitted access; do not claim specific PII or customer data was read unless separately demonstrated. For a user-mediated OAuth/callback pivot, state the user navigation/login condition and code-to-token sequence; do not call it silent takeover. Include material limits that change the impact, not an exhaustive negative-results section. Apply the program overlay's fields, length, artifact types, prohibited claims, and code-reference preferences without padding the report.

The independent judge checks section order, evidence support and actual effect for each material claim, runnable prerequisites, PoC/flag alignment, the malicious request and decisive response, no cross-report references, secret hygiene, company-focused Impact, and remediation of the root cause. Preserve the receipt and name any unresolved gap. Report preparation does not set `submission.state=submitted`.
