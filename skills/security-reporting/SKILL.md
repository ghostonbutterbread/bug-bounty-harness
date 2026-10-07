---
name: security-reporting
description: Use when writing, revising, reviewing, or packaging a BBH finding's Evidence Report, triager submission, and PoC.
version: 1.0.0
---

# BBH Security Reporting

This is the canonical BBH report-writing skill. Use it for a verified, reportable finding; it does not decide whether an unproven candidate is reportable. Apply program-specific rules and the relevant live-testing policy separately. `poc-tooling-policy` owns creation versus live execution; `triager-first-poc-authoring` owns the executable reviewer artifact. A report package is not an external submission.

## Artifacts and identity

Use one stable FID and one current file per stage in `reports/<FID>/`:

1. **`EVIDENCE.md`:** living internal source of truth, seeded when a proven finding is recorded. Maintain claim-to-evidence pointers, prerequisites, sanitized observations, controls, negatives, variants, limits, corrections, PoC pointer, and cleanup state. An initial scaffold is not complete proof. Keep raw credentials, cookies, tokens, and unapproved private content out.
2. **`REPORT.md`:** rough, editable report beginning with the currently demonstrated vulnerability. Its Summary, Technical details, How to reproduce, Impact, and Remediation give the eventual submission its spine; short open questions and evidence pointers may remain while investigating. The ledger-derived generated version is a starting draft, not the Evidence Report or a submission-ready claim. Revise this same file as the boundary and impact become clearer; preserve hand edits during ledger refresh.
3. **`SUBMISSION.md`:** one concise, triager-facing derivative, created automatically by the reporting agent once the boundary is understood and the evidence supports the claim. It may compress or change the impact angle of the rough report, but cannot introduce unproven claims. A prepared file is not an external submission; review and refine the same file rather than creating versioned siblings.
4. **PoC:** `poc.<ext>` in the same finding packet, a small executable walkthrough of the actual boundary break, with visible actor actions, decisive evidence, verification, and cleanup. The extension matches the deliverable format; `triager-first-poc-authoring` owns this final-artifact naming contract. The assigned finding/PoC owner prepares it; the coordinator is accountable for the final artifact alongside the submission. Do not ship the research harness merely because it worked.
5. **Judge Receipt:** separate review result (`PASS`, `REVISE`, or `BLOCKED`) under `_meta/`, with claim coverage, overlay checks, revisions, and residual gaps. Do not overwrite the three report files with it.

These are distinct stages, not one formatting tier applied to every file. `EVIDENCE.md` keeps the complete provenance and observations; `REPORT.md` is an editable rough draft. The five-section presentation under **Submission structure** applies to `SUBMISSION.md` (or the program's form), not to evidence capture or a research draft. Load this skill for final-submission creation or edits without turning those upstream records into polished submission copies.

**Revision locality is an explicit ownership boundary.** When Ryushe or a reviewer names a section, paragraph, sentence, or other region to revise or condense, edit only that region of the existing `SUBMISSION.md`. Preserve all text outside it, including headings, examples, formatting, and adjacent sections; do not regenerate the whole submission, re-run a draft writer over it, or opportunistically apply other review suggestions. Inspect the before/after diff against the requested region. If a necessary correction outside that region is discovered, flag the exact conflict and seek an expanded edit scope rather than silently changing it. A general request to revise the whole submission, or an explicitly expanded scope, permits a broader edit; fact-checking and review of the full artifact still do not by themselves authorize rewriting it.

At first verified finding, apply `impact-fit-policy` to state attacker starting access, gained capability, proof observation, and demonstrated consequence; record the FID promptly. After a new FID, decide whether a material boundary or impact question remains. For a straightforward finding whose proof already answers it, record that conclusion and move to drafting; do not force additional testing. Otherwise the primary hunter dispatches one focused per-FID subagent with sanitized evidence, owned-fixture and scope limits, one decision question, and a stop condition. The child investigates the actual boundary and discriminating controls under the live-testing and Attempts policies; the parent reconciles its observations and corrections into the same FID, `EVIDENCE.md`, and `REPORT.md`. Do not launch live work from a ledger or report writer, delay capture until every possible impact is tested, or treat hypothesized escalations as proven.

## PoC ownership and report handoff

PoC authorship follows finding context, not agent rank. For each FID, the coordinating agent names one finding/PoC owner in the work packet or handoff. If the main hunter established the proof, it can author the PoC; if a hunting subagent established it, that subagent can author the PoC within its bounded assignment and return the artifact with sanitized evidence, prerequisites, limits, and cleanup status. A child that only mapped or investigated a piece returns observations rather than being presumed the PoC author. The coordinator reconciles the returned proof, owns the single final artifact and report handoff, and fills any gap itself or delegates focused construction/refinement with the exact claim, evidence, owned prerequisites, scope and side-effect boundaries, and a stop condition. The PoC author loads `poc-tooling-policy` and `triager-first-poc-authoring`; delegation does not expand live-testing authority. The reporting agent owns `SUBMISSION.md` and alignment of the report's reproduction and claims with the PoC; invoking this reporting skill does not make it the PoC author or authorize it to run the exploit. Return an evidence or PoC gap to the finding owner/coordinator rather than inventing a step or independently launching live validation from the report task.

At handoff, supply both full, absolute paths explicitly: **Report:** the current `reports/<FID>/SUBMISSION.md` when prepared (otherwise label `reports/<FID>/REPORT.md` as a draft); **PoC:** the final `reports/<FID>/poc.<ext>` with its actual extension. Verify both files exist before presenting their paths; never substitute a scratch harness or imply that a prepared submission was sent to the platform. If either artifact is still missing, state the gap rather than presenting a presumed path as complete.

Reuse recorded request/response, independent effect verification, fixture ownership, and cleanup status when preparing the PoC and report. In particular, do not repeat a destructive, irreversible, metered, or otherwise material state-changing action (such as an owned bucket write) merely to polish an artifact. Test PoC structure and failure paths offline where possible; any additional live test needs a specific unresolved proof question and the applicable scope, authorization, and live-testing controls. If a reviewer-facing PoC cannot safely self-run the material step, provide a clear gated/manual handoff and label prior evidence as prior evidence, not a new run.

When the boundary is understood, the reporting agent authors one concise five-section draft from `EVIDENCE.md` and `REPORT.md` in task-owned scratch, then prepares the canonical file with:

```bash
bbh agents/finding_submission.py <program> <FID> --lane <lane> \
  --from-file <scratch/concise-draft.md> --evidence-pointer <exact-index-id>
```

Repeat `--evidence-pointer` for independently cited observations. Before invoking, replace the scaffold's `Pending` sections with verified evidence, state `Verified: ...` under `## Claim and status`, and preserve a concise evidence index with exact IDs. A program-mandated form with different headings uses `--program-form` only after checking that overlay. The command checks exact FID, packet, nonempty structural sections and pointers and creates `SUBMISSION.md` once; it does **not** judge claim truth, program compliance, secret hygiene, or external submission. The reporting agent must inspect those directly and request independent review. Do not create an extra submission version in the packet or imply that the CLI alone certifies readiness.

Before creating `SUBMISSION.md`, establish the attacker model, failed control, actual result, independent proof of the claimed consequence, reproducible prerequisites, and material limits. When a link is missing, name the test or blocker in `EVIDENCE.md` and keep working in `REPORT.md`; do not polish uncertainty into a submission. Preserve the existing `SUBMISSION.md` on later updates; a changed claim calls for review and targeted revision, never silent regeneration or `v2` copies. `FINALIZED.md` is a legacy optional Bounty Core copy, not the canonical submission and not evidence of external submission. Only record a platform submission after Ryushe confirms it through `manual-hunter`.

## Evidence-first sequence

Record the protected capability and the observation that proves it before claiming impact. Populate the create-only `EVIDENCE.md` scaffold with the growing investigation; its useful sections are:

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

Let `REPORT.md` remain an evolving explanation: retain competing impact angles and open proof questions there and in `EVIDENCE.md` while investigating. When preparing `SUBMISSION.md`, lead with the **highest demonstrated impact**, not the longest list of possible actions. In the Summary, state the vulnerability and failed boundary, then the proven attacker outcome and its consequence. Include another impact only when evidence shows it is materially distinct rather than an ordinary action already encompassed by the lead (for example, separately persistent organization access after recovery, if verified). Do not list routine account actions after a proven account takeover merely to inflate the claim. Script execution alone does not prove takeover; name session-only access, enduring account control, and their prerequisites accurately. The Impact section explains the lead and any distinct non-subsumed consequence without repeating the Summary; keep speculative chains in `EVIDENCE.md` or as explicitly unresolved questions in the rough report. Place decisive supporting evidence beside reproduction steps and cite the corresponding evidence-index pointers rather than adding an undifferentiated evidence dump.

Use the program form when it mandates different labels; otherwise:

```markdown
# <specific vulnerability> allows <security-relevant outcome>

## Summary
<one compact paragraph: vulnerability and failed boundary → highest demonstrated impact; add only distinct, proven non-subsumed consequences>

## Technical details
<brief root cause: attacker-controlled action/input, missing or incorrect control, causal link to result>

## How to reproduce
**Prerequisites:**
- <Required role/account and controlled resource or feature state.>
- <If applicable, required special permission, plan, or human-only setup; otherwise, when verified, “Default user/plan permissions suffice.” Omit this bullet if neither is established.>

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

Prefer concise bullets for scan-friendly lists, especially prerequisites; use prose where sequence or causality reads better. List only what the reviewer actually needs to reproduce the finding. Name a special plan or permission only when it is required; if default user/plan access has been verified to suffice, say so in one bullet rather than speculating about elevated access. If access requirements are unverified, preserve that uncertainty in the Evidence Report and do not assert that default access suffices.

Do not invent flags when the default PoC takes none. Give necessary nontrivial external setup (create/configure/activate an integration and locate its ID) only if the PoC cannot provision it. In the report, explain what the PoC does in a sentence or two; let its run walk the reviewer through provisioning, exploit, verification, and cleanup. Do not narrate its guided output again.

For request-based findings, make manual replay a short chronological setup → malicious request → decisive result. Show the **actual relevant requests**, especially the malicious one, and the observed response body or verified state change beside it. Include method, path, necessary headers/body and stable application fields; replace only triager-supplied values with clear placeholders. Omit incidental client headers, auth material, unrelated response fields, and raw private data. An HTTP success status alone is not proof of the claimed effect. For purely UI/browser findings, include request-level replay when it helps understand the proof; a minimal inline payload may itself be the clearest proof. Keep complete sanitized traces and variants in the Evidence Report.

Use neutral imperative steps, not a first-person research diary. Define attacker and victim accurately; do not imply a separate victim was tested when only an owned attacker browser was used. State expected secure versus actual behavior where it clarifies the flaw. Each prose paragraph and list item is one unbroken Markdown source line; do not hard-wrap or insert manual `<br>` spacing. Keep technical details causal rather than a source walkthrough, Impact about production consequences rather than test actions, and Remediation limited to the demonstrated path.

Never cite, link, name, or refer a triager to another one of our reports. Private prior reports may inform internal drafting only when Ryushe requests a comparison; every submission stands on its own prerequisites, malicious request, observed result, and evidence. The paired Evidence Report validates the submission internally, not as a cross-report dependency for the triager.

## Claim and program boundaries

For multi-organisation access, state the proven membership and role-permitted access; do not claim specific PII or customer data was read unless separately demonstrated. For a user-mediated OAuth/callback pivot, state the user navigation/login condition and code-to-token sequence; do not call it silent takeover. Include material limits that change the impact, not an exhaustive negative-results section. Apply the program overlay's fields, length, artifact types, prohibited claims, and code-reference preferences without padding the report.

The independent judge checks section order, whether the Summary leads with the highest demonstrated impact and includes only proven non-subsumed additional consequences, evidence support and actual effect for each material claim, runnable prerequisites, PoC/flag alignment with the lead impact, the malicious request and decisive response, no cross-report references, secret hygiene, company-focused Impact, and remediation of the root cause. For runnable PoCs, use `triager-first-poc-authoring`'s reviewer-output check: an exit code or `200` without the promised observation is not a passing replay; distinguish prior evidence and gated/unrun live steps. Preserve the receipt and name any unresolved gap. Report preparation does not set `submission.state=submitted`.
