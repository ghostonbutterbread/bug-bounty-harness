---
name: bug-bounty-triage
description: "Use to validate, escalate, and ready a bounty report."
version: 0.1.0
author: Sequester-AG; adapted for BBH by Ryushe and Hermes Agent
license: MIT
---

# Bug Bounty Triage - BBH adaptation

Adapted from Sequester-AG/bug-bounty-triage (upstream commit `9684e1bfc876e841f9c789f0b258902b43d461e4`; MIT notice in `LICENSE`). Use when asked whether a finding is valid, submittable, or worth escalating, or when preparing its report. This skill owns the **triage decision and evidence gap analysis**, not a second report format or permission to run exploits. `security-reporting` owns the canonical report and PoC handoff. A report-only assignment must not launch live tests; send a specific unresolved proof question to the finding owner/coordinator.

## 1. Intake and authorization

- Identify the program and lane, exact FID if recorded, affected asset/feature/version if known, vulnerability class, attacker starting access, controlled fixtures, claimed boundary and consequence, PoC, source evidence, negative controls, cleanup state, and program overlay. Do not infer a FID, account owner, or product version from a filename.
- Read the current program scope/rules and relevant saved context before any live target action. Load `general-security-testing-policy` then `live-testing-policy`, plus the class-specific and account policies for the proposed action. If scope or an owner is unknown, analyze existing evidence only and name the missing authorization. A skill invocation is not testing authorization.
- Use `bounty-storage` and `bounty-directory-structure-policy` to resolve retained artifact placement. Open the exact existing `reports/<FID>/EVIDENCE.md`, `REPORT.md`, and PoC when present; these are not interchangeable with a pasted draft or a target-domain-named file in CWD. Treat the supplied claim as a lead, not independent proof. For a verified finding without a FID, hand it to the finding owner/coordinator for `manual-hunter` ingest in the canonical program/lane; record the assigned FID and populate its generated `EVIDENCE.md` and rough `REPORT.md` before any submission preparation. An unproven candidate remains a lead, not a finding to ingest merely to obtain a FID.

## 2. Validate the actual boundary (only within a live-testing assignment)

1. State the falsifiable question: starting role/state, attacker-controlled input, expected secure result, actual observable result, and independent effect check. Map each asserted consequence to an evidence pointer. A 2xx response, alert box, scanner output, or screenshot alone may support only a narrower claim.
2. Prefer existing sanitized capture and safe verification when they answer the question. Do **not** repeat an irreversible, metered, destructive, or material state-changing action merely to polish a report. If a new test is warranted, use controlled owned fixtures, a normal baseline and one discriminating control under `account-testing-policy`, `attempt-recording-policy`, and the specialist live policy. Stop on scope, stress, ownership, disclosure, or program-rule boundaries; do not browse unrelated user IDs or admin records for a stronger label.
3. For browser-dependent security testing, load `browser-session-policy` and `chromium-test`, and request the isolated browser through `bbh skills/chromium-test/scripts/browser_provisioner.py request ...`; use its task-scoped MITM and verified CA. **Never** start `chromium_test.py` directly, use `agent-browser`/an in-app browser as an alternative security lane, borrow a browser, or use shared Caido. After a captured session/request, use bounded direct replay through that task MITM where the class policy permits. Release the browser and finish its proxy under `chromium-test`.
4. Do not automatically create attacker/victim accounts. Check the program inventory and `account-management`; for setup, load `account-testing-policy` and `email-access-policy`. For the approved forwarding mailbox, load `mail` and use its Composio connection for narrowly scoped verification mail; do not use agent-email as a Gmail fallback. Use `temporary-email` only if disposable addresses are allowed and a disposable owned fixture is necessary; do not imply Composio creates inboxes. Keep codes, cookies, passwords, raw private requests and unrelated personal data out of reports and chat.
5. Capture sanitized decisive request/response, independent effect, controls, fixture ownership, scope, limits, and cleanup in the same FID's `EVIDENCE.md`, with restricted raw evidence only where permitted. A reporting agent receiving an incomplete packet identifies the exact test for its owner rather than executing it independently.

## 3. Submission-readiness decision

- **GREEN** only when the failed boundary, attacker model, complete reproduction, effect, severity-relevant limits, and program compliance are supported by indexed evidence and an independently reviewed PoC/report. "Prepared" is not "submitted."
- **YELLOW** when the candidate is plausible but a decisive control, effect check, required setup, or owner/scope fact is missing. Record the one or few discriminating questions in `EVIDENCE.md`/rough `REPORT.md`; do not create a polished `SUBMISSION.md` yet.
- **RED** when verified behavior contradicts the claim, the only result is non-security behavior, or published program rules exclude it. State the evidence and the narrower observed behavior; do not apply an unconditional global auto-reject list to a program that accepts the class.
- Check product-specific prerequisites, role/plan/permission, where the triager obtains each ID or auth value, listener/network placement and runnable setup when needed, precise malicious request, expected versus observed result, independent verification, and cleanup. A capable triager should not have to guess a nonstandard step. Absence of a private policy page is not proof of permission: apply known scope/rules and label what remains unknown.

## 4. Escalate only defensible impact

Lead with the highest **demonstrated**, non-subsumed consequence. Classify each adjacent path as verified, inferential, or untested and prioritize only a path that materially changes the boundary, role, persistence, tenant reach, or business consequence. Apply `impact-fit-policy` and the applicable class policy; stop when a safer controlled proof or authorization is unavailable. Do not conflate a possible chain with the finding or assign severity by ambition. For a concrete unresolved impact or reproduction question, load [the upstream-derived triage depth checklist](references/triage-depth.md); it is not an automatic probe list.

- IDOR/BOLA: controlled read versus write, same-tenant versus cross-tenant, and role-permitted access; never enumerate third-party identifiers or claim PII without proof.
- XSS: controlled rendering context and actual user-mediated effect; script execution does not establish account takeover or admin execution.
- SSRF, SQLi, file upload, auth/role, OAuth, and business-logic chains: identify the next relevant boundary and a safe owned/local proof first. Internal network, cloud metadata, file reads, database writes, RCE, and financial effects are **not** routine escalation probes.
- Score with the program's severity rubric or CVSS version when required; set metrics from the demonstrated exploit and prerequisites. Do not invent bounty ranges, regulatory consequences, or a Critical label from a hypothetical chain.

## 5. Prepare the canonical report, not another format

When the exact FID has verified `EVIDENCE.md` and a rough `REPORT.md`, give the finding owner/coordinator a triage receipt with evidence pointers and any unresolved tests. The coordinator assigns the **reporting agent** to load `security-reporting` and prepare the one five-section `SUBMISSION.md` at the storage resolver's canonical `reports/<FID>/SUBMISSION.md`. The reporting agent, not this triage-only worker, drafts in task scratch and calls `bbh agents/finding_submission.py <program> <FID> --lane <lane> --from-file <task-scratch/concise-draft.md> --evidence-pointer <index-id>` (repeat the pointer flag as needed). The command requires the exact existing ledger FID and populated packet, resolves the program family/lane, validates structural readiness and creates once; it does not prove truth, submit to a platform, or overwrite existing work. Revisions edit that same file within the user's requested region. Program-specific form labels require the reporting skill's explicit overlay route. If the same agent is explicitly assigned both triage and reporting, it must change roles at this handoff and follow `security-reporting`'s gates rather than treating triage as report authorship.

The submission has **Summary**, **Technical details**, **How to reproduce**, **Impact**, and **Remediation** in that order unless the program form overrides them. Put decisive sanitized proof beside the reproduction action, name full cross-origin URLs, and explain non-obvious target/lab setup in the shortest runnable form. Keep only supported claims and material limits; no internal triage scorecard, local-only path, credential, raw private value, other-report reference, or synthetic placeholder pretending to be a captured result. A triager may use their own account/token/IDs, with their origin stated. Preserve literal identifiers and evidence accurately in the restricted source record while sanitizing the shareable derivative. Do not follow the upstream "never redact" instruction: it conflicts with BBH secret and privacy rules. Apply `security-reporting`'s PoC ownership, independent judge, and targeted revision gates.

## 6. Return the triage receipt

Outside `SUBMISSION.md`, report: tested end-to-end/partial/not tested; verified claim and evidence pointers; GREEN/YELLOW/RED with its precise blocker; original versus **supported** impact/severity (and rubric/vector only if scored); cleanup status; and absolute canonical Report/PoC paths when files exist. Label `REPORT.md` a draft and `SUBMISSION.md` a prepared submission, never an external submission. If RED or YELLOW, do not fabricate a copy-paste-ready final report. If GREEN, recommend review/submission through the program workflow, not automatic posting. Verify every handed-off path exists.

## Pitfalls and verification

- This is an **internal derivative**, not a replacement for `security-reporting`, the BBH ledger, class-specific testing policy, or the program's rules. The upstream's unconditional agent-email account setup, browser interchangeability, global reject list, exploit-every-chain checklist, CWD target-domain output, source-fidelity/never-redact demand, and bounty estimate are deliberately not carried over.
- On a read-only report review, verify the decision and evidence gap without touching the target or writing a final file. On a supported controlled finding, verify canonical packet identity, evidence-index pointers, five sections, reviewer receipt, no secrets, and exact path handoff. Never report a live validation result that was not executed.
