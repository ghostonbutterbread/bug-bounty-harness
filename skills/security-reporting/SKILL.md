---
name: security-reporting
description: Route a verified BBH finding from its ledger FID and Evidence Report to the standalone Bunny final-report skill.
version: 2.0.0
---

# BBH Finding Reporting Handoff

This is the canonical **BBH handoff**, not a second report writer. The separate `bunny-report-and-triage` skill owns triage, the reviewer-facing report, and its PoC presentation. A prepared file is not a platform submission. Follow program rules and the applicable live-testing policies separately; loading a reporting skill grants no live-testing authority.

## Capture, then report

At first independently demonstrated vulnerability, apply `impact-fit-policy`: identify attacker starting access, newly gained protected capability, proof observation, and demonstrated consequence. Ingest promptly through `manual-hunter` with explicit program and lane. A new FID has a create-only `reports/<FID>/EVIDENCE.md` scaffold and a ledger record, **not** a generated rough `REPORT.md` or `SUBMISSION.md`.

Fill `EVIDENCE.md` with the actual proof before calling the package ready. An initial scaffold or ledger assertion is not proof. Preserve one exact FID and these evidence sections:

```markdown
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

State the role and owned fixture, expected control and actual result, an independently checked effect, material limits, cleanup, and exact sanitized evidence pointers. Distinguish observed facts from interpretation; a `200`, an error, or an echo alone proves only that narrower observation. Keep credentials, tokens, raw cookies, private bodies, and unrelated personal data out of the ledger, Evidence Report, and shareable report. If a material proof value cannot safely be shared without disclosing protected content, keep it in its approved restricted evidence location and mark the reporting gate blocked rather than fabricate or silently redact a decisive value. Program and storage privacy rules take precedence over a fork's request to copy material values verbatim.

When a material boundary or impact question remains, the finding owner may investigate it under the applicable live-testing, ownership, Attempts, and side-effect controls; reconcile new observations into the *same* FID and `EVIDENCE.md`. Do not delay proven-finding capture for speculative escalation. Do not make a report writer rerun destructive, irreversible, metered, non-owned, or otherwise material state-changing actions merely to polish an artifact. A newly authored scripted PoC is not called live-tested if its final form was not run; record the exact blocker and leave readiness unresolved. Separate authorized validation is a decision about scope and effects, not an automatic consequence of loading Bunny.

## Bunny final-report route

Resolve the exact program, family/lane, FID, and packet from the ledger and storage resolver. Supply the selected ledger finding, the **absolute** `reports/<FID>/EVIDENCE.md` path, evidence pointers and owned-fixture/prerequisite context, relevant program overlay, and explicit live-authorization limits to the installed standalone `bunny-report-and-triage` skill. If that skill is absent, stop and report the missing dependency; do not substitute a local `SUBMISSION.md` writer. The skill's name is unrelated to opting into Bunny campaign orchestration.

Ask Bunny to triage the existing evidence and produce the one final `reports/<FID>/<target-domain>-<vuln-type>-<FID>.md` report, preserving the exact FID. Let it choose a simple inline curl for one fixed request, or a `poc.<ext>` for dependent/stateful reproduction, per its own contract. A standalone or scripted PoC uses `triager-first-poc-authoring` and `poc-tooling-policy`; a simple inline curl does not need that authoring skill. The finding owner/coordinator remains accountable for the scope, effect proof, final artifact, and cleanup; the reporter does not inherit new permission to exploit. If the proof or an owned prerequisite is missing, record the gap in `EVIDENCE.md` and return it to the owner rather than inventing a reportable outcome.

Verify the generated report and any PoC are in the **same FID packet**, correctly named, match the Evidence Report and program requirements, contain no unapproved private material, and include the decisive result rather than just a request or HTTP status. A fresh independent reviewer checks claim-to-evidence and PoC alignment and records `PASS`, `REVISE`, or `BLOCKED` under `_meta/`; Bunny's own readiness assessment does not replace that review. Revise the one final report in place within the requested scope, preserving other text; do not create versioned siblings or a competing final. Never cite another of our reports to a triager. Cross-origin steps need the full URL including scheme and authority; same-origin follow-ups may be relative when their base is unambiguous.

At handoff give the full absolute **Report** path to the FID-named file and, if standalone, the actual **PoC** path; for inline curl name its section instead. Verify each exists and state readiness and any blocker. Existing `REPORT.md`/`SUBMISSION.md` files in older packets are historical content: preserve them and use an explicit FID-specific migration/review rather than deleting, overwriting, or regenerating them. Only Ryushe's confirmation of external submission updates `submission.state=submitted` through `manual-hunter`; a confirmed finding or completed report never implies submission.
