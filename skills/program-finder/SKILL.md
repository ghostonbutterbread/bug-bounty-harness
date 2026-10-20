---
name: program-finder
description: Use when shortlisting paid bug-bounty programs before target selection.
---

# Program Finder

Find a small, source-backed shortlist of *currently paid* bug-bounty programs
before choosing a target. This is public program discovery, not reconnaissance
of an authorized asset: it creates no account, probes no target, and grants no
permission to test. Once a program is selected, load `general-security-testing-policy`,
`program-testing-policy`, and `/pullscope` for its actual rules and scope before
any target interaction.

## Candidate sources and fit

When the selection criterion is a named technology, CVE, library, or converter, load `stack-to-program` first to produce evidence-labeled product and directory candidates. Then verify current paid status and program rules here. A dependency or directory join alone is neither a paid-program confirmation nor testing permission.

Start with current public directories and program pages (including YesWeHack,
Intigriti, HackerOne, Bugcrowd, and direct programs where relevant). `/bountylens`
may contribute program/stat candidates; it is not the authority for a reward,
permission, payout speed, or current rules. Retain a source URL for every fact.

Unless Ryushe supplies different criteria, prefer a confirmed critical maximum
near $3,000–$6,000, lower *evidenced* activity, and faster payout or critical
remediation where public evidence supports them. These are ranking preferences,
not eligibility gates or claims that unknown data is favorable. Product type,
source-visible apps, browser extensions, uploads, rendering, and integrations
are tie-breakers after broad discovery, not filters unless explicitly requested.

## Procedure

1. Collect public program candidates with canonical program/rules links and
   stated reward ranges. If a direct site exposes only `security.txt`, treat it
   as a contact route, **not** proof of a paid program.
2. Check each candidate's current published bounty statement, scope, and
   exclusions. Keep the exact source and observation date; remove candidates
   with unconfirmed payments or authorization from a *paid-program* shortlist.
   Do not contact an asset merely to resolve unclear rules.
3. Record only decision-useful evidence: confirmed maximum reward, product
   shape, published activity, and sourced payout/remediation information. Use
   `unknown` for unreported fields. Submission-to-close ratios and missing
   report counts are not reliable measures of competition, duplicates, payout
   speed, or remediation quality.
4. Return the requested number of distinct programs with a concise reason for
   each. Explain any exception to a requested payout range rather than quietly
   changing it. Name the most promising place to open first and the material
   unknowns; do not manufacture a numeric score unless asked.

Use one short bullet per program: name/platform; sourced critical maximum;
application; evidenced activity or `unknown`; payout/remediation evidence or
`unknown`; canonical rules URL. A shortlist is not testing permission: it is a
decision aid, not a stored program policy, scope artifact, or permission to run
`/recon`.

## JavaScript Lens — not applicable before selection

A target's JavaScript bundle is not evidence that a program is paid or in scope.
This skill uses public program declarations only. After target selection and
published-rule verification, route actual source/runtime mapping to `/js` and
`/live-map` under the normal live-testing gates.

## Verification

Confirm that each retained program has a current public reward/rules source,
that every claimed payout/activity/remediation detail is supported by its own
source, and that unavailable facts remain `unknown`. No target request or
account operation is part of this workflow.
