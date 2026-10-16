---
name: program-severity-scoring
description: Score confirmed findings against the program's rules.
---

# Program Severity Scoring

Use after a finding's protected capability and demonstrated consequence are
confirmed, before entering its severity in the BBH ledger. This skill chooses a
supported **program rating**, not a vulnerability-class default or a BBH
normalization label. It does not authorize additional live testing or submission.

## Procedure

1. Read the current published program brief, scope, and rating rules for the
   selected program. Start with its saved `program-policy.md` where available,
   but verify the controlling published program rules when accessible; note the
   source and any date/version. A supplemental testing-policy note cannot
   override published rules. Do not use a different program's historical
   finding as a rating authority.
2. Apply the published program's specific overrides, exclusions, and caps first.
   If it delegates a class or impact to a platform rubric, consult that rubric
   (for example, the applicable VRT) and retain any program-specific overrides.
   Use CVSS, its specified version and vector, only when the program requires
   CVSS for the rating. Do not silently substitute CVSS or a generic platform
   P-tier for a missing program rule. If sources conflict and priority cannot
   be resolved, record the conflict rather than picking the higher number.
3. Match the rule to the **demonstrated** consequence, attacker prerequisites,
   reachable resource, and negative boundaries in the evidence. A bug label,
   hypothetical cross-account access, or possible chain is not proof of that
   impact. If a higher consequence is plausible but unproven, state the missing
   proof and use only a rating supported by current evidence. Apply any scope
   exclusion or severity cap from the program before selecting its own label.
4. Record the program's label verbatim and these fields alongside the finding:
   `Scoring Authority` (specific program rule, delegated platform rubric, or
   required CVSS source/version), `Severity Rationale` (observed impact and
   why that rule fits), and `Program Constraint` when a cap, exclusion, or
   override changes the result. Include uncertainty and the missing proof when
   relevant. Pass that label to the ledger or report pipeline; normalization is not scoring.
   BBH's canonical `EXCEPTIONAL` through `INFO` mapping only normalizes a
   supplied label and cannot establish whether it was earned.

## Unknown and stop conditions

If the controlling program policy or delegated rubric is inaccessible, the
rules conflict, or the demonstrated consequence cannot be matched to a rule,
do not invent a rating. Do not assign a provisional high severity (including
P1) from the vulnerability name. Keep severity `UNKNOWN`, name the unresolved
source or evidence gap in `Severity Rationale`, and request the missing policy
or appropriate review. A proven finding can be captured without claiming a
premature rating; do not imply `UNKNOWN` means low impact or that normalization
resolved the uncertainty. If program rules require a scored rating before
submission, leave report readiness blocked until resolved.

## Verification

Check that the cited controlling rule actually applies to this program and
that the reported label is its own supported label after overrides/caps. Check
that every claimed consequence has a corresponding observation and that
`Scoring Authority`, `Severity Rationale`, and any `Program Constraint` agree
with the severity supplied to the ledger. No rule or adequate proof means
`UNKNOWN`, not an estimated P-tier.
