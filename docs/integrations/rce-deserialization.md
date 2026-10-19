# RCE Deserialization Reasoning — Draft Integration Dossier

## Intent and boundary

Ryu's Discord request (thread/message `1561803260686246100`) uses Simon Koeck's
DevSite session/pickle report to augment RCE reasoning, especially overlooked
headers/cookies and deserialization in unexpected state. Draft only: no target
traffic, runtime projection, beta/main merge, push, or new live-cookie tooling.

- Owner/task: Hermes, `t_fcbc9d77` on the bug-bounty-harness board.
- Branch: `feat/rce-deserialization`.
- Worktree: `~/worktrees/bbh-rce-deserialization`.
- Base: `origin/beta`, `9f56eb16d480eda212f7f76108a329d434aa9d9a`.
- Intended integration target after a separate adoption decision: `beta`.
- Recovery checkpoint: implementation commit
  `eee4f0bec6080548f855bf70fd1097324820e754`; a later dossier-only commit records
  final review/verification. The feature branch retains both commits.

## Implemented contract

General carrier guidance lives in `rce-surface-mapping`, not in a pickle-only
checklist. The thin `rce` and `rce-exploration` routes load a focused
`rce-deserialization` packet for accepted-control, integrity, representation,
reconstruction, and trigger questions. The case reference records verified
primary-source provenance, distinguishes default Flask tagged JSON from the
application's embedded pickle, and avoids public payloads or prescribed delays.

Checked neighbors: `rce`, `rce-exploration`, `rce-surface-mapping`,
`rce-validation`, `cookie-session-analysis`, and `agents/index.md`.
General discovery remains with mapping; mechanism analysis with the new packet;
proof selection and authorization stay with existing validation/live policy.
The CookieMonster route stays synthetic-only. No new escalation overlay or root
policy rule is introduced, so no impact-escalation/root-context edit is needed.

## Evidence and outstanding checks

Primary report, Flask API, Python pickle warning and pickletools documentation
retrieved through safe-fetch; capture references/hashes are in the case file.
Focused routing/contract regression: 21 passed, 10 subtests passed. Four edited/new
skill frontmatters parsed successfully. An isolated negative fixture removing the
class-entry route was rejected by the route guard as intended.

The first background launch selected Python without pytest. Pinning the
interpreter exposed missing checkout-local launcher dependencies; the documented
`./setup.sh --install-python-deps` created the task worktree's `.venv` without
changing dispatchers or runtime projection. Final `.venv/bin/python -m pytest -q
tests`: **286 passed, 186 subtests passed**. `git diff --check` passed.
Independent read-only review approved the draft without blockers. The reviewer
reran focused checks: **21 passed, 10 subtests passed**, verified all four primary
capture hashes, and exercised three reader scenarios: intact default Flask
JSON; compromised-integrity nested pickle consumed at callback; and header-driven
parser/error rendering without object loading. These are reader/packaging checks,
not executed target tests or a live efficacy claim.

Reviewed nine-file snapshot manifest SHA-256:
`6e4d140ef1bb6852ecff6d7e06e536835d28f05722ae48fd2816dc53acfed60b`.
The parent reconstructed that snapshot from the implementation commit, reverting
only the dossier's test-receipt paragraph in memory; the hash matched exactly.
No skill/reference/test changed after review. Final dossier-only evidence changes
are outside the mechanism contract.

## Activation and successor

Stop at a committed, independently reviewed feature draft. A later explicit
adoption can integrate into beta, test the integrated tree, and project the new
skill to intended consumers. No active runtime is changed by this draft.
