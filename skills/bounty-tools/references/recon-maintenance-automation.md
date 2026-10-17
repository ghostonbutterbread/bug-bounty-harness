# Recon maintenance automation — design boundary

**Status: proposed, offline-review-only.** This reference preserves useful
constraints from a Ghost-local design sketch; BBH beta does **not** implement
its proposed persistent scheduler or scanner queue. Reading this reference
must not create/enable a cron job, start a worker, admit a target, or expand a
program's testing permission. `/recon` owns user-invoked full passes,
`/recon-ry` owns its actual collection/status and sequential exact-host queue,
and `/bounty-tools` owns one tool's artifacts and stop conditions.

## Ownership for a future recurring maintenance worker

- **Planner:** build candidates only from the selected saved-scope and
  source-attributed evidence, with reason, lane eligibility, collision bucket,
  effective rate, and coverage intention.
- **Optional reviewer:** choose only from already validated candidate identities
  and declared wordlist names; reject proposed commands, cookies, targets, new
  URLs, scope edits, payloads, and rate changes. Invalid/absent review falls
  back deterministically with a recorded reason. It never receives execution
  authority.
- **Executor:** on *every* launch, revalidate persisted queue rows against
  current published rules, approved origin/path, typed configuration, rate,
  locks, resource budget, and the relevant AI Policies. Rebuild executable argv
  from trusted config, never execute a stored `command`/shell string. `offline`
  is enforceable only when the runner actually blocks live-capable tools.
- **Post-processor:** retain bounded raw evidence; validate each normalized
  candidate against saved scope and planned origin before Recon Bus promotion.
  Filter wildcard/CDN/WAF-equivalent responses and inspect scanner output for
  credential/header leaks before any public handoff. A process exit of zero is
  not proof of meaningful discovery.

## Acceptance gates before any implementation or activation

Design tests should prove candidate and wordlist confinement, invalid-review
fallback, queue lock/collision and lease recovery, multi-entry aggregate rate,
real downstream argument compatibility, secret-redacted artifacts, normalized
output idempotence, and correct stop behavior. Account for unexamined candidates
without an obligation to launch an unbounded queue. Persistent worker ownership,
RAM/disk/output limits, and old-owner retirement belong to
`service-lifecycle-policy`; queue leases alone do not prove a single host owner.

Do not repurpose current `tool-run` as a gated scheduler: it executes supplied
argv, writes command/output and manifest after exit, and may promote successful
outputs. `watch-runs` is a one-invocation completed-run promotion pass, not a
resident supervisor. `recon_full.py` is plan-only. The Recon-Ry queue is a
sequential host operation, not an arbitrary persisted scanner queue; the
separate incremental Recon-Ry evidence handoff must not become a second
scanner-admission pathway. Do not claim a signed-release/authenticated-plan
CLI or scheduled FFUF/Arjun/Naabu pipeline until implemented and verified in
its owning source and selected runtime.

For a proposed live qualification later, require an explicit operator decision,
current program scope/rate/account review, correct task transport, one scoped
fixture, process **and** semantic result checks, artifact/secret review,
cleanup, and a go/no-go receipt. No live qualification or timer is part of this
reference's publication.
