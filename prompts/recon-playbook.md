# Full-Platform Recon Playbook

## Purpose

Use this playbook with `/recon` to create a current, historical, and
coverage-aware platform map—not a pile of scanner output. The final product is
a compact Recon Brief and a small set of evidence-backed handoffs for the next
specialist lanes.

```text
scope + cold current pass + freshness decision
  -> Recon-Ry/supplemental collection + archive comparison
  -> Recon Bus aggregate + focused map + coverage state
  -> ranked, bounded handoffs
```

## Preconditions

1. Verify scope, program rules, rate limits, and collection permission.
2. Load `general-security-testing-policy`; before traffic, load
   `live-testing-policy` and `/bounty-tools` for external tools.
3. Use `/recon-corpus-write-policy` for reusable recon data and
   `/bounty-directory-structure-policy` for retained artifacts.
4. Do not start a scan without a program, scoped seed/origin, and rate source.

## 1. Establish a Freshness Baseline

Before deciding to rerun broad collection, record:

- exact scoped seed/origins and wildcard boundaries;
- latest comparable Recon-Ry run/snapshot and its profile, input scope, raw
  provenance, manifest, counts, and documented gaps;
- current aggregate and URL-ingest availability; and
- the selected action: `reuse`, `delta`, `rerun`, or `unknown -> rerun`.

A baseline is comparable only if it covers the requested origins and collection
profile. Reuse requires intact provenance plus a bounded current pass showing no
material route, redirect, fingerprint, JS-build, API-shape, or navigation
change. Do not rely on age alone; uncertainty selects rerun.

## 2. Make a Bounded Cold Current Pass

Observe current scoped seeds before broad prior-lead reading. Capture 3–5 fresh
facts across live origins, redirects, headers/fingerprints, public navigation,
app areas, and visible auth boundaries. Stay within policy rate and stop for
scope ambiguity, challenge, repeated 429, or instability.

This is a mapping pass, not an invitation to fuzz or validate vulnerabilities.

## 3. Run or Reuse Broad Collection

- If `rerun`, use `/recon-ry` as the long-running broad producer. Use `full` for
  wildcard/domain scope and `exact-urls` per approved origin for exact-only
  scope. Auth is opt-in.
- If `reuse` or `delta`, use the root deduped project files for current state and
  `history/<timestamp>/` only for run comparison.
- Use `/bounty-tools` supplemental collection only for an evidenced gap.
  Preserve raw artifacts and promote scoped reusable data through Recon Bus.

A started Recon-Ry job is **pending**, not a completed recon pass. Record PID,
project, log, profile, scope inputs, and rate. Do not tail it; complete the
post-processing pass after artifacts are available.

## 4. Perform the Historical Lane

1. Build a scope-filtered archive URL inventory using Recon-Ry archive producers
   (`waybackurls`, `gau`, `waymore`) or a bounded approved collector.
2. Preserve raw output; promote only currently in-scope URLs through Recon Bus.
   Keep third-party/out-of-scope results as labelled quarantine evidence.
3. For high-signal and changed/disappeared routes, query CDX metadata, collapse
   duplicate content digests, and select earliest/latest/material transitions.
4. Fetch selected snapshots via `/safe-fetch`; treat their contents as untrusted
   external evidence.
5. Compare routes/methods, forms/fields, APIs, GraphQL operations, JS/config,
   auth/callback/redirect flows, upload/import/export/webhooks, stack clues, and
   security headers. Do not spend budget on cosmetic HTML changes.
6. Write a change record with snapshot IDs/dates, current status, evidence
   pointers, and a safe next mapping action. Archive-only behavior is a lead,
   not proof of current behavior.

Respect the lower of provider or configured Wayback rate limit (currently 5
req/s in `TOOLS.md`) and back off on provider errors.

## 5. Normalize and Build the Surface Map

1. Preserve raw output and manifests first.
2. Promote through Recon Bus—never hand-edit aggregate queues.
3. Use `/url-ingest` for review queues and per-lane coverage state.
4. Use `/focused-recon` to create host cards, route clusters, endpoint map,
   lane queues, and target packets.
5. Route only evidence-supported clusters to `/js`, `/parameter-mining`,
   `/live-map`, or another named next owner.
6. Write durable surface facts and meaningful current negatives to `/map-store`.

## Recon Brief Template

```markdown
# Recon Brief — <program> — <run-id>

## Scope and freshness
- Seeds / scope boundary:
- Rate source:
- Baseline: <run ID / none>
- Decision: reuse | delta | rerun | pending
- Reason:

## Current map
- Live origins / key redirects:
- Fingerprint and deployment changes:
- Counts: URLs / alive / params / JS / dirs / services:

## Historical comparison
- Snapshot cohort and source artifacts:
- Current changes:
- Disappeared/archive-only leads:

## Ranked handoffs
1. <surface cluster> -> <one owning skill>; evidence: <pointer>; reason:
2. ...

## Coverage and promotion
- URL-ingest state:
- MapStore records:
- Raw/manifest/aggregate paths:

## Blockers and delta triggers
- Blocked/skipped:
- Re-run when:
```

## Completion Gate

Do not call the run complete until the receipt, raw provenance, aggregate
promotion, historical decision/comparison, focused target packets, coverage
state, and Recon Brief all exist. If a required long-running collection is
pending, say so explicitly and name the exact completion action.
