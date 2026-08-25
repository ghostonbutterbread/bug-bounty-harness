---
name: leads
description: Use to query and reconcile evidence-backed cross-run vulnerability leads for one program.
---

# Cross-Run Leads

Use when asked what unresolved leads exist across a program, where to push
harder, what recurring weakness patterns are evidenced, or what blockers need
operator help:

```text
/leads <program> [--class <vuln-class>]
/leads <program> --push
/leads <program> --blocked
/leads <program> --needs-you
/leads <program> --weaknesses
```

This is a cross-run evidence-synthesis skill, not a live-testing lane and not XSS-specific. `/manual` remains the current-run manual inspection queue.

## Ownership and visibility

MapStore is the public lead projection. A reusable observed fact that leaves an
unresolved, bounded security question must be written to MapStore with `lead`,
the vulnerability-class tag, lifecycle status, pressure/blocker metadata, and
sanitized evidence pointers. Attempts retain exact probes. The Hypothesis Ledger
retains the owning agent's unfinished branches and wake conditions.

Do not expose another live agent's private hypotheses. A caller may incorporate
only its own private hypotheses plus explicit delegated or reclaimable branches.
A lead card may link a hypothesis ID without copying private rationale into the
public projection.

## Lead CLI

Use the BBH wrapper rather than hand-writing MapStore bodies:

```bash
python3 agents/leads.py create --program <program> --class <vuln-class> --surface <surface> \\
  --title "<concise lead>" --observed-basis "<fact>" --candidate-chain "<chain>" \\
  --exact-unknown "<one question>" --next-discriminator "<safe check>" \\
  --evidence-ref "<sanitized pointer>"
python3 agents/leads.py search --program <program> --class <vuln-class>
python3 agents/leads.py update-status --program <program> --path <MapStore-relative-path> \\
  --status needs_recheck --reason "<evidence-backed blocker>"
```

`create` adds the public `lead` and class tags, `search` reads only public
lead projections, and `update-status` appends a lifecycle annotation without
deleting evidence. Do not use this CLI to copy another live agent's private
hypotheses into MapStore.

## Retrieval

Use MapStore's existing lead intent and tag/status filters. For example:

```bash
PYTHONPATH=".:$HOME/projects/bounty-core" \
python3 agents/map_store.py query --program <program> --family web_bounty --lane web \
  --surface <vuln-class> --intent old-leads --tags lead,<vuln-class> \
  --status active,candidate,needs_recheck
```

`--class` is optional: a lead is class-neutral and may concern XSS, IDOR, SSRF,
authz, CSRF, race, upload, AI, or another scoped class. Use only concrete
surface, class, URL, role, feature, or blocker filters; do not preload a broad
historical queue at the start of a new live hunt.

## Lead card

Synthesize evidence into this shape:

```text
Rank and state: <Push now | Strengthen | Needs you | Waiting | Archived>
Class and surface: <class> — <route/API/feature>
Observed basis: <demonstrated reusable behavior>
Candidate chain: <control/condition -> trust boundary -> consequence>
Exact unknown: <one question preventing proof>
Blocker: <none | account | role | fixture | browser | artifact | challenge | scope | rate>
Next discriminator: <next permitted discriminator>
Wake condition: <specific event or resource that reopens work>
Evidence: <MapStore, Attempts, report, and permitted hypothesis pointers>
Why ranked: <information gain and impact distance>
```

Do not call a lead a finding without proof of execution and meaningful impact.
Do not label a whole class closed because one representation, endpoint, or
consumer failed.

## Ranking

`--push` prioritizes proven control, proximity to a meaningful trust boundary,
a known transform/consumer, one bounded unknown, and a permitted next action.
`--blocked` shows lead cards with an explicit blocker. `--needs-you` shows only
blockers requiring an operator action or decision, ordered by the appropriate
operator unblock: account/role, owned fixture, normal browser recovery, missing artifact,
specific scope decision, or cooldown. Do not list agent-resolvable work there.

`--weaknesses` groups observed lead cards by recurring trust-boundary pattern
(such as second consumer/context shift, authorization seam, server fetcher,
parser boundary, or role gate). Label the result as observed pattern, not a
vulnerability claim.

## Lifecycle reconciliation

A lead is a current projection, not a write-only note. Update the same public
lead when material evidence changes; retain attempts and prior evidence pointers
rather than overwriting history. Every lead touched during a run receives a disposition:

- **strengthened** — new observed basis or narrower discriminator;
- **active/candidate** — still has a safe next action;
- **needs_recheck** — an explicit account, role, fixture, browser, artifact, or
  environment prerequisite remains;
- **control recorded** — a demonstrated control's enforcement is established for the relevant path;
- **stale** — the app, route, account state, or consumer changed;
- **promoted** — proof became a linked finding;
- **archived** — meaningful reachable variants are covered, with a concrete
  evidence-backed reason and wake condition.

A rate limit pauses only its affected lead until the recorded cooldown/stability
wake condition. A persistent CAPTCHA or bot challenge may be classified with a
normal owned-browser baseline, but is not permission for an evasion campaign;
record the appropriate operator handoff if it remains blocking. Continue
independent leads while blocked cards wait.

## Completion check

Before returning, verify every card is evidence-backed, class-neutral, current
as of its last observation, tied to one next discriminator or blocker, and does
not disclose secrets, raw private requests, cookies, tokens, or another live
agent's private hypotheses.
