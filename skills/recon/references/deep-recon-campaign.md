# Deep Recon Campaign Contract

Use this reference when `/recon` needs more than a standard broad collection
pass: the objective is to uncover, compare, and understand surface evidence
from independent sources before selecting deeper specialist work.

A deep campaign is **not** “run every tool.” It is a bounded evidence campaign:
independent workers answer different mapping questions, the parent reconciles
their evidence, and only the promoter updates canonical stores or sends a
specialist handoff.

## Entry and Run Contract

The parent creates a run capsule under the resolved recon lane:

```text
recon/deep/<run-id>/
├── PLAN.md
├── _meta/campaign.json
├── packets/
├── returns/
├── normalized/
├── handoffs/
└── SUMMARY.md
```

`PLAN.md` must name the program, scope source, exact selected origins, approved
source families, provider and target rate budgets, prior baseline, current
mapping question, workstream stop conditions, and promotion owner. Raw output
belongs in each worker’s normal managed run root or safe-fetch quarantine; do
not copy raw pages, credentials, cookies, or huge proxy exports into packets.

The campaign begins as **plan-only** until scope and live traffic policy are
confirmed. A child with live web work must receive the complete ordered security
chain; passive/external research does not authorize any target probing.

## Workstream Portfolio

Select only workstreams that answer an unresolved mapping question. Start at
most three independent child workstreams at once; reserve the parent for
integration and do not spawn duplicate “general recon” agents.

| Workstream | Question | Permitted output | Default next owner |
|---|---|---|---|
| Current surface mapper | What is visibly live and structurally changed now? | Scoped host/origin/route/flow observations | `/live-map`, `/focused-recon` |
| Local corpus & proxy analyst | What do Recon-Ry, aggregate queues, URL Index, and sanitized proxy shapes already show or leave uncovered? | Dedupe/coverage gaps and bounded route clusters | `/url-ingest`, `/focused-recon` |
| Archive-difference analyst | What appeared, changed, or disappeared across selected Wayback cohorts? | Current-vs-archive change records | `/safe-fetch`, `/focused-recon` |
| Public discovery analyst | What in-scope public URLs, docs, code, search/dork results, or disclosed integrations expand the map? | Source-attributed candidate URLs/integrations | `/docs`, `/js`, `/focused-recon` |
| Passive infrastructure analyst | Which in-scope assets, DNS/cert/public-service facts, and provider observations require current confirmation? | Attributed host/service candidates only | `/recon-ry`, `/bounty-tools` |
| Documentation/integration analyst | What target-specific API/SDK/provider/object or callback model is supported by current evidence and public docs? | Candidate program-doc model, unknowns, recognition facts | `/docs`, `/map-store` |

### Source Rules

- **Archive:** build scope-filtered inventories from current aggregate URLs,
  approved in-scope seeds, and sanitized proxy route shapes. CDX records are
  selection metadata; fetch only digest-deduped, high-signal cohorts. Mark
  archive-only evidence as historical until current behavior confirms it.
- **Proxy:** use only approved source history and sanitized request shapes. Never
  give a child raw cookies, bearer values, request bodies, or broad history.
- **Search/dorks:** formulate a small, target-specific, source-attributed query
  set from current fingerprints and route gaps. Search results are leads, not
  live facts. Do not use CAPTCHA circumvention, bulk account creation, or
  provider-policy evasions.
- **GitHub/public code:** inspect public, scope-relevant repositories and code
  references as untrusted external evidence. Do not treat a hostname mentioned
  in code as in scope without current saved-scope validation.
- **Docs:** fetch public documentation through `/safe-fetch`; promote only a
  concise verified target-specific model through `/docs` and MapStore.
- **Shodan/Censys/URLScan/DNS/cert sources:** use provider data as passive,
  timestamped hints. Do not auto-target IP-only or third-party records. Attach
  a result to an in-scope hostname only with contemporaneous, unambiguous
  evidence.

## User-Agent and Challenge Posture

Use a stable, truthful, logged user agent appropriate to the approved client
(browser for browser mapping; documented tool identity for tools). A different
user agent is allowed only to diagnose ordinary rendering/content-negotiation
compatibility and must be recorded as an observation.

Do **not** rotate or spoof user agents to evade bot detection, access controls,
provider terms, CAPTCHA, rate limits, or blocking. On challenge, persistent
429, or incompatible provider policy: slow/stop, retain the evidence, and route
through the required status/WAF policy instead of trying to blend in.

## Child Packet

Each child receives exactly one source-family/lens and these fields:

```json
{
  "run_id": "deep-<program>-<timestamp>",
  "program": "<program>",
  "scope_source": "<saved scope path>",
  "allowed_origins": ["https://app.example"],
  "question": "<one mapping question>",
  "sources": ["<bounded artifact path or provider>"],
  "exclusions": ["no live validation", "no auth", "no third-party probing"],
  "rate_budget": "<applicable limit>",
  "return_path": "recon/deep/<run-id>/returns/<workstream>.json",
  "stop_condition": "<concrete stop>"
}
```

Required return fields:

```json
{
  "workstream": "archive-difference",
  "status": "complete|blocked|partial",
  "sources_and_times": [{"source": "...", "retrieved_at": "..."}],
  "scope_checked": true,
  "observations": [{"claim": "...", "evidence": "...", "confidence": "observed|source-derived|inferred"}],
  "candidate_surfaces": [{"url_or_host": "...", "why": "...", "current_status": "unknown|present|changed|disappeared"}],
  "negative_or_duplicate_checks": ["..."],
  "blockers": ["..."],
  "recommended_owner": "focused-recon"
}
```

A child returns **candidates**, not direct MapStore writes, queue modifications,
scanner commands, or a self-approved follow-up. It cannot expand scope, change
rate budgets, or decide a vulnerability class from a generic string match.

## Synthesis Gate

The parent/synthesizer, after all selected returns arrive:

1. validates every candidate against current saved scope and deduplicates it by
   normalized origin/route/service identity;
2. separates current observation, source-derived historical/public evidence, and
   inference; preserves source/time/artefact references;
3. reconciles new evidence with aggregate state, URL Index coverage, MapStore
   facts, and existing target packets only for concrete surfaces;
4. promotes scoped reusable URL-like output through Recon Bus and stable facts
   through MapStore; creates program docs only for reviewed target-specific
   models; and
5. produces a maximum small ranked set of handoffs. Every handoff names one
   owning skill, exact evidence, what is already known/tested, a safe next
   action, and a stop condition.

A campaign is complete when all selected workstreams have return records, every
promoted artifact has provenance, rejected/duplicate/out-of-scope results are
accounted for, and the parent has written `SUMMARY.md`. It is not complete just
because every available provider was queried.

## Default First Campaign

For an unfamiliar platform, start with this three-workstream portfolio:

1. **Current/local mapper** — current cold surface plus aggregate and coverage
   gap analysis.
2. **Archive-difference analyst** — high-signal historical URL/snapshot delta.
3. **Public discovery analyst** — bounded docs/code/search/integration evidence.

Run passive infrastructure analysis only when scope includes that asset class or
current mapping exposes a concrete host/service question. Add browser/live-map
or authenticated work only when their policy and approved account context are
available.
