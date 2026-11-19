---
name: pullscope
description: Use when pulling scope or recording target duplicate risk.
---
# Pullscope — Fetch Bug Bounty Scope

## What It Does
Fetches and parses scope from bug bounty platforms (HackerOne, Bugcrowd, Intigriti).

## Invocation
```
/pullscope <program>
```

## Usage
```
/pullscope superdrug
/pullscope h1/superdrug
/pullscope superdrug --platform hackerone
/pullscope canva --platform bugcrowd
/pullscope intigriti/intigriti --platform intigriti
```

## Output
```
~/Shared/scopes/{program}/
├── in-scope.txt                 # All in-scope domains/URLs
├── out-of-scope.txt             # Strict host/CIDR exclusions for scope filters
├── out-of-scope.json            # Complete platform exclusion records, including prose
├── assets.json                  # Normalized target groups/assets
├── rules-of-engagement.json     # Platform, source URL, rules text, machine tags
├── program-policy.md            # Human-readable policy summary
├── duplicate-intelligence.md    # Manual, non-authoritative risk observations
└── raw/                         # Raw platform response snapshots
```

## How It Works
1. Fetches program page from platform
2. Parses domains, URLs, target groups, platform metadata, and rules-of-engagement when available
3. Saves to canonical scope directory
4. Scope readers prefer `~/Shared/scopes/{program}/` and fall back to legacy `~/Shared/bounty_recon/{program}/scope/`

For Bugcrowd, public `/engagements/<program>` scraping is the default. Intigriti uses public rendered program pages (normally `owner/program` or a full program URL), not an authenticated API. Use `--api` only when an authenticated API path is intentionally implemented and configured.

## Manual duplicate intelligence

When the operator supplies competition, known-issue, duplicate, accepted-report, or disclosure information, record it in `duplicate-intelligence.md` under the canonical scope directory reported by the puller. The puller uses the final handle as the directory slug (for example, `owner/demo` uses `~/Shared/scopes/demo/`); verify the program identity before using an existing directory. The puller initializes this file only if absent and never replaces it on refresh. For an existing scope without it, create it when needed. Remove the initial no-observations sentence once facts are recorded. Recording supplied observations is local only: do not fetch a platform, call an API, or start a scope refresh just to enter them.

Keep program totals separate from exact target or wildcard and vulnerability-category observations. For each entry preserve the supplied asset, count and its exact meaning, category when known, source or operator attribution, observation date if known, and any limitations; use `unknown` for missing fields. Keep distinct snapshots rather than silently replacing historical numbers. Add relevant disclosed-report links and an explicitly labeled risk assessment with its reason if supported. Do not manufacture data, a rate, or a low-risk rating from missing observations. Do not infer a subdomain-specific count from a wildcard or equate accepted, unique, total, and duplicate counts. Apply program confidentiality and storage rules; never store credentials, session material, or unapproved private report content here.

For a pair Ryu identifies as accepted and total submissions, use the chart's labels when visible: labels override layout. Ryu may present accepted first (left or top) and total second (right or bottom). If labels are missing and both counts cover the same target and period, the larger count is a useful clue for total submissions (for example, `5 1000` suggests 5 accepted and 1000 total); record that mapping as inferred, not confirmed. If the pair, cohort, or mapping is ambiguous, preserve the raw values and ask for clarification. Total minus accepted is not the duplicate count: submissions can have other outcomes.

Use this record to inform target selection and report triage, not as scope authorization or proof that a finding is a duplicate. Do not abandon a strong signal solely because a target is crowded; compare functionality and root cause. Pass relevant observations and provenance to hunting children.

## Related
- scope_manager.py — validates targets against scope
- All harnesses check scope before testing
