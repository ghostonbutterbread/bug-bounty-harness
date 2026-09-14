---
name: pullscope
description: Use when pulling bug bounty scope, checking in-scope assets, fetching HackerOne, Bugcrowd, or Intigriti program scope, or initializing normalized target lists before recon or testing.
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
└── raw/                         # Raw platform response snapshots
```

## How It Works
1. Fetches program page from platform
2. Parses domains, URLs, target groups, platform metadata, and rules-of-engagement when available
3. Saves to canonical scope directory
4. Scope readers prefer `~/Shared/scopes/{program}/` and fall back to legacy `~/Shared/bounty_recon/{program}/scope/`

For Bugcrowd, public `/engagements/<program>` scraping is the default. Intigriti uses public rendered program pages (normally `owner/program` or a full program URL), not an authenticated API. Use `--api` only when an authenticated API path is intentionally implemented and configured.

## Related
- scope_manager.py — validates targets against scope
- All harnesses check scope before testing
