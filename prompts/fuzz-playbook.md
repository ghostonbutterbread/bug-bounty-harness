# Web Fuzzing Playbook

## Overview

Use this as a decision tree: seed the target space from recon, choose the narrowest fuzz lane, classify hits by response signal, pivot only where the response suggests a real surface, then report the endpoints that deserve follow-up.

## Decision Tree

1. Start from known hosts, paths, and technologies.
2. If you still need breadth, run path discovery first.
3. If a path is confirmed interesting, move to parameter or extension fuzzing for that surface.
4. If auth boundaries or redirects appear, classify them as follow-up leads rather than final findings.
5. Report only endpoints, files, or parameters with meaningful signal.

## 1. Seed The Space

Do not fuzz blind when recon has already narrowed the attack surface.

### Good Seeds

- Paths from recon output
- JavaScript bundle references
- Technology-specific conventions
- Admin, API, debug, and export names already seen in the app
- Historical URLs or archived endpoints

## 2. Choose Lane

| Lane | Use When | Goal |
|------|----------|------|
| Path discovery | Host coverage is incomplete | Find hidden directories, APIs, and panels |
| Extension discovery | Backups or source leaks are plausible | Find `.bak`, `.old`, `.zip`, `.env`, and similar assets |
| Parameter discovery | A specific endpoint already exists | Find hidden toggles, filters, and debug flags |
| Vhost discovery | Shared hosting or internal hostnames are suspected | Find alternate applications on the same IP or domain |

## 3. Classify Hits

Not every `200` matters, and not every `403` is noise.

### Signals To Keep

- `200` with admin, API, debug, config, backup, or documentation content
- `301`, `302`, `307` that redirect into a real feature path
- `401` or `403` on sensitive paths that imply a real endpoint exists
- `405` that proves a valid route is present
- Response-size outliers that break the normal error template

### Signals To Deprioritize

- Generic wildcard responses
- Empty `204` without a meaningful route name
- CDN or router catch-all pages that normalize every request

## 4. Pivot

Escalate only where the hit meaningfully changes your map.

### Common Pivots

- Hidden admin path -> authz, IDOR, or WAF follow-up
- Debug or docs endpoint -> secrets, SSRF, or recon follow-up
- Backup or config file -> high-priority exposure review
- New API route -> parameter fuzzing and auth analysis
- Protected endpoint -> note as an auth boundary instead of forcing a bypass immediately

## 5. Report

Write the result to:

`$HARNESS_SHARED_BASE/{program}/agent_shared/findings/fuzz/findings.md`

Include:

- URL or endpoint discovered
- Fuzz lane that found it
- Status code and response-size signal
- Why it is interesting
- Recommended next test, if any
