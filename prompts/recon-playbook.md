# Reconnaissance Playbook

## Overview

Use this as a decision tree: choose the seed target, discover reachable infrastructure, crawl the exposed web surface, analyze the collected content for follow-up signal, then report only the recon outputs that materially change the attack map.

## Decision Tree

1. Start from the scoped seed host or domain.
2. If the surface is unknown, prioritize discovery first.
3. If the host is reachable, crawl it for URLs, forms, params, and JS.
4. If content is collected, analyze it for technologies, secrets, API routes, and interesting files.
5. Report only artifacts that create a new testing lane for another module.

## 1. Discover

Goal: understand what is alive and what kind of stack you are looking at.

### Collect

- Open ports and service banners
- Response headers and technology hints
- WAF indicators
- Additional HTTP surfaces that should be crawled

### Stop And Re-scope If

- The target is clearly out of scope
- The host is dead and there are no alternate scoped hosts
- The scan would require aggressive network probing outside program rules

## 2. Crawl

Goal: turn the live host into a concrete web map.

### Collect

- Reachable URLs
- Forms and actions
- Parameter names
- JavaScript files
- Interesting redirects or auth boundaries

### Keep It Tight

- Stay on scoped hosts
- Prefer breadth-first collection before deep recursion
- Record the source URL for each newly discovered endpoint when possible

## 3. Analyze

Goal: extract high-value signals from the collected content.

### High-Value Signals

- API endpoints
- Secrets or tokens
- WAF or CDN fingerprints
- Admin or debug paths
- Uploads, webhooks, exports, and renderers
- Technology-specific modules that suggest XSS, SSRF, IDOR, or auth follow-up

### Deprioritize

- Generic marketing pages
- Duplicate URLs with only trivial tracking params
- Static assets that do not expand the attack surface

## 4. Organize

Write durable artifacts so later modules can consume them without repeating recon.

Primary output directory:

`$HARNESS_SHARED_BASE/{program}/agent_shared/findings/recon/`

Common artifacts:

- `urls.txt`
- `params.txt`
- `js_files.txt`
- `tech_stack.txt`
- `summary.json`

## 5. Report

Write the result to:

`$HARNESS_SHARED_BASE/{program}/agent_shared/findings/recon/findings.md`

Include:

- Seed target scanned
- Key surface changes discovered
- Technologies or WAFs observed
- High-value follow-up leads for other modules
