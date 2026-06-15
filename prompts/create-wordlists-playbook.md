# Create Wordlists Playbook

## Purpose

Create target-aware wordlist packs from evidence. Keep source attribution so
future agents know why a candidate exists.

## Canonical Inputs

Try these sources in order when available:

- Program recon root: `~/Shared/web_bounty/<program>/web/recon/`
- Aggregate recon files: `aggregated/urls.txt`, `params.txt`, `jsfiles.txt`,
  `dirs.txt`, `wild.txt`, `alive.txt`
- Technology fingerprint:
  `~/Shared/web_bounty/<program>/web/recon/fingerprint/technology.json`
- Local/agent proxy centralized datasets
- Ryushe proxy request history, best effort only
- JavaScript files and fetched/cached bundles
- Documentation, OpenAPI, Swagger, GraphQL, robots, sitemap, help-center paths
- Local common wordlists under `/usr/share/wordlists`

Ryushe proxy rule:

- Always try it as a source when creating target packs.
- If unavailable, write a short note such as
  `Ryushe proxy unavailable: <reason>. Continuing with other sources.`
- Do not stop generation solely because Ryushe proxy is unavailable.
- Do not persist raw secrets from proxy material.

## Pack Types

Write separate packs by source and purpose:

- `javascript-routes.txt`
- `javascript-params.txt`
- `url-params.txt`
- `proxy-routes.txt`
- `proxy-params.txt`
- `tech-docs-routes.txt`
- `subdomain-patterns.txt`
- `target-nouns.txt`

Suggested output root:

```text
~/Shared/web_bounty/<program>/web/recon/wordlists/generated/<run-id>/
```

This Shared path is the staging area for target-specific evidence-derived
packs. It keeps private target patterns, proxy-derived candidates, and
unreviewed generated lists out of the reusable GitHub wordlist project.

Reusable/global packs should be promoted into the GitHub-style wordlist repo:

```text
~/projects/ghost-wordlists/wordlists/
```

Promotion rule:

- promote only candidates that are generic or reusable across targets
- do not promote private target structure, raw proxy-derived paths, secrets, or
  anything that exposes a specific program's internal naming
- keep promoted packs in the right subtree, such as `common/`, `purpose/`, or
  `tech/`
- update the repo manifest when adding a stable pack

Each run should include:

```text
manifest.json
packs/*.txt
notes.md
```

## Extraction Ideas

JavaScript:

- URLs and paths: `/api/...`, `/graphql`, `/v1/...`
- query keys and form field names
- object keys likely sent to APIs
- feature flags and action names
- API resource nouns and route prefixes
- GraphQL operation names and field names

URLs:

- query parameter keys
- recurring route nouns
- versioned API prefixes
- file extensions
- locale or tenant path patterns

Technology fingerprint:

- select framework/CMS/platform docs-derived packs
- select common sensitive endpoints for detected stack
- record confidence and evidence used

Subdomains:

- combine observed naming conventions with common subdomain lists
- keep observed-derived candidates separate from generic public lists

## Chunking And Agent Context

Do not dump huge raw files into an agent prompt. Use deterministic extraction,
line-count summaries, top-N samples, and source manifests. If a source is too
large, process it by file or by bounded line windows, then write the extracted
pack to disk.

## Exit Checklist

- Generated packs are source-separated.
- `manifest.json` lists inputs, source paths, counts, and timestamp.
- Ryushe proxy status is recorded.
- No raw secrets are written.
- Reusable packs are promoted to `~/projects/ghost-wordlists/wordlists/` when
  safe; target-specific packs remain in Shared staging.
- `/use-wordlists` can consume the pack paths directly.
