# Smart Fuzzing Configuration and Design

## Current implementation status

Today, the scheduler resolves and records a policy only:

```yaml
smart_fuzzing:
  enabled: true|false
  ai:
    enabled: true|false
    mode: evidence_pack_only
```

The automated Katana/docs/proxy/JS pack builder and the profiles below are a **draft**. They are not accepted runtime configuration or a claim that an LLM is called today.

## Desired configuration

Use independent deterministic and AI switches, then select how their results are combined:

```yaml
smart_fuzzing:
  enabled: true

  deterministic:
    enabled: true

  ai:
    enabled: true
    profiles:
      evidence_pack: true
      ranked_campaigns: true
      differential_403_review: true
      secret_review: false

  mode: hybrid # deterministic | ai | hybrid | all

  lanes:
    web:
      # A missing field inherits the program/global field.
      mode: all
      ai:
        profiles:
          secret_review: true
```

Precedence is:

```text
global → program → lane
```

A missing lane override inherits the enclosing setting.

## Mode matrix

| Mode | Runs | Intended use |
|---|---|---|
| `deterministic` | source parsers, tech mappings, known service packs, response clustering | Reproducible baseline and known-good coverage |
| `ai` | evidence synthesis and candidate/ranking proposals | Research-only comparison; never the default sole executor |
| `hybrid` | deterministic output first, then AI ranks/adds bounded candidates | Default operational mode |
| `all` | deterministic plus every enabled AI profile as separate, bounded analysis lanes | Maximum coverage; outputs merge only after validation/deduplication |

`all` does **not** mean every scanner or every payload runs at once. It means independent analysis/profile workers can produce candidate packs concurrently. The scheduler still owns host/backend admission, rate limits, commands, scope, and manual-review gates.

## Responsibilities

### Deterministic layer

Strong at repeatable extraction and classification:

- Katana route and directory normalization
- JavaScript route/string/parameter extraction
- sanitized proxy request-shape extraction
- HTTP headers, stack/product/service fingerprints
- Nmap service hints
- robots, sitemap, OpenAPI and GraphQL discovery where observed
- curated technology packs, e.g. nginx, S3/CloudFront, API, GraphQL
- response signatures, wildcard calibration, and fuzz-history accounting

It must emit source-attributed facts, not guesses.

### AI layer

Strong at deciding relevance from the accumulated evidence:

- synthesize route nouns from Katana/JS/proxy/docs facts
- identify likely technology-specific file/route families
- read official documentation and extract cited endpoint/configuration vocabulary
- rank deterministic packs by expected signal and duplicate/noise risk
- turn differential 401/403/405 evidence into a narrow review packet
- identify likely secret-bearing *downloaded artifacts* for offline review

AI output is a candidate proposal, not execution authority.

## Evidence-pack contract

Every candidate must retain:

```json
{
  "candidate": "openapi.json",
  "kind": "path",
  "sources": ["official_docs", "katana"],
  "evidence_refs": ["..."],
  "confidence": "high",
  "target_host": "scoped host only",
  "proposed_by": "deterministic|ai:<profile>",
  "reason": "..."
}
```

The harness rejects a candidate if it is outside saved scope, lacks a target-local source, violates an approved wordlist policy, or would change an operator-controlled rate/command/auth setting.

## AI profiles

### `evidence_pack`

Input: sanitized Katana, JS, proxy, headers, service, URL-index, and documentation facts.

Output: source-attributed route/parameter/file vocabulary for target-local temporary wordlists.

### `ranked_campaigns`

Input: deterministic packs plus fuzz history, response clusters, and prior exhaustion/noise records.

Output: ordered campaign tiers. It cannot add an unapproved target, alter traffic policy, or schedule a scan.

### `differential_403_review`

Input: only route-specific, baseline-differential 401/403/405 evidence.

Output: a review packet for the existing bounded bypass harness. Uniform CDN/WAF denial surfaces are excluded. The profile cannot launch broad bypass traffic itself.

### `secret_review`

Input: only artifacts already lawfully downloaded or observed within scope: JS bundles, public source maps, config/manifest files, downloads, and checked-in exposed files.

Output: local secret-pattern candidates with file offsets, type/classification, and redacted fingerprints for review.

It must never guess credentials, brute-force login values, validate third-party keys, transmit secrets externally, or persist raw secrets into reports. A separate future local script should own detection and redacted reporting; the AI may triage its findings.

## `all`-mode worker model

When `mode: all`, spawn bounded independent analysis workers:

```text
worker 1: deterministic evidence collector
worker 2: AI evidence-pack synthesis
worker 3: AI campaign ranking
worker 4: AI differential-403 review
worker 5: local secret-review triage, only when explicitly enabled
             ↓
provenance validator + deduper + scope gate
             ↓
reviewable target-local packs and queues
             ↓
existing FFUF / Arjun / bypass execution gates
```

Workers do not receive credentials, raw auth headers, scanner execution authority, or permission to mutate scope/rates/commands. They receive sanitized evidence references and return structured JSON proposals.

## Implementation order

1. Implement deterministic evidence-pack generation and a JSONL schema.
2. Add source provenance, target-local validation, deduplication, and pack tests.
3. Add `hybrid` evidence-pack AI proposal worker in dry-run mode.
4. Implement AI profile selection and `all` fan-out with fixed resource limits.
5. Add ranked campaign output, still review-only initially.
6. Add differential-403 packet generation wired to the existing bypass review gate.
7. Add local secret-review script for already-downloaded artifacts, redacted-only output.
8. Permit promotion from profile output to temporary FFUF packs only after test coverage and operator review.

## Non-negotiable execution controls

AI and deterministic analysis never override:

```text
saved scope
host/backend admission and rate budget
manual review requirements
authentication availability or host applicability
scanner command templates
raw credential handling
result-promotion and finding-evidence requirements
```
