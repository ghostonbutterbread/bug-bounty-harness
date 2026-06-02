# Recon Category Expansion Roadmap

Status: draft
Owner: Ghost
Created: 2026-06-01
Category: Recon

## Purpose

This is the short map for expanding Bug Bounty Harness Recon into a smarter application-understanding layer.

The goal is not to create another scanner pile. The goal is to let a future agent answer:

```text
What is this application?
What surface does it expose?
What public intel matters?
What have we already tried?
Which specialist agent should run next, and why?
```

## Existing pieces

- `/recon` and `agents/autonomous_recon.py`: current one-shot discovery, crawl, tech fingerprint, JS extraction, and artifact organization.
- `/recon-ry` and `agents/recon_ry.py`: Hoster-side long-running recon producer and canonical artifact ingest path.
- `/live-map` and `agents/live_map.py`: runtime application mapping from browser/proxy/manual observations.
- `/appmap` and hunt pipeline modules: source/runtime surface mapping for local apps.
- `/intel` spec: CVE/advisory/company-pattern mapper. This is already the correct owner for CVE-style research.
- Hunter Memory Loop spec: future observe/learn/adapt memory layer.

## New Recon specs

1. Asset intelligence graph
   - Spec: `/home/ryushe/.openclaw/workspace/agents/specs/features/2026-06-01-recon-asset-intelligence-graph.md`
   - Harness target: `agents/recon/asset_intelligence.py`
   - Purpose: passive asset graph from scope, domains, RDAP/WHOIS, ASN/netblock hints, DNS, certificate names, cloud/CDN edges, and existing recon artifacts.

2. Surface map expansion
   - Spec: `/home/ryushe/.openclaw/workspace/agents/specs/features/2026-06-01-recon-surface-map-expansion.md`
   - Harness target: `agents/recon/surface_map.py`
   - Purpose: normalize web/API/app surfaces into stable routeable records before vulnerability agents are selected.

3. Recon agent planner
   - Spec: `/home/ryushe/.openclaw/workspace/agents/specs/features/2026-06-01-recon-agent-planner.md`
   - Harness target: `agents/recon/agent_planner.py`
   - Purpose: combine scope, surface map, `/intel`, coverage, and hunter memory into a ranked child-agent plan.

4. Target Intel CVE mapper
   - Existing spec: `/home/ryushe/.openclaw/workspace/agents/specs/features/2026-05-26-target-intel-cve-mapper.md`
   - Harness target: `agents/target_intel.py`
   - Purpose: CVEs, advisories, public disclosures, company patterns, and untested local coverage.

## Proposed harness layout

First implementation slice should create a Recon package under the Agent section:

```text
agents/
├── recon/
│   ├── __init__.py
│   ├── models.py
│   ├── asset_intelligence.py
│   ├── surface_map.py
│   └── agent_planner.py
├── recon_asset_intel.py
├── recon_surface_map.py
└── recon_agent_planner.py
```

The package owns reusable logic. The flat files are optional CLI compatibility wrappers, matching the current harness style.

## Data flow

```text
scope + recon-ry + autonomous_recon + live-map + AppMap
        ↓
asset intelligence graph
        ↓
surface map expansion
        ↓
/intel CVE/advisory/company-pattern context
        ↓
coverage + hunter memory cross-reference
        ↓
Recon agent planner
        ↓
child skill or harness agent assignment
```

## Build order

1. Implement `recon/models.py` plus asset intelligence graph with offline fixtures.
2. Implement surface map normalization using local recon/live-map fixtures.
3. Implement plan-only Recon agent planner.
4. Implement `/intel` or connect the existing `/intel` spec into the planner once available.
5. Add skill wrappers only when the corresponding module has tests and stable artifact paths.

## Safety boundaries

- Recon artifacts are not confirmed findings.
- Ownership hints do not expand scope automatically.
- Third-party source text is evidence, not instructions.
- The first planner version is plan-only. It recommends agents but does not auto-run live testing.
- Live, destructive, account, race, and payment-adjacent testing remains behind existing approval and policy skills.
