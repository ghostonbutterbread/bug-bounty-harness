# XSS Canary Reflection Mapper

## Metadata

```md
Status: review
Type: feature
Owner: Ghost / Codex
Canonical path: docs/xss-canary-reflection-mapper-spec.md
Index path: SPEC.md
Supersedes: none
Replaced by: none
Implementation commit: 03b038f3ab4e2c6e82724a1e1137177cf2ad1536
Last updated: 2026-06-17
Last reviewed: 2026-06-17
```

## Label and indexing

- Spec label: `xss-canary-reflection-mapper`
- Category index updated: not applicable
- Root index updated: not applicable

## Claim / concurrency

- Claimed by: Ghost / Codex
- Claimed at: 2026-06-17
- Files/areas expected to change:
  - `/home/ryushe/projects/bug_bounty_harness/skills/xss/scripts/`
  - `/home/ryushe/projects/bug_bounty_harness/skills/xss/SKILL.md`
  - `/home/ryushe/projects/bug_bounty_harness/skills/xss/references/`
  - Bug Bounty Harness XSS/JS/proxy helpers if implementation needs shared code
- Conflicts with:
  - none known
- Safe parallel work:
  - XSS payload/playbook text improvements that do not change the mapper script contract
  - JS analyzer improvements that only add new source candidates

## Goal

Build a script-first XSS canary reflection mapper that combines existing parameter discovery, proxy traffic, JavaScript-derived candidates, and authenticated headless-browser crawling into a compact source-to-sink map for XSS agents.

The script should do deterministic collection and classification. Agents should only receive high-signal records where XSS reasoning is useful: escape strategy, payload family selection, and proof planning.

## Scope

### Included

- Create a canonical XSS scripts home under `skills/xss/scripts/`.
- Ingest candidate sources from existing tools and artifacts:
  - Dalfox, kxss, Gxss, Dursgo, Katana, Arjun, or similar parameter/reflection output when available.
  - Proxy-store / Caido-derived request summaries and saved request packets.
  - JavaScript analyzer output for routes, params, API fields, storage keys, and DOM clues.
  - URL-ingest/recon/live-map outputs for sitemap expansion.
- Generate unique inert canaries per source, route, field, and run.
- Submit canaries through low-rate, policy-aware HTTP or Playwright/headless-browser flows.
- Crawl/search follow-up locations for each canary across:
  - raw HTTP responses
  - rendered DOM text and attributes
  - network/XHR/fetch responses
  - localStorage/sessionStorage when browser access is available
  - later pages after owned submit/save/update flows
- Classify each sink context when feasible:
  - HTML text
  - quoted attribute
  - unquoted attribute
  - URL-bearing attribute
  - inline JavaScript string
  - JSON/bootstrap/data blob
  - DOM sink/source hints such as `innerHTML`, router state, storage, or `postMessage`
- Emit structured artifacts for agents:
  - `sources.jsonl`
  - `sinks.jsonl`
  - `edges.jsonl`
  - `agent_packets/*.md`
  - optional screenshots/DOM snippets with sensitive values redacted
- Route promising edges into `/xss`, `/reflected-xss`, `/stored-xss`, or `/dom-xss` with compact context packets.

### Non-goals

- Do not replace Dalfox, Katana, Dursgo, kxss, Gxss, Arjun, or existing crawler/scanner tools.
- Do not spray generic XSS payloads across the application.
- Do not store live cookies, bearer tokens, API keys, CSRF tokens, private configs, or other secrets in mapper artifacts.
- Do not test destructive state-changing flows unless a policy/account record explicitly marks the owned resource safe.
- Do not require agents to crawl the whole app from scratch.

## Work items

| Item | Status | Dependencies | Notes |
|---|---|---|---|
| 1. Canonical scripts home | completed | none | Created `skills/xss/scripts/` docs and expected artifact contract. |
| 2. Input adapters | completed | item 1 | Parses generic JSON/JSONL, URL lists, nested tool-style records, parameter dictionaries/lists, and kxss/Gxss-style text. |
| 3. Canary model | completed | item 1 | Stable run id, source id, field id, and inert `GHOST_XSS_*` marker format. |
| 4. HTTP submission mode | completed | items 2-3 | Writes public `planned_requests.jsonl`, owner-only `private_replay_requests.jsonl`, and supports live-by-default `fetch` with saved program scope or explicit host allowlist, request cap, and rate delay. |
| 5. Browser submission/crawl mode | completed | items 2-3 | Supports Playwright `browser-fetch` for rendered DOM and storage capture when Playwright is installed, using the same scope/allowlist and private replay controls. |
| 6. Reflection search | completed | items 4-5 | Scans saved raw/HTML/JSONL response artifacts, HTTP fetch output, and browser DOM/storage output for canaries. |
| 7. Context classifier | completed | item 6 | Classifies HTML text, attributes, URL attributes, inline JavaScript, and JSON/bootstrap-like blobs. |
| 8. Agent packet writer | completed | items 6-7 | Produces small XSS-lane packets with full URL, source, sink, context, evidence, and stop reason. |
| 9. Tests and fixtures | completed | items 1-8 | Added focused pytest fixtures and local HTTP E2E smoke coverage. |

## Progress log

### 2026-06-17 — Ghost

- Summary: Created the Codex goal/spec from Ryushe's XSS mapper design discussion.
- Changed: Added this feature spec and a canonical XSS scripts directory README.
- Verification: Pending implementation.
- Remaining: Build the mapper script, fixtures, tests, and XSS skill routing update.
- Blockers: none.

### 2026-06-17 — Ghost / Codex first implementation slice

- Summary: Claimed the spec and implemented the offline-safe mapper core.
- Changed: Added `skills/xss/scripts/xss_canary_mapper.py`, tests, and mapper README usage.
- Verification: `python3 -m pytest skills/xss/scripts/test_xss_canary_mapper.py -q` passed (`3 passed`); `python3 -m py_compile skills/xss/scripts/xss_canary_mapper.py skills/xss/scripts/test_xss_canary_mapper.py` passed; CLI help smoke passed.
- Remaining: Add richer tool-specific adapters and a policy-aware live/browser submitter in later slices.
- Blockers: none.

### 2026-06-17 — Ghost / Codex full mapper slice

- Summary: Built out the remaining mapper spec into a review-ready BBH implementation.
- Changed: Added secret-safe URL artifact handling, nested tool-style record parsing, `fetch` live HTTP collection with explicit execution/host gates, optional Playwright `browser-fetch`, expanded tests, and README usage.
- Verification: `python3 -m pytest skills/xss/scripts/test_xss_canary_mapper.py -q` passed (`8 passed`); `python3 -m py_compile skills/xss/scripts/xss_canary_mapper.py skills/xss/scripts/test_xss_canary_mapper.py` passed; CLI help smoke passed; local `127.0.0.1` HTTP E2E smoke planned, fetched, scanned, and emitted a reflected-XSS agent packet.
- Remaining: Commit/sync when desired; add more schema-specific adapters as real tool outputs expose edge cases.
- Blockers: Playwright browser-fetch is implemented but not browser-executed in this runtime because the focused smoke used the dependency-free HTTP path.

### 2026-06-17 — Ghost manual review fixes

- Summary: Codex CLI read-only review was attempted but blocked by missing API authentication (`401 Unauthorized`), so Ghost performed a manual review pass.
- Findings fixed: live HTTP fetch could follow redirects outside the allowlisted host; blocked-host records did not count against `--max-requests`; live fetch/browser-fetch persisted full response/storage bodies instead of canary snippets.
- Changed: Added no-redirect HTTP opener, exact-host request cap accounting, browser route aborts for non-allowlisted requests, snippet-only live artifacts, and regression tests for live gate refusal, snippet-only storage, redirect handling, and blocked-host max cap.
- Verification: `python3 -m pytest skills/xss/scripts/test_xss_canary_mapper.py -q` passed (`8 passed`); `python3 -m py_compile ...` passed.
- Remaining: External reviewer pass when Codex CLI auth is available.
- Blockers: Codex CLI review auth is unavailable in this runtime.

### 2026-06-17 — Ghost live-default adjustment

- Summary: Updated mapper semantics after Ryushe clarified that a crawler/mapper should use live collection by default.
- Changed: `fetch` and `browser-fetch` no longer require `--execute-live`; live collection now requires either `--program` saved scope or explicit `--allow-host`. Added `--offline` as the no-network opt-out. Planning now emits owner-only `private_replay_requests.jsonl` for raw replay URLs while keeping public artifacts redacted. Secret-bearing replay is available with explicit `--allow-sensitive-replay`.
- Verification: `python3 -m pytest skills/xss/scripts/test_xss_canary_mapper.py -q` passed (`10 passed`); `python3 -m py_compile ...` passed; local live-default HTTP smoke planned, fetched, scanned, emitted one edge/packet, and verified `private_replay_requests.jsonl` mode `0600`.
- Remaining: Consider deeper project policy parsing for per-program default rate delays if normalized scope metadata grows a structured field for it.
- Blockers: none.

## Success criteria

- A future agent can find the mapper goal from BBH docs and the XSS skill scripts directory.
- The first implementation has a CLI with safe artifact behavior, fixture tests, and no live secrets in public outputs. Status: complete.
- Given tool/proxy/JS inputs, the mapper emits source-to-sink edges without loading large raw URL/tool outputs into agent context. Status: complete for generic JSON/JSONL/text inputs; tool-specific schema expansion can continue incrementally.
- Agent packets are small enough for XSS lane workers and include exact context classification plus evidence references. Status: complete.
- Live/browser mode respects existing live-testing, injection-testing, proxy-routing, account, and scope policies. Status: complete at script gate level through saved program scope or explicit host allowlist, request cap, rate delay, no raw secret headers, owner-only private replay artifacts, and explicit sensitive replay opt-in; operator policy still controls target authorization before use.

## Verification plan

- Unit-test adapters with synthetic Dalfox/kxss/Katana/proxy-store/JS analyzer samples.
- Run fixture E2E against local pages covering reflected, stored-like, DOM, encoded, and inert contexts.
- Verify artifacts redact sensitive fields and avoid cookie/token values.
- Run `git diff --check` after implementation.
- Run focused XSS mapper tests before any real target run.

## Archive trigger

Archive this spec when:

- all success criteria are complete
- verification is recorded
- review/self-review is complete
- `Implementation commit` is set to a verified commit hash or `none - reason`
