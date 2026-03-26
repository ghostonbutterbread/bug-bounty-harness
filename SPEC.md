# Bug Bounty Harness — Integration Spec

## Context

We have a working orchestrator at `~/projects/bounty-tools/orchestrator/`:
- `state_manager.py` — manages campaign/target state (JSON-based)
- `findings_store.py` — stores confirmed and potential findings
- `hunt.py` — spawns and coordinates sub-agents per task
- `spawn_codex.py` — spawns Codex agents for heavy lifting
- `context_prep.py` — builds context for agents

We have test modules:
- `bac_checks.py` — 16 test cases (P0-P2) for BAC/IDOR/auth
- `credential_store.py` — per-program credential management
- `fuzz_command.py` — web fuzzing

**Goal:** Build a harness layer that ties these together using Anthropic's long-running agent patterns.

---

## Architecture

```
~/projects/bounty-tools/harness/
├── campaign.json           ← THE source of truth (state_manager compatible)
├── harness_core.py         ← Scope checker, rate limiter, request budget
├── baseline_capture.py     ← Capture authenticated baselines before testing
├── test_catalog.py         ← Loads/updates bac_checks into campaign state
├── verifier.py             ← Verifies findings (reduces false positives)
├── run_campaign.py         ← CLI: python run_campaign.py --target X --agent Y
└── agents/
    ├── initializer.py      ← One-shot: setup campaign, crawl, capture baselines
    ├── bac_tester.py      ← Runs BAC/IDOR tests from catalog
    └── analyzer.py        ← Deduplicates and verifies findings
```

---

## Design Principles

1. **Anthropic harness patterns**
   - Every session starts by reading campaign state
   - Every session ends by writing updated state + git commit
   - Feature/test catalog is a floor, not a ceiling (agent can discover more)
   - Self-verification gate: findings must be verified before marked "confirmed"

2. **Integration with existing modules**
   - State: reuse `state_manager.py` JSON format, extend with harness fields
   - Credentials: use `credential_store.py` for multi-account tokens
   - Tests: load from `bac_checks.py` into the test catalog
   - Fuzzing: use `fuzz_command.py` as a sub-capability
   - Logging: use `subagent_logger.py` for audit trail

3. **Multi-account support**
   - `credential_store.py` already handles per-program credentials
   - Need to support: User A session + User B session simultaneously
   - Baseline capture must capture per-account responses

4. **Request constraints (enforced, not requested)**
   - Scope: hard block on out-of-scope URLs
   - Rate: per-endpoint rate limiting (configurable)
   - Budget: max requests per session (configurable, prevents WAF bans)
   - Cooldown: automatic backoff if 429s detected

---

## campaign.json Schema (extends state_manager)

```json
{
  "campaign_id": "superdrug_20260326",
  "target": "https://www.superdrug.com",
  "created": "2026-03-26T10:00:00Z",
  "last_session": "2026-03-26T10:00:00Z",
  "scope": {
    "domains": ["superdrug.com", "api.superdrug.com"],
    "require_auth": true,
    "auth_type": "session_cookie",
    "account_a": "cred_store:superdrug:account_a",
    "account_b": "cred_store:superdrug:account_b"
  },
  "stats": {
    "total_requests": 0,
    "requests_this_session": 0,
    "max_requests_per_session": 500,
    "rate_limit_rpm": 30
  },
  "test_catalog": [
    {
      "id": "BAC-001",
      "module": "bac_checks",
      "test_name": "IDOR in object retrieval",
      "priority": "P1",
      "status": "pending",
      "attempts": 0,
      "last_attempt": null,
      "notes": ""
    }
  ],
  "findings": {
    "confirmed": [],
    "potential": [],
    "false_positive": []
  },
  "baselines": {},
  "initializer_complete": false
}
```

---

## File-by-File Implementation

### harness_core.py

Harness enforcement layer. All agent code imports this.

```python
class HarnessConstraints:
    - check_scope(url) -> bool  # hard block
    - check_rate(endpoint) -> bool  # automatic cooldown
    - check_budget() -> bool  # session request budget
    - record_request(endpoint, response)  # for rate/budget tracking
    - should_defer(reason) -> bool  # cooldown active?

class CampaignState:
    - load(campaign_id) -> dict
    - save(campaign_id, state)
    - update_test_status(campaign_id, test_id, status, notes)
    - add_finding(campaign_id, finding)
    - git_commit(campaign_id, message)  # clean exit protocol
```

### baseline_capture.py

Before any vulnerability test, capture legitimate responses.

```python
def capture_baseline(campaign_state, endpoint, account="a"):
    # 1. Make authenticated request as account
    # 2. Store request + response in baselines/{endpoint_hash}_{account}.json
    # 3. Return path for analyzer to compare against

class BaselineStore:
    - capture(endpoint, account, request, response)
    - get(endpoint, account) -> dict
    - diff(endpoint, account_a_resp, account_b_resp) -> dict
```

### test_catalog.py

Loads bac_checks.py tests into the campaign state.

```python
def build_test_catalog(target, auth_info) -> list[dict]:
    # Load all P0-P2 tests from bac_checks.py
    # Filter to endpoints that exist for this target
    # Return list of test dicts ready for campaign.json
```

### verifier.py

Reduces false positives. A finding needs evidence.

```python
def verify_finding(finding, baseline, mutated_response) -> VerificationResult:
    # 1. Check if mutated response != baseline (something changed)
    # 2. Check if changed content is semantically different (LLM comparison?)
    # 3. Check if it matches known vuln patterns
    # 4. Return: confirmed / potential / false_positive + confidence score
```

### agents/initializer.py

One-shot setup agent.

```
1. Load campaign.json (or create new)
2. Recon: crawl target, discover endpoints, filter to scope
3. Auth: extract session cookies for account_a and account_b
4. Baselines: for each interesting endpoint, capture baseline responses
5. Catalog: build test_catalog from bac_checks.py, filter to discovered endpoints
6. Mark initializer_complete = true
7. Git commit
```

### agents/bac_tester.py

Iterative BAC testing agent.

```
1. Load campaign.json
2. Select highest-priority pending test
3. Capture baseline for that endpoint (if not already done)
4. Run the BAC test (with constraints enforced)
5. Run verifier on result
6. Add finding to potential or confirmed
7. Mark test as complete
8. If more pending tests, continue; else exit
9. Git commit
```

### agents/analyzer.py

Post-processing agent (can run between sessions or after tester).

```
1. Load all potential findings
2. Deduplicate (same endpoint + same vuln type = merge)
3. For each: run verifier with fresh request
4. Move verified → confirmed, unverified → false_positive
5. Report summary
```

### run_campaign.py

CLI entry point.

```python
python run_campaign.py init --target superdrug --url https://...
python run_campaign.py run --campaign superdrug_20260326 --agent bac_tester
python run_campaign.py run --campaign superdrug_20260326 --agent analyzer
python run_campaign.py status --campaign superdrug_20260326
python run_campaign.py report --campaign superdrug_20260326
```

---

## Integration Points with Existing Code

| Existing Module | Integration |
|----------------|-------------|
| `state_manager.py` | Extend its JSON schema with harness fields; reuse load/save patterns |
| `findings_store.py` | Use same finding schema; extend with verification_status |
| `credential_store.py` | Reference credentials by `cred_store:program:key` in campaign.json |
| `bac_checks.py` | `build_test_catalog()` reads P0-P2 tests, returns dicts for campaign |
| `subagent_logger.py` | All agents use SubagentLogger for audit trail |
| `spawn_codex.py` | `bac_tester.py` and `initializer.py` spawn Codex for complex tasks |

---

## Constraints (Enforced in Code)

```python
# These are NOT prompts — they're raise HarnessViolation() if violated

MAX_REQUESTS_PER_SESSION = 500      # configurable
RATE_LIMIT_RPM = 30                 # per endpoint, configurable
SCOPE_DOMAINS = from campaign.json   # hard block, no exceptions
INITIALIZER_MUST_RUN_FIRST = True    # can't run tests without baselines
FINDING_MUST_VERIFY = True           # can't go confirmed without verifier
```

---

## Success Criteria

1. A campaign can be created with `python run_campaign.py init --target X --url Y`
2. Initializer captures baselines and builds test catalog automatically
3. BAC tester runs tests with hard scope/rate/budget enforcement
4. Findings require verification before being marked confirmed
5. Campaign state persists across sessions (can stop and resume)
6. All work is git-committed at end of session for recovery
7. Codex is spawned for: complex recon, advanced fuzzing, LLM-assisted response analysis

---

## Implementation Order

1. `harness_core.py` + `campaign.json` schema (foundation, no deps)
2. `test_catalog.py` (reads bac_checks.py, produces catalog dicts)
3. `baseline_capture.py` (HTTP capture, no AI needed)
4. `verifier.py` (basic diff, extensible)
5. `run_campaign.py` CLI scaffold
6. `agents/initializer.py` — one-shot setup
7. `agents/bac_tester.py` — iterative tester
8. `agents/analyzer.py` — deduplication/verification
9. Integration: hook into `orchestrator/telegram_commands.py` for `/hunt` command
