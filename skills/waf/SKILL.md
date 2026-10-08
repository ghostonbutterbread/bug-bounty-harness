---
name: waf
description: Use when detecting, fingerprinting, or bypassing WAF blocks, rate limits, payload filtering, blocked probes, CDN security rules, or application firewall behavior during testing.
---
# WAF Skill

A WAF block is a question about the control and the protected consumer, not a
reason to rotate generic payloads. This skill owns the adaptive loop and optional
interceptor mechanics. It does not prove the underlying vulnerability class.

For live filtering load `waf-live-policy` and the inherited scope, rate,
challenge, and stop rules. Load `blocker-first-analysis` to locate the blocker,
`hypothesis-expansion-policy` to deepen or defer it, and `bypass` for generic
parser questions. For a plausible XSS path whose next obstacle is filtering,
load `xss-waf-evasion` after the XSS lane and `xss-payload-engineering`.

## Adaptive blocker loop

1. **Baseline:** Preserve one clean, in-scope request and the smallest
   one-variable change that reproducibly blocks. Record request representation,
   client/session, route, response signatures, and a green control for transient
   challenge windows. A bare 403, vendor banner, or changed status is not yet a
   classified WAF rule. Stop or slow as `waf-live-policy` requires.
2. **Locate the control:** Compare edge/CDN, bot/rate, origin application
   validation, sanitizer, and later browser processing. Ask which bytes the
   control inspected, which transformations it applied, and whether the
   relevant attacker-controlled source ever crossed it. Use a matched rule ID
   or logs when available; a vendor fingerprint is a lead, not a rule guarantee.
   An unknown control remains a behavior-first comparison, not a reason to
   guess a vendor trick.
3. **Retrieve narrowly:** Once the route/control is concrete, query MapStore
   `app-facts`/`dedupe` for this app's observed behavior, then ResearchMap for
   portable mechanisms matching the vendor *and* request component, parser,
   transform, or consumer. The current surface chooses the query; old cards do
   not choose a new target. Read relevant program notes only for that question.
4. **Sufficiency gate:** Do the observations and retrieved knowledge explain a
   *plausible way past this blocker* that still matters to the downstream
   consumer? State what the control likely sees, what the origin/browser would
   see instead, the transport or configuration precondition, a negative control,
   and the predicted outcome. If yes, construct that candidate. If not, do
   bounded, fingerprint-led source research (`technology-research`; for XSS use
   `xss-technology-research`) before another family. Compare upstream docs,
   source, and relevant research with observed conditions; no local card or
   search result is not a negative target finding. When research remains thin,
   return to a distinct empirical discriminator rather than stalling or spraying.
5. **Test and learn:** Change one causal factor where feasible, keep a green
   control, and compare block → actual origin behavior → class-specific consumer
   proof. A 200/challenge change alone is not a bypass proof. If blocked,
   update the model and choose a non-equivalent mechanism; if accepted, verify
   the intended value and postcondition before claiming success. Record exact
   probes via the class lane's Attempts contract and durable app facts in
   MapStore, with sanitized evidence pointers. Promote one portable, source-cited
   mechanism to ResearchMap only after its recognition signal, preconditions,
   smallest check, caveats, and review meet the existing card-admission rules.

A card is a hypothesis accelerator, not a prerequisite or an exhaustive bypass
bank. Vendor-specific tricks belong in reviewed, condition-matched ResearchMap
cards; target outcomes belong in MapStore. For XSS-specific candidate grammar,
consumer proof, and source pointers, load `xss-waf-evasion`.

## Optional interceptor harness

Use `agents/bypass_harness.py` when you need a CLI entrypoint and want `agents/waf_interceptor.py` engaged automatically. Use `agents/waf_interceptor.py` directly only when embedding the interceptor into a custom harness or a narrow manual repro.

```bash
bbh agents/bypass_harness.py --target https://target.com/admin --type 403 \
  --program target --concurrency 5 --rps 1
```

## Module

`agents/waf_interceptor.py`

## Mode Matrix

| Mode | Use When | What It Does |
|------|----------|--------------|
| `fingerprint` | You need to identify the blocking layer first | Detects likely WAF family from responses |
| `tier1` | Plain requests are blocked but payloads are simple | Retries with delays, header rotation, cookies, and path tricks |
| `tier2` | Payload-carrying requests are blocked after Tier 1 | Obfuscates query values in addition to Tier 1 bypasses |
| `wrap` | Another harness already made the request | Reuses the existing response and only retries if blocked |

## Primary Commands

```bash
# WAF-aware 403 probing
bbh agents/bypass_harness.py --target https://target.com/admin --type 403 \
  --program target --concurrency 5 --rps 1

# WAF-aware SSRF probing
bbh agents/bypass_harness.py --target https://target.com/fetch?url=x --type ssrf \
  --param url --program target --concurrency 5 --rps 1
```

## CLI Notes

### `agents/bypass_harness.py`

| Option | Description |
|--------|-------------|
| `--target`, `-t` | Target URL (required) |
| `--type`, `-T` | Bypass type such as `403`, `ssrf`, `idor`, or `race` |
| `--param`, `-p` | Parameter name for injection-driven types |
| `--program` | Program name for shared storage |
| `--output-dir`, `-o` | Override raw artifact directory |
| `--timeout` | Request timeout in seconds |
| `--concurrency`, `-c` | Max parallel requests |
| `--rps` | Requests per second |
| `--verbose`, `-v` | Verbose debug output |
| `--quiet`, `-q` | Show hits only |

## Direct Interface

## Quick Start

```python
from agents.waf_interceptor import WAFInterceptor

# Sync (uses requests)
waf = WAFInterceptor(target="https://target.com", program="acme")
resp = waf.get("/admin")
resp = waf.post("/api/login", json={"user": "test"})

# Async (pass existing httpx.AsyncClient)
resp = await waf.aget("/admin", client=client)

# Wrap an already-made response (zero-cost if not blocked)
resp = await waf.wrap_async(client, "GET", url, resp)
```

## Supported WAFs (13 types)

| WAF | Detection Method |
|---|---|
| Akamai | Body: `AkamaiGHost`, `Reference #`, `AS-DOS-CID` |
| Cloudflare | Body: `Ray ID:`, `cf-ray` header, `Checking your browser` |
| AWS WAF / CloudFront | Body: `Generated by cloudfront`, `X-Cache: Error` header |
| Imperva / Incapsula | Body: `Incapsula incident ID`, `incap_ses` cookie |
| F5 BIG-IP | Body: `TS=4b63`, `support ID`, `BIGipServer` cookie |
| Sucuri | Body: `Sucuri WebSite Firewall`, `sucuri-waf` header |
| Wordfence | Body: `generated by Wordfence`, `wordfence.com` |
| ModSecurity | Body: `ModSecurity`, `mod_security` |
| FortiWeb | Body: `FortiWeb`, `Attack ID:` |
| Citrix NetScaler | Body: `Netscaler`, `NSC_` cookie |
| DDoS-Guard | Body: `DDoS protection by`, `ddos-guard` |
| PerimeterX | Body: `px-captcha`, `pxi.pub` |
| DataDome | Body/header: `datadome` |

## Interceptor mutation limits

The interceptor offers fixed vendor-labelled and generic retries (delay,
headers, path representations, cookies, and query-value obfuscation). Those are
*tool capabilities*, not a per-vendor proof or an exhaustive XSS payload
engine. Select a mode only when its mutation tests the observed control; do not
use retry volume, forged client-IP headers, or bot-profile rotation as an
unexplained default. `tier2` changes query values; it does not automatically
handle JSON/body encoding, the application's parser, or browser execution.
An edge pass must be checked against the origin and class-specific consumer.

## Output Files

```
~/Shared/bounty_recon/{program}/agent_shared/findings/waf/
├── blocks_log.txt    # Every WAF block: WAF name, method, path, status, evidence
├── bypasses_log.txt  # Every successful bypass: technique + result status
└── summary.json      # Running stats: total_requests, waf_blocks, bypass_success, bypass_fail
```

## Integration in bypass_harness.py

Already integrated. All `_get()` calls in `BypassOrchestrator` automatically:
1. Make the normal request
2. Check for WAF block with `detect_waf()`
3. If blocked → retry with `wrap_async()` until bypass succeeds or list exhausted
4. Log all blocks and bypasses to the WAF output directory

## Standalone Detection

```python
from agents.waf_interceptor import WAFInterceptor
import httpx

resp = httpx.get("https://target.com/admin")
waf_name = WAFInterceptor.fingerprint(resp)
print(waf_name)  # "Cloudflare" | "Akamai" | None
```

## Stats

```python
waf = WAFInterceptor(target=..., program=...)
# ... make requests ...
waf.print_summary()
# [WAF Interceptor Summary]
#   Total requests : 150
#   WAF blocks     : 12 (8.0%)
#   Bypasses OK    : 9 (75.0%)
#   Bypasses fail  : 3
```

## Files

- **Playbook:** `prompts/waf-playbook.md`
- **Shared Root:** `$HARNESS_SHARED_BASE/{program}/agent_shared/`
- **WAF Findings:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/waf/findings.md`
- **WAF Artifacts:** `$HARNESS_SHARED_BASE/{program}/agent_shared/findings/waf/`

## Harness use after the decision loop

1. Establish and classify the blocker with the adaptive loop above; apply the
   live-testing policy chain before any probe. Read relevant existing notes for
   this *selected* surface, not as a broad cold-start target selector.
2. Consult `prompts/waf-playbook.md` only when its trigger/lane answers the
   current question. The harness does not implement an XSS-specific bypass mode;
   use the selected XSS lane and `xss-waf-evasion` for that consumer.
3. If the chosen mutation is supported, use `agents/bypass_harness.py` or embed
   `agents/waf_interceptor.py` for a narrow comparison. Do not interpret its
   `bypass_success` counter as class-specific exploit proof.
4. Store exact attempts in the owning class lane. Record stable control facts and
   evidence pointers in MapStore and follow the finding/report owner when a
   verified impact exists. Avoid treating the interceptor logs as a parallel
   canonical WAF findings ledger.
