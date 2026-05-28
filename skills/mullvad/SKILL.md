---
name: mullvad
description: "Switch Mullvad VPN relays for scoped bug bounty connectivity, DNS failures, transient page-load failures, or suspected VPN exit-node blocking."
---

# Mullvad Relay Switching

Use when a scoped bug bounty workflow is failing because the current VPN path appears unhealthy: repeated DNS failures, page-load timeouts, connection resets, stuck browser loads, or a likely blocked Mullvad exit IP.

Do not use relay switching to evade target rules, rate limits, account bans, WAF enforcement, or explicit blocking after noisy testing. Treat it as network-path recovery unless Ryushe explicitly approves a different use.

## Required Preflight

1. Confirm the task is in scope and live testing is allowed.
2. Read `$HARNESS_ROOT/prompts/mullvad-playbook.md`.
3. Check current state:
   ```bash
   mullvad status
   mullvad relay get
   ```
4. Capture the exact network symptom before switching: DNS error, timeout, HTTP status, browser error, or proxy observation.

## West Coast Relay Ladder

Prefer these city-level constraints first:

```bash
mullvad relay set location us sea && mullvad reconnect --wait
mullvad relay set location us lax && mullvad reconnect --wait
mullvad relay set location us sjc && mullvad reconnect --wait
```

Nearby fallbacks if the West Coast city pool is unhealthy:

```bash
mullvad relay set location us phx && mullvad reconnect --wait
mullvad relay set location us den && mullvad reconnect --wait
mullvad relay set location ca van && mullvad reconnect --wait
```

If a city works but one relay looks bad, rotate within the same city:

```bash
mullvad relay set location us sea us-sea-wg-401 && mullvad reconnect --wait
mullvad relay set location us lax us-lax-wg-409 && mullvad reconnect --wait
mullvad relay set location us sjc us-sjc-wg-501 && mullvad reconnect --wait
```

## When To Switch

Switch after two or three clean retries when:

- DNS lookup fails or returns inconsistent results.
- Browser pages hang before the first meaningful response.
- The same scoped URL fails from one relay but proxy/browser setup appears correct.
- The target appears to block the current exit IP before application logic is reached.
- Mullvad reports connected, but traffic is timing out through the current relay.

Do not switch repeatedly during active payload testing. Pause testing, diagnose the network symptom, switch once, reconnect, verify, then continue.

## Verification

After each switch:

```bash
mullvad status
getent hosts target.example
curl -I --max-time 15 https://target.example/
```

Replace `target.example` with the full in-scope host. Do not paste cookies, tokens, auth headers, or private URLs into chat.

## Evidence Note

Record under the active program notes:

- prior relay and visible location
- new city/relay
- exact failure symptom
- command used
- post-switch status
- whether the scoped page/API recovered

## Stop Conditions

Stop and ask Ryushe if the target explicitly blocks VPNs, the issue looks like an account or application ban instead of network routing, the workflow is state-changing, or more than three relay changes fail to restore basic connectivity.
