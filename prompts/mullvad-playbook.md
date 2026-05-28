# Mullvad Relay Switching Playbook

## Goal

Recover scoped bug bounty connectivity when the current Mullvad exit path is likely causing DNS failures, page-load timeouts, resets, or exit-node blocking.

This playbook is not a bypass policy. It does not authorize evading target rules, rate limits, or enforcement after noisy testing.

## Decision Tree

1. Confirm the target and action are in scope.
2. Retry the exact load/request two or three times with normal spacing.
3. Check whether the problem is local, proxy, VPN, or target-side.
4. Switch one relay city or host.
5. Verify with status, DNS, and a low-noise request.
6. Continue only if the symptom resolves.

## Pre-Switch Checks

Run:

```bash
mullvad status
mullvad relay get
```

Then check the specific failure class:

- DNS issue: `getent hosts <host>`
- page does not load: browser error text, proxy status, or `curl -I --max-time 15 <url>`
- suspected exit-IP block: same host fails immediately from current relay before application behavior is reached

If Caido or browser proxy settings changed recently, fix proxy configuration before rotating VPN relays.

## Relay Order

Stay West Coast by default:

1. Seattle: `mullvad relay set location us sea && mullvad reconnect --wait`
2. Los Angeles: `mullvad relay set location us lax && mullvad reconnect --wait`
3. San Jose: `mullvad relay set location us sjc && mullvad reconnect --wait`

Nearby fallback:

1. Phoenix: `mullvad relay set location us phx && mullvad reconnect --wait`
2. Denver: `mullvad relay set location us den && mullvad reconnect --wait`
3. Vancouver: `mullvad relay set location ca van && mullvad reconnect --wait`

Use city-level switching first. Use host-level switching only when a city works but one specific relay appears bad.

Example host-level switches:

```bash
mullvad relay set location us sea us-sea-wg-401 && mullvad reconnect --wait
mullvad relay set location us lax us-lax-wg-409 && mullvad reconnect --wait
mullvad relay set location us sjc us-sjc-wg-501 && mullvad reconnect --wait
```

Refresh available relays when commands fail because a relay hostname no longer exists:

```bash
mullvad relay update
mullvad relay list
```

## Verification After Switch

Use the smallest checks that answer whether routing recovered:

```bash
mullvad status
getent hosts <host>
curl -I --max-time 15 <url>
```

For browser work, reload one in-scope page once. Do not immediately resume high-volume probing.

## Notes Format

```text
Mullvad relay switch:
Prior status:
Prior relay:
Symptom:
New relay command:
New status:
Verification:
Result:
Next action:
```

## Guardrails

- Do not rotate relays to bypass target rate limits, bans, account restrictions, or explicit anti-VPN policy.
- Do not use non-West-Coast regions unless the West Coast ladder fails and Ryushe approves wider fallback.
- Do not disconnect Mullvad to test without VPN unless Ryushe asks.
- Do not run destructive or state-changing workflow tests immediately after a relay change; verify basic connectivity first.
- Stop after three failed relay changes and report the network symptom instead of cycling indefinitely.
