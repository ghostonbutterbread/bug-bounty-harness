---
name: intercepted-proxy
description: "Capture and, when justified, modify one browser request family through a task-scoped MITM listener."
---

# Intercepted Proxy

Use when a live task needs to observe or alter one browser request while its state, nonce, CSRF value, or browser-generated context is fresh.

## Transport Rule

Use a task-owned `mitmproxy`/`mitmdump` listener unless the agent itself is executing on **Abommie**, where local Caido is permitted. Outside Abommie, Ryushe’s Caido may supply read-only source shape only; the task MITM listener captures the agent’s live browser history.

## Preflight

1. Read scope, account ownership, `live-testing-policy`, and `proxy-routing-policy`.
2. Request the security browser through the provisioner (default task MITM),
   or lease a separate task listener for a no-browser run. Record run ID,
   listener, flow-file path, CA/profile path, and stop condition.
3. Verify the listener is task-owned, bound as intended, and its flow file is owner-restricted.
4. Require the provisioner's `proxy_cert_mode: import` and trusted CA receipt;
   it configures the isolated browser's proxy before launch.
5. Confirm one safe baseline flow appears in the task flow file before attempting mutation.

## One-Request Lifecycle

1. Trigger exactly one owned, scoped browser action.
2. Identify the target request family in the task MITM capture.
3. Default provisioner mitmdump is capture-only. If a supported, verified way
   to install/remove an exact host/path rule for this task exists, use that
   temporary mechanism for live modification. Otherwise use a bounded direct
   replay through the same task MITM, or stop if the action is non-replayable.
4. Change one approved variable, forward/send once, and observe the response
   and owned state. Never claim to have paused a capture-only listener.
5. Remove any temporary rule immediately and verify cleanup. Release the
   browser; finish the task proxy after replay and record a sanitized trail.

## Guardrails

- One MITM lane and one mutation family at a time.
- Do not mutate before a successful agent-MITM baseline exists.
- Do not leave task MITM listeners, rules, browsers, or profiles running after the recorded task ends.
- Do not log raw cookies, tokens, auth/CSRF headers, payment data, credentials, or private bodies.
- Stop for non-owned impact, public/staff-visible workflows, money, human review, unclear ownership, or target instability.

## Evidence

Record runtime, MITM host:port, flow-file reference, browser proxy/CA verification, target URL/method/status, sanitized mutation, owned effect, and cleanup confirmation. If Caido source history informed the test, label it separately from the agent-MITM replay.