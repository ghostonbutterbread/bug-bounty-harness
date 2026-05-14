# Hunt Pipeline Live Safety Policy

Status: active
Owner: Ghost / Ryushe
Canonical path: `docs/hunt-pipeline-live-safety-policy.md`
Last updated: 2026-05-14

## Purpose

This document is the durable safety policy for promoted hunt-pipeline live testing. It captures the phase 20 direction: approve a bounded live environment, then let agents hunt inside that environment while preventing unwanted external connections and vendor/customer-visible actions.

The goal is not to make live agents useless. The goal is to let them test aggressively inside a controlled VM/tunnel boundary while defaulting to private, reversible, non-public actions.

## Core model

Phase 20 has two guardrails that must work together:

1. **VM Guard / environment approval** — controls where agents may connect.
2. **Private-by-default action policy** — controls what agents may do after connecting.

Environment approval alone is not enough. An agent inside an approved VM could still perform harmful or unwanted actions in a real app, such as posting publicly, inviting users, sending messages, or submitting payment. Action policy catches that class of risk.

Action policy alone is not enough either. Agents also need a network/process boundary so they do not wander into unrelated machines, local network assets, metadata services, or unmanaged external hosts.

## VM Guard: environment-scoped approval

Promoted runs should bind to one approved VM/tunnel environment rather than whitelisting every individual in-VM tool.

Once the run is bound to an approved environment, these in-environment surfaces are allowed by default unless explicitly denied:

- Ghidra MCP servers
- other MCP servers running inside the VM
- CDP/debug endpoints exposed by target apps or browsers inside the VM
- SSH-local services for the VM
- local target processes and analysis tooling
- localhost services reached through approved tunnel bindings

The guardrail is:

> Stay inside the approved VM/tunnel boundary. Do not connect to unapproved machines or unmanaged external hosts.

### Environment approval records should capture

- `environment_id`, e.g. `aitestvm`, `aitestzone`, or a generated fixture id
- environment type, e.g. `windows-vm`, `linux-vm`, `fixture-local`
- approved route roots, e.g. hostnames, VM IPs, local tunnel binds, loopback ports
- denied route patterns, e.g. arbitrary LAN, public internet, metadata IP ranges, non-approved hosts
- target/run intent, e.g. app name, engine/process, target path, binary hash when available
- approval owner and timestamp
- expiration or teardown expectation
- whether the environment is disposable/snapshot-backed

### VM Guard requirements

Before spawning promoted live agents, runtime must verify:

- the promotion decision references an approved environment id
- the environment approval record is valid and unexpired
- the plan target/run intent matches the environment approval
- generated attachment instructions stay within approved route roots
- denied routes override allowed routes
- missing or malformed environment approval fails closed before run-state/spec/adapter writes

## Private-by-default action policy

Live testing should default to private, local, sandboxed, or read-only behavior.

If an action cannot be performed privately or in a sandbox/test mode, the agent should stop at a proof plan and ask for exact-test approval instead of executing.

### Allowed by default

Allowed actions are private, reversible, local, or read-only. Examples:

- static analysis
- debugger inspection
- read-only UI flow mapping
- local/VM-only target interaction
- private drafts visible only to the test account/self
- self-only settings changes that can be reverted
- screenshots, traces, logs, and evidence capture with redaction
- reaching the final confirmation step of a risky flow without submitting it
- using test/sandbox endpoints explicitly approved for the run

### Approval required for exact test

These actions may be valid vulnerability tests, but they require explicit approval for the exact action, target, account, and environment:

- payments, purchases, subscriptions, refunds, credits, coupons, gift cards, or checkout submission
- public posts, publishing, comments, reactions, follows, ratings, reviews, or social actions
- guild/community/workspace/server/channel creation when visible to others
- invites, DMs, emails, notifications, SMS, webhooks, or messages to real users/systems
- account creation beyond approved test accounts
- bulk creation, crawling, scraping, mass update, or load-generating actions
- changing organization, tenant, billing, role, permission, or shared resource state
- uploading files that become public or visible to vendor/customer systems
- any action that persists vendor/customer-visible data

### Blocked unless explicitly approved

These should not happen in normal promoted runs:

- destructive changes
- spam-like behavior
- irreversible financial/account state changes
- credential harvesting or exfiltration
- lateral movement outside the VM/test environment
- persistence, malware-like behavior, or privilege escalation outside the target test scope
- attempts to access unrelated tenants/users/customers
- bypassing VM Guard, route restrictions, or approval gates

## Example decisions

### Payment vulnerability hypothesis

Allowed by default:

- inspect payment flow code
- map UI/API steps
- identify request fields and confirmation boundary
- test in a documented sandbox/test payment mode
- stop before final payment submission

Approval required:

- submitting a real checkout/payment/refund
- testing with real payment instruments
- altering live billing state

### Chat/guild/community application

Allowed by default:

- inspect local app behavior
- create private drafts if visible only to self/test account
- test in a private sandbox guild/workspace approved for the run
- stop at public-post confirmation boundary

Approval required:

- creating public guilds/servers/channels
- sending invites/messages/notifications
- posting publicly
- interacting with real users or shared communities

### Desktop app with CDP and Ghidra MCP

Allowed by default inside approved VM:

- enumerate CDP targets
- inspect renderer state
- query Ghidra MCP
- capture screenshots/logs
- run read-only probes against local target process

Blocked:

- connecting to non-approved hosts outside the VM/tunnel boundary
- opening arbitrary public websites unless explicitly part of the target and approval

## Runtime behavior expectations

Promoted live runtime should inject a concise version of this policy into agent prompts and runtime metadata.

Agents should classify intended live steps as one of:

- `allowed_private`
- `approval_required`
- `blocked`

When uncertain, agents should downgrade to `approval_required` and stop before execution.

The pipeline should record the policy decision in evidence/session metadata so future reviews can see why an action was or was not taken.

## Iteration note

This policy should evolve as we discover new app classes and risky action categories. Add examples here instead of burying them in chat logs.
