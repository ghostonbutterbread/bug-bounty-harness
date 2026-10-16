# Prerequisite-aware blocker contract

Use this when a missing account capability, role, tenant membership, integration, plan, normal workflow state, or owned object fixture prevents a valid live-test comparison.

## Boundary

A blocker is an append-only lifecycle record, distinct from:

- **Attempts:** exact requests, browser actions, and mutations sent.
- **Error Store:** observed product/runtime failure behavior.
- **MapStore:** durable observed target facts.
- **Hypothesis Ledger:** private untested chains.
- **Bounty Notes:** the human-facing decision and handoff.

## Minimum record

Record the exact operation (`subject`), authorization test scope, stable prerequisite key, typed reason, non-secret account/resource references, evidence pointer, and smallest concrete wake condition. Do not include cookies, bearer values, or URL userinfo. Redact URL userinfo before persistence.

Open records describe an external prerequisite for an exact subject and test
scope; they are not a testing or coverage gate. Before honoring a known record,
freshly assess whether ordinary authorized remediation can now clear it. Later
`resolved` or `superseded` events preserve the append-only history. Derive
current status from the full event history before applying a presentation limit.

## Coverage wording

An open external prerequisite means: **not demonstrated under the recorded
conditions**. It does not close the route, prohibit other authorized work, or
supersede fresh evidence from a newly available fixture.

A successful login, two usable account aliases, an in-scope SPA route, or a routing/method matrix does not prove the normal feature state was exercised. Verify the feature-specific capability and the owned fixture first. Routing observations may still be recorded, but cannot be reported as coverage for the unavailable feature.

## Core-first integration

When a harness adapter imports the canonical blocker store, commit and publish the storage implementation first. Pin the adapter to that exact immutable Core revision, then perform a runtime smoke check without source-path injection. Tests that inject an uncommitted source tree do not verify the pinned runtime dependency.