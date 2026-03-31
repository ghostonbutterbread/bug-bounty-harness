# Race Condition Testing Playbook

## Overview

Use this as a decision tree: map the stateful action, capture the single-request baseline, choose the race shape that matches the workflow, verify duplicated or inconsistent state under concurrency, then report the exact preconditions and outcome.

## Decision Tree

1. Identify the state-changing action first.
2. Capture the normal single-request baseline.
3. If the action should be single-use, go down the duplicate-use lane.
4. If the action is quota- or balance-gated, go down the limit lane.
5. If checks and writes are separated, go down the TOCTOU lane.
6. Verify actual state divergence, then report the workflow and impact.

## 1. Map The Action

Good race candidates usually consume or transition something valuable.

### Common Targets

- Coupon redemption and gift cards
- Wallet credits, refunds, and transfers
- Inventory reservation and booking
- One-time links, password resets, and verification flows
- Approval, cancellation, and refund workflows

### Capture

- Exact endpoint and method
- Request body or token
- Preconditions required before the action
- Observable state before the request

## 2. Choose Lane

| Lane | Use When | What To Confirm |
|------|----------|-----------------|
| Duplicate use | A token, coupon, or invite should be consumed once | More than one request succeeds before invalidation |
| Limit bypass | A quota or balance should block repeats | Concurrent requests all pass the same pre-check |
| TOCTOU | Check and write happen in separate steps | Authorization or balance becomes stale between them |
| Workflow conflict | Multiple endpoints mutate the same object | Invalid final state or conflicting transition accepted |

## 3. Verify

Response variance alone is not enough. You need state evidence.

### Verification Standard

1. Reproduce the burst with the minimum concurrency that triggers the issue.
2. Capture:
   - baseline response
   - concurrent response mix
   - resulting state after the burst
3. Confirm one of:
   - duplicate redemption
   - negative or inconsistent balance
   - double booking or stock overrun
   - invalid workflow state
4. Record the exact concurrency and timing approach that made it reproducible.

### Status Rules

- `Confirmed`: concurrent requests caused duplicated or inconsistent state.
- `Potential`: response variance exists, but the resulting state is not yet proven unsafe.
- `False Positive`: concurrency only changed transient responses, not the committed state.

## 4. Report

Write the result to:

`$HARNESS_SHARED_BASE/{program}/agent_shared/findings/race/findings.md`

Include:

- Workflow or endpoint raced
- Preconditions required
- Request count and concurrency used
- Baseline outcome versus raced outcome
- Proof of duplicated or inconsistent committed state
