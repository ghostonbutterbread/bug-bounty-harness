---
name: findings
description: Use when viewing, listing, filtering, summarizing, or checking bug bounty findings, including /findings requests by program or severity.
---
# Findings — View Bug Bounty Findings

## What counts as a vulnerability here

Every ledger entry passed the claim-time classification gate at ingest: it
names the protected resource or capability obtained and the observation that
demonstrates obtaining it. When you summarize or brief findings, report those
two things per finding in plain language — what an attacker got and how it was
proven — not scanner labels, tool names, or raw request jargon. An entry whose
observation is only a status code or error string is a signal (Informational),
not a vulnerability; say so rather than inflating it.

## Invocation
```
/findings
/findings superdrug
/findings --severity P1
```
