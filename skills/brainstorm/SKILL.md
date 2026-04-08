# Brainstorm — Multi-Agent Collaboration

## What It Does
Spawns Claude CLI sub-agent to collaboratively brainstorm approaches, find flaws, and think like developers.

## Invocation
```
/brainstorm <problem or question>
```

## How It Works

1. **Ghost (me)** — Orchestrator, know system context, memory, Ryushe's preferences
2. **Claude CLI (sub-agent)** — Red team capable, creative, security-focused

## When to Use

- Starting a new bug bounty program or target
- Looking at a new part of an application
- Thinking like the developer: "What did they NOT intend?"
- Finding assumptions developers made
- Discovering auth bypasses (direct navigation to endpoints)
- Reverse engineering business logic

## Example Uses

```
/brainstorm superdrug.com - they're using Akamai WAF. How do we approach testing?
/brainstorm When testing signup flows, what are common bypasses where devs assume auth checks but don't verify them?
/brainstorm What could go wrong with a chatbot that has access to user data and uses AI?
```

## Brainstorming Framework

When analyzing an application, think about:

**Auth Assumptions:**
- Direct navigation to endpoints (bypass initial checks)
- What happens if we skip step 1 in a multi-step flow?
- Session tokens in URLs vs cookies
- What does the backend verify vs what the frontend checks?

**Data Handling:**
- What does the model have access to that users don't?
- Can we poison data the model reads?
- Hidden API endpoints the UI hides but backend doesn't protect

**Business Logic:**
- Time-of-check vs time-of-use (TOCTOU)
- Race conditions
- What happens if we do X instead of expected Y?

## Rules

- Think like the developer — what did they NOT intend?
- Find assumptions — "It assumes the user will always..."
- Challenge expected flows — what if we skip steps?
- Document edge cases and potential bypasses
