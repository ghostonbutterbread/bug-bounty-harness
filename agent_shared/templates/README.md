# Agent Shared Knowledge Base

Welcome, hunting agent! This is the shared knowledge base for the **{program}** bug bounty program.

## Quick Start

**Before doing anything:**
1. Read `notes/summary.md` — quick overview of what's been done
2. Read `notes/observations.md` — WAF behavior, auth info, interesting quirks
3. Read `checklist.md` — what's been tested and what's pending
4. Read `todo.md` — current priorities

**After testing:**
1. Update `checklist.md` — mark items tested
2. Add findings to `findings/{vuln-type}/`
3. Update `todo.md` — what should be tested next
4. Update `notes/summary.md` — refresh the overview
5. Store reusable workflow maps under `application-structure/` when proxy analysis reveals durable user flows

## Directory Structure

```
{program}/
├── README.md              # This file
├── notes/
│   ├── summary.md         # Quick overview (read FIRST)
│   └── observations.md    # WAF, auth, interesting quirks
├── checklist.md           # Testing checklist (mark as you go)
├── todo.md               # Priority queue
├── application-structure/
│   ├── auth/
│   ├── cart/
│   ├── checkout/
│   └── ...               # One markdown file per mapped flow
└── findings/
    ├── xss/
    │   └── findings.md   # XSS findings
    ├── idor/
    │   └── findings.md   # IDOR findings
    ├── sqli/
    │   └── findings.md   # SQL injection findings
    └── ...
        └── findings.md   # Add new folders as needed!
```

## Creating New Finding Folders

**IMPORTANT:** If you test for a vulnerability type that doesn't have a folder under `findings/`, CREATE IT!

```bash
# Example: testing for XXE, no folder exists
mkdir -p ~/Shared/bounty/{program}/agent_shared/findings/xxe
# Then create xxe/findings.md using the findings template
```

## File Update Rules

| File | When to Update |
|------|----------------|
| `checklist.md` | After testing each vulnerability type |
| `findings/{vuln}/findings.md` | After finding anything (confirmed or potential) |
| `application-structure/{flow-type}/{flow}.md` | After mapping a reusable application flow |
| `todo.md` | When priorities change or new tasks are identified |
| `notes/summary.md` | After completing a testing session |
| `notes/observations.md` | When discovering WAF behavior, auth patterns, etc. |

---

*Last updated by: {agent}*
*Date: {date}*
