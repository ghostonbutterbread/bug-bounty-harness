# Todo — {program}

## Priority Queue

Format: `[#] VULN_TYPE — Target — Reason — Agent`

Example:
```
[1] XSS — /api/search — Parameter "q" reflects in HTML — @claude
[2] IDOR — /api/user/{id} — Sequential user IDs — @ghost
```

---

## Top Priority

```
[P1] VULN_TYPE
     Target: URL or endpoint
     Reason: Why this matters
     Assigned: @agent (or unassigned)
     Status: pending/in-progress/complete
```

## Medium Priority

```
[P2] VULN_TYPE
     Target: URL or endpoint
     Reason: Why this matters
     Assigned: @agent (or unassigned)
     Status: pending/in-progress/complete
```

## When Done

```
[P3] VULN_TYPE
     Target: URL or endpoint
     Reason: Why this matters
     Assigned: @agent (or unassigned)
     Status: pending/in-progress/complete
```

---

## Recently Completed

```
[done] XSS — /search?q= — Found reflected XSS, needs auth testing — @claude — 2026-03-30
[done] IDOR — /api/profile/123 — No IDOR, fixed — @codex — 2026-03-29
```

---

## New Tasks Discovered

```
[new] VULN_TYPE — Target — Notes — Found by — Date
[new] SSTI — /api/render — Possible template injection — @claude — 2026-03-31
```

---

*Last updated by: {agent}*
*Date: {date}*
