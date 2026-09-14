# HackerOne host-like scope identifiers

- **Status:** review-ready
- **Task:** `t_25a3d658`
- **Branch:** `fix/hackerone-host-like-scope-identifiers`
- **Base / target:** `161c54a71e75dcd2243b6199ff0ccf76e540ff64` → `beta`

## Change

Normalize obvious host-formatting artifacts during HackerOne parsing: `v1. kidswebservices.com` becomes `v1.kidswebservices.com`; `dev.epicgames.com/*` becomes `dev.epicgames.com`. Exact HTTP(S) URLs remain unchanged and prose remains excluded.

## Verification

Focused scope/Recon-Ry suite: 140 passed. Live saved Epic raw-snapshot parse: 63 domains, 7 URLs, including both normalized entries.
