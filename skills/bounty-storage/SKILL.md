---
name: bounty-storage
description: "Route bug bounty files between cloud-backed Shared, mounted bounty artifacts, and local scratch."
---

# Bounty Storage

Use before writing bug bounty artifacts, run outputs, downloaded corpora, large
recon datasets, screenshots, proxy data, browser profiles, or durable findings
state.

Canonical policy:

`/home/ryushe/projects/ai-policies/policies/bug-bounty/bounty-storage.md`

## Hot Rules

Resolve the active program family/lane first, then choose storage:

1. Canonical truth and small indexes/manifests -> resolved `~/Shared` lane.
2. Large persistent non-secret artifacts -> `/mnt/bounty`.
3. Disposable active work -> local scratch on the machine doing the work.
4. Always leave a small Shared manifest or artifact-map pointer for large data.

Never put raw cookies, bearer tokens, auth headers, CSRF tokens, reset links,
passwords, API keys, private request bodies, private headers, or raw sensitive
files in `~/Shared` or `/mnt/bounty`. Store only sanitized manifests, indexes,
hashes, field names, counts, and replay templates there.

Do not hard-code legacy roots when a resolver exists. Prefer
`agents/storage_resolver.py`, `bounty_core.storage`, `context/target_profile.json`,
or the Shared `bounty_path_resolve.py` helper.

## First Move

If scripts are relevant, check existing helper indexes before writing a new one:

```text
~/Shared/bounty_recon/_shared/script-index.md
~/Shared/bounty_recon/_shared/scripts/README.md
$HARNESS_ROOT/SCRIPT_INDEX.md
```

Small reusable wrappers and records can live in Shared. Heavy inputs, raw
outputs, dependencies, virtualenvs, fixtures, and generated corpora should not.

## Storage Decision

- Shared: scope, rules, sanitized credentials references, findings, proof
  packets, reports, ledgers, compact summaries, manifests, artifact maps,
  curated aggregate lists, sanitized request contracts, small reusable scripts.
- `/mnt/bounty`: raw JS/source bundles, scraped pages, screenshots/videos, proxy
  flows/HARs, browser profiles, CDP traces, parser intermediates, long fuzz/recon
  runs, redownloadable corpora with manifests.
- Scratch: active downloads, parser temp files, partial output, retry state, tool
  logs, throwaway experiments.
- Restricted local evidence only: raw secret-bearing captures or exact sensitive
  proof when approved and protected with owner-only permissions.

Open `references/storage-layout.md` for canonical layouts and path examples.
Open `references/run-manifests.md` for large-run manifests, artifact maps,
archive pointers, and handoff requirements.

## Fallback Order

For large artifacts:

1. `/mnt/bounty` if writable.
2. Current host artifact directory.
3. `~/workdir/<program>/<run_id>/`.
4. Write a compact Shared manifest with actual path and regeneration command.

Do not silently dump large data into `~/Shared` because `/mnt/bounty` is absent.

## Exit Checklist

- Heavy data is outside Shared unless explicitly cloud-backed.
- Shared has a manifest, artifact map, or curated aggregate pointer.
- Raw secrets are absent from Shared, `/mnt/bounty`, prompts, commits, and chat.
- Missing/stale/moved artifact pointers are marked instead of silently trusted.
- Handoffs include manifest path, artifact pointer, hash/chunk/range, compact
  evidence excerpt, allowed scope, and stop condition.
