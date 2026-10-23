# Bounty Storage Layout

## Shared Truth

Use `~/Shared` for small canonical truth that should be backed up and easy for
Ryushe and agents to inspect:

```text
~/Shared/bounty_recon/<program>/
  scope/
  credentials/              # references only, no secrets
  agent_shared/
    findings/
    hunter-loop/
    application-map/
  ghost/<skill-or-lane>/

~/Shared/web_bounty/<program>/web/
  recon/
    urls/
      urls.txt
      params.txt
      endpoints.txt
    js/
      js_urls.txt
    artifact-map.md
  findings/
  reports/

~/Shared/bounty_recon/<program>/apk/
  recon/
    artifact-map.md
  findings/
  reports/
```

Canonical aggregates should stay fixed:

```text
~/Shared/web_bounty/<program>/web/recon/urls/urls.txt
~/Shared/web_bounty/<program>/web/recon/urls/endpoints.txt
~/Shared/web_bounty/<program>/web/recon/urls/params.txt
~/Shared/web_bounty/<program>/web/recon/js/js_urls.txt
~/Shared/bounty_recon/<program>/apk/recon/endpoints.txt
~/Shared/bounty_recon/<program>/apk/recon/deeplinks.txt
~/Shared/bounty_recon/<program>/apk/recon/permissions.txt
```

Do not create ad hoc files inside aggregate directories just because a tool used
a different output name. Raw output stays in `/mnt/bounty`; curated unique items
are promoted to fixed Shared aggregates.

## Mounted Bounty Artifacts

Preferred path: `/mnt/bounty`.

Use program-first layout with stable category/corpus directories for lookup and
`runs/<run_id>/` for provenance:

```text
/mnt/bounty/<program>/
  web/
    recon/
      fuzzing/<target-slug>/runs/<run_id>/
      subdomains/runs/<run_id>/
      javascript/
        downloads/by-host/
        downloads/by-sha256/
        sourcemaps/
        chunks/
        indexes/
        runs/<run_id>/
      pages/
      api/
    screenshots/
      admin/
      auth/
      billing/
      settings/
      unknown/
      runs/<run_id>/
    proxy/
      flows/
      har/
      runs/<run_id>/
    videos/
    browser-profiles/
    cdp-traces/
  apk/
    static/decompile/
    static/jadx/
    static/apktool/
    dynamic/traces/
    dynamic/frida/
    dynamic/screenshots/
    runs/<run_id>/

/mnt/bounty/cache/
  content-addressed/<sha256-prefix>/<sha256>
  downloads/
```

For JavaScript, `downloads/by-host/` is the human browse path and
`downloads/by-sha256/` is the dedupe path. For screenshots, stable folders are
the browseable library and `runs/<run_id>/` preserves run history.

Desktop-app installers and extracted binary bundles (for example `app.asar` or
exe/dll trees) are heavy artifacts, not Shared truth. Keep non-secret bundles in
the resolved program's `/mnt/bounty` artifact lane with a small sanitized Shared
manifest or artifact-map pointer. An existing program layout may use a dedicated
binary category; do not create a competing root solely to match an example.
Inspect extracted files for embedded credentials or private user data before
promotion; raw sensitive material stays in restricted local evidence only.

## Existing Bulk-Artifact Symlinks

An existing Shared artifact-map entry may point at a large artifact relocated to
`/mnt/bounty`, with a symlink left at its former Shared path. Before writing or
re-exporting that path, inspect the entry **and** the path type. Do not replace
the symlink with a bulk copy or follow an unexpected link as a write target.
Verify the mapped destination is the intended, accessible non-secret artifact
and compare its recorded hash (or regenerate a hash when needed); if it is
missing or mismatched, mark the pointer stale and resolve ownership before any
download or replacement. A symlink is not a portable artifact: verify the
configured sync transport's actual link handling and the peer's exact path
before claiming another machine received it. Keep a sanitized manifest/pointer
so a consumer can locate or regenerate the bytes without relying on the link.

For a relocation, copy to a task-owned destination first and verify complete
content against the source before changing either path. Preserve the original
until the owner approves the final pointer and cleanup; never automatically
delete a Shared file, replace a symlink, or clear sync trash as part of a
storage-layout instruction.

## Local Scratch

Preferred scratch:

```text
~/workdir/<program>/<run_id>/
```

Accept existing host conventions:

```text
/home/ryushe/artifacts/<program>/<run_id>/
/tmp/<throwaway-task>/
```

Scratch is not canonical. Export a manifest or summary to Shared and move
retained heavy artifacts to `/mnt/bounty` when available.
