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
