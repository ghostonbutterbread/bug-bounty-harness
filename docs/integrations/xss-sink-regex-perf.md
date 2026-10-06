# XSS sink inventory: regex performance + compiled React raw-HTML coverage

- **Base:** `beta` @ `30482cb`
- **Target:** `beta`
- **Branch:** `fix/xss-sink-regex-perf-20261006`
- **Worktree:** `/home/ryushe/projects/_wt/bbh-xss-regex-perf-20261006`

## Intent

Two defects found while running the new `sink_sites` census against 36 live
Hollister bundles (`www.hollisterco.com`, in scope, `h1:ryushe` UA, <=2 req/s).

### Defect 1 — `PARAM_NAME_RE` catastrophic backtracking (`agents/js_analyzer.py`)

`extract_signals` never completed on
`/static/orchestration/91003964/libs/designsystem.js`: **26+ minutes of CPU at 93%
with zero open sockets**, no manifest emitted, blocking the whole 36-URL run.

Root cause: the prefix `[A-Za-z0-9_.:-]*` is greedy, unbounded, and its class
matches **every base64 character**. That bundle is 906,794 chars of which
**439,188 (48%)** are inline `sourceMappingURL=data:...;base64` blobs, longest
unbroken non-whitespace run **156,948 chars**. With no anchor, the engine retried
from ~440,000 start offsets x ~157,000 backtracks each.

Not source-map fetching: these are inline `data:` URIs (nothing to fetch),
`--source-maps off` stalled on the same artifact, and the process held no sockets.
Not the new `sink_sites` code: all 218 rules scan that bundle in **2.6s**.

**Fix:** anchor the match at a token boundary with `(?<![A-Za-z0-9_.:-])`. Inside a
157KB base64 run there is then **one** valid start position instead of 157,000.

### Defect 2 — compiled React raw HTML invisible (`agents/xss_sink_sites.py`)

`React.dangerouslySetInnerHTML` required `\s*=`, which only matches **JSX source**.
Compiled/minified React emits the object-property form
`{dangerouslySetInnerHTML:{__html:x}}` — a **colon**. On a target built entirely
from compiled React MFEs the rule reported **1** site where ground truth is **88
occurrences across 14 bundles**.

**Fix:** `\s*=` -> `\s*[:=]`, covering both JSX source and compiled output.

## Implemented contract

| file | change |
|---|---|
| `agents/js_analyzer.py` | `PARAM_NAME_RE` gains a leading `(?<![A-Za-z0-9_.:-])` boundary assertion + comment |
| `agents/xss_sink_sites.py` | `React.dangerouslySetInnerHTML` pattern `\s*=` -> `\s*[:=]` |

No signature added or removed; rule count stays 218. No identifier, path, config
key, or command changed, so no reference-impact audit is required.

## Evidence

- `agents/test_xss_sink_sites.py` — **133 passed**
- `agents/test_js_analyzer.py` — **174 passed**
- Defect 1, `designsystem.js`: `extract_signals` **TIMEOUT (26+ min) -> 1.45s**.
  `PARAM_NAME_RE` alone: TIMEOUT -> 0.15s.
- Defect 1 output stability: legacy `global.js` (2,058,490 chars) **388 -> 388 unique,
  identical**; `globalV2.js` **232 -> 231** (the single loss is a mid-token start,
  which the boundary assertion intentionally excludes).
- Defect 2, 36 live bundles: `React.dangerouslySetInnerHTML` **1 -> 51** sites across
  11 bundles. Per-bundle counts match grep ground truth wherever the 8-per-rule cap
  is not reached (`checkoutMFE.js` 5/5, `customer.js` 3/3, `miniBag.js` 2/2,
  `searchPage.js` 1/1, `landingPages.js` 1/1).
- Defect 2 false positives: **51 of 51** matches carry `__html` within 60 chars;
  **0** without. `react-dom.production.min.js` correctly still reports 0 — its
  internal `"dangerouslySetInnerHTML"` string/property references are not
  object-literal sinks.
- Corpus total sink sites across the 36 bundles: **507 -> 577**.

## Blockers / deferred

- **`master` (stable) carries Defect 1 identically.** Verified:
  `bug_bounty_harness-stable` @ `5e7aecf`, `agents/js_analyzer.py:42`, same
  unanchored prefix, same remote. Per `bugfix-lifecycle-policy` `master` is the
  lower owning branch for Defect 1 and should receive the same one-line change,
  then be merged forward. **Not done here** — this worktree is based on `beta` and
  the stable lane was outside the requested scope. Trigger: operator approval to
  touch the stable lane.
- Defect 2's sibling rules `Vue.v-html`, `Alpine.x-html`, `Astro.set:html` are
  attribute spellings that likewise do not survive a build. **Unmeasured** — left
  untouched to keep this change one coherent scope. Vue's compiled form is a vnode
  `innerHTML` prop rather than `v-html:`, so `[:=]` would not be the same fix.
- Separately observed, **not addressed here**: inline source maps are unsupported
  end-to-end. `extract_signals` searches only `text[-3000:]` for
  `sourceMappingURL`, and `normalize_url()` rejects `data:`, so this bundle's 30
  inline maps are reported as "no source map" rather than "inline, unsupported",
  and the per-module packet/sink pass never runs for such bundles.
- No per-artifact watchdog: one pathological artifact can still consume a whole run
  and emit no manifest. Defect 1 removes the known trigger, not the class.

## Activation boundary

Both changes are pure pattern edits in the static scanner. No network, filesystem,
or output-schema behavior changes. Re-running `inventory` is required before any
previously-recorded zero-hit `framework_raw_html` result is treated as coverage.

## Next

Independent release gate, then merge to `beta`. Not pushed.
