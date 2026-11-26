# Integration dossier: feat/scope-check-ingest

- Task: fix the scope matcher, expose it as a read-only JSON `classify` CLI for
  the Bounty Board, and scope-filter URL ingest by default
- Worktree: `~/projects/bbh-feat-scope-check-ingest`
- Branch: `feat/scope-check-ingest`
- Base (origin/beta): `1cb7071e240a8c23a5efa8a9efe4e4258b05d7ec`
- Merge target: beta (Hermes merges after independent review)
- Companion: Bounty Board builder (separate repo) consumes `classify`

## Intent

Ryu, verbatim:

> bounty board can show oos urls i would love to make it so that our program
> when showing the urls they have been scope checked pls idk if that means
> recchecking before showing. or what. pls think of efficiency when you make a
> plan

> yup hide them default then we can show oos with a filter
> I like filtering oos on ingest and the failover is if no scope preent try to
> pull, if cant pull then run without scope 9some programs have openscope)

BBH's part: a correct matcher, a JSON CLI the Board can call to hide
out-of-scope URLs, and no out-of-scope URLs entering the URL index by default.

## What changed

Files: `agents/scope_validator.py`, `agents/scope_seed_files.py`,
`agents/url_ingest.py`, new `agents/test_scope_classify.py`,
new `agents/test_scope_review_regressions.py`,
`agents/test_url_ingest.py`, `agents/test_recon_store.py`, `agents/recon_ry.py`,
`prompts/url-ingest-playbook.md`,
`skills/url-ingest/references/url-ingest-reference.md`.

### 1. Matcher fixes

- **Platform-export lines** (`scope_seed_files.parse_scope_line`, revised
  after review). Only the first ` | ` column counts. A whitespace-free value
  passes through unchanged. A column with whitespace mixes rules and prose:
  - every token a rule (`a.x.test, b.x.test`): keep all;
  - **exclusions**: keep every token that is itself a host, wildcard, glob, IP,
    CIDR or URL, after stripping `(),;:`, so `admin.x (legacy)` and
    `Corp - 10.1.0.0/16 and 10.2.0.0/16` still exclude everything they name.
    Such lines are recorded as *lossy*. A line with no rule-shaped token is
    skipped;
  - **grants**: keep a rule only from the exact `<words> - <rule>` export
    shape, where the words contain no rule (`Infra - 192.0.2.0/28` gives
    `192.0.2.0/28`). Anything else is skipped, so `All assets except
    admin.x` grants nothing.
  - Skipped lines are counted in `scope_summary()` and in classify's
    `skipped_lines`.
- **Host globs.** New `glob` entry type and URL-host globs. A leading `*.`
  keeps its meaning. Any other `*` matches 1+ characters inside one label for
  an allow and may span dots for an exclusion. An **allow** glob is valid only
  if (a) at least two whole literal labels sit right of its last `*` label and
  (b) every starred label starts with a literal (a prefix family such as
  `app*` or `api-*`). Otherwise it grants nothing, as on base: `*.*`,
  `acme.*`, `*acme.example.test`, `acme*.test`,
  `https://*acme.example.test/*`. Exclusion globs stay wide. No public-suffix
  list is a dependency, so none is used.
- **Speed.** Rules are parsed once (`ip_network`, safe host, compiled globs,
  parsed URL pattern). The target host and IP are worked out once per target,
  not once per rule.

Before and after, synthetic equivalents (`*.example.test`):

| Scope | Target | Before | After |
|---|---|---|---|
| `https://a.acme.example.test/api/* \| api \| In Scope \| ...` | `https://a.acme.example.test/api/v1` | out | in |
| `https://acme.example.test/* \| website \| ...` | `https://acme.example.test/` | out | in |
| `Acme Infrastructure - 192.0.2.0/28 \| other \| ...` | `192.0.2.5` | out | in |
| exclusion `customer.*.isp.example.test`, allow `*.isp.example.test` | `customer.foo.isp.example.test` | out | out |
| same | `other.isp.example.test` | **out** | in |
| allow `app*.hub.example.test` | `app1.hub.example.test` | out | in |
| allow `*.acme.example.test`, exclusion prose `Third party vendors` | `a.acme.example.test` | **out** | in |

Hermes thought bug 2 never excluded the glob host. Re-measured, it is worse
than that: an infix-glob or prose exclusion was an "invalid exclusion
authority", and those deny *every* target. So each affected program was fully
out of scope, not just missing the exclusion. Measured on copies of the saved
in-scope and out-of-scope files (counts only): 2 of 56 programs denied all
targets before, 0 after; 6 entries are now parsed as globs.

Perf (same box, loaded; 60 rules with 20 CIDRs, 5,000 mixed targets):
`partition` 7.32 s before, 0.19 s after; `classify_target` x5,000 0.19 s. A
CLI run with 50,000 targets via `scripts/bbh` takes 3.6 s wall, 40 MB RSS,
including interpreter start. The test bound is 5 s for partition plus classify
of 5,000.

### 2. `classify` CLI

`bbh agents/scope_validator.py classify <program> [--scopes-base DIR] --json`,
stdin `{"targets": [...]}`. Implements the shared contract as written:
`version`, `program`, `scope_dir` (resolved, so alias symlinks show the real
directory), `scope_state` (`loaded`/`empty`/`missing`), `signature`,
`entries`, `exclusions`, `skipped_lines` (additive field: prose lines that
yielded no rule), and one `results` item per target in input order,
with the target echoed back unchanged. States are `in`/`out`/`partial`/`unchecked`.
Full URLs are never `partial`. Exit 2 for usage errors (bad JSON, wrong
shape, more than 50,000 targets, bad program name). Exit 1 for an unreadable
or unparseable scope file. Both print one line on stderr. A missing scope
exits 0. The CLI never writes, pulls or uses the network.

Python API: `ScopeValidator.classify_target(target) -> (state, rule, reason)`
and `classify_program(program, targets, scopes_base)`.

### 3. Filter at ingest by default

- `ingest()` and `aggregate_recon()` default to `scope_filter="auto"`, with
  `repull_scope=None` meaning `scope_filter != "off"`. The CLI
  `--scope-filter` default is now `auto` for `ingest` and `aggregate`
  (`aggregate` previously never repulled from the CLI).
- Fallback (unchanged logic, now the default): scope on file filters. With no
  scope, try the HackerOne, Bugcrowd and Intigriti pulls. If those fail, ingest
  unfiltered with `scope_mode=no_scope_after_pull`.
- Pull backoff: if an `imports` row with `scope_source=no_scope_after_pull`
  is less than 24 h old (`SCOPE_PULL_RETRY_AFTER`), skip the pull. Record
  `scope_source=no_scope_pull_skipped` and a `scope_note` with the failure
  time and retry time. The row's `scope_mode` is also
  `no_scope_pull_skipped` (same unfiltered outcome). Skipped rows do not
  extend the window. A scope saved
  in the meantime is used at once, because the saved-scope check runs first.
  No new files; existing index rows are untouched.
- `agents/recon/bus.py::index_delta` still passes `off` on purpose.

## Decisions

1. **`rule` is the rule text**, not the full file line: the first ` | ` column
   or the extracted token, with ` :: ` annotations removed and before
   optional-group expansion. The full export line (`| api | In Scope | tags:...`)
   would be noise on the Board. Example: `https://a.x/api/*`, not the whole
   pipe line.
2. **Bare host vs root URL rule.** A bare host matched by a URL rule with no
   path (e.g. `https://root.example.test`) is `in`. A bare host cannot carry
   the rule's scheme or port. 30 programs list host-only URL entries; if these
   counted as `out`, the Board would hide their hosts. `is_in_scope()` (the
   ingest filter) stays strict here, and URLs are what get ingested.
3. **`partial` reason** for a host rule plus a path exclusion: `in scope except
   paths under /admin/ (<rule>)`.
4. **Comma or space-separated host lists** (`a.x.test, b.x.test`, seen once in
   real data) keep every token when every token is a rule.
5. **Pure-prose exclusion lines are skipped.** Before, they denied the whole
   program. No host matcher could enforce lines such as `3rd party services`.
   A line naming any rule-shaped token still excludes it. A whitespace-free
   invalid exclusion (`bad_host!.x`) still denies all, as before.
6. **`classify` reads only `<scopes-base>/<program>/`.** It never reads the
   legacy `~/Shared/bounty_recon` fallback, so the Board's
   `--scopes-base <board-root>/scopes` never mixes in another root. This is the
   new `ScopeValidator(include_legacy=False)` option.
7. **`signature`** is the sha256 of `in-scope.txt`, `out-of-scope.txt` and
   `excluded.txt` (name, length, bytes, in that order) when present.
   `rules-of-engagement.json` is excluded because it does not affect verdicts.
   With no files it is the sha256 of nothing.
8. **`scope_state: empty`** also covers a directory whose in-scope entries
   are all unusable (prose or invalid hosts).
9. **Bare `host:port`** is classified by host. Inputs that are neither a host
   nor an http(s) URL (`HTTPS://X` with an upper-case scheme, `host/path`
   without a scheme) are `out` with reason `not a valid host or URL`. This
   matches the ingest filter.
10. `get_domains()` no longer returns infix-glob entries such as
    `app*.x.test`. They are now `glob` entries, not junk exact domains, and
    nothing in the repo consumed them.
11. A platform pull that times out (90 s) or cannot launch now counts as a
    failed pull. Before, `TimeoutExpired` aborted the whole ingest; with
    `auto` as the default, that would have broken the fallback.
12. **Recon-Ry refuses prose-bearing scope lines.** Its launch guard relied on
    prose becoming invalid entries. `ScopeValidator` now records
    `skipped_scope_lines` and `lossy_scope_lines` (exclusion lines that kept
    rules beside prose), and `recon_ry.validate_recon_scope_containment`
    refuses on both. Refusing on any lossy exclusion line is slightly stricter
    than "fewer rules than rule-shaped tokens". Exclusion parsing keeps every
    rule-shaped token, so that count never differs for exclusions, and the
    reviewer's repro (`Corp - 10.1.0.0/16 and 10.2.0.0/16`) requires a refusal.
    The prose may qualify scope in ways host filters cannot represent. A grant
    in the `<words> - <rule>` shape keeps its only rule-shaped token and does
    not refuse. Infix globs are still refused, because Recon-Ry cannot
    represent them.
13. Skipped-pull imports record `scope_mode=no_scope_pull_skipped` (review F4);
    the backoff keys on `scope_source` of real failed pulls.
14. **Allow-glob rule (b)** goes slightly beyond the reviewer's two-label
    rule. `*acme.example.test` has two literal labels right of its `*` label,
    yet the repro requires it to grant nothing (arbitrary-prefix lookalikes).
    All 4 real allow globs are `prefix*.x.x` and still grant. The cost: an
    allow such as `customer.*.x.y.z` (whole-label `*`) now grants nothing;
    real data only has that shape as an exclusion.

## Tests

Command:

```bash
PYTHONPATH=$PWD .venv/bin/python -m pytest -q -p no:cacheprovider <files>
```

- Baseline (before change): the 18 test files that touch `scope_validator`,
  `url_ingest`, `scope_puller` or `recon/bus.py` gave 1306 passed, 59 subtests
  passed.
- After: see below. A `sitecustomize` guard fails any `scope_puller`
  subprocess.
- `agents/test_recon_store.py` already ran real scope pulls (network) before
  this change, because `recon_store` passes `auto`. An autouse fixture now
  isolates scopes and mocks `_try_repull_scope`.

Final run, on the committed tree, of the 18 baseline files plus
`agents/test_scope_seed_files.py`, `agents/test_scope_classify.py`,
`agents/test_recon_ry.py`, `tests/test_recon_ry_scope_files.py`,
`tests/test_skill_triage_routes.py`, `tests/test_skill_hygiene.py` and
`tests/test_data_store_guidance.py`: **1454 passed, 63 subtests passed**
(684 s, box load ~20). The network guard recorded 0 scope-puller calls.
New: `agents/test_scope_classify.py`, 38 tests. `agents/test_url_ingest.py`
gains 9 tests and updates the old-default matrix and CLI cases.

An intermediate run showed 6 failures, both fixed before the final run:
3 in `test_recon_store` (the puller guard tripped because the fixture
patched the wrong module object) and 3 in `test_recon_ry_handoff_safety`
(prose refusal, see decision 12).

## Gaps

- A *grant* like `a.x.test (production)` is skipped as prose (by the review's
  F3 rule). No real in-scope line has this shape today; the line is counted
  in `skipped_lines`.
- Without a public-suffix list, a narrow-looking allow glob under a
  multi-label public suffix (`app*.co.uk`) still passes the two-label rule.
- Mid-label globs in optional-group patterns (`app*(-eu)?.x`) are not
  expanded into seeds. The matcher handles each expanded variant.
- Recon seed and scope-file writers (`recon_seed_lines`,
  `recon_scope_file_lines`) still skip infix globs. They receive values from
  the puller, not saved lines, and Recon-Ry cannot represent globs.
- The Board must still respect `unchecked` (no scope on file) and decide how
  to show it. BBH does not pull scope from `classify`.

## Decisions for Ryu

- Open-scope programs: after one failed pull, ingest skips pulling for 24 h.
  Change `SCOPE_PULL_RETRY_AFTER` if a different window is wanted.
- Programs that had prose or infix-glob exclusions were previously treated as
  fully out of scope by every scope check (gates, recon, ingest). After merge
  they open up to their real scope. That is the intended fix, but agents may
  now reach hosts that were wrongly blocked before.

## Review

### Round 1: BLOCK (F1, F2 blockers; F3, F4, skip-surfacing should-fix)

Fixed in `cf912641` (F1, F3, skipped-line surfacing), `a29592d0` (F2) and
`45daa463` (F4). Each commit has regression tests.
`agents/test_scope_review_regressions.py` copies the reviewer's 12 repros
verbatim (only `mkdir(parents=True)` added) plus 24 cases of its own. The
reviewer's repro file at its original path passes 12/12.

### Real-scope survey after the fixes

Read-only, on copies of each program's `in-scope.txt` and `out-of-scope.txt`.
For each program, probe targets were derived from every rule-shaped token
(literal host, `zprobe.` subdomain, glob instantiation, CIDR addresses, URL
path and a sibling path). Each probe was checked with `is_in_scope` on base
`1cb7071e` and on the new tip. 56 programs; 6 change, every change out to in,
**none in to out**:

| Program (anonymised) | Probes changed | Cause |
|---|---|---|
| A | 61 | export-pipe CIDR and URL grants now live (45 dead grants revived) |
| B | 51 | infix-glob exclusion no longer denies all; the glob still excludes its hosts |
| C | 48 | prose exclusion line no longer denies all (1 skipped exclusion line) |
| D | 21 | export-pipe URL grants now live |
| E | 6 | `prefix*.x.x` allow globs now grant |
| F | 2 | export-pipe URL grant now live |

No real line is *lossy*. Skipped line shapes (letters/digits masked as `x`):
grants `x x x` x3, `x x x x` x2, `x (x)` x2, `x x`, `x x x x x`,
`x (x: x, x, x)`, `x x (x)x x x x x x x`, `x x/x x | ...`, and one long
sentence; one exclusion `x x x | x | ...`. All are pure prose with no
rule-shaped token.

### Tests after round 1 fixes

Same file set as the first final run, plus `agents/test_scope_review_regressions.py`
and the reviewer's repro file: **1502 passed, 63 subtests passed** (818 s,
loaded box). The network guard recorded 0 scope-puller calls. The reviewer's
repro file on its own: 12 passed. One intermediate failure, the aggregate
test still expecting the old skipped-pull `scope_mode`, was fixed in a
follow-up test commit.

### Round 2

Independent re-review of a1cf9450: F1 to F4 fixed; BLOCK on N1. An exclusion
host wrapped or joined in a shape the token stripper does not unwrap
(`[a.x] internal`, `"a.x" internal`, `<a.x> internal`, `a.x;b.x internal`,
`a.x/* internal`, `Mapped ::ffff:10.0.0.1 internal`) was skipped, so the host
was allowed where base refused everything. Minor: an in-scope line
`Out of scope - a.x` granted `a.x` through the `<words> - <rule>` path.

Fixes (Hermes): in exclusion mode, leftover prose that still looks like a host
or address (`[a-z0-9-]\.[a-z0-9-]`, an IPv6 fragment, `::`) adds the whole
first field as an invalid exclusion, so every target is refused (fail closed,
as base); pure prose such as `3rd party services` stays skipped. Named grants
whose words say out of scope, exclud or except grant nothing. `skipped_lines`
in `classify` counts skipped lines only, not lossy ones.

Tests: `agents/test_scope_review_regressions.py` round-2 cases (the reviewer's
6 repros plus pure-prose-still-skipped, negated named grants, named grant
still grants). With a1cf9450's `scope_seed_files.py` swapped in, 9 of the 11
new cases fail and the reviewer's round-2 repro file fails; on the fix all
pass. Real-scope survey a1cf9450 vs fix (read-only, all 56 programs): no
program changes; spacex, rapyd and klaviyo stay open, the rapyd prose
exclusion stays skipped.
