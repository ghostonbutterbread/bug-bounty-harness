# Error Intelligence integration dossier

## Intent

Expose Bounty Core's Error Store through a BBH-native CLI and a reusable
Error Intelligence skill. Agents should capture server/application/client error
behavior during normal mapping and may pursue an explicit error-focused pass;
this change does not build generic vulnerability-cue routing.

## Branch and target

- Feature branch: `feat/error-intelligence`
- Base: BBH `origin/beta` at `10a13f3`
- Intended integration target: `beta`
- Required Core dependency: `feat/error-store` repair commit
  `75cbcc6193f5070052e30a12de214d9e2b5b1904`, pending re-review and Core beta
  integration.

## Implemented contract

- `agents/error_store.py` follows BBH's global `--root`, `--family`, and
  `--lane` pattern and exposes `record` and bounded `query` commands.
- `record` forwards only structured, redaction-enforced Error Store fields.
- `query --intent events` returns events; `query --intent dedupe` additionally
  returns the bounded Core fingerprint summary.
- `skills/error-intelligence/SKILL.md` describes default error-aware mapping,
  routes object-access questions to IDOR/BOLA rather than merging the skills,
  keeps Attempts/MapStore/Hypothesis/Findings responsibilities separate, and
  explicitly excludes baseline Akamai/other branded edge errors from Error Store
  unless a controlled differential provides a documented novelty basis.

## Evidence

- RED: `BOUNTY_CORE_TEST_SOURCE=<core-source> python3 -m pytest
  agents/test_error_store.py -q` failed before `agents/error_store.py` existed.
- GREEN: `BOUNTY_CORE_TEST_SOURCE=<core-source> python3 -m pytest
  agents/test_error_store.py -q` passed after the wrapper was added and again
  after the documented global-option order and route (`--subject`) query filter
  were corrected.
- Independent review also identified the Core free-text bearer-redaction blocker;
  BBH remains gated on repair commit `75cbcc6` being re-reviewed and integrated
  into Core beta.
- Existing broader BBH tests currently fail to collect/run in this environment
  because their subprocess fixtures clear `PYTHONPATH` while the checkout does
  not have its pinned Bounty Core dependency installed. This is tracked as
  `PC-20260904-173501-3134d32b`; it is not attributed to Error Store behavior.

## Activation boundary

Do not merge or activate this BBH branch until the Core commit has independent
review, an immutable reviewed beta ref exists, and this branch pins that exact
ref in `requirements-bounty-core.txt`. Re-run the focused CLI test using the
pinned package, then independently review both diffs.

## Resume point

Await Core repair re-review for `75cbcc6193f5070052e30a12de214d9e2b5b1904`;
if accepted, merge it to Core beta, pin that resulting immutable beta commit here,
run isolated focused regression tests, then re-review and integrate BBH.
