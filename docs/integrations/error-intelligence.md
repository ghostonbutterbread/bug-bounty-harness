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
- Required Core dependency: reviewed Core `beta` commit
  `0a73cd7e982f06fc5c830e5658c201a9593f0fc3`, now pinned in
  `requirements-bounty-core.txt`.

## Implemented contract

- `agents/error_store.py` follows BBH's global `--root`, `--family`, and
  `--lane` pattern and exposes `record` and bounded `query` commands.
- `record` forwards only structured, redaction-enforced Error Store fields;
  `--layer edge` additionally requires a persisted `--novelty-basis`, so routine
  branded/WAF templates are rejected before any event is written.
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
- Core bearer-redaction repair was independently accepted and integrated into
  Core beta as `0a73cd7`; this branch now pins that exact immutable commit.
- Existing broader BBH tests currently fail to collect/run in this environment
  because their subprocess fixtures clear `PYTHONPATH` while the checkout does
  not have its pinned Bounty Core dependency installed. This is tracked as
  `PC-20260904-173501-3134d32b`; it is not attributed to Error Store behavior.

## Activation boundary

Do not merge or activate this BBH branch until the Core commit has independent
review, an immutable reviewed beta ref exists, and this branch pins that exact
ref in `requirements-bounty-core.txt`. Re-run the focused CLI test using the
pinned package, then independently review both diffs.

## Activation decision

Independent re-review accepted edge-gate commit
`d9be3f75405cbff13b59bb764e9ebe2b1dd397fd`: missing edge novelty evidence is
rejected before storage, a supplied basis is structured/redacted, and non-edge
records remain unaffected (`2 passed`). The feature is approved for BBH `beta`
integration; it does not activate any runtime agent or generate network traffic.

## Resume point

Merge this clean reviewed feature into BBH `beta`, install the pinned dependency
in an isolated temporary test environment, run the BBH suite, then push beta.
