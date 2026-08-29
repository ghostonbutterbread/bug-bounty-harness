# JS source-map packet-bounds dossier

- Status: reviewed fix ready for beta.
- Feature branch: `fix/js-source-map-packet-bounds`.
- Base: `beta` at `7807c784aae83243d6ca3acf2a6f8bd2604b0eeb`.
- Target: `beta`.

## Contract

Source-map review now has explicit per-bundle packet and expanded-source-byte limits, records truncated modules, rejects unsafe chunk overlap settings, and recognizes legacy `//@ sourceMappingURL` directives. This resolves the independent review’s resource-safety and compatibility findings.

## Evidence

`uv run --with pytest pytest agents/test_js_analyzer.py -q` passed: 20 tests. `python3 -m py_compile agents/js_analyzer.py` passed.

## Next action

Commit, merge into clean beta, rerun focused tests, and remove this branch-local dossier from beta.
