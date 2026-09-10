# JavaScript native fast-model fanout

## Intent

Remove the stale `agents/js_team.py` planning layer from `/js deep`. Deep JavaScript review should fan out directly through the active CLI's native delegation capability, prefer the current fast sibling of the parent model's generation when available, and return to the parent model for synthesis.

## Ownership

- Task: `PC-20260910-180201-1040cd76`
- Branch: `fix/js-native-fast-fanout`
- Worktree: `/home/ryushe/worktrees/bbh-js-native-fast-fanout`
- Base: `eefb8d4b2b47ef33565c71410df94d9efc213d04` (`beta`)
- Target: `beta`

## Contract

- `js_analyzer.py inventory` remains the artifact-producing prerequisite.
- The active parent reads the inventory and directly dispatches bounded mapper/anomaly workers.
- Workers use the active CLI's native model routing. The skill prefers the current fast sibling of the parent model's generation but remains portable across CLIs, does not hardcode model names, and does not claim reduced cost when the selection was unavailable.
- The parent model verifies cited packet evidence, synthesizes stage-one results, and selects any specialist follow-up wave.
- Offline workers do not make live target requests; live validation remains a separate policy-governed handoff.
- The analyzer labels hardcoded regex/keyword output as deterministic, non-exhaustive seed coverage. Hits are starting points; misses cannot establish completion or absence.
- Ambiguous framework behavior, computed routes, semantic dataflow, and unfamiliar technology interpretation stay with source-reading agents rather than scripts.
- Future BBH helpers inherit the same observed-fact/seed/unknown contract from the executable and RAG templates.
- Concurrent agent review is allowed only after a producer atomically publishes a complete independent packet; shared indexes and outputs are not concurrently mutated by workers.
- Agent-discovered deterministic rules require preserved evidence, a failing fixture, implementation, and review before promotion into a script.
- Remove `js_team.py`, its tests, and all live documentation references.

## Evidence

- Baseline: `python3 -m pytest agents/test_js_team.py -q` → 4 passed; confirms the current wrapper exists and intentionally refuses execution rather than spawning workers.
- Focused suite: `python3 -m pytest agents/test_js*.py -q` → 28 passed after the native-fanout, coverage, and atomic-publication changes.
- RED: `python3 -m pytest agents/test_js_analyzer.py::test_inventory_writes_metadata_and_packets -q` failed with missing `signal_coverage` before implementation.
- GREEN: the same focused test passed after adding machine-readable coverage metadata and packet caveats.
- RED: `python3 -m pytest agents/test_js_analyzer.py::test_write_text_atomic_publishes_complete_packet_without_temp_file -q` failed because no atomic publisher existed.
- GREEN: the atomic publisher and inventory packet test passed together (`2 passed`).
- Review RED: packet mode remained `0600` and a failed write leaked its hidden
  temporary file; both focused regressions failed before correction.
- Review GREEN: atomic packets now publish as `0644`, failure cleanup removes
  the temporary file, and both focused regressions pass.
- Static checks: `git diff --check` and `python3 -m compileall -q agents` → passed.
- Reference audit: bounded repository search found no live `js_team.py`, `JavaScript Team`, `staged wrapper`, `js_team_plan`, or old MapStore candidate-path references outside this branch-local dossier.
- Independent review: blocked the first release candidate on two stale skill
  sentences, atomic packet permissions/cleanup, and ambiguous concurrent/model
  discovery wording; the branch includes focused corrections for re-review.

## Activation boundary

Repository change only. Merging to `beta` does not change an active synchronized
skill lane or runtime configuration. Fast-worker selection depends on whichever
CLI loads the skill and its native advertised model-routing capabilities.

## Next action

Implementation checkpoint: `d9b399f` on `fix/js-native-fast-fanout` (current branch tip will include a later dossier-only handoff commit). Request independent re-review of the full branch, including the cross-cutting script contract and CLI-portable model routing.
