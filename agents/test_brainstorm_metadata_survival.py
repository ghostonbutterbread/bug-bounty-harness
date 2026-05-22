from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from agents.base_team import AgentSpec, BaseTeam
from agents.base_team.review import stage2_ghost_review
from agents.brainstorm_spec import parse_brainstorm_spec, spec_to_agent_intents
from agents.ledger import ledger_get


class DummyTeam(BaseTeam):
    def get_static_profiles(self) -> list[AgentSpec]:
        return []

    def generate_dynamic_from_surfaces(
        self,
        surfaces: list[dict],
        *,
        snapshot_id: str,
    ) -> list[AgentSpec]:
        return []


def _brainstorm_spec_text() -> str:
    return """# Brainstorm Spec: Canva Desktop EXE

## Metadata
- Program: canva
- Family: binaries
- Lane: exe
- Target kind: electron-exe
- Target path: input/app_asar
- Created: 2026-04-30
- Status: active

## Target mental model
Canva Desktop is an Electron application wrapping a rich design/editor web app.

## Impact primitives
### P001 - ElectronBridge host RPC access
- Source: `window.ElectronBridge.requestMessagePort`
- Impact: renderer JS can potentially reach host RPC modules
- Status: active

## Hypotheses
### H001 - SVG import can create renderer script execution
- Status: untested
- Priority: high
- Surface: import-upload-render
- Entry point: user imports or pastes SVG/design asset
- Expected chain: imported SVG/pasted content -> renderer script execution -> ElectronBridge host RPC
- Suggested agents:
  - canva-svg-import-xss
- Focus files:
  - dist/**/*.js
  - **/*svg*
- Tags: xss, import, renderer, electron-bridge

## Coverage log
| Hypothesis | Agent | Status | Result | Linked FIDs | Run ID | Notes |
|---|---|---|---|---|---|---|
"""


class BrainstormMetadataSurvivalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.tmp = Path(self.tempdir.name)
        self.home = self.tmp / "home"
        self.home.mkdir(parents=True, exist_ok=True)
        self.home_patcher = patch.dict(os.environ, {"HOME": str(self.home)})
        self.home_patcher.start()
        self.addCleanup(self.home_patcher.stop)

        self.target = self.tmp / "target"
        self.target.mkdir()
        (self.target / "dist").mkdir()
        (self.target / "dist" / "renderer.js").write_text("renderSvg(uploaded);\n", encoding="utf-8")
        self.output_root = self.tmp / "canonical-storage"
        self.team = DummyTeam("canva", "apk", self.target, output_root=self.output_root, max_agents=1)

    def _metadata(self) -> dict:
        spec_path = self.tmp / "brainstorm" / "spec.md"
        spec_path.parent.mkdir(parents=True, exist_ok=True)
        spec_path.write_text(_brainstorm_spec_text(), encoding="utf-8")
        spec = parse_brainstorm_spec(spec_path)
        intent = spec_to_agent_intents(spec)[0]
        return intent.finding_metadata()

    def _ledger_payload(self) -> dict:
        return json.loads(self.team.ledger_path.read_text(encoding="utf-8"))

    def _reviewed_finding(self, finding: dict, *, note: str) -> dict:
        return {
            **finding,
            "review_tier": "CONFIRMED",
            "tier": "CONFIRMED",
            "safety_assumption": "Imported SVG content is sanitized before renderer preview.",
            "assumption_break": "The preview path reaches script-capable renderer code.",
            "intended_behavior_analysis": "Script execution from imported assets is unintended.",
            "exploit_path": "Victim imports attacker SVG and preview executes renderer script.",
            "impact": "Renderer script execution can reach privileged bridge calls.",
            "review_notes": note,
        }

    def test_brainstorm_agent_intent_metadata_survives_normal_finding_lifecycle(self) -> None:
        expected_metadata = self._metadata()
        raw_finding = {
            **expected_metadata,
            "agent": expected_metadata["brainstorm_agent_key"],
            "category": "class",
            "class_name": "xss",
            "type": "SVG import renderer script execution",
            "file": "dist/renderer.js",
            "line": 1,
            "description": "SVG preview rendering reaches script-capable renderer code.",
            "severity": "HIGH",
            "source": "user-supplied SVG import",
            "trust_boundary": "imported file to renderer preview",
            "flow_path": "import -> preview -> renderer",
            "sink": "renderSvg(uploaded)",
            "exploitability": "Attacker shares an SVG/design asset that the victim imports.",
        }

        normalized = self.team._normalize_finding(raw_finding)
        self.assertIsNotNone(normalized)
        for key, value in expected_metadata.items():
            self.assertEqual(normalized[key], value)

        reserved = self.team.deduplicate_findings([raw_finding], self.team.load_ledger())
        self.assertEqual(len(reserved), 1)
        self.assertEqual(reserved[0]["fid"], "D01")
        for key, value in expected_metadata.items():
            self.assertEqual(reserved[0][key], value)

        confirmed, dormant, novel = stage2_ghost_review(
            reserved,
            self.target,
            self.team.program,
            self.team.team_type,
            output_root=self.output_root,
            review_single=lambda finding, _target: self._reviewed_finding(
                finding,
                note="Confirmed for metadata survival test.",
            ),
            max_workers=1,
            write_reports=False,
        )
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(dormant, [])
        self.assertEqual(novel, [])
        for key, value in expected_metadata.items():
            self.assertEqual(confirmed[0][key], value)

        updated = self.team.update_reviewed_findings(confirmed)
        self.assertEqual(len(updated), 1)
        for key, value in expected_metadata.items():
            self.assertEqual(updated[0][key], value)

        readback = ledger_get(
            self.team.program,
            "D01",
            family=self.team.storage.family,
            lane=self.team.storage.lane,
            root_override=self.team.storage.base_root,
        )
        self.assertIsNotNone(readback)
        for key, value in expected_metadata.items():
            self.assertEqual(readback[key], value)

        stored = self._ledger_payload()["findings"][0]
        for key, value in expected_metadata.items():
            self.assertEqual(stored[key], value)

    def test_brainstorm_metadata_survives_parallel_review_with_staggered_completion(self) -> None:
        expected_metadata = self._metadata()
        raw_findings = [
            {
                **expected_metadata,
                "agent": expected_metadata["brainstorm_agent_key"],
                "category": "class",
                "class_name": "xss",
                "type": "SVG import renderer script execution",
                "file": "dist/renderer.js",
                "line": 1,
                "description": "SVG preview rendering reaches script-capable renderer code.",
                "severity": "HIGH",
                "source": "user-supplied SVG import",
                "trust_boundary": "imported file to renderer preview",
                "flow_path": "import -> preview -> renderer",
                "sink": "renderSvg(uploaded)",
                "exploitability": "Attacker shares an SVG/design asset that the victim imports.",
            },
            {
                **expected_metadata,
                "agent": expected_metadata["brainstorm_agent_key"],
                "category": "class",
                "class_name": "xss",
                "type": "Pasted SVG renderer script execution",
                "file": "dist/renderer.js",
                "line": 1,
                "description": "Pasted SVG preview rendering reaches script-capable renderer code.",
                "severity": "HIGH",
                "source": "user-pasted SVG import",
                "trust_boundary": "pasted file to renderer preview",
                "flow_path": "paste -> preview -> renderer",
                "sink": "renderSvg(uploaded)",
                "exploitability": "Attacker convinces the victim to paste an SVG payload.",
            },
        ]

        reserved = self.team.deduplicate_findings(raw_findings, self.team.load_ledger())
        self.assertEqual([finding["fid"] for finding in reserved], ["D01", "D02"])

        def review_single(finding: dict, _target: Path) -> dict:
            if finding["fid"] == "D01":
                time.sleep(0.05)
            return self._reviewed_finding(finding, note="Confirmed for parallel metadata survival test.")

        confirmed, dormant, novel = stage2_ghost_review(
            reserved,
            self.target,
            self.team.program,
            self.team.team_type,
            output_root=self.output_root,
            review_single=review_single,
            max_workers=2,
            write_reports=False,
        )

        self.assertEqual(len(confirmed), 2)
        self.assertEqual(dormant, [])
        self.assertEqual(novel, [])
        by_fid = {finding["fid"]: finding for finding in confirmed}
        self.assertEqual(set(by_fid), {"D01", "D02"})
        for finding in by_fid.values():
            for key, value in expected_metadata.items():
                self.assertEqual(finding[key], value)


if __name__ == "__main__":
    unittest.main()
