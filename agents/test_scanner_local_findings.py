"""Guardrails for scanner-local finding collectors.

These scanners may emit local JSON/Markdown/campaign artifacts, but BUGSPEC-2
canonical ledger writes must stay in the team orchestration layer after review.
"""

from __future__ import annotations

import ast
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from agents import secrets_finder, zero_day_hunter  # noqa: E402


CANONICAL_LEDGER_MODULES = {
    "agents.ledger",
    "agents.ledger_v2",
    "bounty_core.ledger",
}


def _imports_for(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
    return imports


class ScannerLocalFindingGuardrailTests(unittest.TestCase):
    def test_zero_day_hunter_route_local_constants_and_generic_names_are_not_tainted(self) -> None:
        source = """
import json
import os

@app.route("/health")
def healthcheck():
    payload = "uptime"
    os.system("uptime")
    os.system(payload)
    json.loads("{}")
""".strip()

        findings = zero_day_hunter.PythonAnalyzer(Path("app.py"), source).analyze()

        self.assertEqual(findings, [])

    def test_zero_day_hunter_route_context_only_amplifies_proven_request_taint(self) -> None:
        source = """
import os

@app.route("/run")
def handler(request):
    os.system(request.args.get("cmd"))
""".strip()

        findings = zero_day_hunter.PythonAnalyzer(Path("app.py"), source).analyze()

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "python-os-command-injection")
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_scanner_modules_do_not_import_canonical_ledger_writers(self) -> None:
        for module in (zero_day_hunter, secrets_finder):
            path = Path(module.__file__).resolve()
            imported = _imports_for(path)
            self.assertTrue(
                CANONICAL_LEDGER_MODULES.isdisjoint(imported),
                f"{path.name} imported canonical ledger modules: "
                f"{sorted(CANONICAL_LEDGER_MODULES & imported)}",
            )

    def test_zero_day_hunter_add_finding_is_scanner_local_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir) / "app.py"
            source_path.write_text(
                "def handler(request):\n"
                "    return eval(request.args.get('cmd'))\n",
                encoding="utf-8",
            )

            hunter = zero_day_hunter.ZeroDayHunter(severity="MEDIUM", lang="python")
            with patch("bounty_core.ledger.add_finding") as ledger_add:
                files_scanned, findings = hunter.scan_file(source_path)

            self.assertEqual(files_scanned, 1)
            self.assertEqual(len(findings), 1)
            ledger_add.assert_not_called()

    def test_secrets_finder_save_results_keeps_legacy_local_sinks_outside_ledger(self) -> None:
        class FakeCampaignState:
            instances: list["FakeCampaignState"] = []

            def __init__(self) -> None:
                self.add_finding = Mock()
                self.instances.append(self)

        finding = secrets_finder.FindingRecord(
            type="github_token",
            severity="CRITICAL",
            value="ghp_" + "A" * 36,
            source_file="bundle.js",
            source_path="/tmp/bundle.js",
            line_number=7,
            line_context="const token = 'ghp_...';",
            description="GitHub token found in source",
            impact="Can permit repository, package, or workflow access",
            source_kind="js",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            finder = secrets_finder.SecretsFinder(
                program="Example Program",
                campaign_id="campaign-1",
                max_workers=1,
            )
            finder._add_finding(finding)

            with (
                patch("bounty_core.ledger.add_finding") as ledger_add,
                patch.object(secrets_finder, "CampaignState", FakeCampaignState),
                patch.object(secrets_finder, "create_finding", Mock(return_value={"id": "local-1"})),
                patch.object(secrets_finder, "save_finding", Mock(return_value="/tmp/local-1.json")),
            ):
                outputs = finder.save_results(Path(tmpdir) / "out")

            self.assertTrue(Path(outputs["json"]).is_file())
            self.assertTrue(Path(outputs["report"]).is_file())
            self.assertTrue(Path(outputs["meta"]).is_file())
            ledger_add.assert_not_called()
            self.assertEqual(len(FakeCampaignState.instances), 1)
            FakeCampaignState.instances[0].add_finding.assert_called_once()


if __name__ == "__main__":
    unittest.main()
