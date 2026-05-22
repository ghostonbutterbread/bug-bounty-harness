"""Focused tests for shared hunting policy resolution and prompt injection."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agents.base_team.review import build_review_prompt  # noqa: E402
from agents.base_team_core import parse_args as parse_base_team_args  # noqa: E402
import agents.hunting_policy as hunting_policy_module  # noqa: E402
from agents.hunting_policy import (  # noqa: E402
    appmap_candidate_policy_metadata,
    apply_appmap_promotion_policy,
    resolve_hunting_policy,
    resolve_policy_selection,
)
from agents.zero_day_team import _parse_cli_args as parse_zero_day_args  # noqa: E402


class HuntingPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.tmp = Path(self.tempdir.name)

    def test_clean_python_process_can_import_agents_package_from_repo_root(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        result = subprocess.run(
            [sys.executable, "-c", "import agents.hunting_policy"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_default_policy_selection_is_off_until_explicitly_enabled(self) -> None:
        self.assertEqual(resolve_policy_selection(None), "off")
        self.assertFalse(resolve_hunting_policy(target_kind="electron-exe", target_path=self.tmp).enabled)

    def test_auto_enables_for_electron_target_kind(self) -> None:
        policy = resolve_hunting_policy("auto", target_kind="electron-exe", target_path=self.tmp)

        self.assertTrue(policy.enabled)
        self.assertEqual(policy.id, "electron-application-first-loose")
        self.assertEqual(policy.mode, "auto")
        self.assertEqual(dict(policy)["id"], "electron-application-first-loose")

    def test_auto_enables_for_app_asar_package_evidence(self) -> None:
        package_json = self.tmp / "app_asar" / "resources" / "app.asar" / "package.json"
        package_json.parent.mkdir(parents=True)
        package_json.write_text('{"main":"index.js","devDependencies":{"electron":"^30.0.0"}}', encoding="utf-8")

        policy = resolve_hunting_policy("auto", target_kind=None, target_path=self.tmp)

        self.assertTrue(policy.enabled)
        self.assertEqual(policy.id, "electron-application-first-loose")

    def test_off_disables_and_aliases_resolve(self) -> None:
        off_policy = resolve_hunting_policy("none", target_kind="electron-exe", target_path=self.tmp)
        alias_policy = resolve_hunting_policy("electron-entry-first", target_path=self.tmp)

        self.assertFalse(off_policy.enabled)
        self.assertEqual(off_policy.id, "off")
        self.assertTrue(alias_policy.enabled)
        self.assertEqual(alias_policy.id, "electron-application-first-loose")

    def test_auto_non_electron_target_is_disabled(self) -> None:
        policy = resolve_hunting_policy("auto", target_kind="web", target_path=self.tmp)

        self.assertFalse(policy.enabled)

    def test_explicit_off_wins_over_policy_config(self) -> None:
        config = self.tmp / "policy.json"
        config.write_text('{"id":"custom-policy","enabled":true}', encoding="utf-8")

        off_policy = resolve_hunting_policy("off", target_kind="electron-exe", target_path=self.tmp, policy_config=config)
        no_triage_policy = resolve_hunting_policy(
            resolve_policy_selection("auto", no_triage_policy=True),
            target_kind="electron-exe",
            target_path=self.tmp,
            policy_config=config,
        )

        self.assertFalse(off_policy.enabled)
        self.assertEqual(off_policy.id, "off")
        self.assertFalse(no_triage_policy.enabled)
        self.assertEqual(no_triage_policy.id, "off")

    def test_custom_policy_config_is_neutral_and_accepts_custom_selection(self) -> None:
        config = self.tmp / "policy.json"
        config.write_text('{"id":"custom-policy","enabled":true,"hunt_posture":"custom"}', encoding="utf-8")

        policy = resolve_hunting_policy("custom-policy", target_kind="web", target_path=self.tmp, policy_config=config)

        self.assertTrue(policy.enabled)
        self.assertEqual(policy.id, "custom-policy")
        self.assertEqual(policy.hunt_posture, "custom")
        self.assertEqual(policy.prioritize, [])
        self.assertEqual(policy.deprioritize, [])
        self.assertEqual(policy.allow_if_evidence, [])
        self.assertEqual(policy.applies_to, {})

    def test_named_policy_can_load_from_config_folder(self) -> None:
        policy = resolve_hunting_policy("electron-application-first-loose", target_path=self.tmp)

        self.assertTrue(policy.enabled)
        self.assertEqual(policy.id, "electron-application-first-loose")
        self.assertIn("ipc", policy.deprioritize)

    def test_future_named_policy_can_load_from_config_folder(self) -> None:
        config_dir = self.tmp / "policies"
        config_dir.mkdir()
        (config_dir / "strict-program-scope.json").write_text(
            '{"id":"strict-program-scope","enabled":true,"hunt_posture":"scope-strict"}',
            encoding="utf-8",
        )
        original_dir = hunting_policy_module.DEFAULT_POLICY_CONFIG_DIR
        hunting_policy_module.DEFAULT_POLICY_CONFIG_DIR = config_dir
        self.addCleanup(setattr, hunting_policy_module, "DEFAULT_POLICY_CONFIG_DIR", original_dir)

        policy = resolve_hunting_policy("strict-program-scope", target_kind="web", target_path=self.tmp)

        self.assertTrue(policy.enabled)
        self.assertEqual(policy.id, "strict-program-scope")
        self.assertEqual(policy.hunt_posture, "scope-strict")
        self.assertEqual(policy.config_path, str(config_dir / "strict-program-scope.json"))

    def test_named_policy_prefers_ai_policies_package_root(self) -> None:
        ai_root = self.tmp / "ai-policies" / "policies"
        package_dir = ai_root / "bug-bounty"
        package_dir.mkdir(parents=True)
        package_path = package_dir / "desktop-entry-first.json"
        package_path.write_text(
            '{"id":"desktop-entry-first","enabled":true,"hunt_posture":"repo-packaged"}',
            encoding="utf-8",
        )

        with patch.dict("os.environ", {"AI_POLICIES_ROOT": str(ai_root)}):
            policy = resolve_hunting_policy("desktop-entry-first", target_kind="electron-exe", target_path=self.tmp)

        self.assertTrue(policy.enabled)
        self.assertEqual(policy.id, "desktop-entry-first")
        self.assertEqual(policy.hunt_posture, "repo-packaged")
        self.assertEqual(policy.config_path, str(package_path))

    def test_auto_electron_policy_can_resolve_from_ai_policies_package_root(self) -> None:
        ai_root = self.tmp / "ai-policies" / "policies"
        package_dir = ai_root / "bug-bounty"
        package_dir.mkdir(parents=True)
        package_path = package_dir / "electron-application-first-loose.json"
        package_path.write_text(
            '{"id":"electron-application-first-loose","enabled":true,"hunt_posture":"repo-packaged"}',
            encoding="utf-8",
        )

        with patch.dict("os.environ", {"AI_POLICIES_ROOT": str(ai_root)}):
            policy = resolve_hunting_policy("auto", target_kind="electron-exe", target_path=self.tmp)

        self.assertTrue(policy.enabled)
        self.assertEqual(policy.id, "electron-application-first-loose")
        self.assertEqual(policy.mode, "auto")
        self.assertEqual(policy.hunt_posture, "repo-packaged")
        self.assertEqual(policy.config_path, str(package_path))

    def test_prompt_snippet_uses_soft_deprioritization_language(self) -> None:
        policy = resolve_hunting_policy("electron-application-first", target_path=self.tmp)
        snippet = policy.snippet("agent").lower()

        self.assertIn("guides priority", snippet)
        self.assertIn("not a hard ban", snippet)
        self.assertIn("soft-deprioritized", snippet)
        self.assertIn("not banned", snippet)
        self.assertIn("ipc", snippet)

    def test_review_prompt_includes_policy_metadata_only_when_enabled(self) -> None:
        finding = {
            "file": "missing.js",
            "line": 1,
            "type": "HostRpc exposed",
            "description": "Bridge method appears reachable.",
        }
        enabled = resolve_hunting_policy("electron-application-first", target_path=self.tmp)
        disabled = resolve_hunting_policy("off", target_kind="electron-exe", target_path=self.tmp)

        enabled_prompt = build_review_prompt(
            finding,
            self.tmp,
            resolve_source_path=lambda _file: None,
            source_excerpt=lambda _path, _line: "UNAVAILABLE",
            safe_int=lambda value: int(value or 0),
            policy=enabled,
            policy_snippet=enabled.snippet("review"),
        )
        disabled_prompt = build_review_prompt(
            finding,
            self.tmp,
            resolve_source_path=lambda _file: None,
            source_excerpt=lambda _path, _line: "UNAVAILABLE",
            safe_int=lambda value: int(value or 0),
            policy=disabled,
            policy_snippet=disabled.snippet("review"),
        )

        self.assertIn("policy_id", enabled_prompt)
        self.assertIn("finding_role", enabled_prompt)
        self.assertIn("entry_status", enabled_prompt)
        self.assertIn("impact_amplifiers", enabled_prompt)
        self.assertIn("standalone critical", enabled_prompt)
        self.assertIn('"chain_requirements":"specific prerequisite needed for exploitation, or empty string"', enabled_prompt)
        self.assertNotIn("finding_role", disabled_prompt)
        self.assertNotIn("impact_amplifiers", disabled_prompt)

    def test_cli_parse_policy_flags(self) -> None:
        zero_args = parse_zero_day_args(
            [
                "canva",
                str(self.tmp),
                "--triage-policy",
                "electron-entry-first",
                "--policy-config",
                str(self.tmp / "policy.json"),
            ]
        )
        base_args = parse_base_team_args(
            [
                "--program",
                "canva",
                "--target-path",
                str(self.tmp),
                "--team-type",
                "0day_team",
                "--no-triage-policy",
            ]
        )

        self.assertEqual(zero_args.triage_policy, "electron-entry-first")
        self.assertEqual(zero_args.policy_config, str(self.tmp / "policy.json"))
        self.assertTrue(base_args.no_triage_policy)
        self.assertEqual(base_args.hunting_policy, "off")

    def test_appmap_policy_holds_deprioritized_ipc_candidate_without_app_entry(self) -> None:
        policy = resolve_hunting_policy("electron-application-first", target_path=self.tmp)
        candidate = {
            "id": "C0001",
            "flow_id": "F0001",
            "surface_id": "S0001",
            "score": 0.86,
            "priority": "high",
            "question": "Can raw IPC reach exec?",
            "source": {"id": "S0001", "kind": "ipc", "file": "src/main.js", "line": 10},
            "boundary": {"id": "B0001", "kind": "electron-boundary", "file": "src/main.js", "line": 11},
            "sink": {"id": "K0001", "kind": "process-exec", "file": "src/main.js", "line": 12},
        }

        metadata = appmap_candidate_policy_metadata(candidate, policy)
        promoted, rejected = apply_appmap_promotion_policy([candidate], [], policy)

        self.assertEqual(metadata["decision"], "hold")
        self.assertEqual(metadata["reportability"], "hold_for_chain")
        self.assertEqual(metadata["entry_status"], "missing")
        self.assertEqual(metadata["policy_id"], "electron-application-first-loose")
        self.assertEqual(promoted, [])
        self.assertEqual(rejected[0]["candidate_id"], "C0001")
        self.assertTrue(rejected[0]["hold_for_chain"])

    def test_appmap_policy_promotes_app_entry_candidate_with_submit_reportability(self) -> None:
        policy = resolve_hunting_policy("electron-application-first", target_path=self.tmp)
        candidate = {
            "id": "C0001",
            "flow_id": "F0001",
            "surface_id": "S0001",
            "score": 0.8,
            "priority": "high",
            "question": "Can config reach exec?",
            "source": {"id": "S0001", "kind": "config", "file": "src/main.js", "line": 10},
            "boundary": {"id": "B0001", "kind": "electron-boundary", "file": "src/main.js", "line": 11},
            "sink": {"id": "K0001", "kind": "process-exec", "file": "src/main.js", "line": 12},
        }

        metadata = appmap_candidate_policy_metadata(candidate, policy)
        promoted, rejected = apply_appmap_promotion_policy([candidate], [], policy)

        self.assertEqual(metadata["decision"], "promote")
        self.assertEqual(metadata["reportability"], "submit")
        self.assertEqual(metadata["finding_role"], "entry")
        self.assertEqual(metadata["entry_status"], "proven")
        self.assertEqual(len(promoted), 1)
        self.assertEqual(promoted[0]["policy"]["policy_id"], "electron-application-first-loose")
        self.assertEqual(rejected, [])


if __name__ == "__main__":
    unittest.main()
