#!/usr/bin/env python3
"""Focused tests for cron_orchestrator.py."""

from __future__ import annotations

import contextlib
import io
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import agents.cron_orchestrator as M


class FakeScopeValidator:
    def __init__(self, program: str, strict: bool = False):
        self.program = program
        self.strict = strict

    def is_in_scope(self, target: str) -> bool:
        return target.endswith("example.com")


class TestCronOrchestrator(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.naabu_dir = self.root / "naabu"
        self.naabu_dir.mkdir()
        self.naabu_ports = self.naabu_dir / "ports.jsonl"
        self.naabu_ports.write_text(
            json.dumps({"host": "api.example.com", "port": 8443}) + "\n"
            + json.dumps({"host": "api.example.com", "port": 9443}) + "\n",
            encoding="utf-8",
        )
        self.url_db = self.root / "url_index.sqlite"
        self._init_url_db()
        self.config = self._config()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _init_url_db(self) -> None:
        with sqlite3.connect(self.url_db) as conn:
            conn.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, host TEXT)")
            conn.execute(
                "INSERT INTO urls (url, host) VALUES (?, ?)",
                ("https://api.example.com/v1/users", "api.example.com"),
            )

    def _config(self) -> dict:
        return {
            "version": 1,
            "defaults": {
                "rate_limit": {
                    "global_http_rps": 15,
                    "unauthenticated_rps": 15,
                    "authenticated_rps": 15,
                }
            },
            "platforms": {"bugcrowd": {"state": "active"}},
            "programs": {
                "demo": {
                    "platform": "bugcrowd",
                    "state": "active",
                    "targets": {
                        "home": {"base_urls": ["https://www.example.com"]},
                        "api": {"base_urls": ["https://api.example.com"]},
                    },
                    "target_selection": {
                        "strategy": "recon_ry_ranked_agent_selected_queue",
                        "default_target": "home",
                        "ranking_inputs": [str(self.url_db), str(self.naabu_dir)],
                    },
                    "jobs": {
                        "nmap_enrichment": {
                            "state": "manual_review_required",
                            "mode": "passive_enrichment_from_naabu",
                            "inputs": {
                                "naabu_ports": [str(self.naabu_ports)],
                                "require_saved_scope": True,
                                "max_hosts_per_run": 3,
                                "max_ports_per_host": 20,
                            },
                            "command_template": [
                                "nmap",
                                "-sV",
                                "--version-light",
                                "-Pn",
                                "-T2",
                                "-p",
                                "<naabu-discovered-ports>",
                                "<selected-host>",
                            ],
                            "outputs": {
                                "run_root": str(self.root / "tools" / "nmap" / "runs" / "<run-id>"),
                            },
                        },
                        "juicy_target_fuzz": {
                            "state": "manual_review_required",
                            "command_template": [
                                "ffuf",
                                "-u",
                                "<selected-base-url>/FUZZ",
                                "-w",
                                "<composed-wordlist>",
                                "-rate",
                                "<effective-rate>",
                            ],
                            "wordlists": {
                                "strategy": "catalog_smart_target_mapping",
                                "catalog_roots": [str(self.root / "wordlists")],
                            },
                        },
                        "authenticated_parameter_mining": {
                            "state": "manual_review_required",
                            "inputs": {"endpoint_queue": str(self.root / "queue.txt")},
                            "command_template": [
                                "arjun",
                                "-i",
                                "<endpoint-queue>",
                                "-oJ",
                                "<run-root>/raw/arjun.json",
                            ],
                        },
                    },
                }
            },
        }

    def test_validate_accepts_configured_jobs(self) -> None:
        self.assertEqual(M.validate_config(self.config), [])

    def test_validate_rejects_unknown_job(self) -> None:
        data = yaml.safe_load(yaml.safe_dump(self.config))
        data["programs"]["demo"]["jobs"]["mystery"] = {}
        errors = M.validate_config(data)
        self.assertTrue(any("unknown job mystery" in error for error in errors))

    def test_read_lines_defaults_to_unlimited(self) -> None:
        path = self.root / "large.txt"
        path.write_text("\n".join(f"https://{index}.example.com" for index in range(6001)), encoding="utf-8")

        self.assertEqual(len(M.read_lines(path)), 6001)
        self.assertEqual(len(M.read_lines(path, limit=3)), 3)

    def test_urls_from_url_ingest_defaults_to_unlimited(self) -> None:
        with sqlite3.connect(self.url_db) as conn:
            conn.executemany(
                "INSERT INTO urls (url, host) VALUES (?, ?)",
                [(f"https://api.example.com/{index}", "api.example.com") for index in range(6000)],
            )

        self.assertEqual(len(M.urls_from_url_ingest(self.url_db)), 6001)
        self.assertEqual(len(M.urls_from_url_ingest(self.url_db, limit=10)), 10)

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_plan_selects_api_target_and_builds_nmap_command_from_naabu(self) -> None:
        payload = M.plan(self.config, "demo")
        self.assertEqual(payload["selected_target"]["host"], "api.example.com")
        nmap_job = payload["jobs"][0]
        self.assertEqual(nmap_job["status"], "planned")
        self.assertEqual(nmap_job["ports"], [8443, 9443])
        self.assertEqual(nmap_job["command"][-2:], ["8443,9443", "api.example.com"])
        self.assertIn("has naabu/nmap service hint", payload["selected_target"]["reasons"])

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_nmap_enrichment_skips_without_naabu_ports(self) -> None:
        self.naabu_ports.unlink()
        payload = M.plan(self.config, "demo")
        nmap_job = payload["jobs"][0]
        self.assertEqual(nmap_job["status"], "skipped")
        self.assertEqual(nmap_job["reason"], "missing_naabu_output_or_no_ports_for_selected_host")

    def test_parse_port_line_supports_json_text_and_url(self) -> None:
        self.assertEqual(M.parse_port_line('{"host":"api.example.com","port":8443}'), ("api.example.com", 8443))
        self.assertEqual(M.parse_port_line("api.example.com:9443"), ("api.example.com", 9443))
        self.assertEqual(M.parse_port_line("https://api.example.com:10443"), ("api.example.com", 10443))

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_rate_budget_splits_same_host_live_http_jobs(self) -> None:
        self.config["programs"]["demo"]["jobs"]["authenticated_parameter_mining"]["inputs"][
            "endpoint_queue"
        ] = str(self.root / "queue.txt")
        (self.root / "queue.txt").write_text("https://api.example.com/v1/users\n", encoding="utf-8")

        payload = M.plan(self.config, "demo")
        fuzz = next(job for job in payload["jobs"] if job["job"] == "juicy_target_fuzz")
        params = next(job for job in payload["jobs"] if job["job"] == "authenticated_parameter_mining")

        self.assertEqual(payload["rate_policy"]["global_http_rps"], 15)
        self.assertEqual(fuzz["rate_budget"]["allocated_rps"], 7)
        self.assertEqual(params["rate_budget"]["allocated_rps"], 7)
        self.assertEqual(fuzz["command"][-1], "7")

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_timeout_scales_with_wordlist_size_without_default_ceiling(self) -> None:
        wordlist = self.root / "big-wordlist.txt"
        wordlist.write_text("\n".join(f"candidate-{index}" for index in range(10000)), encoding="utf-8")
        self.config["programs"]["demo"]["jobs"]["juicy_target_fuzz"]["wordlists"]["include"] = [str(wordlist)]
        payload = M.plan(self.config, "demo")

        timeout = M._compute_timeout(
            {"timeout_seconds": 300, "timeout_seconds_max": None, "timeout_margin": 1.5},
            payload,
            self.config["programs"]["demo"],
        )

        self.assertEqual(timeout, 1000)

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_timeout_ceiling_is_only_applied_when_explicit(self) -> None:
        wordlist = self.root / "huge-wordlist.txt"
        wordlist.write_text("\n".join(f"candidate-{index}" for index in range(10000)), encoding="utf-8")
        self.config["programs"]["demo"]["jobs"]["juicy_target_fuzz"]["wordlists"]["include"] = [str(wordlist)]
        payload = M.plan(self.config, "demo")

        timeout = M._compute_timeout(
            {"timeout_seconds": 300, "timeout_seconds_max": 700, "timeout_margin": 1.5},
            payload,
            self.config["programs"]["demo"],
        )

        self.assertEqual(timeout, 700)

    def test_non_waf_fuzz_errors_do_not_create_stop_annotation(self) -> None:
        root = self.root / "ffuf-run"
        (root / "raw").mkdir(parents=True)
        (root / "logs").mkdir()
        (root / "raw" / "ffuf.json").write_text(
            json.dumps({"results": [{"status": 200, "length": 123}, {"status": 404, "length": 50}]}),
            encoding="utf-8",
        )
        (root / "logs" / "stdout.txt").write_text(
            "\n".join(["[ERROR] connection reset"] * 3000),
            encoding="utf-8",
        )
        (root / "logs" / "stderr.txt").write_text("connection reset\n" * 3000, encoding="utf-8")
        manifest = {"paths": {"root": str(root)}, "materialized_inputs": {"wordlist": {"candidate_count": 6001}}}

        M._check_cf_block("demo", {"job": "juicy_target_fuzz"}, root, manifest)

        self.assertNotIn("cloudflare_block", manifest)
        self.assertNotIn("consecutive_error_burst", manifest)

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_run_prepare_only_writes_manifests_without_execution(self) -> None:
        with patch.object(M, "DEFAULT_ARTIFACT_ROOT", self.root / "shared"):
            payload = M.run(self.config, "demo", execute=False, approve_manual=False)

        nmap_job = next(job for job in payload["jobs"] if job["job"] == "nmap_enrichment")
        manifest = json.loads(Path(nmap_job["manifest_path"]).read_text(encoding="utf-8"))
        self.assertEqual(payload["mode"], "prepare-only")
        self.assertEqual(manifest["status"], "prepared_not_executed")
        self.assertEqual(manifest["execution_decision"], "execute_flag_not_set")
        self.assertTrue(Path(nmap_job["run_root"], "command.txt").is_file())

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_prepare_fuzz_materializes_large_wordlist_without_truncation(self) -> None:
        wordlist = self.root / "large-fuzz.txt"
        wordlist.write_text("\n".join(f"candidate-{index}" for index in range(6001)), encoding="utf-8")
        self.config["programs"]["demo"]["jobs"]["juicy_target_fuzz"]["wordlists"]["include"] = [str(wordlist)]

        with patch.object(M, "DEFAULT_ARTIFACT_ROOT", self.root / "shared"):
            payload = M.run(self.config, "demo", execute=False, approve_manual=False)

        fuzz = next(job for job in payload["jobs"] if job["job"] == "juicy_target_fuzz")
        manifest = json.loads(Path(fuzz["manifest_path"]).read_text(encoding="utf-8"))
        command = Path(fuzz["run_root"], "command.txt").read_text(encoding="utf-8")
        composed = Path(manifest["materialized_inputs"]["wordlist"]["path"])
        self.assertEqual(manifest["materialized_inputs"]["wordlist"]["candidate_count"], 6001)
        self.assertEqual(len(M.read_lines(composed)), 6001)
        self.assertNotIn("<dry-run-composed-wordlist>", command)
        self.assertNotIn("<ffuf-run-root>", command)
        self.assertNotIn(" -nc ", command)
        self.assertIn(str(composed), command)

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_run_execute_requires_active_or_manual_approval(self) -> None:
        self.config["programs"]["demo"]["jobs"]["nmap_enrichment"]["state"] = "active"
        self.config["programs"]["demo"]["jobs"]["nmap_enrichment"]["command_template"] = [
            sys.executable,
            "-c",
            "print('cron-ok')",
        ]
        with patch.object(M, "DEFAULT_ARTIFACT_ROOT", self.root / "shared"):
            payload = M.run(self.config, "demo", execute=True, approve_manual=False)

        nmap_job = next(job for job in payload["jobs"] if job["job"] == "nmap_enrichment")
        manifest = json.loads(Path(nmap_job["manifest_path"]).read_text(encoding="utf-8"))
        stdout = Path(nmap_job["run_root"], "logs", "stdout.txt").read_text(encoding="utf-8")
        self.assertEqual(manifest["status"], "completed")
        self.assertEqual(manifest["execution_decision"], "active_execute_allowed")
        self.assertEqual(stdout.strip(), "cron-ok")

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_disabled_platform_blocks_execution_even_when_job_active(self) -> None:
        self.config["platforms"]["bugcrowd"]["state"] = "paused"
        self.config["programs"]["demo"]["jobs"]["nmap_enrichment"]["state"] = "active"
        self.config["programs"]["demo"]["jobs"]["nmap_enrichment"]["command_template"] = [
            sys.executable,
            "-c",
            "print('should-not-run')",
        ]
        with patch.object(M, "DEFAULT_ARTIFACT_ROOT", self.root / "shared"):
            payload = M.run(self.config, "demo", execute=True, approve_manual=False)

        nmap_job = next(job for job in payload["jobs"] if job["job"] == "nmap_enrichment")
        manifest = json.loads(Path(nmap_job["manifest_path"]).read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "blocked")
        self.assertEqual(manifest["execution_decision"], "platform_bugcrowd_paused")

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_manual_approval_auto_allowlists_in_scope_targets(self) -> None:
        self.config["programs"]["demo"]["jobs"]["nmap_enrichment"]["command_template"] = [
            sys.executable,
            "-c",
            "print('manual-ok')",
        ]
        with patch.object(M, "DEFAULT_ARTIFACT_ROOT", self.root / "shared"):
            # In-scope target + approve_manual → auto-allowlisted even without explicit approved_jobs
            scoped = M.run(self.config, "demo", execute=True, approve_manual=True)
            # Explicit allowlist still works as before
            allowed = M.run(
                self.config,
                "demo",
                execute=True,
                approve_manual=True,
                approved_jobs={"nmap_enrichment"},
            )

        scoped_nmap = next(job for job in scoped["jobs"] if job["job"] == "nmap_enrichment")
        allowed_nmap = next(job for job in allowed["jobs"] if job["job"] == "nmap_enrichment")
        scoped_manifest = json.loads(Path(scoped_nmap["manifest_path"]).read_text(encoding="utf-8"))
        allowed_manifest = json.loads(Path(allowed_nmap["manifest_path"]).read_text(encoding="utf-8"))
        self.assertEqual(scoped_manifest["status"], "completed")
        self.assertEqual(scoped_manifest["execution_decision"], "manual_review_approved_by_scope")
        self.assertEqual(allowed_manifest["status"], "completed")
        self.assertEqual(allowed_manifest["execution_decision"], "manual_review_approved")

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_live_http_job_without_rate_hook_is_blocked(self) -> None:
        queue = self.root / "queue.txt"
        queue.write_text("https://api.example.com/v1/users\n", encoding="utf-8")
        self.config["programs"]["demo"]["jobs"]["authenticated_parameter_mining"]["state"] = "active"
        self.config["programs"]["demo"]["jobs"]["authenticated_parameter_mining"]["inputs"]["endpoint_queue"] = str(queue)
        with patch.object(M, "DEFAULT_ARTIFACT_ROOT", self.root / "shared"):
            payload = M.run(self.config, "demo", execute=True)

        params = next(job for job in payload["jobs"] if job["job"] == "authenticated_parameter_mining")
        manifest = json.loads(Path(params["manifest_path"]).read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "blocked")
        self.assertEqual(manifest["execution_decision"], "live_http_rate_not_enforced_in_command")

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_subprocess_start_failure_is_recorded_and_does_not_abort_run(self) -> None:
        self.config["programs"]["demo"]["jobs"]["nmap_enrichment"]["state"] = "active"
        self.config["programs"]["demo"]["jobs"]["nmap_enrichment"]["command_template"] = [
            "/definitely/missing/ghost-command",
        ]
        with patch.object(M, "DEFAULT_ARTIFACT_ROOT", self.root / "shared"):
            payload = M.run(self.config, "demo", execute=True)

        nmap_job = next(job for job in payload["jobs"] if job["job"] == "nmap_enrichment")
        manifest = json.loads(Path(nmap_job["manifest_path"]).read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "blocked")
        self.assertEqual(manifest["block_reason"], "subprocess_start_failed")

    def test_run_ids_include_unique_suffix(self) -> None:
        self.assertNotEqual(M.execution_run_id(), M.execution_run_id())

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_cli_run_flag_invokes_execution(self) -> None:
        self.config["programs"]["demo"]["jobs"]["nmap_enrichment"]["state"] = "active"
        self.config["programs"]["demo"]["jobs"]["nmap_enrichment"]["command_template"] = [
            sys.executable,
            "-c",
            "print('flag-ok')",
        ]
        config_path = self.root / "config.yaml"
        config_path.write_text(yaml.safe_dump(self.config), encoding="utf-8")

        with patch.object(M, "DEFAULT_ARTIFACT_ROOT", self.root / "shared"):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    M.main(["run", "demo", "--config", str(config_path), "--run"]),
                    0,
                )

        manifests = list((self.root / "tools" / "nmap" / "runs").glob("*/manifest.json"))
        self.assertEqual(len(manifests), 1)
        manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "completed")
        self.assertEqual(manifest["execution_decision"], "active_execute_allowed")


if __name__ == "__main__":
    unittest.main()
