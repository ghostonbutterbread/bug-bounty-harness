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
                                "<selected-ports>",
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

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_scheduler_config_expands_program_placeholders_in_program_values(self) -> None:
        config_root = self.root / "config"
        (config_root / "programs").mkdir(parents=True)
        (config_root / "defaults.yaml").write_text("version: 1\n", encoding="utf-8")
        (config_root / "programs" / "demo.yaml").write_text(
            "programs:\n  demo:\n    aggregate: ~/Shared/web_bounty/<program>/web/recon/aggregated/alive.txt\n",
            encoding="utf-8",
        )

        loaded = M.load_scheduler_config("demo", config_root=config_root)

        self.assertEqual(
            loaded["programs"]["demo"]["aggregate"],
            "~/Shared/web_bounty/demo/web/recon/aggregated/alive.txt",
        )

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_postprocess_ffuf_writes_deduped_leads_handoff_and_report(self) -> None:
        root = self.root / "ffuf-run"
        raw = root / "raw"
        raw.mkdir(parents=True)
        (raw / "ffuf.json").write_text(
            json.dumps(
                {
                    "results": [
                        {"url": "https://api.example.com/admin", "status": 403, "length": 12, "words": 2, "lines": 1},
                        {"url": "https://api.example.com/openapi.json", "status": 200, "length": 30, "words": 4, "lines": 2},
                        {"url": "https://api.example.com/admin", "status": 403, "length": 12, "words": 2, "lines": 1},
                        {"url": "https://outside.invalid/redirect", "status": 200, "length": 99, "words": 9, "lines": 1},
                    ]
                }
            ),
            encoding="utf-8",
        )
        outputs = {
            "fuzz_history": str(self.root / "fuzz_history.jsonl"),
            "status_leads": str(self.root / "status_leads.jsonl"),
            "forbidden_leads": str(self.root / "403.jsonl"),
        }
        job = {"job": "juicy_target_fuzz", "target": {"host": "api.example.com", "base_url": "https://api.example.com"}, "outputs": outputs, "post_run": {"handoff_path": str(self.root / "403_handoff.md"), "report_path": str(self.root / "report.md")}}
        manifest = {"paths": {"root": str(root)}}

        summary = M.postprocess_completed_job("demo", job, root, "run-1", manifest)

        self.assertEqual(summary["status_leads"]["new"], 2)
        self.assertEqual(summary["forbidden_leads"]["new"], 1)
        self.assertEqual(len([json.loads(line) for line in M.read_lines(Path(outputs["status_leads"]))]), 2)
        self.assertIn("https://api.example.com/admin", Path(self.root / "403_handoff.md").read_text(encoding="utf-8"))
        self.assertIn("403", Path(self.root / "report.md").read_text(encoding="utf-8"))

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_postprocess_ffuf_quarantines_large_uniform_surface_instead_of_creating_leads(self) -> None:
        root = self.root / "ffuf-uniform-run"
        raw = root / "raw"
        raw.mkdir(parents=True)
        (raw / "ffuf.json").write_text(
            json.dumps(
                {"results": [
                    {"url": f"https://api.example.com/path-{index}", "status": 301, "length": 167, "words": 1, "lines": 1}
                    for index in range(3)
                ]}
            ),
            encoding="utf-8",
        )
        outputs = {
            "fuzz_history": str(self.root / "uniform-history.jsonl"),
            "status_leads": str(self.root / "uniform-status-leads.jsonl"),
            "forbidden_leads": str(self.root / "uniform-403.jsonl"),
        }
        job = {
            "job": "juicy_target_fuzz",
            "target": {"host": "api.example.com", "base_url": "https://api.example.com"},
            "outputs": outputs,
            "inputs": {"uniform_response_threshold": 3},
            "post_run": {"report_path": str(self.root / "uniform-report.md")},
        }
        manifest = {"paths": {"root": str(root)}}

        summary = M.postprocess_completed_job("demo", job, root, "run-uniform", manifest)

        self.assertEqual(summary["uniform_surface"]["response_count"], 3)
        self.assertEqual(summary["uniform_surface"]["signature"]["status"], 301)
        self.assertEqual(summary["status_leads"]["new"], 0)
        self.assertFalse(Path(outputs["status_leads"]).exists())
        self.assertTrue((root / "normalized" / "quarantined_uniform_results.jsonl").is_file())
        self.assertEqual(manifest["ffuf_surface"]["classification"], "uniform_response_surface")

    def test_write_job_heartbeat_records_pid_elapsed_and_log_growth(self) -> None:
        root = self.root / "heartbeat-run"
        logs = root / "logs"
        logs.mkdir(parents=True)
        (logs / "stdout.txt").write_text("progress\n", encoding="utf-8")
        manifest = {"started_at": "2026-07-17T00:00:00Z", "status": "running"}

        heartbeat = M.write_job_heartbeat(root, manifest, pid=4242, event="progress")

        self.assertEqual(heartbeat["pid"], 4242)
        self.assertEqual(heartbeat["event"], "progress")
        self.assertEqual(heartbeat["stdout_bytes"], len("progress\n"))
        self.assertTrue((root / "heartbeat.json").is_file())
        self.assertEqual(json.loads((root / "heartbeat.json").read_text(encoding="utf-8"))["pid"], 4242)

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_postprocess_arjun_writes_parameter_artifacts_and_endpoint_queue(self) -> None:
        root = self.root / "arjun-run"
        raw = root / "raw"
        raw.mkdir(parents=True)
        (raw / "arjun.json").write_text(
            json.dumps({"https://api.example.com/v1/users": {"parameters": ["limit", "cursor"]}, "https://outside.invalid/admin": {"parameters": ["debug"]}}),
            encoding="utf-8",
        )
        outputs = {
            "parameters_jsonl": str(self.root / "parameters.jsonl"),
            "aggregated_params": str(self.root / "params.txt"),
            "parameter_source_log": str(self.root / "parameter_sources.jsonl"),
            "endpoint_queue": str(self.root / "next-endpoints.txt"),
        }
        job = {"job": "authenticated_parameter_mining", "target": {"host": "api.example.com"}, "outputs": outputs, "post_run": {"report_path": str(self.root / "params-report.md")}}
        manifest = {"paths": {"root": str(root)}}

        summary = M.postprocess_completed_job("demo", job, root, "run-2", manifest)

        self.assertEqual(summary["parameters"]["new"], 2)
        self.assertEqual(M.read_lines(Path(outputs["aggregated_params"])), ["cursor", "limit"])
        self.assertEqual(M.read_lines(Path(outputs["endpoint_queue"])), ["https://api.example.com/v1/users"])
        self.assertIn("parameter", Path(self.root / "params-report.md").read_text(encoding="utf-8").lower())

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_parameter_plan_materializes_selected_host_endpoints_from_params_source(self) -> None:
        params = self.root / "params.txt"
        params.write_text(
            "https://api.example.com/v1/users?limit=10\n"
            "https://api.example.com/v1/search?q=ghost\n"
            "http://api.example.com/v1/insecure?debug=true\n"
            "https://api.example.com/assets/app.js\n"
            "https://api.example.com/%20/not-a-route\n"
            "https://www.example.com/?utm_source=test\n"
            "https://outside.invalid/admin?debug=true\n",
            encoding="utf-8",
        )
        job_cfg = self.config["programs"]["demo"]["jobs"]["authenticated_parameter_mining"]
        job_cfg["inputs"].update({"parameter_url_sources": [str(params)], "max_endpoints_per_run": 10})
        selected = M.TargetCandidate(key="api", base_url="https://api.example.com", host="api.example.com", source="test")

        plan = M.build_parameter_plan(self.config["programs"]["demo"], selected)
        capsule = M.prepare_job_capsule("demo", plan, "run-params")

        materialized = capsule["manifest"]["materialized_inputs"]["parameter_endpoints"]
        self.assertEqual(materialized["candidate_count"], 2)
        self.assertEqual(M.read_lines(Path(materialized["path"])), ["https://api.example.com/v1/search", "https://api.example.com/v1/users"])
        self.assertIn(materialized["path"], capsule["command"])
        self.assertEqual(capsule["manifest"]["planned_status"], "planned")

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_structured_agent_review_can_select_only_scoped_candidate_and_allowed_groups(self) -> None:
        review = self.root / "review.json"
        review.write_text(
            json.dumps({"selected_target": "https://api.example.com", "reason": "API evidence", "wordlist_groups": ["api", "invalid"]}),
            encoding="utf-8",
        )
        self.config["programs"]["demo"]["target_selection"]["agent_review"] = {"enabled": True, "mode": "structured_response_file", "response_file": str(review)}
        self.config["programs"]["demo"]["jobs"]["juicy_target_fuzz"]["wordlists"]["tech_wordlists"] = {"api": [str(self.root / "api.txt")]}

        payload = M.plan(self.config, "demo")

        self.assertEqual(payload["selected_target"]["base_url"], "https://api.example.com")
        self.assertEqual(payload["agent_review"]["outcome"], "accepted")
        self.assertEqual(payload["agent_review"]["accepted_wordlist_groups"], ["api"])

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_invalid_structured_agent_review_falls_back_to_deterministic_target(self) -> None:
        review = self.root / "review.json"
        review.write_text(json.dumps({"selected_target": "https://outside.invalid", "wordlist_groups": ["api"]}), encoding="utf-8")
        self.config["programs"]["demo"]["target_selection"]["agent_review"] = {"enabled": True, "mode": "structured_response_file", "response_file": str(review)}

        payload = M.plan(self.config, "demo")

        self.assertNotEqual(payload["selected_target"]["base_url"], "https://outside.invalid")
        self.assertEqual(payload["agent_review"]["outcome"], "fallback")
        self.assertEqual(payload["agent_review"]["reason"], "selected_target_not_in_scoped_candidates")

    def test_validate_accepts_configured_jobs(self) -> None:
        self.assertEqual(M.validate_config(self.config), [])

    def test_validate_rejects_unknown_job(self) -> None:
        data = yaml.safe_load(yaml.safe_dump(self.config))
        data["programs"]["demo"]["jobs"]["mystery"] = {}
        errors = M.validate_config(data)
        self.assertTrue(any("unknown job mystery" in error for error in errors))

    def test_load_scheduler_config_merges_defaults_and_program_file(self) -> None:
        config_root = self.root / "cron-config"
        (config_root / "programs").mkdir(parents=True)
        defaults = {
            "version": 1,
            "runtime": {"mode": "tmux", "tmux": {"enabled": True, "session_template": "{program}-cron-recon"}},
            "defaults": {"rate_limit": {"global_http_rps": 11, "unauthenticated_rps": 11}},
            "platforms": {"bugcrowd": {"state": "active"}},
        }
        program = {"programs": {"demo": self.config["programs"]["demo"]}}
        (config_root / "defaults.yaml").write_text(yaml.safe_dump(defaults), encoding="utf-8")
        (config_root / "programs" / "demo.yaml").write_text(yaml.safe_dump(program), encoding="utf-8")

        data = M.load_scheduler_config("demo", config_root=config_root)

        self.assertEqual(data["runtime"]["mode"], "tmux")
        self.assertEqual(data["defaults"]["rate_limit"]["global_http_rps"], 11)
        self.assertIn("demo", data["programs"])
        self.assertEqual(M.validate_config(data), [])

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
        self.assertIn("-p", nmap_job["command"])
        self.assertIn("8443,9443", nmap_job["command"])
        self.assertNotIn("-p-", nmap_job["command"])
        self.assertEqual(nmap_job["command"][-1], "api.example.com")
        self.assertIn("has naabu/nmap service hint", payload["selected_target"]["reasons"])

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_naabu_uses_scoped_hosts_from_aggregated_domain_sources(self) -> None:
        aggregate = self.root / "alive.txt"
        aggregate.write_text("https://www.example.com/\napi.example.com\nhttps://outside.invalid/\n", encoding="utf-8")
        naabu = self.config["programs"]["demo"]["jobs"].setdefault("naabu_discovery", {})
        naabu.update({
            "state": "manual_review_required",
            "inputs": {
                "require_saved_scope": True,
                "batch_candidate_limit": 10,
                "aggregated_domain_sources": [str(aggregate)],
            },
            "command_template": ["naabu", "-list", "<naabu-hosts-file>", "-json"],
        })
        self.naabu_ports.unlink()
        selected = M.TargetCandidate(key="api", base_url="https://api.example.com", host="api.example.com", source="test")

        plan = M.build_naabu_plan("demo", self.config["programs"]["demo"], selected)

        self.assertEqual(plan["candidate_hosts"], ["api.example.com", "www.example.com"])

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_naabu_source_first_skips_hosts_already_covered_by_recon_inventory(self) -> None:
        naabu = self.config["programs"]["demo"]["jobs"].setdefault("naabu_discovery", {})
        naabu.update({
            "state": "manual_review_required",
            "inputs": {"require_saved_scope": True, "batch_candidate_limit": 2, "source_first": True},
            "command_template": ["naabu", "-list", "<naabu-hosts-file>", "-json"],
        })
        candidates = [
            M.TargetCandidate(key="api", base_url="https://api.example.com", host="api.example.com", source="test"),
            M.TargetCandidate(key="home", base_url="https://www.example.com", host="www.example.com", source="test"),
        ]

        plan = M.build_naabu_plan("demo", self.config["programs"]["demo"], candidates[0], candidates=candidates)

        self.assertEqual(plan["candidate_hosts"], ["www.example.com"])

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_naabu_materializes_a_scoped_ranked_host_batch(self) -> None:
        self.naabu_ports.unlink()
        naabu = self.config["programs"]["demo"]["jobs"].setdefault("naabu_discovery", {})
        naabu.update({
            "state": "manual_review_required",
            "inputs": {"require_saved_scope": True, "batch_candidate_limit": 2},
            "command_template": ["naabu", "-list", "<naabu-hosts-file>", "-json"],
        })
        candidates = [
            M.TargetCandidate(key="api", base_url="https://api.example.com", host="api.example.com", source="test"),
            M.TargetCandidate(key="home", base_url="https://www.example.com", host="www.example.com", source="test"),
        ]
        plan = M.build_naabu_plan("demo", self.config["programs"]["demo"], candidates[0], candidates=candidates)
        capsule = M.prepare_job_capsule("demo", plan, "run-naabu")

        hosts = capsule["manifest"]["materialized_inputs"]["naabu_hosts"]
        self.assertEqual(M.read_lines(Path(hosts["path"])), ["api.example.com", "www.example.com"])
        self.assertIn(hosts["path"], capsule["command"])

    def test_naabu_normalization_attributes_ip_only_output_to_unique_planned_hostname(self) -> None:
        root = self.root / "naabu-ip-only-run"
        raw = root / "raw"
        raw.mkdir(parents=True)
        (raw / "naabu.jsonl").write_text(
            json.dumps({"ip": "203.0.113.9", "port": 8443}) + "\n", encoding="utf-8"
        )
        aggregate = self.root / "ip-only-aggregate.jsonl"
        job = {
            "candidate_hosts": ["api.example.com"],
            "outputs": {"aggregated_ports_jsonl": str(aggregate)},
        }
        with patch.object(M.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("203.0.113.9", 0))]):
            M.normalize_naabu_output("demo", job, root, "run-naabu", {})

        row = json.loads(aggregate.read_text(encoding="utf-8"))
        self.assertEqual(row["host"], "api.example.com")
        self.assertEqual(row["input_host"], "api.example.com")
        self.assertEqual(row["resolved_ip"], "203.0.113.9")

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_nmap_postprocess_promotes_open_ports_to_aggregate_and_http_followup_queues(self) -> None:
        root = self.root / "nmap-run"
        raw = root / "raw"
        raw.mkdir(parents=True)
        (raw / "nmap.xml").write_text(
            """<?xml version='1.0'?><nmaprun><host><address addr='203.0.113.9' addrtype='ipv4'/><ports>\
<port protocol='tcp' portid='8080'><state state='open'/><service name='http' product='nginx' version='1.24'/></port>\
<port protocol='tcp' portid='8443'><state state='closed'/><service name='https'/></port>\
</ports></host></nmaprun>""",
            encoding="utf-8",
        )
        aggregate = self.root / "aggregated-ports.jsonl"
        aggregate_txt = self.root / "aggregated-ports.txt"
        fuzz_queue = self.root / "nmap-http-fuzz.jsonl"
        parameter_queue = self.root / "nmap-http-parameters.txt"
        job = {
            "job": "nmap_enrichment",
            "target": {"host": "api.example.com", "base_url": "https://api.example.com"},
            "outputs": {
                "aggregated_ports_jsonl": str(aggregate),
                "aggregated_ports_txt": str(aggregate_txt),
                "fuzz_endpoint_queue": str(fuzz_queue),
                "parameter_endpoint_queue": str(parameter_queue),
            },
        }
        manifest: dict[str, object] = {}

        summary = M.postprocess_completed_job("demo", job, root, "run-nmap", manifest)

        rows = [json.loads(line) for line in M.read_lines(aggregate)]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["host"], "api.example.com")
        self.assertEqual(rows[0]["resolved_ip"], "203.0.113.9")
        self.assertEqual(rows[0]["port"], 8080)
        self.assertEqual(rows[0]["service"], "http")
        self.assertEqual(M.read_lines(aggregate_txt), ["api.example.com:8080"])
        self.assertEqual(M.read_lines(parameter_queue), ["http://api.example.com:8080/"])
        queued = [json.loads(line) for line in M.read_lines(fuzz_queue)]
        self.assertEqual(queued[0]["url"], "http://api.example.com:8080/")
        self.assertEqual(summary["nmap_open_ports"]["new"], 1)

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_naabu_normalization_preserves_input_hostname_and_resolved_ip_for_nmap(self) -> None:
        root = self.root / "naabu-run"
        raw = root / "raw"
        raw.mkdir(parents=True)
        (raw / "naabu.jsonl").write_text(
            json.dumps({"host": "api.example.com", "ip": "203.0.113.9", "port": 8443}) + "\n"
            + json.dumps({"host": "203.0.113.10", "port": 9443}) + "\n",
            encoding="utf-8",
        )
        aggregate = self.root / "aggregated-ports.jsonl"
        job = {
            "outputs": {"aggregated_ports_jsonl": str(aggregate)},
        }
        manifest: dict[str, object] = {}

        alias_record = json.dumps({"host": "203.0.113.9", "input_host": "api.example.com", "port": 8443})
        self.assertEqual(M.parse_port_line(alias_record), ("api.example.com", 8443))

        M.normalize_naabu_output("demo", job, root, "run-naabu", manifest)

        rows = [json.loads(line) for line in aggregate.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(rows[0]["host"], "api.example.com")
        self.assertEqual(rows[0]["input_host"], "api.example.com")
        self.assertEqual(rows[0]["resolved_ip"], "203.0.113.9")
        self.assertEqual(rows[1]["input_host"], "")
        self.assertEqual(rows[1]["resolved_ip"], "203.0.113.10")

        nmap = self.config["programs"]["demo"]["jobs"]["nmap_enrichment"]
        nmap["inputs"]["naabu_ports"] = [str(aggregate)]
        nmap["inputs"].update({"interesting_ports_only": True, "common_web_ports": [80, 443]})
        selected = M.TargetCandidate(key="api", base_url="https://api.example.com", host="api.example.com", source="test")
        plan = M.build_nmap_plan("demo", self.config["programs"]["demo"], selected)
        self.assertEqual(plan["status"], "planned")
        self.assertEqual(plan["host"], "api.example.com")

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_nmap_drops_unscoped_historic_ip_records_and_keeps_scoped_hostname_evidence(self) -> None:
        self.naabu_ports.write_text(
            json.dumps({"host": "203.0.113.9", "port": 8443}) + "\n"
            + json.dumps({"host": "api.example.com", "port": 8443}) + "\n",
            encoding="utf-8",
        )
        nmap = self.config["programs"]["demo"]["jobs"]["nmap_enrichment"]
        nmap["inputs"].update({
            "interesting_ports_only": True,
            "common_web_ports": [80, 443],
            "max_hosts_per_run": 1,
        })
        selected = M.TargetCandidate(key="api", base_url="https://api.example.com", host="api.example.com", source="test")

        plan = M.build_nmap_plan("demo", self.config["programs"]["demo"], selected)

        self.assertEqual(plan["status"], "planned")
        self.assertEqual(plan["target"]["host"], "api.example.com")
        self.assertNotIn("203.0.113.9", json.dumps(plan))

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_nmap_prefers_unusual_naabu_services_over_common_web_ports(self) -> None:
        self.naabu_ports.write_text(
            json.dumps({"host": "api.example.com", "port": 80}) + "\n"
            + json.dumps({"host": "admin.example.com", "port": 8443}) + "\n",
            encoding="utf-8",
        )
        inputs = self.config["programs"]["demo"]["jobs"]["nmap_enrichment"]["inputs"]
        inputs.update({"interesting_ports_only": True, "common_web_ports": [80, 443]})
        selected = M.TargetCandidate(key="api", base_url="https://api.example.com", host="api.example.com", source="test")

        nmap = M.build_nmap_plan("demo", self.config["programs"]["demo"], selected)

        self.assertEqual(nmap["status"], "planned")
        self.assertEqual(nmap["target"]["host"], "admin.example.com")
        self.assertEqual(nmap["ports"], [8443])

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_nmap_enrichment_skips_without_naabu_ports(self) -> None:
        self.naabu_ports.unlink()
        payload = M.plan(self.config, "demo")
        nmap_job = payload["jobs"][0]
        self.assertEqual(nmap_job["status"], "skipped")
        self.assertEqual(nmap_job["reason"], "missing_naabu_output_or_no_ports_for_selected_host")

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_missing_nmap_ports_plans_naabu_dependency(self) -> None:
        self.naabu_ports.unlink()
        self.config["programs"]["demo"]["jobs"]["naabu_discovery"] = {
            "state": "manual_review_required",
            "tool": "naabu",
            "mode": "selected_host_full_range",
            "inputs": {"ports": "full", "require_saved_scope": True},
            "rate_limit": {"desired_pps": 123},
            "outputs": {
                "run_root": str(self.root / "tools" / "naabu" / "runs" / "<run-id>"),
                "aggregated_ports_jsonl": str(self.root / "aggregated" / "ports.jsonl"),
                "aggregated_ports_txt": str(self.root / "aggregated" / "ports.txt"),
                "services_ports_jsonl": str(self.root / "services" / "ports.jsonl"),
                "services_ports_txt": str(self.root / "services" / "ports.txt"),
            },
        }

        payload = M.plan(self.config, "demo")
        naabu_job = payload["jobs"][0]
        nmap_job = payload["jobs"][1]

        self.assertEqual(naabu_job["job"], "naabu_discovery")
        self.assertEqual(naabu_job["status"], "planned")
        self.assertEqual(naabu_job["ports"], "-")
        self.assertEqual(naabu_job["rate"], 123)
        self.assertIn("naabu", naabu_job["command"][0])
        self.assertEqual(nmap_job["status"], "waiting_on_dependency")
        self.assertEqual(nmap_job["dependency"], "naabu_discovery")
        self.assertEqual(nmap_job["reason"], "waiting_on_naabu_discovery")

    def test_parse_port_line_supports_json_text_and_url(self) -> None:
        self.assertEqual(M.parse_port_line('{"host":"api.example.com","port":8443}'), ("api.example.com", 8443))
        self.assertEqual(M.parse_port_line("api.example.com:9443"), ("api.example.com", 9443))
        self.assertEqual(M.parse_port_line("api.example.com:9443/tcp"), ("api.example.com", 9443))
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

    @patch.object(M, "resolve_host_addresses", return_value=[])
    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_plan_fans_out_scanners_to_selected_targets(self, _resolve) -> None:
        self.config["programs"]["demo"]["target_selection"]["select_n"] = 2

        payload = M.plan(self.config, "demo")
        fuzz_jobs = [job for job in payload["jobs"] if job["job"] == "juicy_target_fuzz"]
        param_jobs = [job for job in payload["jobs"] if job["job"] == "authenticated_parameter_mining"]

        self.assertEqual(len(payload["selected_targets"]), 2)
        self.assertEqual(len(fuzz_jobs), 2)
        self.assertEqual(len(param_jobs), 2)
        self.assertTrue(all(job["job_instance_id"].startswith("juicy_target_fuzz_") for job in fuzz_jobs))

    @patch.object(M, "resolve_host_addresses", return_value=[])
    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_rate_budget_keeps_independent_targets_at_configured_rate(self, _resolve) -> None:
        self.config["programs"]["demo"]["target_selection"]["select_n"] = 2

        payload = M.plan(self.config, "demo")
        fuzz_jobs = [job for job in payload["jobs"] if job["job"] == "juicy_target_fuzz"]

        self.assertEqual(len(fuzz_jobs), 2)
        self.assertEqual([job["rate_budget"]["allocated_rps"] for job in fuzz_jobs], [15, 15])
        self.assertTrue(all(job["rate_budget"]["concurrent_live_http_jobs"] == 1 for job in fuzz_jobs))
        self.assertNotEqual(fuzz_jobs[0]["rate_budget"]["scope"], fuzz_jobs[1]["rate_budget"]["scope"])

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_rate_budget_splits_targets_with_shared_resolved_ip(self) -> None:
        self.config["programs"]["demo"]["target_selection"]["select_n"] = 2

        with patch.object(M, "resolve_host_addresses", return_value=["192.0.2.10"]):
            payload = M.plan(self.config, "demo")

        fuzz_jobs = [job for job in payload["jobs"] if job["job"] == "juicy_target_fuzz"]
        self.assertEqual([job["rate_budget"]["allocated_rps"] for job in fuzz_jobs], [7, 7])
        self.assertTrue(all(job["rate_budget"]["bucket_kind"] == "ip" for job in fuzz_jobs))
        self.assertTrue(all(job["rate_budget"]["scope"] == "ip:192.0.2.10" for job in fuzz_jobs))

    def test_rate_bucket_collapses_cdnish_same_domain_to_domain_bucket(self) -> None:
        jobs = [
            {
                "job": "juicy_target_fuzz",
                "status": "planned",
                "target": {"host": "a.example.com"},
                "technology_map": {"wafs": {"cloudflare": ["cf-ray"]}},
                "command": ["ffuf", "-rate", "<effective-rate>"],
            },
            {
                "job": "juicy_target_fuzz",
                "status": "planned",
                "target": {"host": "b.example.com"},
                "technology_map": {"wafs": {"cloudflare": ["cf-ray"]}},
                "command": ["ffuf", "-rate", "<effective-rate>"],
            },
        ]

        with patch.object(M, "resolve_host_addresses", side_effect=[["192.0.2.1"], ["192.0.2.2"]]):
            M.apply_rate_budgets(self.config, self.config["programs"]["demo"], jobs)

        self.assertEqual([job["rate_budget"]["allocated_rps"] for job in jobs], [7, 7])
        self.assertTrue(all(job["rate_budget"]["bucket_kind"] == "domain" for job in jobs))
        self.assertTrue(all(job["rate_budget"]["scope"] == "domain:example.com" for job in jobs))

    def test_tmux_invocations_render_session_and_split_panes(self) -> None:
        panes = [
            {"shell": "echo first"},
            {"shell": "echo second"},
        ]

        invocations = M.render_tmux_invocations("demo-cron-recon", panes)

        self.assertEqual(invocations[0][:5], ["tmux", "new-session", "-d", "-s", "demo-cron-recon"])
        self.assertEqual(invocations[1][:4], ["tmux", "split-window", "-t", "demo-cron-recon:0"])
        self.assertEqual(invocations[2], ["tmux", "select-layout", "-t", "demo-cron-recon:0", "tiled"])

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_config_runtime_tmux_writes_manifest_and_resolved_config(self) -> None:
        data = yaml.safe_load(yaml.safe_dump(self.config))
        data["runtime"] = {
            "mode": "tmux",
            "tmux": {"enabled": True, "session_template": "{program}-cron-recon"},
        }
        data["programs"]["demo"]["jobs"]["nmap_enrichment"]["state"] = "active"
        data["programs"]["demo"]["jobs"]["nmap_enrichment"]["command_template"] = [
            sys.executable,
            "-c",
            "print('queued')",
        ]

        with patch.object(M, "DEFAULT_ARTIFACT_ROOT", self.root / "shared"):
            with patch.object(M, "launch_tmux_session", return_value={"status": "started", "session": "demo-cron-recon"}):
                payload = M.run(data, "demo", execute=True)

        self.assertEqual(payload["mode"], "tmux")
        self.assertEqual(payload["tmux"]["session"], "demo-cron-recon")
        self.assertTrue(Path(payload["resolved_config_path"]).is_file())
        self.assertTrue(Path(payload["tmux_manifest_path"]).is_file())
        tmux_manifest = json.loads(Path(payload["tmux_manifest_path"]).read_text(encoding="utf-8"))
        self.assertEqual(tmux_manifest["session"], "demo-cron-recon")
        self.assertTrue(tmux_manifest["panes"])

    def test_tmux_launch_command_is_not_available_for_untrusted_manifests(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                M.main(["tmux-launch", str(self.root / "malicious-manifest.json")])

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

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_timeout_defaults_to_none_without_configured_wall_clock_budget(self) -> None:
        payload = M.plan(self.config, "demo")

        timeout = M._compute_timeout({}, payload, self.config["programs"]["demo"])

        self.assertIsNone(timeout)

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
    def test_run_enqueue_writes_shared_queue_sections_and_dedupes(self) -> None:
        queue = self.root / "queue.txt"
        queue.write_text("https://api.example.com/v1/users\n", encoding="utf-8")
        self.config["programs"]["demo"]["jobs"]["authenticated_parameter_mining"]["inputs"]["endpoint_queue"] = str(queue)

        with patch.object(M, "DEFAULT_ARTIFACT_ROOT", self.root / "shared"):
            first = M.run(self.config, "demo", enqueue=True)
            second = M.run(self.config, "demo", enqueue=True)

        queue_path = Path(first["queue"]["queue_path"])
        queue_data = json.loads(queue_path.read_text(encoding="utf-8"))

        self.assertEqual(first["mode"], "enqueue")
        self.assertEqual(first["queue"]["created"], 3)
        self.assertEqual(second["queue"]["created"], 0)
        self.assertEqual(second["queue"]["deduped"], 3)
        self.assertEqual(set(queue_data["queues"]), {"fuzz", "nmap", "parameter_mining"})
        self.assertTrue(all(entry["state"] == "pending" for section in queue_data["queues"].values() for entry in section))

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_queue_drain_executes_only_selected_run_type(self) -> None:
        self.config["programs"]["demo"]["jobs"]["nmap_enrichment"]["state"] = "active"
        self.config["programs"]["demo"]["jobs"]["nmap_enrichment"]["command_template"] = [
            sys.executable,
            "-c",
            "print('queued-nmap')",
        ]

        with patch.object(M, "DEFAULT_ARTIFACT_ROOT", self.root / "shared"):
            enqueued = M.run(self.config, "demo", enqueue=True)
            drained = M.drain_queue(self.config, "demo", run_type="nmap", execute=True, limit=1)

        queue_data = json.loads(Path(enqueued["queue"]["queue_path"]).read_text(encoding="utf-8"))
        nmap_entry = queue_data["queues"]["nmap"][0]
        fuzz_entry = queue_data["queues"]["fuzz"][0]
        stdout = Path(drained["jobs"][0]["run_root"], "logs", "stdout.txt").read_text(encoding="utf-8")

        self.assertEqual(drained["mode"], "queue-drain")
        self.assertEqual(drained["selected_count"], 1)
        self.assertEqual(nmap_entry["state"], "completed")
        self.assertEqual(fuzz_entry["state"], "pending")
        self.assertEqual(stdout.strip(), "queued-nmap")

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_queue_worker_drains_selected_lane_until_idle(self) -> None:
        self.config["programs"]["demo"]["jobs"]["nmap_enrichment"]["state"] = "active"
        self.config["programs"]["demo"]["jobs"]["nmap_enrichment"]["command_template"] = [
            sys.executable,
            "-c",
            "print('worker-nmap')",
        ]

        with patch.object(M, "DEFAULT_ARTIFACT_ROOT", self.root / "shared"):
            enqueued = M.run(self.config, "demo", enqueue=True)
            worker = M.queue_worker(
                self.config,
                "demo",
                run_type="nmap",
                execute=True,
                idle_sleep_seconds=0,
                max_idle_cycles=1,
            )

        queue_data = json.loads(Path(enqueued["queue"]["queue_path"]).read_text(encoding="utf-8"))
        nmap_entry = queue_data["queues"]["nmap"][0]
        stdout = Path(nmap_entry["run_root"], "logs", "stdout.txt").read_text(encoding="utf-8")

        self.assertEqual(worker["mode"], "queue-worker")
        self.assertEqual(worker["status"], "idle")
        self.assertEqual(worker["stop_reason"], "idle_limit_reached")
        self.assertEqual(worker["cycles"], 2)
        self.assertEqual(worker["drained_count"], 1)
        self.assertEqual(nmap_entry["state"], "completed")
        self.assertEqual(stdout.strip(), "worker-nmap")

    def test_queue_worker_blocks_when_lane_worker_lock_is_held(self) -> None:
        with patch.object(M, "DEFAULT_ARTIFACT_ROOT", self.root / "shared"):
            with M.queue_worker_lock("demo", "nmap"):
                worker = M.queue_worker(
                    self.config,
                    "demo",
                    run_type="nmap",
                    execute=True,
                    idle_sleep_seconds=0,
                    max_idle_cycles=1,
                )

        self.assertEqual(worker["status"], "blocked")
        self.assertEqual(worker["block_reason"], "queue_worker_lock_already_held")

    def test_queue_drain_skips_pending_entry_when_other_lane_runs_same_ip_bucket(self) -> None:
        def resolve(host: str) -> list[str]:
            return {
                "a.example.com": ["192.0.2.10"],
                "b.example.com": ["192.0.2.10"],
                "c.example.com": ["192.0.2.20"],
            }.get(host, [])

        def nmap_entry(entry_id: str, host: str, *, state: str = "pending", priority: int = 50) -> dict:
            return {
                "id": entry_id,
                "version": 1,
                "program": "demo",
                "lane": "web",
                "run_type": "nmap",
                "job": "nmap_enrichment",
                "target": {"host": host, "base_url": f"https://{host}", "key": host},
                "target_host": host,
                "priority": priority,
                "state": state,
                "attempts": 0,
                "created_at": f"2026-07-13T00:00:0{priority}Z",
                "updated_at": "2026-07-13T00:00:00Z",
                "job_payload": {
                    "job": "nmap_enrichment",
                    "state": "active",
                    "status": "planned",
                    "target": {"host": host, "base_url": f"https://{host}", "key": host},
                    "command": [sys.executable, "-c", f"print('{host}')"],
                },
            }

        queue_data = {
            "version": 1,
            "queues": {
                "fuzz": [
                    {
                        "id": "fuzz-running",
                        "run_type": "fuzz",
                        "job": "juicy_target_fuzz",
                        "target": {"host": "a.example.com", "base_url": "https://a.example.com"},
                        "target_host": "a.example.com",
                        "state": "running",
                        "policy": {"rate_budget": {"scope": "ip:192.0.2.10", "resolved_addresses": ["192.0.2.10"]}},
                    }
                ],
                "nmap": [
                    nmap_entry("nmap-colliding", "b.example.com", priority=1),
                    nmap_entry("nmap-safe", "c.example.com", priority=2),
                ],
            },
        }

        with patch.object(M, "DEFAULT_ARTIFACT_ROOT", self.root / "shared"):
            qpath = M.queue_path(self.config, "demo", self.config["programs"]["demo"])
            M.write_queue(qpath, queue_data)
            with patch.object(M, "resolve_host_addresses", side_effect=resolve):
                drained = M.drain_queue(self.config, "demo", run_type="nmap", execute=True, limit=1)

        updated = json.loads(qpath.read_text(encoding="utf-8"))
        nmap_section = updated["queues"]["nmap"]

        self.assertEqual(drained["selected_count"], 1)
        self.assertEqual(drained["bucket_skip_count"], 1)
        self.assertEqual(drained["jobs"][0]["block_reason"], "queued_target_not_in_current_plan")
        self.assertEqual(nmap_section[0]["id"], "nmap-safe")
        self.assertEqual(nmap_section[0]["state"], "blocked")
        self.assertEqual(nmap_section[-1]["id"], "nmap-colliding")
        self.assertEqual(nmap_section[-1]["state"], "pending")
        self.assertEqual(nmap_section[-1]["defer_reason"], "active_shared_bucket")

    def test_queue_drain_skips_same_lane_running_bucket_before_next_pick(self) -> None:
        def resolve(host: str) -> list[str]:
            return {
                "a.example.com": ["192.0.2.10"],
                "b.example.com": ["192.0.2.10"],
                "c.example.com": ["192.0.2.20"],
            }.get(host, [])

        def nmap_entry(entry_id: str, host: str, *, state: str = "pending", priority: int = 50) -> dict:
            return {
                "id": entry_id,
                "run_type": "nmap",
                "job": "nmap_enrichment",
                "target": {"host": host, "base_url": f"https://{host}", "key": host},
                "target_host": host,
                "priority": priority,
                "state": state,
                "created_at": f"2026-07-13T00:00:0{priority}Z",
                "updated_at": "2026-07-13T00:00:00Z",
                "job_payload": {
                    "job": "nmap_enrichment",
                    "state": "active",
                    "status": "planned",
                    "target": {"host": host, "base_url": f"https://{host}", "key": host},
                    "command": [sys.executable, "-c", f"print('{host}')"],
                },
            }

        queue_data = {
            "version": 1,
            "queues": {
                "nmap": [
                    nmap_entry("nmap-running", "a.example.com", state="running", priority=0),
                    nmap_entry("nmap-colliding", "b.example.com", priority=1),
                    nmap_entry("nmap-safe", "c.example.com", priority=2),
                ],
            },
        }

        with patch.object(M, "DEFAULT_ARTIFACT_ROOT", self.root / "shared"):
            qpath = M.queue_path(self.config, "demo", self.config["programs"]["demo"])
            M.write_queue(qpath, queue_data)
            with patch.object(M, "resolve_host_addresses", side_effect=resolve):
                drained = M.drain_queue(self.config, "demo", run_type="nmap", execute=True, limit=1)

        updated = json.loads(qpath.read_text(encoding="utf-8"))
        nmap_section = updated["queues"]["nmap"]

        self.assertEqual(drained["selected_count"], 1)
        self.assertEqual(drained["bucket_skip_count"], 1)
        self.assertEqual(drained["jobs"][0]["block_reason"], "queued_target_not_in_current_plan")
        self.assertEqual(nmap_section[0]["id"], "nmap-running")
        self.assertEqual(nmap_section[1]["id"], "nmap-safe")
        self.assertEqual(nmap_section[-1]["id"], "nmap-colliding")
        self.assertEqual(nmap_section[-1]["defer_reason"], "active_shared_bucket")

    def test_queue_drain_reaps_stale_running_entry_with_dead_worker_pid(self) -> None:
        queue_data = {
            "version": 1,
            "queues": {
                "fuzz": [
                    {
                        "id": "fuzz-stale",
                        "run_type": "fuzz",
                        "job": "juicy_target_fuzz",
                        "target": {"host": "a.example.com", "base_url": "https://a.example.com"},
                        "target_host": "a.example.com",
                        "state": "running",
                        "worker_pid": 99999999,
                        "policy": {"rate_budget": {"scope": "ip:192.0.2.10", "resolved_addresses": ["192.0.2.10"]}},
                    }
                ],
                "nmap": [
                    {
                        "id": "nmap-ready",
                        "run_type": "nmap",
                        "job": "nmap_enrichment",
                        "target": {"host": "b.example.com", "base_url": "https://b.example.com", "key": "b"},
                        "target_host": "b.example.com",
                        "priority": 1,
                        "state": "pending",
                        "created_at": "2026-07-13T00:00:01Z",
                        "updated_at": "2026-07-13T00:00:00Z",
                        "job_payload": {
                            "job": "nmap_enrichment",
                            "state": "active",
                            "status": "planned",
                            "target": {"host": "b.example.com", "base_url": "https://b.example.com", "key": "b"},
                            "command": [sys.executable, "-c", "print('ready')"],
                        },
                    }
                ],
            },
        }

        with patch.object(M, "DEFAULT_ARTIFACT_ROOT", self.root / "shared"):
            qpath = M.queue_path(self.config, "demo", self.config["programs"]["demo"])
            M.write_queue(qpath, queue_data)
            with patch.object(M, "resolve_host_addresses", return_value=["192.0.2.10"]):
                drained = M.drain_queue(self.config, "demo", run_type="nmap", execute=True, limit=1)

        updated = json.loads(qpath.read_text(encoding="utf-8"))
        stale_entry = updated["queues"]["fuzz"][0]
        nmap_entry = updated["queues"]["nmap"][0]

        self.assertEqual(drained["stale_reaped_count"], 1)
        self.assertEqual(stale_entry["state"], "stale")
        self.assertEqual(stale_entry["stale_reason"], "worker_pid_not_alive")
        self.assertEqual(nmap_entry["state"], "blocked")
        self.assertEqual(nmap_entry["block_reason"], "queued_target_not_in_current_plan")

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_prepare_fuzz_materializes_large_wordlist_without_truncation(self) -> None:
        wordlist = self.root / "large-fuzz.txt"
        wordlist.write_text("\n".join(f"candidate-{index}" for index in range(6001)), encoding="utf-8")
        tech_wordlist = self.root / "api-fuzz.txt"
        tech_wordlist.write_text("candidate-6000\napi-only\n", encoding="utf-8")
        tech_source = self.root / "httpx.jsonl"
        tech_source.write_text(
            json.dumps({"url": "https://api.example.com", "tech": ["api"], "content_type": "application/json"}) + "\n",
            encoding="utf-8",
        )
        self.config["programs"]["demo"]["jobs"]["juicy_target_fuzz"]["wordlists"]["include"] = [str(wordlist)]
        self.config["programs"]["demo"]["jobs"]["juicy_target_fuzz"]["wordlists"]["tech_sources"] = [str(tech_source)]
        self.config["programs"]["demo"]["jobs"]["juicy_target_fuzz"]["wordlists"]["tech_wordlists"] = {
            "api": [str(tech_wordlist)]
        }

        with patch.object(M, "DEFAULT_ARTIFACT_ROOT", self.root / "shared"):
            payload = M.run(self.config, "demo", execute=False, approve_manual=False)

        fuzz = next(job for job in payload["jobs"] if job["job"] == "juicy_target_fuzz")
        manifest = json.loads(Path(fuzz["manifest_path"]).read_text(encoding="utf-8"))
        command = Path(fuzz["run_root"], "command.txt").read_text(encoding="utf-8")
        composed = Path(manifest["materialized_inputs"]["wordlist"]["path"])
        self.assertEqual(manifest["materialized_inputs"]["wordlist"]["candidate_count"], 6002)
        self.assertEqual(len(M.read_lines(composed)), 6002)
        self.assertIn("api-only", M.read_lines(composed))
        self.assertEqual(fuzz["selected_tech_wordlist_groups"], ["api"])
        self.assertIn("application/json", fuzz["technology_map"]["signals"]["api"][0])
        self.assertNotIn("<dry-run-composed-wordlist>", command)
        self.assertNotIn("<ffuf-run-root>", command)
        self.assertNotIn(" -nc ", command)
        self.assertIn(str(composed), command)

    @patch.object(M, "ScopeValidator", FakeScopeValidator)
    def test_run_blocks_when_program_cron_lock_is_already_held(self) -> None:
        shared = self.root / "shared"
        with patch.object(M, "DEFAULT_ARTIFACT_ROOT", shared):
            with M.cron_run_lock("demo"):
                payload = M.run(self.config, "demo", execute=True, approve_manual=True)

        self.assertEqual(payload["status"], "blocked")
        self.assertEqual(payload["block_reason"], "cron_run_lock_already_held")
        self.assertIsNone(payload["run_lock_path"])
        self.assertTrue(payload["jobs"])
        self.assertTrue(all(job["execution_status"] == "blocked" for job in payload["jobs"]))
        self.assertTrue(all(job["block_reason"] == "cron_run_lock_already_held" for job in payload["jobs"]))

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
    def test_completed_naabu_run_normalizes_ports_for_nmap_inventory(self) -> None:
        self.naabu_ports.unlink()
        aggregated_dir = self.root / "aggregated"
        services_dir = self.root / "services"
        self.config["programs"]["demo"]["jobs"]["nmap_enrichment"]["inputs"]["naabu_ports"] = [
            str(aggregated_dir / "ports.jsonl"),
            str(aggregated_dir / "ports.txt"),
        ]
        self.config["programs"]["demo"]["jobs"]["naabu_discovery"] = {
            "state": "active",
            "tool": "naabu",
            "mode": "selected_host_full_range",
            "inputs": {"ports": "full", "require_saved_scope": True},
            "rate_limit": {"desired_pps": 100},
            "command_template": [
                sys.executable,
                "-c",
                (
                    "from pathlib import Path; "
                    "p=Path('<run-root>/raw/naabu.jsonl'); "
                    "p.write_text('{\"host\":\"api.example.com\",\"port\":8443}\\n"
                    "{\"host\":\"api.example.com\",\"port\":10443}\\n', encoding='utf-8')"
                ),
            ],
            "outputs": {
                "run_root": str(self.root / "tools" / "naabu" / "runs" / "<run-id>"),
                "aggregated_ports_jsonl": str(aggregated_dir / "ports.jsonl"),
                "aggregated_ports_txt": str(aggregated_dir / "ports.txt"),
                "services_ports_jsonl": str(services_dir / "ports.jsonl"),
                "services_ports_txt": str(services_dir / "ports.txt"),
            },
        }

        with patch.object(M, "DEFAULT_ARTIFACT_ROOT", self.root / "shared"):
            payload = M.run(self.config, "demo", execute=True)

        naabu_job = next(job for job in payload["jobs"] if job["job"] == "naabu_discovery")
        nmap_job = next(job for job in payload["jobs"] if job["job"] == "nmap_enrichment")
        manifest = json.loads(Path(naabu_job["manifest_path"]).read_text(encoding="utf-8"))

        self.assertEqual(manifest["status"], "completed")
        self.assertEqual(manifest["normalized_outputs"]["normalized_count"], 2)
        self.assertEqual(nmap_job["status"], "planned")
        self.assertEqual(nmap_job["ports"], [8443, 10443])
        self.assertEqual(nmap_job["execution_status"], "blocked")
        self.assertEqual(nmap_job["execution_decision"], "state_manual_review_required_not_approved")
        self.assertEqual(
            M.read_lines(Path(naabu_job["run_root"]) / "normalized" / "ports.txt"),
            ["api.example.com:8443", "api.example.com:10443"],
        )
        self.assertEqual(M.read_lines(aggregated_dir / "ports.txt"), ["api.example.com:8443", "api.example.com:10443"])
        global_rows = [json.loads(line) for line in M.read_lines(aggregated_dir / "ports.jsonl")]
        self.assertEqual([(row["host"], row["port"]) for row in global_rows], [("api.example.com", 8443), ("api.example.com", 10443)])
        self.assertEqual(M.read_lines(services_dir / "ports.txt"), ["api.example.com:8443", "api.example.com:10443"])

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
    def test_approved_jobs_strictly_limits_manual_run_selection(self) -> None:
        self.config["programs"]["demo"]["jobs"]["nmap_enrichment"]["command_template"] = [
            sys.executable,
            "-c",
            "print('nmap-only')",
        ]
        self.config["programs"]["demo"]["jobs"]["juicy_target_fuzz"]["command_template"] = [
            sys.executable,
            "-c",
            "print('should-not-run')",
            "-rate",
            "<effective-rate>",
        ]

        with patch.object(M, "DEFAULT_ARTIFACT_ROOT", self.root / "shared"):
            payload = M.run(
                self.config,
                "demo",
                execute=True,
                approve_manual=True,
                approved_jobs={"nmap_enrichment"},
            )

        nmap_job = next(job for job in payload["jobs"] if job["job"] == "nmap_enrichment")
        fuzz_job = next(job for job in payload["jobs"] if job["job"] == "juicy_target_fuzz")
        nmap_manifest = json.loads(Path(nmap_job["manifest_path"]).read_text(encoding="utf-8"))
        fuzz_manifest = json.loads(Path(fuzz_job["manifest_path"]).read_text(encoding="utf-8"))
        self.assertEqual(nmap_manifest["status"], "completed")
        self.assertEqual(nmap_manifest["execution_decision"], "manual_review_approved")
        self.assertEqual(fuzz_manifest["status"], "blocked")
        self.assertEqual(fuzz_manifest["execution_decision"], "job_not_selected")

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
