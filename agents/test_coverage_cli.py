"""Subprocess contract for dedicated coverage commands and legacy aliases."""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

REPO_ROOT = Path(__file__).resolve().parent.parent


class CoverageCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.common = ["--program", "sample", "--family", "web_bounty", "--lane", "web",
                       "--root", self.tmp.name]

    def invoke(self, owner: str, command: str, *options: str) -> dict:
        result = subprocess.run(
            [sys.executable, str(REPO_ROOT / "agents" / owner), command, *self.common, *options],
            cwd=REPO_ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_both_cli_names_accept_new_and_legacy_review_alias_with_canonical_output(self) -> None:
        surface_id = self.invoke("coverage.py", "discover", "--kind", "route", "--host", "shop.example",
                                 "--surface-key", "GET /search", "--class-name", "xss",
                                 "--source-ref", "map/routes.jsonl", "--run-id", "map-1")["surface_ids"][0]
        self.assertEqual(self.invoke("me_ledger.py", "surface-brief")["counts"], {"no_assessment": 1})
        for owner, command, status in (("coverage.py", "assess", "bounded_review"),
                                       ("me_ledger.py", "surface-assess", "exhausted")):
            assessed = self.invoke(owner, command, "--surface-id", surface_id,
                                   "--class-name", "xss", "--expected-fingerprint", "",
                                   "--status", status, "--reason", "specific renderer reviewed",
                                   "--boundary", "search text renderer", "--axis", "encoding",
                                   "--evidence-ref", "A-123")
            self.assertEqual(assessed["status"], "bounded_review")
        self.assertEqual(self.invoke("coverage.py", "brief")["counts"], {"bounded_review": 1})
        self.assertEqual([event["status"] for event in self.invoke("me_ledger.py", "surface-history",
                         "--surface-id", surface_id, "--class-name", "xss")["events"]],
                         ["bounded_review", "bounded_review"])

    def test_dedicated_commands_share_state_and_json_contract_with_legacy(self) -> None:
        discovered = self.invoke("coverage.py", "discover", "--kind", "route", "--host", "shop.example",
                                 "--surface-key", "/account", "--class-name", "xss",
                                 "--source-ref", "map/routes.jsonl", "--run-id", "map-1",
                                 "--fingerprint", "v1")
        self.assertEqual(discovered["discovered"], 1)
        surface_id = discovered["surface_ids"][0]
        self.assertEqual(self.invoke("coverage.py", "brief", "--class-name", "xss"),
                         self.invoke("me_ledger.py", "surface-brief", "--class-name", "xss"))
        self.assertEqual(self.invoke("coverage.py", "brief", "--class-name", "xss")["counts"],
                         {"no_assessment": 1})
        assessed = self.invoke("coverage.py", "assess", "--surface-id", surface_id, "--class-name", "xss",
                               "--status", "blocked", "--expected-fingerprint", "v1",
                               "--evidence-ref", "A-123", "--reason", "fixture missing",
                               "--reopen-when", "owned fixture available", "--run-id", "review-1")
        self.assertEqual(assessed["status"], "blocked")
        self.assertEqual(self.invoke("coverage.py", "brief", "--class-name", "xss")["counts"],
                         {"blocked": 1})
        self.assertEqual(self.invoke("coverage.py", "history", "--surface-id", surface_id,
                                     "--class-name", "xss"),
                         self.invoke("me_ledger.py", "surface-history", "--surface-id", surface_id,
                                     "--class-name", "xss"))
        self.assertEqual(self.invoke("coverage.py", "history", "--surface-id", surface_id,
                                     "--class-name", "xss")["events"][0]["evidence_refs"], ["A-123"])
        # Legacy discovery and assessment remain writers to the same dedicated index.
        self.assertEqual(self.invoke("me_ledger.py", "surface-discover", "--kind", "route",
                                     "--host", "shop.example", "--surface-key", "/checkout",
                                     "--class-name", "idor", "--source-ref", "map/routes.jsonl",
                                     "--run-id", "map-2")["discovered"], 1)
        self.assertEqual(self.invoke("coverage.py", "brief", "--class-name", "idor")["counts"],
                         {"no_assessment": 1})
        self.invoke("me_ledger.py", "surface-assess", "--surface-id", surface_id, "--class-name", "xss",
                    "--status", "in_progress", "--expected-fingerprint", "v1", "--evidence-ref", "A-124",
                    "--reason", "fixture available", "--run-id", "review-2")
        self.assertEqual([event["status"] for event in self.invoke(
            "coverage.py", "history", "--surface-id", surface_id, "--class-name", "xss")["events"]],
            ["blocked", "in_progress"])

    def test_xss_canary_plan_imports_fields_as_untested_without_canaries(self) -> None:
        source = Path(self.tmp.name) / "candidate-urls.jsonl"
        source.write_text(json.dumps({"url": "https://shop.example/search?q=hat&sort=asc&session_token=secret"})
                          + "\n" + json.dumps({"url": "https://shop.example/profile", "method": "POST",
                                                  "json_fields": {"name": "Ada"}}) + "\n")
        plan_dir = Path(self.tmp.name) / "plan"
        script = REPO_ROOT / "skills/xss/scripts/xss_canary_mapper.py"
        planned = subprocess.run([sys.executable, str(script), "plan", "--input", str(source),
                                  "--out-dir", str(plan_dir), "--run-id", "map-1"],
                                 cwd=REPO_ROOT, capture_output=True, text=True)
        self.assertEqual(planned.returncode, 0, planned.stderr)
        imported = self.invoke("coverage.py", "discover", "--xss-canary-sources",
                               str(plan_dir / "sources.jsonl"), "--source-ref",
                               "recon/xss/map-1/sources.jsonl")
        self.assertEqual(imported["discovered"], 3)
        brief = self.invoke("coverage.py", "brief", "--class-name", "xss")
        self.assertEqual(brief["counts"], {"no_assessment": 3})
        self.assertEqual({item["input_key"] for item in brief["items"]}, {"query:q", "query:sort", "json:name"})
        self.assertEqual({item["surface_key"] for item in brief["items"]}, {"GET /search", "POST /profile"})
        self.assertEqual({item["consumer"] for item in brief["items"]}, {""})
        self.assertTrue(all(item["source_ref"].startswith("recon/xss/map-1/sources.jsonl:")
                            for item in brief["items"]))
        self.assertEqual(self.invoke("coverage.py", "discover", "--xss-canary-sources",
                                     str(plan_dir / "sources.jsonl"), "--source-ref",
                                     "recon/xss/map-1/sources.jsonl")["surface_ids"], imported["surface_ids"])
        serialized = json.dumps(brief)
        self.assertNotIn("GHOST_XSS", serialized)
        self.assertNotIn("session_token", serialized)
        self.assertNotIn("hat", serialized)

    def test_evidence_audit_links_canonical_attempt_and_mapstore_without_copying_facts(self) -> None:
        from agents.attempts import append_attempt, resolve_attempts_path
        from agents.map_store import MapStore

        run_id = "probe-1"
        path = resolve_attempts_path("sample", family="web_bounty", lane="web",
                                     root_override=self.tmp.name, run_id=run_id)
        attempt = append_attempt(path, {"timestamp": "2026-10-14T00:00:00Z", "tool": "xss_probe",
                                        "target": "https://shop.example/search", "outcome": "warm",
                                        "stop_reason": "browser consumer pending", "detail": "sensitive-probe-detail"})
        maps = MapStore("sample", family="web_bounty", lane="web", root=self.tmp.name)
        observation = maps.write(surface="xss", body="Sensitive reusable fact", scope="surface",
                                 title="Encoding in search", agent="test", run_id=run_id)
        attempt_ref = f"attempt:{run_id}:{attempt['attempt_id']}"
        map_ref = "map:" + observation.relative_to(maps.maps_root).as_posix()
        surface_id = self.invoke("coverage.py", "discover", "--kind", "route", "--host", "shop.example",
                                 "--surface-key", "GET /search", "--input-key", "query:q", "--class-name", "xss",
                                 "--source-ref", "recon/xss/sources.jsonl:1", "--run-id", "mapper-1")["surface_ids"][0]
        self.invoke("coverage.py", "assess", "--surface-id", surface_id, "--class-name", "xss",
                    "--status", "in_progress", "--expected-fingerprint", "",
                    "--reason", "browser consumer remains open", "--evidence-ref", attempt_ref,
                    "--evidence-ref", map_ref, "--evidence-ref", "attempt:probe-1:A-missing",
                    "--evidence-ref", attempt["attempt_id"])
        audited = self.invoke("coverage.py", "verify", "--surface-id", surface_id, "--class-name", "xss")
        self.assertEqual({row["ref"]: row["status"] for row in audited["references"]},
                         {attempt_ref: "resolved", map_ref: "resolved",
                          "attempt:probe-1:A-missing": "missing", attempt["attempt_id"]: "unverified"})
        self.assertNotIn("Sensitive reusable fact", json.dumps(audited))
        self.assertNotIn("sensitive-probe-detail", json.dumps(audited))
        maps.update_status(path=observation.relative_to(maps.maps_root).as_posix(),
                           status="archived", reason="historical evidence retained", agent="test")
        self.assertEqual(self.invoke("coverage.py", "verify", "--surface-id", surface_id,
                                     "--class-name", "xss")["references"][1]["status"], "resolved")
        from agents.coverage_evidence import verify_references
        other_lane = verify_references("sample", family="web_bounty", lane="api",
                                       root_override=self.tmp.name, refs=[attempt_ref, map_ref])
        self.assertEqual([row["status"] for row in other_lane], ["missing", "missing"])
        with maps.index_path.open("a", encoding="utf-8") as handle:
            handle.write("{broken-json\n")
        corrupt = verify_references("sample", family="web_bounty", lane="web",
                                    root_override=self.tmp.name,
                                    refs=[map_ref, "map:absent/index.md"])
        self.assertEqual([row["status"] for row in corrupt], ["resolved", "unverified"])

    def test_non_object_attempt_line_cannot_prove_typed_id_absent(self) -> None:
        from agents.coverage_evidence import verify_references
        from agents.attempts import resolve_attempts_path

        path = resolve_attempts_path("sample", family="web_bounty", lane="web",
                                     root_override=self.tmp.name, run_id="probe-1")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('{"attempt_id":"A-present"}\n[]\n', encoding="utf-8")
        refs = ["attempt:probe-1:A-present", "attempt:probe-1:A-absent"]
        self.assertEqual([row["status"] for row in verify_references(
            "sample", family="web_bounty", lane="web", root_override=self.tmp.name, refs=refs)],
            ["resolved", "unverified"])

    def test_verify_and_brief_do_not_migrate_older_coverage_database(self) -> None:
        discovered = self.invoke("coverage.py", "discover", "--kind", "route", "--host", "shop.example",
                                 "--surface-key", "GET /search", "--class-name", "xss",
                                 "--source-ref", "map/old.jsonl", "--run-id", "map-old")
        surface_id = discovered["surface_ids"][0]
        self.invoke("coverage.py", "assess", "--surface-id", surface_id, "--class-name", "xss",
                    "--status", "in_progress", "--expected-fingerprint", "",
                    "--reason", "consumer remains open", "--evidence-ref", "A-legacy")
        db_path = Path(discovered["coverage_path"])
        with sqlite3.connect(db_path) as db:
            db.execute("DROP TABLE surface_sources")
        audited = self.invoke("coverage.py", "verify", "--surface-id", surface_id, "--class-name", "xss")
        self.assertEqual(audited["references"], [{"ref": "A-legacy", "status": "unverified"}])
        brief = self.invoke("coverage.py", "brief", "--class-name", "xss")
        self.assertEqual(brief["items"][0]["sources"],
                         [{"source_ref": "map/old.jsonl", "run_id": "map-old"}])
        with sqlite3.connect(db_path) as db:
            self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='surface_sources'").fetchone())

    def test_colliding_mapper_inputs_preserve_both_source_provenance(self) -> None:
        inventory = Path(self.tmp.name) / "sources.jsonl"
        base = {"run_id": "map-1", "method": "GET", "vector": "query", "field": "q"}
        inventory.write_text(json.dumps({**base, "source_id": "s1", "url": "https://shop.example/search?q=one"})
                             + "\n" + json.dumps({**base, "source_id": "s2",
                                                    "url": "https://shop.example/search?q=two"}) + "\n")
        imported = self.invoke("coverage.py", "discover", "--xss-canary-sources", str(inventory),
                               "--source-ref", "recon/xss/map-1/sources.jsonl")
        self.assertEqual(imported["discovered"], 1)
        item = self.invoke("coverage.py", "brief", "--class-name", "xss")["items"][0]
        self.assertEqual({source["source_ref"] for source in item["sources"]},
                         {"recon/xss/map-1/sources.jsonl:s1", "recon/xss/map-1/sources.jsonl:s2"})
        self.assertEqual({source["run_id"] for source in item["sources"]}, {"map-1"})
        surface_id = imported["surface_ids"][0]
        self.invoke("coverage.py", "assess", "--surface-id", surface_id, "--class-name", "xss",
                    "--status", "in_progress", "--expected-fingerprint", "",
                    "--reason", "consumer not yet confirmed", "--evidence-ref", "A-legacy")
        self.invoke("coverage.py", "discover", "--xss-canary-sources", str(inventory),
                    "--source-ref", "recon/xss/map-2/sources.jsonl")
        revisited = self.invoke("coverage.py", "brief", "--class-name", "xss")["items"][0]
        self.assertEqual(revisited["status"], "in_progress")
        self.assertEqual(revisited["source_count"], 4)
        self.assertEqual(len(revisited["sources"]), 4)

    def test_xss_unversioned_adapter_reopens_exhaustion_on_new_mapper_run(self) -> None:
        inventory = Path(self.tmp.name) / "sources.jsonl"
        source = {"source_id": "s1", "run_id": "map-1", "method": "GET", "vector": "query",
                  "field": "q", "url": "https://shop.example/search?q=seed", "canary": "GHOST_XSS_private"}
        inventory.write_text(json.dumps(source) + "\n", encoding="utf-8")
        options = ("--xss-canary-sources", str(inventory), "--source-ref", "recon/xss/sources.jsonl")
        surface_id = self.invoke("coverage.py", "discover", *options)["surface_ids"][0]
        self.invoke("coverage.py", "assess", "--surface-id", surface_id, "--class-name", "xss",
                    "--status", "bounded_review", "--expected-fingerprint", "", "--reason", "reviewed",
                    "--boundary", "one renderer", "--axis", "quote", "--evidence-ref", "A-1")
        self.invoke("coverage.py", "discover", *options)
        self.assertEqual(self.invoke("coverage.py", "brief", "--class-name", "xss")["counts"],
                         {"bounded_review": 1})
        inventory.write_text(json.dumps({**source, "run_id": "map-2"}) + "\n", encoding="utf-8")
        self.invoke("coverage.py", "discover", *options)
        brief = self.invoke("coverage.py", "brief", "--class-name", "xss")
        self.assertEqual(brief["counts"], {"stale": 1})
        self.assertEqual(brief["items"][0]["prior_status"], "bounded_review")
        self.assertEqual({row["run_id"] for row in brief["items"][0]["sources"]}, {"map-1", "map-2"})
        self.assertNotIn("GHOST_XSS", json.dumps(brief))

    def test_xss_canary_import_rolls_back_on_secret_bearing_path(self) -> None:
        inventory = Path(self.tmp.name) / "sources.jsonl"
        base = {"source_id": "s1", "run_id": "map-1", "method": "GET",
                "vector": "query", "field": "q", "canary": "GHOST_XSS_private"}
        inventory.write_text(json.dumps({**base, "url": "https://shop.example/search?q=safe"}) + "\n"
                             + json.dumps({**base, "source_id": "s2",
                                           "url": "https://shop.example/password=private?q=safe"}) + "\n")
        result = subprocess.run([sys.executable, str(REPO_ROOT / "agents/coverage.py"), "discover",
                                 *self.common, "--xss-canary-sources", str(inventory),
                                 "--source-ref", "recon/xss/map-1/sources.jsonl"],
                                cwd=REPO_ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("private", result.stderr)
        self.assertEqual(self.invoke("coverage.py", "brief", "--class-name", "xss")["total"], 0)

    def test_jsonl_inventory_and_validation_errors_preserve_legacy_contract(self) -> None:
        inventory = Path(self.tmp.name) / "inventory.jsonl"
        inventory.write_text(json.dumps({"kind": "graphql_argument", "host": "api.example",
                                         "surface_key": "Checkout.placeOrder", "class_names": ["xss", "idor"],
                                         "source_ref": "map/graphql.jsonl", "run_id": "map-1"}) + "\n")
        imported = self.invoke("coverage.py", "discover", "--input-jsonl", str(inventory))
        self.assertEqual(imported["discovered"], 1)
        self.assertEqual(self.invoke("coverage.py", "brief", "--limit", "1")["next_offset"], 1)
        self.assertEqual(self.invoke("coverage.py", "brief", "--limit", "1", "--offset", "1")["total"], 2)
        for owner, command in (("coverage.py", "assess"), ("me_ledger.py", "surface-assess")):
            result = subprocess.run(
                [sys.executable, str(REPO_ROOT / "agents" / owner), command, *self.common,
                 "--surface-id", imported["surface_ids"][0], "--class-name", "xss", "--status", "blocked",
                 "--expected-fingerprint", "", "--evidence-ref", "A-1", "--reason", "fixture missing"],
                cwd=REPO_ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stderr)["error"], "blocked assessment requires reopen_when")

    def test_live_mapper_to_attempt_map_and_coverage_handoff(self) -> None:
        """A real loopback response and mapper output flow into lane-local evidence."""
        from agents.attempts import append_attempt, resolve_attempts_path
        from agents.map_store import MapStore

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                value = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
                body = f"<h1>{value}</h1>".encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        source = Path(self.tmp.name) / "fixture-urls.txt"
        source.write_text(f"http://127.0.0.1:{port}/search?q=seed\n"
                          f"http://127.0.0.1:{port}/unvisited?memo=seed\n")
        plan = Path(self.tmp.name) / "plan"
        script = REPO_ROOT / "skills/xss/scripts/xss_canary_mapper.py"

        def mapper(*options: str) -> dict:
            process = subprocess.run([sys.executable, str(script), *options], cwd=REPO_ROOT,
                                     text=True, capture_output=True)
            self.assertEqual(process.returncode, 0, process.stderr)
            return json.loads(process.stdout)

        mapper("plan", "--input", str(source), "--out-dir", str(plan), "--run-id", "lab-1")
        discovered = self.invoke("coverage.py", "discover", "--xss-canary-sources",
                                 str(plan / "sources.jsonl"), "--source-ref", "recon/xss/lab-1/sources.jsonl")
        self.assertEqual(discovered["discovered"], 2)
        before = self.invoke("coverage.py", "brief", "--class-name", "xss", "--limit", "1")
        self.assertEqual(before["counts"], {"no_assessment": 2})
        self.assertEqual(before["next_offset"], 1)
        fetched = mapper("fetch", "--planned", str(plan / "planned_requests.jsonl"),
                         "--out-dir", str(plan), "--allow-host", "127.0.0.1",
                         "--max-requests", "1", "--rate-delay", "0")
        self.assertEqual(fetched["responses"], 1)
        responses = [json.loads(line) for line in (plan / "responses.jsonl").read_text().splitlines()]
        self.assertIn("GHOST_XSS_lab-1_", responses[0]["body"])
        scanned = mapper("scan", "--sources", str(plan / "sources.jsonl"),
                         "--response", str(plan / "responses.jsonl"), "--out-dir", str(plan))
        self.assertEqual(scanned["sinks"], 1)
        sinks = [json.loads(line) for line in (plan / "sinks.jsonl").read_text().splitlines()]
        self.assertEqual(len(sinks), 1)
        sink = sinks[0]
        sources = [json.loads(line) for line in (plan / "sources.jsonl").read_text().splitlines()]
        selected_source = next(source for source in sources if source["field"] == "q")
        self.assertEqual(sink["source_id"], selected_source["source_id"])
        self.assertEqual(sink["response_id"], responses[0]["response_id"])
        self.assertEqual(sink["context"], "html_text")
        self.assertEqual(self.invoke("coverage.py", "brief", "--class-name", "xss")["counts"],
                         {"no_assessment": 2})  # A scan is not an agent review.

        run_id = "probe-lab-1"
        attempt_path = resolve_attempts_path("sample", family="web_bounty", lane="web",
                                             root_override=self.tmp.name, run_id=run_id)
        attempt = append_attempt(attempt_path, {"timestamp": "2026-10-15T00:00:00Z",
                                                "tool": "xss_canary_mapper.fetch", "target": sink["response_url"],
                                                "outcome": sink["context"],
                                                "stop_reason": "browser consumer not reviewed",
                                                "detail": (f"source={sink['source_id']} response={sink['response_id']} "
                                                           f"sink={sink['sink_id']}")})
        maps = MapStore("sample", family="web_bounty", lane="web", root=self.tmp.name)
        observation = maps.write(surface="xss", body=(f"{sink['context']} reflection: "
                                                     f"source={sink['source_id']} response={sink['response_id']} "
                                                     f"sink={sink['sink_id']}; no execution proof"),
                                 scope="surface", title="Local search reflection", agent="test", run_id=run_id)
        persisted_attempt = json.loads(attempt_path.read_text().splitlines()[0])
        self.assertEqual(persisted_attempt["attempt_id"], attempt["attempt_id"])
        self.assertEqual(persisted_attempt["target"], sink["response_url"])
        self.assertIn(sink["sink_id"], persisted_attempt["detail"])
        self.assertTrue(observation.is_file())
        self.assertIn(sink["source_id"], observation.read_text())
        self.assertIn(sink["response_id"], observation.read_text())
        self.assertIn(observation.relative_to(maps.maps_root).as_posix(), maps.index_path.read_text())
        attempt_ref = f"attempt:{run_id}:{attempt['attempt_id']}"
        map_ref = "map:" + observation.relative_to(maps.maps_root).as_posix()
        question = next(item for item in self.invoke("coverage.py", "brief", "--class-name", "xss")["items"]
                        if item["input_key"] == "query:q")
        assessed = self.invoke("coverage.py", "assess", "--surface-id", question["surface_id"],
                               "--class-name", "xss", "--expected-fingerprint", "", "--status", "in_progress",
                               "--reason", "reflection observed; browser consumer unreviewed",
                               "--evidence-ref", attempt_ref, "--evidence-ref", map_ref, "--run-id", run_id)
        self.assertEqual(assessed["status"], "in_progress")
        audited = self.invoke("coverage.py", "verify", "--surface-id", question["surface_id"],
                              "--class-name", "xss")
        self.assertEqual([row["status"] for row in audited["references"]], ["resolved", "resolved"])
        general = self.invoke("coverage.py", "brief")
        self.assertEqual(general["counts"], {"in_progress": 1, "no_assessment": 1})
        sibling = next(item for item in general["items"] if item["input_key"] == "query:memo")
        self.assertEqual(sibling["status"], "no_assessment")
        self.assertEqual(self.invoke("coverage.py", "history", "--surface-id", sibling["surface_id"],
                                     "--class-name", "xss")["events"], [])
        self.assertNotIn("GHOST_XSS_lab-1_", json.dumps(general))
        self.assertEqual(self.invoke("coverage.py", "brief", "--class-name", "idor")["total"], 0)

        other = ["--program", "sample", "--family", "web_bounty", "--lane", "api", "--root", self.tmp.name]
        result = subprocess.run([sys.executable, str(REPO_ROOT / "agents/coverage.py"), "brief", *other],
                                cwd=REPO_ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["total"], 0)

    def test_general_and_class_briefs_are_independent_across_platform_lanes(self) -> None:
        """The same backend route is a separate client-perspective decision."""
        from agents.attempts import append_attempt, resolve_attempts_path
        from agents.coverage_evidence import verify_references
        from agents.surface_coverage import SurfaceCoverageStore

        lanes = [("web_bounty", "web"), ("web_bounty", "api"),
                 ("binaries", "apk"), ("binaries", "exe"), ("binaries", "mac")]
        stores = {(family, lane): SurfaceCoverageStore("sample", family=family, lane=lane,
                                                       root_override=self.tmp.name)
                  for family, lane in lanes}
        for store in stores.values():
            store.discover_many([{"kind": "route", "host": "api.example",
                                  "surface_key": "GET /records", "input_key": "record_id",
                                  "source_ref": "recon/operations.jsonl", "run_id": "map-1",
                                  "class_names": ["idor", "xss"], "fingerprint": "v1"}])
        self.assertEqual(len({store.path for store in stores.values()}), len(lanes))
        web = stores[("web_bounty", "web")]
        web_idor = web.brief(class_name="idor")["items"][0]
        path = resolve_attempts_path("sample", family="web_bounty", lane="web",
                                     root_override=self.tmp.name, run_id="auth-1")
        attempt = append_attempt(path, {"timestamp": "2026-10-15T00:00:00Z",
                                        "tool": "auth_comparison", "target": "api.example/records",
                                        "outcome": "comparison pending", "stop_reason": "second role unavailable"})
        ref = f"attempt:auth-1:{attempt['attempt_id']}"
        web.assess(web_idor["surface_id"], class_name="idor", status="in_progress",
                   expected_fingerprint="v1", evidence_refs=[ref],
                   reason="one role reviewed; comparison remains open", run_id="auth-1")
        self.assertEqual(web.brief()["counts"], {"in_progress": 1, "no_assessment": 1})
        self.assertEqual(web.brief(class_name="xss")["counts"], {"no_assessment": 1})
        for (family, lane), store in stores.items():
            if (family, lane) == ("web_bounty", "web"):
                continue
            self.assertEqual(store.brief()["counts"], {"no_assessment": 2}, (family, lane))
            self.assertEqual(store.brief(class_name="idor")["counts"], {"no_assessment": 1})
            self.assertEqual(store.brief(class_name="xss")["counts"], {"no_assessment": 1})
            self.assertEqual(verify_references("sample", family=family, lane=lane,
                                               root_override=self.tmp.name, refs=[ref])[0]["status"], "missing")

    def test_live_coverage_never_rewrites_legacy_coverage_json(self) -> None:
        """Legacy static/ad-hoc coverage migration is a separate future task."""
        ledgers = Path(self.tmp.name) / "web_bounty/sample/web/ledgers"
        ledgers.mkdir(parents=True)
        legacy = ledgers / "coverage.json"
        original = b'{"version":1,"rows":[{"status":"exhausted","surface":"legacy"}]}\n'
        legacy.write_bytes(original)
        discovered = self.invoke("coverage.py", "discover", "--kind", "route", "--host", "api.example",
                                 "--surface-key", "GET /orders", "--class-name", "idor",
                                 "--source-ref", "recon/api/orders.jsonl", "--run-id", "map-1")
        surface_id = discovered["surface_ids"][0]
        self.invoke("coverage.py", "assess", "--surface-id", surface_id, "--class-name", "idor",
                    "--expected-fingerprint", "", "--status", "in_progress",
                    "--evidence-ref", "A-legacy", "--reason", "second role not reviewed")
        self.assertEqual(self.invoke("coverage.py", "brief")["counts"], {"in_progress": 1})
        self.assertEqual(self.invoke("coverage.py", "verify", "--surface-id", surface_id,
                                     "--class-name", "idor")["references"][0]["status"], "unverified")
        self.assertEqual(legacy.read_bytes(), original)
        self.assertFalse((ledgers / "shared_brain").exists())


if __name__ == "__main__":
    unittest.main()
