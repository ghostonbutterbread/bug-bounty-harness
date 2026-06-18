#!/usr/bin/env python3
"""Unit tests for url_ingest.py — URL Ingestor + Review Tracker."""

import unittest
import tempfile
import os
import sys
import sqlite3
import json
from pathlib import Path
from unittest.mock import patch

# Mock SHARED_BASE to a temp directory for tests
TEMP_SHARED = Path(tempfile.mkdtemp())

import agents.url_ingest as M


class TestNormalizeUrl(unittest.TestCase):
    def test_basic(self):
        u = M.normalize_url("HTTPS://API.Canva.COM/api/v2/widgets?sort=asc&limit=10")
        self.assertEqual(u, "https://api.canva.com/api/v2/widgets?limit=10&sort=asc")

    def test_param_order_sorted(self):
        u = M.normalize_url("https://example.com/abc?z=1&a=2&m=5")
        self.assertEqual(u, "https://example.com/abc?a=2&m=5&z=1")

    def test_strips_fragment(self):
        u = M.normalize_url("https://example.com/page#section")
        self.assertEqual(u, "https://example.com/page")

    def test_default_scheme(self):
        u = M.normalize_url("example.com/path")
        self.assertTrue(u.startswith("https://"))


class TestUrlHashes(unittest.TestCase):
    def test_url_hash_deterministic(self):
        url = "https://api.canva.com/api/v2/widgets?limit=10&sort=asc"
        h1 = M.url_hashes(url)
        h2 = M.url_hashes(url)
        self.assertEqual(h1, h2)

    def test_url_hash_differs_for_different_urls(self):
        h1 = M.url_hashes("https://a.com")
        h2 = M.url_hashes("https://b.com")
        self.assertNotEqual(h1[0], h2[0])  # url_hash differs

    def test_param_hash_same_for_same_param_keys(self):
        h1 = M.url_hashes("https://a.com?x=1&y=2")
        h2 = M.url_hashes("https://a.com?y=3&x=4")
        self.assertEqual(h1[2], h2[2])  # param_hash same (same keys)

    def test_param_hash_differs_for_different_param_keys(self):
        h1 = M.url_hashes("https://a.com?x=1")
        h2 = M.url_hashes("https://a.com?x=1&y=2")
        self.assertNotEqual(h1[2], h2[2])


class TestIngestRoundtrip(unittest.TestCase):
    def setUp(self):
        self.program = "testprog"
        self.db_path = TEMP_SHARED / self.program / "web" / "recon" / "url_index" / "url_index.sqlite"
        M.SHARED_BASE = TEMP_SHARED
        M.init_db(self.program)

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()

    def test_ingest_dedupes(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("https://api.canva.com/api/v2/widgets?limit=10\n")
            tf.write("https://api.canva.com/api/v2/widgets?limit=10\n")  # exact duplicate
            tf.write("https://api.canva.com/api/v2/widgets?limit=10\n")  # duplicate again
            tf.flush()
            tf_path = tf.name
        try:
            M.ingest(self.program, source_file=tf_path, run_id="test-run")
            with M.get_conn(self.program) as conn:
                count = conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
                self.assertEqual(count, 1)  # exact duplicates collapsed to 1
        finally:
            os.unlink(tf_path)

    def test_ingest_records_source(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("https://example.com/a\nhttps://example.com/b\n")
            tf.flush()
            tf_path = tf.name
        try:
            M.ingest(self.program, source_file=tf_path, run_id="test-run")
            with M.get_conn(self.program) as conn:
                rows = conn.execute(
                    "SELECT source FROM urls ORDER BY id",
                ).fetchall()
                self.assertTrue(all(r["source"] == os.path.basename(tf_path) for r in rows))
        finally:
            os.unlink(tf_path)

    def test_ingest_populates_parameter_map_from_query_urls(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("https://example.com/search?q=test&redirect=https://example.net/\n")
            tf.flush()
            tf_path = tf.name
        try:
            M.ingest(self.program, source_file=tf_path, run_id="param-map-run")
            with M.get_conn(self.program) as conn:
                rows = conn.execute(
                    "SELECT po.param_key, po.location, po.value_shape, po.lane_hints "
                    "FROM parameter_observations po ORDER BY po.param_key"
                ).fetchall()
            self.assertEqual([row["param_key"] for row in rows], ["q", "redirect"])
            self.assertTrue(all(row["location"] == "query" for row in rows))
            redirect = [row for row in rows if row["param_key"] == "redirect"][0]
            self.assertEqual(redirect["value_shape"], "url")
            self.assertIn("ssrf", json.loads(redirect["lane_hints"]))
        finally:
            os.unlink(tf_path)

    def test_ingest_from_stdin_commits_and_logs_import(self):
        import io
        import sys

        old_stdin = sys.stdin
        sys.stdin = io.StringIO(
            "https://stdin.example.com/a\n"
            "https://stdin.example.com/a\n"
            "https://stdin.example.com/b\n"
        )
        try:
            M.ingest(self.program, source_file=None, run_id="stdin-run")
        finally:
            sys.stdin = old_stdin

        with M.get_conn(self.program) as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM urls WHERE host='stdin.example.com'"
            ).fetchone()[0]
            self.assertEqual(count, 2)
            imported = conn.execute(
                "SELECT source_file, run_id, urls_imported FROM imports "
                "WHERE source_file='stdin' ORDER BY id DESC LIMIT 1"
            ).fetchone()
            self.assertIsNotNone(imported)
            self.assertEqual(imported["run_id"], "stdin-run")
            self.assertEqual(imported["urls_imported"], 2)

    def test_ingest_scope_filter_writes_temp_files_and_rejects_out_of_scope(self):
        class DemoScope:
            def __init__(self, program: str, strict: bool = True):
                self.program = program
                self.strict = strict

            def is_empty(self):
                return False

            def scope_summary(self):
                return "example.com"

            def partition(self, urls):
                accepted = [url for url in urls if "example.com" in url]
                rejected = [url for url in urls if "example.com" not in url]
                return accepted, rejected

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("https://example.com/a\n")
            tf.write("https://evil.test/b\n")
            tf.flush()
            tf_path = tf.name
        try:
            with patch.object(M, "ScopeValidator", DemoScope):
                M.ingest(
                    self.program,
                    source_file=tf_path,
                    run_id="scoped-run",
                    scope_filter="auto",
                )
            with M.get_conn(self.program) as conn:
                urls = conn.execute("SELECT canonical_url FROM urls ORDER BY id").fetchall()
                self.assertEqual([row["canonical_url"] for row in urls], ["https://example.com/a"])
                imported = conn.execute(
                    "SELECT urls_read, urls_accepted, urls_rejected, scope_mode, "
                    "scoped_temp_path, rejected_temp_path FROM imports ORDER BY id DESC LIMIT 1"
                ).fetchone()
                self.assertEqual(imported["urls_read"], 2)
                self.assertEqual(imported["urls_accepted"], 1)
                self.assertEqual(imported["urls_rejected"], 1)
                self.assertEqual(imported["scope_mode"], "saved_scope")
                self.assertTrue(Path(imported["scoped_temp_path"]).read_text().strip().endswith("example.com/a"))
                self.assertIn("evil.test", Path(imported["rejected_temp_path"]).read_text())
        finally:
            os.unlink(tf_path)

    def test_ingest_repull_failure_allows_passive_parse_but_labels_import(self):
        class EmptyScope:
            def __init__(self, program: str, strict: bool = True):
                self.program = program
                self.strict = strict

            def is_empty(self):
                return True

            def scope_summary(self):
                return "(no scope loaded)"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("https://unknown.example/a\n")
            tf.flush()
            tf_path = tf.name
        try:
            with patch.object(M, "ScopeValidator", EmptyScope), patch.object(
                M, "_try_repull_scope", return_value=(False, "not found on public platforms")
            ):
                M.ingest(
                    self.program,
                    source_file=tf_path,
                    run_id="no-scope-run",
                    scope_filter="auto",
                    repull_scope=True,
                )
            with M.get_conn(self.program) as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0], 1)
                imported = conn.execute(
                    "SELECT urls_read, urls_accepted, urls_rejected, scope_mode, scope_note "
                    "FROM imports ORDER BY id DESC LIMIT 1"
                ).fetchone()
                self.assertEqual(imported["urls_read"], 1)
                self.assertEqual(imported["urls_accepted"], 1)
                self.assertEqual(imported["urls_rejected"], 0)
                self.assertEqual(imported["scope_mode"], "no_scope_after_pull")
                self.assertIn("not found", imported["scope_note"])
        finally:
            os.unlink(tf_path)

    def test_ingest_scope_filter_auto_repulls_by_default(self):
        class EmptyScope:
            def __init__(self, program: str, strict: bool = True):
                self.program = program
                self.strict = strict

            def is_empty(self):
                return True

            def scope_summary(self):
                return "(no scope loaded)"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("https://unknown.example/a\n")
            tf.flush()
            tf_path = tf.name
        try:
            with patch.object(M, "ScopeValidator", EmptyScope), patch.object(
                M, "_try_repull_scope", return_value=(False, "not found on public platforms")
            ) as repull:
                M.ingest(
                    self.program,
                    source_file=tf_path,
                    run_id="default-repull-run",
                    scope_filter="auto",
                )
            repull.assert_called_once_with(self.program)
            with M.get_conn(self.program) as conn:
                imported = conn.execute(
                    "SELECT scope_mode, scope_source, scope_note "
                    "FROM imports ORDER BY id DESC LIMIT 1"
                ).fetchone()
                self.assertEqual(imported["scope_mode"], "no_scope_after_pull")
                self.assertEqual(imported["scope_source"], "no_scope_after_pull")
                self.assertIn("not found", imported["scope_note"])
        finally:
            os.unlink(tf_path)

    def test_ingest_scope_filter_can_disable_repull(self):
        class EmptyScope:
            def __init__(self, program: str, strict: bool = True):
                self.program = program
                self.strict = strict

            def is_empty(self):
                return True

            def scope_summary(self):
                return "(no scope loaded)"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("https://unknown.example/a\n")
            tf.flush()
            tf_path = tf.name
        try:
            with patch.object(M, "ScopeValidator", EmptyScope), patch.object(
                M, "_try_repull_scope", return_value=(False, "should not be called")
            ) as repull:
                M.ingest(
                    self.program,
                    source_file=tf_path,
                    run_id="no-repull-run",
                    scope_filter="auto",
                    repull_scope=False,
                )
            repull.assert_not_called()
            with M.get_conn(self.program) as conn:
                imported = conn.execute(
                    "SELECT scope_mode, scope_source FROM imports ORDER BY id DESC LIMIT 1"
                ).fetchone()
                self.assertEqual(imported["scope_mode"], "no_saved_scope")
                self.assertEqual(imported["scope_source"], "saved_scope")
        finally:
            os.unlink(tf_path)

    def test_ingest_tracks_first_and_last_seen(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write("https://unique.example.com/path\n")
            tf.flush()
            tf_path = tf.name
        try:
            M.ingest(self.program, source_file=tf_path, run_id="test-run")
            with M.get_conn(self.program) as conn:
                row = conn.execute("SELECT first_seen, last_seen FROM urls").fetchone()
                self.assertIsNotNone(row["first_seen"])
                self.assertEqual(row["first_seen"], row["last_seen"])
        finally:
            os.unlink(tf_path)


class TestMark(unittest.TestCase):
    def setUp(self):
        self.program = "testprog2"
        self.db_path = TEMP_SHARED / self.program / "web" / "recon" / "url_index" / "url_index.sqlite"
        M.SHARED_BASE = TEMP_SHARED
        M.init_db(self.program)
        # Insert a URL directly so we can mark it
        with M.get_conn(self.program) as conn:
            now = "2026-06-02T00:00:00"
            conn.execute(
                "INSERT INTO urls (canonical_url, url_hash, route_hash, param_hash, "
                "host, path, param_keys, source, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("https://example.com/page", "a" * 64, "b" * 64, "c" * 64,
                 "example.com", "/page", "[]", "test", now, now)
            )

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()

    def test_mark_inserts_observation(self):
        M.mark(self.program, "https://example.com/page",
               lane="xss", status="surface_reviewed", notes="quick scan", run_id="r1")
        with M.get_conn(self.program) as conn:
            row = conn.execute(
                "SELECT * FROM observations WHERE url_id=1 AND lane='xss'"
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["status"], "surface_reviewed")
            test = conn.execute(
                "SELECT * FROM test_runs WHERE url_id=1 AND lane='xss'"
            ).fetchone()
            self.assertIsNotNone(test)
            self.assertEqual(test["skill"], M.DEFAULT_TEST_SKILL)
            self.assertEqual(test["test_family"], M.DEFAULT_TEST_FAMILY)

    def test_mark_updates_existing_observation(self):
        M.mark(self.program, "https://example.com/page",
               lane="xss", status="surface_reviewed", run_id="r1",
               skill="user-agent-fuzz", test_family="header-behavior")
        M.mark(self.program, "https://example.com/page",
               lane="xss", status="deep_reviewed", run_id="r2",
               skill="param-fuzz", test_family="parameter-mining")
        with M.get_conn(self.program) as conn:
            count = conn.execute("SELECT COUNT(*) FROM observations WHERE url_id=1 AND lane='xss'"
                                 ).fetchone()[0]
            self.assertEqual(count, 1)
            status = conn.execute(
                "SELECT status FROM observations WHERE url_id=1 AND lane='xss'"
            ).fetchone()["status"]
            self.assertEqual(status, "deep_reviewed")
            test_count = conn.execute(
                "SELECT COUNT(*) FROM test_runs WHERE url_id=1 AND lane='xss'"
            ).fetchone()[0]
            self.assertEqual(test_count, 2)

    def test_mark_records_specific_test_metadata_append_only(self):
        M.mark(
            self.program,
            "https://example.com/page",
            lane="recon",
            status="surface_reviewed",
            skill="user-agent-fuzz",
            test_family="header-behavior",
            technique="desktop-vs-mobile-agent",
            request_variant="changed User-Agent only",
            response_summary="status and length unchanged",
            notes="No behavior delta.",
            run_id="r-ua",
            agent_id="agent-1",
        )
        M.mark(
            self.program,
            "https://example.com/page",
            lane="recon",
            status="deep_reviewed",
            skill="param-fuzz",
            test_family="parameter-mining",
            technique="known-param-wordlist",
            response_summary="extra debug parameter rejected",
            run_id="r-param",
            agent_id="agent-2",
        )

        with M.get_conn(self.program) as conn:
            rows = conn.execute(
                "SELECT skill, test_family, technique, request_variant, response_summary "
                "FROM test_runs WHERE url_id=1 ORDER BY id"
            ).fetchall()
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["skill"], "user-agent-fuzz")
            self.assertEqual(rows[0]["test_family"], "header-behavior")
            self.assertEqual(rows[0]["request_variant"], "changed User-Agent only")
            self.assertEqual(rows[1]["skill"], "param-fuzz")
            self.assertEqual(rows[1]["test_family"], "parameter-mining")

    def test_mark_can_track_two_params_for_same_url_and_lane(self):
        url = "https://example.com/page?q=test&redirect=https://example.net/"
        M.mark(
            self.program,
            url,
            lane="xss",
            status="surface_reviewed",
            skill="gf",
            test_family="dynamic-filter",
            param_key="q",
            run_id="r-q",
        )
        M.mark(
            self.program,
            url,
            lane="xss",
            status="dismissed",
            skill="gf",
            test_family="dynamic-filter",
            param_key="redirect",
            run_id="r-redirect",
        )

        with M.get_conn(self.program) as conn:
            observations = conn.execute(
                "SELECT lane, param_key, status FROM observations "
                "WHERE lane='xss' ORDER BY param_key"
            ).fetchall()
            tests = conn.execute(
                "SELECT param_key, skill, test_family FROM test_runs "
                "WHERE lane='xss' ORDER BY param_key"
            ).fetchall()
        self.assertEqual(
            [(row["param_key"], row["status"]) for row in observations],
            [("q", "surface_reviewed"), ("redirect", "dismissed")],
        )
        self.assertEqual([row["param_key"] for row in tests], ["q", "redirect"])
        self.assertTrue(all(row["skill"] == "gf" for row in tests))

    def test_query_next_exact_param_ignores_other_params_tested_on_same_url(self):
        url = "https://example.com/page?q=test&redirect=https://example.net/"
        M.mark(
            self.program,
            url,
            lane="xss",
            status="surface_reviewed",
            skill="gf",
            test_family="dynamic-filter",
            param_key="q",
            run_id="r-q",
        )

        import io, sys

        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        M.query_next(
            self.program,
            lane="xss",
            skill="gf",
            test_family="dynamic-filter",
            param_key="redirect",
            limit=10,
        )
        output = sys.stdout.getvalue()
        sys.stdout = old_stdout
        self.assertIn("redirect=", output)

    def test_mark_invalid_status_rejected(self):
        # Should not raise, just prints error and returns
        M.mark(self.program, "https://example.com/page",
               lane="xss", status="invalid_status")

    def test_mark_new_url_auto_ingests(self):
        M.mark(self.program, "https://new.example.com/path",
               lane="ssrf", status="discovered", run_id="r1")
        with M.get_conn(self.program) as conn:
            row = conn.execute("SELECT * FROM urls WHERE host LIKE '%new.example.com%'"
                               ).fetchone()
            self.assertIsNotNone(row)


class TestStats(unittest.TestCase):
    def setUp(self):
        self.program = "testprog3"
        self.db_path = TEMP_SHARED / self.program / "web" / "recon" / "url_index" / "url_index.sqlite"
        M.SHARED_BASE = TEMP_SHARED
        M.init_db(self.program)
        with M.get_conn(self.program) as conn:
            now = "2026-06-02T00:00:00"
            conn.execute(
                "INSERT INTO urls (canonical_url, url_hash, route_hash, param_hash, "
                "host, path, param_keys, source, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("https://x.com/a", "a" * 64, "b" * 64, "c" * 64, "x.com", "/a", "[]", "test", now, now)
            )
            conn.execute(
                "INSERT INTO urls (canonical_url, url_hash, route_hash, param_hash, "
                "host, path, param_keys, source, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("https://x.com/b", "d" * 64, "e" * 64, "f" * 64, "x.com", "/b", "[]", "test", now, now)
            )
            conn.execute(
                "INSERT INTO observations (url_id, lane, status, created_at) VALUES (1, 'xss', 'deep_reviewed', ?)",
                (now,)
            )
            conn.execute(
                "INSERT INTO test_runs (url_id, lane, skill, test_family, status, started_at, completed_at) "
                "VALUES (1, 'xss', 'xss', 'reflected-probe', 'deep_reviewed', ?, ?)",
                (now, now),
            )
            conn.execute(
                "INSERT INTO imports (source_file, program, urls_imported, imported_at) "
                "VALUES (?, ?, ?, ?)", ("alive.txt", self.program, 2, now)
            )
            conn.commit()

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()

    def test_stats_shows_total_urls(self):
        import io, sys
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        M.stats(self.program)
        output = sys.stdout.getvalue()
        sys.stdout = old_stdout
        self.assertIn("Total URLs: 2", output)
        self.assertIn("xss:reflected-probe", output)

    def test_brief_shows_compact_summary(self):
        import io, sys

        M.mark(
            self.program,
            "https://x.com/search?q=test",
            lane="recon",
            status="surface_reviewed",
            skill="recon",
            test_family="brief-smoke",
        )
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        M.brief(self.program, limit=10)
        output = sys.stdout.getvalue()
        sys.stdout = old_stdout
        self.assertIn("URL Index Brief", output)
        self.assertIn("x.com", output)
        self.assertIn("q:", output)


class TestAggregateRecon(unittest.TestCase):
    def setUp(self):
        self.program = "aggprog"
        M.SHARED_BASE = TEMP_SHARED
        self.program_root = TEMP_SHARED / self.program / "web" / "recon"
        self.source_root = self.program_root / "recon-ry" / "www.example.com" / "runs" / "2026-06-11" / "run1"
        self.source_root.mkdir(parents=True, exist_ok=True)
        (self.source_root / "urls.txt").write_text(
            "https://www.example.com/a\n"
            "https://www.example.com/assets/app.js\n",
            encoding="utf-8",
        )
        (self.source_root / "params_raw.txt").write_text(
            "https://www.example.com/search?q=test\n"
            "https://www.example.com/search?q=test\n",
            encoding="utf-8",
        )
        (self.source_root / "js_files.txt").write_text(
            "https://www.example.com/assets/app.js\n",
            encoding="utf-8",
        )
        (self.source_root / "live.txt").write_text(
            "https://live.example.com/\n",
            encoding="utf-8",
        )
        (self.source_root / "live-hosts.txt").write_text(
            "https://docs.example.com\n",
            encoding="utf-8",
        )
        (self.source_root / "url_seed.txt").write_text(
            "https://seed.example.com\n",
            encoding="utf-8",
        )
        (self.source_root / "baseline-wild.txt").write_text(
            "seed.example.com\n",
            encoding="utf-8",
        )
        (self.source_root / "subdomains.txt").write_text(
            "api.example.com\n",
            encoding="utf-8",
        )
        (self.source_root / "ffuf-results.tsv").write_text(
            "docs.example.com\tadmin\t200\t12\t2\t1\thttps://docs.example.com/admin\n",
            encoding="utf-8",
        )
        (self.source_root / "selected-2000.jsonl").write_text(
            '{"url":"https://www.example.com/apps/search?q=logo","source":"url-map"}\n'
            '{"url":"https://www.example.com/static/runtime.js","source":"url-map"}\n',
            encoding="utf-8",
        )

    def tearDown(self):
        import shutil

        shutil.rmtree(TEMP_SHARED / self.program, ignore_errors=True)

    def test_aggregate_writes_central_files_deltas_and_imports(self):
        from unittest.mock import Mock

        with patch.object(M.subprocess, "run", return_value=Mock(returncode=1)):
            manifest = M.aggregate_recon(
                self.program,
                source_roots=[str(self.source_root)],
                run_id="agg-run",
                ingest_outputs=True,
                scope_filter="off",
            )

        aggregate_dir = self.program_root / "aggregated"
        self.assertEqual(Path(manifest["aggregate_dir"]), aggregate_dir)
        self.assertTrue((aggregate_dir / "urls.txt").exists())
        self.assertTrue((aggregate_dir / "alive.txt").exists())
        self.assertTrue((aggregate_dir / "params_raw.txt").exists())
        self.assertTrue((aggregate_dir / "params.txt").exists())
        self.assertTrue((aggregate_dir / "jsfiles.txt").exists())
        self.assertTrue((aggregate_dir / "runs" / "agg-run" / "delta" / "urls.txt").exists())
        self.assertIn(
            "https://www.example.com/search?q=test",
            (aggregate_dir / "params.txt").read_text(encoding="utf-8"),
        )
        self.assertIn(
            "https://live.example.com/",
            (aggregate_dir / "alive.txt").read_text(encoding="utf-8"),
        )
        self.assertIn(
            "https://docs.example.com",
            (aggregate_dir / "alive.txt").read_text(encoding="utf-8"),
        )
        self.assertIn(
            "https://seed.example.com",
            (aggregate_dir / "urls.txt").read_text(encoding="utf-8"),
        )
        self.assertIn(
            "api.example.com",
            (aggregate_dir / "wild.txt").read_text(encoding="utf-8"),
        )
        self.assertIn(
            "https://docs.example.com/admin",
            (aggregate_dir / "dirs.txt").read_text(encoding="utf-8"),
        )
        self.assertIn(
            "https://www.example.com/apps/search?q=logo",
            (aggregate_dir / "params_raw.txt").read_text(encoding="utf-8"),
        )
        self.assertIn(
            "https://www.example.com/assets/app.js",
            (aggregate_dir / "jsfiles.txt").read_text(encoding="utf-8"),
        )
        self.assertIn(
            "https://www.example.com/static/runtime.js",
            (aggregate_dir / "jsfiles.txt").read_text(encoding="utf-8"),
        )

        with M.get_conn(self.program) as conn:
            total = conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
            imports = conn.execute("SELECT COUNT(*) FROM imports").fetchone()[0]
        self.assertGreaterEqual(total, 3)
        self.assertGreaterEqual(imports, 1)

    def test_aggregate_cli_prefers_input_and_keeps_source_root_alias(self):
        for flag in ("--input", "--source-root"):
            with self.subTest(flag=flag):
                with patch.object(M, "aggregate_recon") as aggregate:
                    with patch.object(
                        sys,
                        "argv",
                        [
                            "url_ingest.py",
                            "aggregate",
                            self.program,
                            flag,
                            str(self.source_root),
                            "--run-id",
                            f"cli-{flag.lstrip('-')}",
                            "--no-ingest",
                        ],
                    ):
                        M.main()

                    aggregate.assert_called_once()
                    kwargs = aggregate.call_args.kwargs
                    self.assertEqual(kwargs["source_roots"], [str(self.source_root)])
                    self.assertFalse(kwargs["ingest_outputs"])


class TestQueryStatus(unittest.TestCase):
    def setUp(self):
        self.program = "testprog4"
        self.db_path = TEMP_SHARED / self.program / "web" / "recon" / "url_index" / "url_index.sqlite"
        M.SHARED_BASE = TEMP_SHARED
        M.init_db(self.program)
        with M.get_conn(self.program) as conn:
            now = "2026-06-02T00:00:00"
            conn.execute(
                "INSERT INTO urls (canonical_url, url_hash, route_hash, param_hash, "
                "host, path, param_keys, source, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("https://target.com/api/v2/users?id=1", "aaa", "bbb", "ccc",
                 "target.com", "/api/v2/users", '["id"]', "alive.txt", now, now)
            )
            conn.execute(
                "INSERT INTO observations (url_id, lane, status, created_at) "
                "VALUES (1, 'idor', 'deep_reviewed', ?)", (now,)
            )
            conn.commit()

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()

    def test_status_returns_all_lanes(self):
        import io, sys
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        M.query_status(self.program, limit=10)
        output = sys.stdout.getvalue()
        sys.stdout = old_stdout
        self.assertIn("target.com", output)
        self.assertIn("[idor]", output)

    def test_status_by_lane(self):
        import io, sys
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        M.query_status(self.program, lane="idor", limit=10)
        output = sys.stdout.getvalue()
        sys.stdout = old_stdout
        self.assertIn("deep_reviewed", output)

    def test_next_excludes_matching_test_family_only(self):
        with M.get_conn(self.program) as conn:
            now = "2026-06-02T00:00:00"
            conn.execute(
                "INSERT INTO urls (canonical_url, url_hash, route_hash, param_hash, "
                "host, path, param_keys, source, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("https://target.com/api/v2/search?q=1", "ddd", "eee", "fff",
                 "target.com", "/api/v2/search", '["q"]', "alive.txt", now, now)
            )
            conn.execute(
                "INSERT INTO test_runs (url_id, lane, skill, test_family, status, started_at, completed_at) "
                "VALUES (1, 'recon', 'user-agent-fuzz', 'header-behavior', 'surface_reviewed', ?, ?)",
                (now, now),
            )
            conn.commit()

        import io, sys
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        M.query_next(
            self.program,
            lane="recon",
            skill="param-fuzz",
            test_family="parameter-mining",
            limit=10,
        )
        output = sys.stdout.getvalue()
        sys.stdout = old_stdout
        self.assertIn("api/v2/users", output)
        self.assertIn("api/v2/search", output)

        sys.stdout = io.StringIO()
        M.query_next(
            self.program,
            lane="recon",
            skill="user-agent-fuzz",
            test_family="header-behavior",
            limit=10,
        )
        output = sys.stdout.getvalue()
        sys.stdout = old_stdout
        self.assertNotIn("api/v2/users", output)
        self.assertIn("api/v2/search", output)

    def test_next_param_preset_filters_by_parameter_keys(self):
        with M.get_conn(self.program) as conn:
            now = "2026-06-02T00:00:00"
            conn.execute(
                "INSERT INTO urls (canonical_url, url_hash, route_hash, param_hash, "
                "host, path, param_keys, source, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("https://target.com/search?q=test", "111", "222", "333",
                 "target.com", "/search", '["q"]', "alive.txt", now, now)
            )
            conn.execute(
                "INSERT INTO urls (canonical_url, url_hash, route_hash, param_hash, "
                "host, path, param_keys, source, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("https://target.com/oembed?url=https://target.com/x", "444", "555", "666",
                 "target.com", "/oembed", '["url"]', "alive.txt", now, now)
            )
            conn.execute(
                "INSERT INTO urls (canonical_url, url_hash, route_hash, param_hash, "
                "host, path, param_keys, source, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("https://target.com/plain", "777", "888", "999",
                 "target.com", "/plain", "[]", "alive.txt", now, now)
            )
            conn.commit()

        import io, sys
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        M.query_next(
            self.program,
            lane="xss",
            skill="xss",
            test_family="reflected-probe",
            param_preset="xss",
            limit=10,
        )
        output = sys.stdout.getvalue()
        sys.stdout = old_stdout
        self.assertIn("/search?q=test", output)
        self.assertNotIn("/oembed", output)
        self.assertNotIn("/plain", output)

        sys.stdout = io.StringIO()
        M.query_next(
            self.program,
            lane="ssrf",
            skill="ssrf",
            test_family="url-fetcher-probe",
            param_preset="ssrf",
            limit=10,
        )
        output = sys.stdout.getvalue()
        sys.stdout = old_stdout
        self.assertIn("/oembed?url=", output)
        self.assertNotIn("/search?q=test", output)
        self.assertNotIn("/plain", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
