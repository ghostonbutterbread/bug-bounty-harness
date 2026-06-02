#!/usr/bin/env python3
"""Unit tests for url_ingest.py — URL Ingestor + Review Tracker."""

import unittest
import tempfile
import os
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

    def test_mark_updates_existing_observation(self):
        M.mark(self.program, "https://example.com/page",
               lane="xss", status="surface_reviewed", run_id="r1")
        M.mark(self.program, "https://example.com/page",
               lane="xss", status="deep_reviewed", run_id="r2")
        with M.get_conn(self.program) as conn:
            count = conn.execute("SELECT COUNT(*) FROM observations WHERE url_id=1 AND lane='xss'"
                                 ).fetchone()[0]
            self.assertEqual(count, 1)
            status = conn.execute(
                "SELECT status FROM observations WHERE url_id=1 AND lane='xss'"
            ).fetchone()["status"]
            self.assertEqual(status, "deep_reviewed")

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
