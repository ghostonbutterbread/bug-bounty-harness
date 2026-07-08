"""Tests for map_store.py"""

from __future__ import annotations

import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

# Make the harness agents importable
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents.map_store import (
    MapStore,
    iso_now,
    normalize_url,
    observation_slug,
    parse_time_filter,
    slugify,
    url_to_dirname,
    APP_SCOPE,
    SURFACE_SCOPE,
    URL_SCOPE,
)


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------


class TestNormalizeUrl:
    def test_scheme_normalised(self):
        # normalize_url preserves the scheme; doesn't force https
        assert normalize_url("https://app.com") == "https://app.com/"
        assert normalize_url("http://app.com") == "http://app.com/"

    def test_trailing_slash_stripped(self):
        assert normalize_url("https://app.com/login/") == "https://app.com/login"

    def test_root_path_preserved(self):
        assert normalize_url("https://app.com/") == "https://app.com/"

    def test_query_sorted(self):
        result = normalize_url("https://app.com?a=1&c=3&b=2")
        assert "a=1" in result
        assert "b=2" in result
        assert "c=3" in result
        # Order should be a, b, c
        assert "a=1&b=2&c=3" in result

    def test_host_lowercased(self):
        assert normalize_url("https://App.COM/Login") == "https://app.com/Login"

    def test_no_scheme_defaults_https(self):
        assert normalize_url("app.com/login") == "https://app.com/login"

    def test_empty(self):
        assert normalize_url("") == ""


class TestUrlToDirname:
    def test_simple_url(self):
        # / becomes _s_ in dirname encoding
        result = url_to_dirname("https://app.com/login")
        assert result == "app.com_s_login"

    def test_with_query(self):
        result = url_to_dirname("https://app.com/login?next=/admin")
        assert "login" in result
        assert "next" in result

    def test_empty(self):
        assert url_to_dirname("") == "_root"

    def test_no_scheme(self):
        result = url_to_dirname("app.com/login")
        assert "app.com" in result
        assert "login" in result


class TestSlugify:
    def test_spaces_to_dashes(self):
        assert slugify("hello world") == "hello-world"

    def test_special_chars_removed(self):
        assert slugify("csrf@token!") == "csrf-token"

    def test_fallback(self):
        assert slugify("!!!", fallback="unknown") == "unknown"

    def test_observation_slug_uses_title_and_run(self):
        assert (
            observation_slug(
                surface="recon",
                scope=APP_SCOPE,
                title="Href sweep",
                run_id="run-1",
            )
            == "recon-href-sweep-run-1"
        )


class TestTimeFilters:
    def test_parse_iso_time_filter(self):
        parsed = parse_time_filter("2026-07-08T15:00:00Z")
        assert parsed == datetime(2026, 7, 8, 15, 0, tzinfo=timezone.utc)

    def test_parse_date_time_filter(self):
        parsed = parse_time_filter("2026-07-08")
        assert parsed == datetime(2026, 7, 8, 0, 0, tzinfo=timezone.utc)

    def test_parse_relative_time_filter(self):
        parsed = parse_time_filter("24h")
        assert parsed.tzinfo is not None


# ---------------------------------------------------------------------------
# MapStore integration tests (real temp dir, no real program)
# ---------------------------------------------------------------------------


class TestMapStore:
    """Integration tests using a real MapStore backed by a temp directory."""

    @pytest.fixture
    def store(self, tmp_path: Path):
        """Create a MapStore pointed at a temp shared root."""
        # Create a minimal shared structure
        web_root = tmp_path / "web_bounty" / "testprog" / "web"
        recon = web_root / "recon"
        recon.mkdir(parents=True)
        (web_root / "context").mkdir(parents=True)
        (web_root / "notes").mkdir(parents=True)
        (web_root / "ledgers").mkdir(parents=True)
        (web_root / "reports").mkdir(parents=True)

        # Write minimal target_profile.json so storage_resolver works
        profile = {
            "program": "testprog",
            "family": "web_bounty",
            "lane": "web",
            "root_mode": "shared-default",
            "base_root": str(tmp_path),
            "family_root": str(tmp_path / "web_bounty"),
            "program_root": str(tmp_path / "web_bounty" / "testprog"),
            "canonical_root": str(web_root),
            "reports_root": str(web_root / "reports"),
            "ledger_root": str(web_root / "ledgers"),
            "working_root": str(web_root / "working"),
            "context_root": str(web_root / "context"),
            "notes_root": str(web_root / "notes"),
            "shared_root": str(tmp_path / "web_bounty" / "testprog" / "shared"),
            "recon_root": str(recon),
            "input_root": "",
            "allow_lane_autocreate": True,
        }
        (web_root / "context" / "target_profile.json").write_text(
            json.dumps(profile, indent=2)
        )

        return MapStore("testprog", root=str(tmp_path), create=True)

    def test_init_creates_structure(self, store: MapStore):
        root = store.init()
        assert root.exists()
        assert (root / "map.jsonl").exists()
        assert (root / "_app" / "index.md").exists()
        assert (root / "_crossref").exists()
        assert (root / ".mapstore.lock").exists()

    def test_write_url_scope(self, store: MapStore):
        store.init()
        path = store.write(
            url="https://app.com/login",
            surface="xss",
            body="## CSRF Token\n\nFound CSRF token `_csrf` in hidden input.\n",
            tags=["csrf", "xss-reflected"],
            agent="xss-worker",
            title="XSS at /login",
        )
        assert path.exists()
        assert "xss/app.com_s_login/xss-at-login/index.md" in str(path)
        content = path.read_text(encoding="utf-8")
        assert "CSRF Token" in content
        assert "Surface: xss" in content
        assert "URL: https://app.com/login" in content
        assert "#csrf" in content

    def test_write_app_scope(self, store: MapStore):
        store.init()
        path = store.write(
            surface="electron",
            body="Renderer is sandboxed. No nodeIntegration.\n",
            scope=APP_SCOPE,
            tags=["sandboxed-renderer"],
        )
        assert "_app/electron-sandboxed-renderer/index.md" in str(path)
        assert (store.maps_root / "_app" / "index.md").exists()

    def test_write_surface_scope(self, store: MapStore):
        store.init()
        path = store.write(
            surface="xss",
            body="All XSS here is sandbox-only.\n",
            scope=SURFACE_SCOPE,
            tags=["sandbox-only"],
        )
        assert "xss/_surface/xss-sandbox-only/index.md" in str(path)
        assert (store.maps_root / "xss" / "_surface").exists()

    def test_app_scope_writes_do_not_overwrite_each_other(self, store: MapStore):
        store.init()
        first = store.write(
            surface="recon",
            body="Href sweep found navigation endpoints.\n",
            scope=APP_SCOPE,
            title="href-sweep",
        )
        second = store.write(
            surface="recon",
            body="Sourcemap gap remains unresolved.\n",
            scope=APP_SCOPE,
            title="sourcemap-gap",
        )

        assert first != second
        assert "Href sweep" in first.read_text(encoding="utf-8")
        assert "Sourcemap gap" in second.read_text(encoding="utf-8")
        entries = store.query(scope=APP_SCOPE)
        assert len(entries) == 2
        assert {entry["title"] for entry in entries} == {"href-sweep", "sourcemap-gap"}

    def test_app_scope_duplicate_titles_get_collision_safe_paths(self, store: MapStore):
        store.init()
        first = store.write(
            surface="recon",
            body="First app-wide note.\n",
            scope=APP_SCOPE,
            title="shared title",
        )
        second = store.write(
            surface="recon",
            body="Second app-wide note.\n",
            scope=APP_SCOPE,
            title="shared title",
        )

        assert first != second
        assert first.parent.name == "recon-shared-title"
        assert second.parent.name == "recon-shared-title-2"
        assert len(store.query(scope=APP_SCOPE)) == 2

    def test_write_updates_index(self, store: MapStore):
        store.init()
        store.write(
            url="https://app.com/login",
            surface="js",
            body="CSP: unsafe-inline allowed.\n",
            tags=["csp", "xss-relevant"],
            agent="js-worker",
        )
        entries = store._read_index()
        assert len(entries) == 1
        assert entries[0]["url"] == "https://app.com/login"
        assert entries[0]["surface"] == "js"
        assert entries[0]["scope"] == "url"
        assert "csp" in entries[0]["tags"]
        assert "xss-relevant" in entries[0]["tags"]

    def test_query_by_url_and_surface(self, store: MapStore):
        store.init()
        store.write(
            url="https://app.com/login",
            surface="js",
            body="JS observations.\n",
            tags=["csp"],
        )
        store.write(
            url="https://app.com/login",
            surface="xss",
            body="XSS observations.\n",
            tags=["reflected"],
        )
        store.write(
            url="https://app.com/signup",
            surface="xss",
            body="Signup XSS.\n",
            tags=["stored"],
        )

        # Query login, XSS surface only
        results = store.query(url="https://app.com/login", surface="xss")
        assert len(results) == 1
        assert results[0]["surface"] == "xss"
        assert results[0]["url"] == "https://app.com/login"

    def test_query_url_without_trailing_slash(self, store: MapStore):
        store.init()
        store.write(
            url="https://app.com/login",
            surface="js",
            body="Test.\n",
        )
        # Query with trailing slash
        results = store.query(url="https://app.com/login/")
        assert len(results) == 1

    def test_query_cross_surface_relevance(self, store: MapStore):
        store.init()
        store.write(
            url="https://app.com/login",
            surface="js",
            body="CSP: unsafe-inline.\n",
            tags=["csp", "xss-relevant"],
        )
        store.write(
            url="https://app.com/login",
            surface="ssrf",
            body="Webhook candidate.\n",
            tags=["webhook"],
        )

        # XSS agent queries — should see JS entry (tagged xss-relevant)
        # but NOT SSRF entry
        results = store.query(url="https://app.com/login", surface="xss")
        surfaces = {r["surface"] for r in results}
        assert "js" in surfaces  # tagged xss-relevant
        assert "ssrf" not in surfaces  # not relevant

    def test_query_app_wide_always_visible(self, store: MapStore):
        store.init()
        store.write(
            surface="electron",
            body="Renderer sandboxed.\n",
            scope=APP_SCOPE,
            tags=["sandboxed-renderer"],
        )
        store.write(
            url="https://app.com/login",
            surface="ssrf",
            body="SSRF candidate.\n",
            tags=["webhook"],
        )

        # XSS agent querying login — should see app-wide entry even
        # though it's not XSS surface
        results = store.query(url="https://app.com/login", surface="xss")
        assert any(r["scope"] == APP_SCOPE for r in results)

    def test_query_all_surfaces(self, store: MapStore):
        store.init()
        store.write(
            url="https://app.com/login",
            surface="js",
            body="JS notes.\n",
        )
        store.write(
            url="https://app.com/login",
            surface="xss",
            body="XSS notes.\n",
        )
        store.write(
            url="https://app.com/login",
            surface="auth",
            body="Auth notes.\n",
        )

        # No surface filter → all surfaces for this URL
        results = store.query(url="https://app.com/login")
        surfaces = {r["surface"] for r in results}
        assert surfaces == {"js", "xss", "auth"}

    def test_query_keeps_crossfamily_entry_with_same_relative_path(self, store: MapStore):
        store.init()
        store.write(
            url="https://app.com/login",
            surface="api",
            body="Web bounty observation.\n",
        )
        local_entry = store._read_index()[0]
        cross_family_entry = {
            **local_entry,
            "body": "Binary observation.",
            "_crossfamily_source": "binaries/exe",
        }

        results = store.query(
            url="https://app.com/login",
            cross_family_entries=[cross_family_entry],
        )

        assert len(results) == 2
        assert {r.get("_crossfamily_source", "local") for r in results} == {
            "local",
            "binaries/exe",
        }

    def test_url_scope_writes_do_not_overwrite_same_endpoint_surface(self, store: MapStore):
        store.init()
        first = store.write(
            url="https://app.com/login",
            surface="js",
            body="First version.\n",
            tags=["v1"],
            title="script inventory",
        )
        second = store.write(
            url="https://app.com/login",
            surface="js",
            body="Updated version.\n",
            tags=["v2"],
            title="sourcemap gap",
        )

        assert first != second
        assert "First version" in first.read_text(encoding="utf-8")
        assert "Updated version" in second.read_text(encoding="utf-8")
        entries = store._read_index()
        assert len(entries) == 2
        assert {entry["title"] for entry in entries} == {"script inventory", "sourcemap gap"}

    def test_url_scope_duplicate_titles_get_collision_safe_paths(self, store: MapStore):
        store.init()
        first = store.write(
            url="https://app.com/upload",
            surface="xss",
            body="Filename marker reflected.\n",
            tags=["xss"],
            title="filename parameter",
        )
        second = store.write(
            url="https://app.com/upload",
            surface="xss",
            body="Filename quote transform tested.\n",
            tags=["xss"],
            title="filename parameter",
        )

        assert first != second
        assert first.parent.name == "filename-parameter"
        assert second.parent.name == "filename-parameter-2"
        results = store.query(url="https://app.com/upload", surface="xss")
        assert len(results) == 2

    def test_write_updates_parent_pointer_index(self, store: MapStore):
        store.init()
        store.write(
            url="https://app.com/upload",
            surface="xss",
            body="Filename marker reflected.\n",
            tags=["xss"],
            title="filename baseline",
        )
        store.write(
            url="https://app.com/upload",
            surface="xss",
            body="Quote transform tested.\n",
            tags=["xss"],
            title="quote transform",
        )

        pointer = store.maps_root / "xss" / url_to_dirname("https://app.com/upload") / "index.md"
        content = pointer.read_text(encoding="utf-8")
        assert "Observations: https://app.com/upload" in content
        assert "[filename baseline](filename-baseline/index.md)" in content
        assert "[quote transform](quote-transform/index.md)" in content

    def test_parallel_cli_writes_preserve_all_observations(self, store: MapStore):
        store.init()
        repo_root = Path(__file__).resolve().parents[1]
        root = str(store._layout.base_root)
        procs = []
        for idx in range(4):
            procs.append(subprocess.Popen([
                sys.executable,
                "agents/map_store.py",
                "write",
                "--program",
                "testprog",
                "--root",
                root,
                "--url",
                "https://app.com/upload",
                "--surface",
                "xss",
                "--title",
                f"parallel note {idx}",
                "--tags",
                "xss,parallel",
                "--body",
                f"Parallel body {idx}",
            ], cwd=repo_root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))

        for proc in procs:
            stdout, stderr = proc.communicate(timeout=20)
            assert proc.returncode == 0, f"stdout={stdout}\nstderr={stderr}"

        results = store.query(url="https://app.com/upload", surface="xss")
        assert len(results) == 4
        assert {entry["title"] for entry in results} == {
            "parallel note 0",
            "parallel note 1",
            "parallel note 2",
            "parallel note 3",
        }

    def test_read_obs(self, store: MapStore):
        store.init()
        path = store.write(
            url="https://app.com/login",
            surface="js",
            body="Test content.\n",
        )
        rel_path = path.relative_to(store.maps_root).as_posix()
        content = store.read_obs(rel_path)
        assert content is not None
        assert "Test content" in content

    def test_read_obs_missing(self, store: MapStore):
        store.init()
        assert store.read_obs("nonexistent/path.md") is None

    def test_rebuild_crossref(self, store: MapStore):
        store.init()
        store.write(
            url="https://app.com/login",
            surface="js",
            body="JS at login.\n",
            tags=["csp"],
        )
        store.write(
            url="https://app.com/login",
            surface="xss",
            body="XSS at login.\n",
            tags=["reflected"],
        )
        store.write(
            surface="electron",
            body="App-wide: sandboxed.\n",
            scope=APP_SCOPE,
        )

        count = store.rebuild_crossref()
        assert count >= 1

        crossref_file = (
            store.maps_root
            / "_crossref"
            / url_to_dirname("https://app.com/login")
            / "index.md"
        )
        assert crossref_file.exists()

        content = crossref_file.read_text(encoding="utf-8")
        assert "js" in content
        assert "xss" in content
        assert "App-Wide" in content

    def test_crossfamily_tagging(self, store: MapStore):
        store.init()
        store.write(
            surface="electron",
            body="Renderer sandboxed.\n",
            scope=APP_SCOPE,
            crossfamily=["web_bounty/canva/web"],
        )
        entries = store._read_index()
        assert "web_bounty/canva/web" in entries[0]["crossfamily"]

    def test_write_invalid_scope_raises(self, store: MapStore):
        store.init()
        with pytest.raises(ValueError, match="Invalid scope"):
            store.write(
                url="https://app.com/",
                surface="js",
                body="test",
                scope="invalid",
            )

    def test_multiple_writes_different_urls(self, store: MapStore):
        store.init()
        store.write(url="https://app.com/a", surface="js", body="A")
        store.write(url="https://app.com/b", surface="js", body="B")
        store.write(url="https://app.com/c", surface="js", body="C")

        entries = store._read_index()
        assert len(entries) == 3

        # Query for just one
        results = store.query(url="https://app.com/b")
        assert len(results) == 1
        assert results[0]["url"] == "https://app.com/b"

    def test_query_empty_store(self, store: MapStore):
        store.init()
        results = store.query(url="https://app.com/login")
        assert results == []

    def test_query_filters_by_since_until_and_limit(self, store: MapStore):
        store.init()
        store.write(url="https://app.com/old", surface="xss", body="Old", title="old")
        store.write(url="https://app.com/new", surface="xss", body="New", title="new")
        entries = store._read_index()
        for entry in entries:
            if entry["title"] == "old":
                entry["timestamp"] = "2026-07-07T12:00:00Z"
            elif entry["title"] == "new":
                entry["timestamp"] = "2026-07-08T12:00:00Z"
        store._write_index(entries)

        recent = store.query(since=parse_time_filter("2026-07-08"))
        assert [entry["title"] for entry in recent] == ["new"]

        older = store.query(until=parse_time_filter("2026-07-07T23:59:59Z"))
        assert [entry["title"] for entry in older] == ["old"]

        limited = store.query(limit=1)
        assert len(limited) == 1
        assert limited[0]["title"] == "new"

    def test_index_sorted_newest_first(self, store: MapStore):
        store.init()
        store.write(url="https://app.com/1", surface="js", body="1")
        store.write(url="https://app.com/2", surface="js", body="2")
        store.write(url="https://app.com/3", surface="js", body="3")

        entries = store._read_index()
        timestamps = [e["timestamp"] for e in entries]
        assert timestamps == sorted(timestamps, reverse=True)
