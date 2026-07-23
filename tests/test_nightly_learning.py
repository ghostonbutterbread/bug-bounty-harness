"""Tests for the report-only passive AppSec learning runner."""
from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "nightly_learning.py"
SPEC = importlib.util.spec_from_file_location("nightly_learning", SCRIPT_PATH)
assert SPEC and SPEC.loader
nightly_learning = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = nightly_learning
SPEC.loader.exec_module(nightly_learning)


def registry_data() -> dict:
    return {"version": 1, "sources": [{"id": "lostsec_medium", "name": "lostsec Medium", "url": "https://lostsec.medium.com/", "type": "medium_author_or_publication", "tags": ["appsec"], "enabled": True, "priority": 80, "fetch_strategy": "medium_feed"}]}


def test_registry_rejects_duplicate_ids_and_non_https_urls() -> None:
    data = registry_data()
    duplicate = dict(data["sources"][0])
    duplicate["url"] = "http://example.test/"
    data["sources"].append(duplicate)

    errors = nightly_learning.validate_registry(data)

    assert any("duplicate id" in error for error in errors)
    assert any("canonical HTTPS" in error for error in errors)


def test_beta_writes_auditable_report_without_notes_or_cards(tmp_path: Path) -> None:
    registry = tmp_path / "sources.yaml"
    registry.write_text(yaml.safe_dump(registry_data()), encoding="utf-8")
    sources = nightly_learning.load_registry(registry)

    def fake_fetch(source, _max_chars):
        return {"type": "SanitizedDocument", "verdict": "allow", "fetched_at": "2026-07-20T00:00:00Z", "sha256": "abc", "artifact_dir": "/quarantine/example", "raw_artifact": "safe-fetch://quarantine/example/raw.bin", "risk_flags": [], "recommended_mode": "normal", "truncated": False}

    report_path, report = nightly_learning.run_beta(sources, tmp_path / "reports", fetch=fake_fetch, now=datetime(2026, 7, 20, tzinfo=timezone.utc))

    assert report_path.is_file()
    assert report["mode"] == "beta-report-only"
    assert report["counts"] == {"new": 1, "duplicate": 0, "needs_review": 0, "failed": 0}
    assert not (tmp_path / "cards").exists()
    assert "no cards, notes, skills" in (tmp_path / "reports" / "2026-07-20.md").read_text(encoding="utf-8")

    _, repeat = nightly_learning.run_beta(sources, tmp_path / "reports", fetch=fake_fetch, now=datetime(2026, 7, 21, tzinfo=timezone.utc))
    assert repeat["counts"] == {"new": 0, "duplicate": 1, "needs_review": 0, "failed": 0}


def test_beta_routes_non_allow_documents_to_review(tmp_path: Path) -> None:
    source = nightly_learning.Source("review", "Review", "https://example.test/", "web_index", ["appsec"], True, 1, "html_index")

    _, report = nightly_learning.run_beta([source], tmp_path, fetch=lambda *_: {"type": "SanitizedDocument", "verdict": "review", "risk_flags": ["prompt_injection"]}, now=datetime(2026, 7, 20, tzinfo=timezone.utc))

    assert report["counts"] == {"new": 0, "duplicate": 0, "needs_review": 1, "failed": 0}
    assert report["records"][0]["risk_flags"] == ["prompt_injection"]
