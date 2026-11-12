from __future__ import annotations

import json
from pathlib import Path

import pytest

from agents import scope_puller


def _review_path(tmp_path: Path, slug: str = "demo") -> Path:
    path = tmp_path / "Shared" / "scopes" / slug / "scope-review.json"
    path.parent.mkdir(parents=True)
    return path


def test_apply_scope_review_is_noop_without_file(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(scope_puller.Path, "home", lambda: tmp_path)
    data = {"domains": {"www.example.test"}, "out_of_scope": []}
    out = scope_puller.apply_scope_review("demo", data)
    assert out is data
    assert "scope_review_applied" not in out


def test_apply_scope_review_grant_exclusion_and_skip(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(scope_puller.Path, "home", lambda: tmp_path)
    review = {
        "source": "operator",
        "grants": [{
            "platform_name": "*.example.test",
            "entry": "*.example.test",
            "reason": "wildcard grant",
        }],
        "exclusions": [
            {
                "platform_name": "support.example.*",
                "entry": "support.example.test",
                "reason": "tld",
            },
            {
                "platform_name": "*.other.test",
                "skip": True,
                "reason": "would over-exclude",
            },
        ],
    }
    _review_path(tmp_path).write_text(json.dumps(review), encoding="utf-8")
    data = {
        "program": "demo",
        "platform": "bugcrowd",
        "domains": set(),
        "urls": {"https://www.example.test/"},
        "out_of_scope": [
            {"name": "support.example.*", "uri": "", "group": "other"},
            {"name": "*.other.test", "uri": "", "group": "other"},
            {"name": "jobs.example.test", "uri": "", "group": "other"},
        ],
        "assets": [],
        "rules": {},
    }
    out = scope_puller.apply_scope_review("demo", data)
    assert "*.example.test" in out["domains"]
    names = [str(target.get("name") or "") for target in out["out_of_scope"]]
    assert "support.example.test" in names
    assert "*.other.test" not in names
    assert "jobs.example.test" in names
    verbatim = [str(target.get("name") or "") for target in out["platform_exclusions_verbatim"]]
    assert "*.other.test" in verbatim
    scope_puller.save_scope("demo", out)
    saved = json.loads((tmp_path / "Shared/scopes/demo/out-of-scope.json").read_text(encoding="utf-8"))
    assert any(row.get("name") == "*.other.test" for row in saved)
    policy = (tmp_path / "Shared/scopes/demo/program-policy.md").read_text(encoding="utf-8")
    assert "## Reviewed Scope Resolution" in policy
    assert "`*.example.test`" in policy
    assert "`support.example.test`" in policy


def test_apply_scope_review_rejects_invalid_grant(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(scope_puller.Path, "home", lambda: tmp_path)
    _review_path(tmp_path).write_text(json.dumps({
        "grants": [{"platform_name": "", "entry": "*.example.test"}],
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid reviewed grant"):
        scope_puller.apply_scope_review("demo", {"domains": set(), "out_of_scope": []})
