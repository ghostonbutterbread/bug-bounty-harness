from __future__ import annotations

import json
from pathlib import Path

from agents import scope_puller
import program_config
import pytest


def test_scope_puller_imports_as_package() -> None:
    assert scope_puller.canonical_program_slug("https://bugcrowd.com/engagements/demo") == "demo"


def test_bugcrowd_scope_preserves_wildcard_name_when_uri_is_root_url(monkeypatch) -> None:
    raw = {
        "data": {
            "brief": {},
            "engagementConfiguration": {},
            "scope": [
                {
                    "id": "group-1",
                    "name": "In Scope Targets",
                    "inScope": True,
                    "targets": [
                        {
                            "id": "target-1",
                            "name": "*.flourish.studio",
                            "uri": "https://flourish.studio/",
                            "category": "website",
                        },
                        {
                            "id": "target-2",
                            "name": "*.xyzbmojn.net",
                            "uri": "https://xyzbmojn.net/",
                            "category": "website",
                        },
                    ],
                }
            ],
        }
    }
    monkeypatch.setattr(scope_puller, "fetch_json", lambda _url: raw)

    html = (
        '<div data-api-endpoints="'
        + json.dumps({"engagementBriefApi": {"getBriefVersionDocument": "/engagements/demo/brief"}}).replace('"', "&quot;")
        + '"></div>'
    )
    parsed = scope_puller.parse_bugcrowd_public_engagement("demo", html)

    assert "*.flourish.studio" in parsed["domains"]
    assert "*.xyzbmojn.net" in parsed["domains"]
    assert "https://flourish.studio/" in parsed["urls"]
    assert "https://xyzbmojn.net/" in parsed["urls"]


def test_hackerone_structured_scope_keeps_only_eligible_network_assets() -> None:
    team = {
        "structured_scopes": {"edges": [
            {"node": {"asset_type": "WILDCARD", "asset_identifier": "*.example.com", "eligible_for_submission": True, "eligible_for_bounty": True, "instruction": "test carefully", "max_severity": "critical"}},
            {"node": {"asset_type": "URL", "asset_identifier": "https://api.example.com/v1", "eligible_for_submission": True, "eligible_for_bounty": False, "instruction": "", "max_severity": "high"}},
            {"node": {"asset_type": "OTHER", "asset_identifier": "https://docs.example.com/guide", "eligible_for_submission": True, "eligible_for_bounty": False, "instruction": "", "max_severity": "low"}},
            {"node": {"asset_type": "OTHER", "asset_identifier": "Tier A - Core Assets", "eligible_for_submission": True, "eligible_for_bounty": True, "instruction": "", "max_severity": "high"}},
            {"node": {"asset_type": "GOOGLE_PLAY_APP_ID", "asset_identifier": "com.example.android", "eligible_for_submission": True, "eligible_for_bounty": True, "instruction": "", "max_severity": "medium"}},
            {"node": {"asset_type": "SOURCE_CODE", "asset_identifier": "https://github.com/example/private-repo", "eligible_for_submission": True, "eligible_for_bounty": True, "instruction": "", "max_severity": "medium"}},
            {"node": {"asset_type": "SOURCE_CODE", "asset_identifier": "https://api.example.com/documentation", "eligible_for_submission": True, "eligible_for_bounty": True, "instruction": "", "max_severity": "medium"}},
            {"node": {"asset_type": "URL", "asset_identifier": "https://out.example.com", "eligible_for_submission": False, "eligible_for_bounty": False, "instruction": "excluded", "max_severity": "none"}},
        ]},
    }
    parsed = scope_puller.parse_hackerone_scope(team)
    assert parsed["domains"] == {"*.example.com"}
    assert parsed["urls"] == {"https://api.example.com/v1", "https://docs.example.com/guide", "https://api.example.com/documentation"}
    # assets.json preserves every eligible structured asset, even types that
    # cannot become a network target (such as a mobile package identifier).
    assert [item["name"] for item in parsed["assets"]] == ["critical", "high", "medium", "low"]
    assert [item["uri"] for item in parsed["out_of_scope"]] == ["https://out.example.com"]


def test_hackerone_pull_uses_structured_scope_without_page_scrape(monkeypatch) -> None:
    saved = {}
    monkeypatch.setattr(scope_puller, "fetch_hackerone_team", lambda handle: {
        "policy": "No denial of service.", "submission_state": "open", "offers_bounties": True,
        "structured_scopes": {"edges": [{"node": {"asset_type": "URL", "asset_identifier": "https://api.example.com", "eligible_for_submission": True, "eligible_for_bounty": True, "instruction": "", "max_severity": "high"}}]},
    })
    monkeypatch.setattr(scope_puller, "save_scope", lambda program, data: saved.update(program=program, data=data))
    result = scope_puller.pull_scope("https://hackerone.com/demo/policy_scopes", "hackerone")
    assert saved["program"] == "demo"
    assert result["urls"] == {"https://api.example.com"}
    assert result["rules"]["source_brief_url"] == scope_puller.HACKERONE_GRAPHQL


def test_hackerone_fetch_paginates_every_structured_scope_page(monkeypatch) -> None:
    requests = []
    responses = iter([
        {
            "data": {"team": {
                "handle": "demo", "policy": "policy",
                "structured_scopes": {
                    "edges": [{"node": {"asset_identifier": "one.example.com"}}],
                    "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"},
                },
            }},
        },
        {
            "data": {"team": {
                "handle": "demo", "policy": "policy",
                "structured_scopes": {
                    "edges": [{"node": {"asset_identifier": "two.example.com"}}],
                    "pageInfo": {"hasNextPage": False, "endCursor": "cursor-2"},
                },
            }},
        },
    ])

    class Response:
        def __init__(self, body):
            self.body = body

        def read(self):
            return json.dumps(self.body).encode()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def fake_urlopen(request, timeout):
        assert timeout == 30
        requests.append(json.loads(request.data.decode()))
        return Response(next(responses))

    monkeypatch.setattr(scope_puller.urllib.request, "urlopen", fake_urlopen)

    team = scope_puller.fetch_hackerone_team("demo")

    assert [request["variables"]["after"] for request in requests] == [None, "cursor-1"]
    assert [edge["node"]["asset_identifier"] for edge in team["structured_scopes"]["edges"]] == [
        "one.example.com", "two.example.com",
    ]


def test_hackerone_fetch_refuses_scope_response_without_pagination_metadata(monkeypatch) -> None:
    class Response:
        def read(self):
            return json.dumps({
                "data": {"team": {"handle": "demo", "structured_scopes": {"edges": []}}},
            }).encode()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(scope_puller.urllib.request, "urlopen", lambda *_args, **_kwargs: Response())

    with pytest.raises(RuntimeError, match="pagination metadata"):
        scope_puller.fetch_hackerone_team("demo")


def test_program_config_prefers_pulled_scope_over_scope_prose(monkeypatch, tmp_path: Path) -> None:
    scopes = tmp_path / "scopes"
    web_bounty = tmp_path / "web_bounty"
    (scopes / "demo").mkdir(parents=True)
    (scopes / "demo" / "in-scope.txt").write_text("# scope\n*.example.com\nHTTPS://api.example.com/v2\n")
    scope_md = web_bounty / "demo" / "web" / "scope"
    scope_md.mkdir(parents=True)
    (scope_md / "scope.md").write_text("Out of scope: returns.example.com and hackerone.com\n")
    monkeypatch.setattr(program_config, "SCOPES_DIR", scopes)
    monkeypatch.setattr(program_config, "BASE_DIR", web_bounty)
    cfg = program_config.ProgramConfig.load("demo")
    # A path-scoped URL must not be widened into a host-wide campaign allow-list.
    assert cfg.scope_domains == ["*.example.com"]


def test_save_scope_rejects_an_empty_network_scope() -> None:
    with pytest.raises(RuntimeError, match="refusing to overwrite scope files"):
        scope_puller.save_scope("demo", {"domains": set(), "urls": set()}, legacy=False)
