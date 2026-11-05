from __future__ import annotations

import json
from pathlib import Path

from agents import scope_puller
import program_config
import pytest
from agents.scope_validator import ScopeValidator


def test_scope_puller_imports_as_package() -> None:
    assert scope_puller.canonical_program_slug("https://bugcrowd.com/engagements/demo") == "demo"


def test_bugcrowd_descriptive_web_apps_grant_is_written(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(scope_puller.Path, "home", lambda: tmp_path)
    raw = {"data": {"scope": [{"name": "in", "inScope": True, "targets": [
        {"name": "*.example.test Web Apps", "uri": ""},
    ]}]}}
    monkeypatch.setattr(scope_puller, "fetch_json", lambda _: raw)
    html = '<div data-api-endpoints="{&quot;engagementBriefApi&quot;:{&quot;getBriefVersionDocument&quot;:&quot;/brief&quot;}}"></div>'
    parsed = scope_puller.parse_bugcrowd_public_engagement("demo", html)
    scope_puller.save_scope("demo", parsed)
    assert (tmp_path / "Shared/scopes/demo/in-scope.txt").read_text().splitlines()[-1] == "*.example.test"


def test_bugcrowd_descriptive_exclusion_overrides_wildcard(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(scope_puller.Path, "home", lambda: tmp_path)
    data = {
        "platform": "bugcrowd", "domains": {"*.example.test"}, "urls": set(),
        "out_of_scope": [{"name": "private.example.test Web Apps", "uri": ""}],
    }
    scope_puller.save_scope("demo", data)
    assert (tmp_path / "Shared/scopes/demo/out-of-scope.txt").read_text() == "private.example.test\n"
    assert (tmp_path / "Shared/bounty_recon/demo/scope/out-of-scope.txt").read_text() == "private.example.test\n"
    validator = ScopeValidator("demo", scopes_base=tmp_path / "Shared/scopes")
    assert validator.is_in_scope("https://public.example.test/")
    assert not validator.is_in_scope("https://private.example.test/")


@pytest.mark.parametrize("name", [
    "Not private.example.test Web Apps",
    "private.example.test and admin.example.test Web Apps",
    "private.example.test Web Apps except admin.example.test",
    "Private applications",
])
def test_bugcrowd_ambiguous_exclusion_refuses_all_writes(monkeypatch, tmp_path: Path, name: str) -> None:
    monkeypatch.setattr(scope_puller.Path, "home", lambda: tmp_path)
    path = tmp_path / "Shared/scopes/demo/in-scope.txt"
    path.parent.mkdir(parents=True)
    path.write_text("previous scope\n")
    data = {
        "platform": "bugcrowd", "domains": {"*.example.test"}, "urls": set(),
        "out_of_scope": [{"name": name, "uri": ""}],
    }
    with pytest.raises(RuntimeError, match="unresolved Bugcrowd exclusion"):
        scope_puller.save_scope("demo", data)
    assert path.read_text() == "previous scope\n"
    assert not (path.parent / "out-of-scope.txt").exists()


def test_bugcrowd_exclusion_with_uri_and_ambiguous_name_is_blocked(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(scope_puller.Path, "home", lambda: tmp_path)
    data = {"platform": "bugcrowd", "domains": {"*.example.test"}, "urls": set(),
            "out_of_scope": [{"name": "All other applications", "uri": "https://private.example.test/"}]}
    with pytest.raises(RuntimeError, match="unresolved Bugcrowd exclusion"):
        scope_puller.save_scope("demo", data)
    assert not (tmp_path / "Shared/scopes/demo/in-scope.txt").exists()


def test_bugcrowd_exclusion_keeps_both_uri_and_different_host_name(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(scope_puller.Path, "home", lambda: tmp_path)
    data = {"platform": "bugcrowd", "domains": {"*.example.test"}, "urls": set(),
            "out_of_scope": [{"name": "admin.example.test", "uri": "https://private.example.test/path"}]}
    scope_puller.save_scope("demo", data)
    validator = ScopeValidator("demo", scopes_base=tmp_path / "Shared/scopes")
    assert not validator.is_in_scope("https://private.example.test/other")
    assert not validator.is_in_scope("https://admin.example.test/")
    assert validator.is_in_scope("https://public.example.test/")


@pytest.mark.parametrize("name", [
    "Not private.example.test Web Apps",
    "private.example.test and admin.example.test Web Apps",
    "private.example.test Web Apps except admin.example.test",
    "private.example.test Web Apps (not in scope)",
    "https://private.example.test and admin.example.test Web Apps",
    "https://private.example.test/path not in scope",
])
def test_bugcrowd_ambiguous_names_do_not_grant(name: str) -> None:
    domains, urls = set(), set()
    scope_puller.add_bugcrowd_target_to_scope(domains, urls, name=name, uri="")
    assert domains == set()
    assert urls == set()


@pytest.mark.parametrize("name,uri,extra_urls", [
    ("*.example.test", "https://example.test/private", set()),
    ("*.example.test", "https://different.example.test/", set()),
    ("*.example.test", "https://example.test/", {"https://*.example.test/"}),
    ("*.example.test Web Apps", "https://example.test/private", set()),
])
def test_bugcrowd_uri_does_not_gain_unrelated_or_path_wide_wildcard(name, uri, extra_urls) -> None:
    domains, urls = set(), set()
    scope_puller.add_bugcrowd_target_to_scope(domains, urls, name=name, uri=uri)
    assert domains == set()
    assert urls == {uri} | extra_urls


def test_bugcrowd_wildcard_uri_keeps_its_path() -> None:
    domains, urls = set(), set()
    uri = "https://*.example.test/private"
    scope_puller.add_bugcrowd_target_to_scope(domains, urls, name="", uri=uri)
    assert domains == set()
    assert urls == {uri}


def test_bugcrowd_explicit_uri_precedes_descriptive_name() -> None:
    domains, urls = set(), set()
    uri = "https://api.example.test/private path"
    scope_puller.add_bugcrowd_target_to_scope(domains, urls, name="*.example.test Web Apps", uri=uri)
    assert domains == set()
    assert urls == {uri}


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

    assert not parsed["domains"]
    assert "https://*.flourish.studio/" in parsed["urls"]
    assert "https://*.xyzbmojn.net/" in parsed["urls"]
    assert "https://flourish.studio/" in parsed["urls"]
    assert "https://xyzbmojn.net/" in parsed["urls"]


def test_intigriti_public_page_parses_rendered_in_and_out_of_scope_cards() -> None:
    html = """
    <lib-asset-detail><div class="asset-container"><div class="asset-name"><span>*.in.example.com</span></div><div>Wildcard</div><div>Tier 2</div></div></lib-asset-detail>
    <lib-asset-detail><div class="asset-container"><div class="asset-name"><a>https://api.example.com/v1</a></div><div>URL</div><div>Tier 3</div></div></lib-asset-detail>
    <lib-asset-detail><div class="asset-container oos-asset"><div class="asset-name"><span>*.out.example.com</span></div><div>Wildcard</div><div>Out of scope</div></div></lib-asset-detail>
    <lib-asset-detail><div class="asset-container oos-asset"><div class="asset-name"><span>example CTF</span></div><div>Other</div><div>Out of scope</div></div></lib-asset-detail>
    """
    parsed = scope_puller.parse_intigriti_public_program("owner/demo", html)

    assert parsed["domains"] == {"*.in.example.com"}
    assert parsed["urls"] == {"https://api.example.com/v1"}
    assert [target["uri"] for target in parsed["out_of_scope"]] == ["*.out.example.com", "example CTF"]
    assert parsed["rules"]["platform"] == "intigriti"


def test_intigriti_shorthand_uses_public_program_url_and_saves_scope(monkeypatch) -> None:
    fetched: list[str] = []
    saved = {}
    scope_data = {"domains": {"*.example.com"}, "urls": set(), "out_of_scope": [], "assets": [], "rules": {}}
    monkeypatch.setattr(scope_puller, "fetch_page", lambda url: fetched.append(url) or "<rendered-page>")
    monkeypatch.setattr(scope_puller, "parse_intigriti_public_program", lambda program, page: scope_data)
    monkeypatch.setattr(scope_puller, "save_scope", lambda program, data: saved.update(program=program, data=data))

    assert scope_puller.pull_scope("owner/demo", "intigriti") is scope_data
    assert fetched == ["https://app.intigriti.com/researcher/programs/owner/demo"]
    assert saved == {"program": "owner/demo", "data": scope_data}


def test_hackerone_parser_normalizes_host_like_scope_identifiers() -> None:
    parsed = scope_puller.parse_hackerone_scope(
        {"structured_scopes": {"edges": [
            {"node": {"asset_type": "OTHER", "asset_identifier": "v1. kidswebservices.com", "eligible_for_submission": True}},
            {"node": {"asset_type": "OTHER", "asset_identifier": "dev.epicgames.com/*", "eligible_for_submission": True}},
            {"node": {"asset_type": "OTHER", "asset_identifier": "EOS C# SDK", "eligible_for_submission": True}},
        ]}}
    )
    assert parsed["domains"] == {"v1.kidswebservices.com", "dev.epicgames.com"}
    assert parsed["urls"] == set()


def test_routable_scope_entry_normalizes_obvious_host_formatting_without_widening() -> None:
    assert scope_puller.routable_scope_entry("v1. kidswebservices.com") == "v1.kidswebservices.com"
    assert scope_puller.routable_scope_entry("dev.epicgames.com/*") == "dev.epicgames.com"
    assert scope_puller.routable_scope_entry("Any other Epic games owned asset") is None
    assert scope_puller.routable_scope_entry("https://api.example.com/v1. release") == "https://api.example.com/v1. release"


def test_save_scope_preserves_exact_in_scope_urls(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(scope_puller.Path, "home", lambda: tmp_path)
    scope_puller.save_scope(
        "example",
        {"domains": ["v1. kidswebservices.com", "dev.epicgames.com/*"], "urls": ["https://api.example.com/v1. release"], "out_of_scope": []},
    )
    content = (tmp_path / "Shared/scopes/example/in-scope.txt").read_text()
    assert "v1.kidswebservices.com" in content
    assert "dev.epicgames.com\n" in content
    assert "https://api.example.com/v1. release" in content


def test_save_scope_writes_out_of_scope_files_for_canonical_and_legacy_locations(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(scope_puller.Path, "home", lambda: tmp_path)
    scope_puller.save_scope(
        "demo",
        {
            "domains": {"*.example.com"},
            "urls": {"https://api.example.com/v1"},
            "out_of_scope": [
                {"uri": "private.example.com", "category": "url", "group": "out-of-scope"},
                {"uri": "*.excluded.example.com", "category": "wildcard", "group": "out-of-scope"},
                {"uri": "HTTPS://upper.example.com/private", "category": "url", "group": "out-of-scope"},
                {"uri": "10.0.0.1/8", "category": "cidr", "group": "out-of-scope"},
                {"uri": "2001:db8::1/64", "category": "cidr", "group": "out-of-scope"},
                {"uri": "192.0.2.1", "category": "ip", "group": "out-of-scope"},
                {"uri": "any example CTF", "category": "other", "group": "out-of-scope", "description": "human-only exclusion"},
            ],
            "assets": [],
            "rules": {},
        },
    )

    canonical = tmp_path / "Shared" / "scopes" / "demo" / "out-of-scope.txt"
    legacy = tmp_path / "Shared" / "bounty_recon" / "demo" / "scope" / "out-of-scope.txt"
    structured = tmp_path / "Shared" / "scopes" / "demo" / "out-of-scope.json"
    expected = "*.excluded.example.com\n10.0.0.0/8\n192.0.2.1\n2001:db8::/64\nprivate.example.com\nupper.example.com\n"
    assert canonical.read_text() == expected
    assert legacy.read_text() == expected
    assert json.loads(structured.read_text())[-1]["uri"] == "any example CTF"


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
    query = requests[0]["query"]
    assert "query TeamScope($handle: String!, $after: String)" in query
    assert "after: $after" in query
    assert "pageInfo" in query and "hasNextPage" in query and "endCursor" in query
    assert [edge["node"]["asset_identifier"] for edge in team["structured_scopes"]["edges"]] == [
        "one.example.com", "two.example.com",
    ]


def test_hackerone_fetch_refuses_a_repeated_pagination_cursor(monkeypatch) -> None:
    responses = iter([
        {"data": {"team": {"structured_scopes": {
            "edges": [], "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"},
        }}}},
        {"data": {"team": {"structured_scopes": {
            "edges": [], "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"},
        }}}},
    ])

    class Response:
        def read(self):
            return json.dumps(next(responses)).encode()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(scope_puller.urllib.request, "urlopen", lambda *_args, **_kwargs: Response())

    with pytest.raises(RuntimeError, match="cannot continue scope pagination"):
        scope_puller.fetch_hackerone_team("demo")


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
