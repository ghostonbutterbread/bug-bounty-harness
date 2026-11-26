"""Scope inventory, history, release-changed signal and --if-older-than.

Synthetic scope dirs under tmp_path and ``*.example.test`` names only. Every
HTTP call is mocked; an autouse guard fails any real release request.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agents import scope_inventory as inv
from agents import scope_puller

T0 = datetime(2026, 11, 1, 10, 0, 0, tzinfo=timezone.utc)


_REAL_LOCK_DIR = inv.lock_dir  # captured before the autouse fixture replaces it


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(scope_puller.Path, "home", lambda: tmp_path)

    def no_network(*_args, **_kwargs):
        raise AssertionError("unexpected network call")

    monkeypatch.setattr(inv, "http_request", no_network)
    monkeypatch.setattr(inv, "lock_dir", lambda: tmp_path / "locks")
    monkeypatch.setattr(inv.urllib.request, "urlopen", no_network)
    monkeypatch.setattr(scope_puller.urllib.request, "urlopen", no_network)
    monkeypatch.setattr(scope_puller, "fetch_page", no_network)
    return tmp_path


def scope_dir(tmp_path: Path, name: str = "demo") -> Path:
    base = tmp_path / "Shared" / "scopes" / name
    base.mkdir(parents=True, exist_ok=True)
    return base


def write_scope(base: Path, *, assets=None, oos=None, in_lines=(), out_lines=(), platform="hackerone"):
    if assets is not None:
        (base / "assets.json").write_text(json.dumps(assets))
    if oos is not None:
        (base / "out-of-scope.json").write_text(json.dumps(oos))
    (base / "in-scope.txt").write_text("# In-scope domains and URLs\n" + "".join(f"{l}\n" for l in in_lines))
    (base / "out-of-scope.txt").write_text("".join(f"{l}\n" for l in out_lines))
    (base / "rules-of-engagement.json").write_text(json.dumps({
        "platform": platform, "source_url": f"https://{platform}.example.test/demo"}))


def items_by_key(base: Path) -> dict[str, dict]:
    doc = json.loads((base / inv.ITEMS_FILE).read_text())
    return {item["key"]: item for item in doc["items"]}


def history(base: Path) -> list[dict]:
    path = base / inv.HISTORY_FILE
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def h1_team(nodes):
    return {"structured_scopes": {"edges": [{"node": node} for node in nodes]}}


def h1_node(asset_type, identifier, *, submit=True, bounty=True, severity="critical", instruction=""):
    return {"asset_type": asset_type, "asset_identifier": identifier, "eligible_for_submission": submit,
            "eligible_for_bounty": bounty, "max_severity": severity, "instruction": instruction}


H1_NODES = [
    h1_node("URL", "https://app.example.test"),
    h1_node("URL", "https://api.example.test/v2/*", severity="high"),
    h1_node("WILDCARD", "*.example.test"),
    h1_node("CIDR", "192.0.2.0/24"),
    h1_node("OTHER", "3rd party services", bounty=False, severity="none"),
    h1_node("APPLE_STORE_APP_ID", "1234567890"),
    h1_node("GOOGLE_PLAY_APP_ID", "com.example.test.app"),
    h1_node("SOURCE_CODE", "https://github.com/example-test/repo"),
    h1_node("DOWNLOADABLE_EXECUTABLES", "https://dl.example.test/client.exe"),
    h1_node("DOWNLOADABLE_EXECUTABLES", "Desktop client for Windows"),
    h1_node("URL", "status.example.test", submit=False, bounty=False, severity="none"),
]


def save_h1(nodes=H1_NODES, *, release_check=False, name="demo"):
    data = scope_puller.parse_hackerone_scope(h1_team(nodes))
    data.update({"program": name, "platform": "hackerone",
                 "rules": {"platform": "hackerone", "source_url": "https://hackerone.example.test/demo"}})
    scope_puller.save_scope(name, data, legacy=False, release_check=release_check)


# --------------------------------------------------------------------------
# Normalization per platform shape


def test_hackerone_asset_types_normalize_through_save_scope(isolated):
    save_h1()
    items = items_by_key(scope_dir(isolated))
    assert items["web_host:app.example.test"]["enforced"] is True
    assert items["web_url:https://api.example.test/v2/*"]["max_severity"] == "high"
    assert items["web_wildcard:*.example.test"]["platform_type"] == "WILDCARD"
    assert items["cidr:192.0.2.0/24"]["enforced"] is False  # CIDR is not an H1 network seed today
    other = items["other:3rd party services"]
    assert (other["kind"], other["eligible_for_bounty"], other["enforced"]) == ("other", False, False)
    assert items["ios_app:1234567890"]["platform_type"] == "APPLE_STORE_APP_ID"
    assert items["android_app:com.example.test.app"]["eligible_for_bounty"] is True
    assert items["source_code:https://github.com/example-test/repo"]["enforced"] is False
    assert items["executable:https://dl.example.test/client.exe"]["kind"] == "executable"
    assert items["executable:desktop client for windows"]["identifier"] == "desktop client for windows"
    status = items["web_host:status.example.test"]
    assert status["in_scope"] is False and status["enforced"] is True
    for item in items.values():
        assert item["key"] == f"{item['kind']}:{item['identifier']}"
        assert item["release"] is None  # no release check requested


def test_bugcrowd_nested_groups_with_categories(isolated):
    base = scope_dir(isolated)
    write_scope(base, platform="bugcrowd", assets=[
        {"name": "Tier 1 targets", "in_scope": True, "description": "Core apps", "targets": [
            {"name": "app.example.test", "uri": "", "category": "website", "in_scope": True, "group": "Tier 1 targets"},
            {"name": "Public API", "uri": "https://api.example.test/v1/", "category": "api", "in_scope": True,
             "group": "Tier 1 targets"},
            {"name": "Example iOS", "uri": "https://apps.apple.com/us/app/example/id1234567890",
             "category": "ios", "in_scope": True, "group": "Tier 1 targets"},
            {"name": "Example Android", "uri": "https://play.google.com/store/apps/details?id=com.example.test.app",
             "category": "android", "in_scope": True, "group": "Tier 1 targets"},
        ]},
        {"name": "Other", "in_scope": True, "targets": [
            {"name": "Any other asset owned by Example", "uri": "", "category": "other", "in_scope": True},
            {"name": "198.51.100.0/24", "uri": "", "category": "cidr", "in_scope": True},
        ]},
        {"name": "Out of scope", "in_scope": False, "targets": [
            {"name": "blog.example.test", "uri": "", "category": "website", "in_scope": False},
        ]},
    ], oos=[{"name": "blog.example.test", "uri": "", "category": "website", "in_scope": False}],
        in_lines=["app.example.test", "https://api.example.test/v1/", "198.51.100.0/24"],
        out_lines=["blog.example.test"])
    inv.write_inventory(base, source="rebuild", program="demo", now=T0)
    items = items_by_key(base)
    assert items["web_host:app.example.test"]["tier"] == "1"
    assert items["web_host:app.example.test"]["description"] == "Core apps"
    assert items["web_url:https://api.example.test/v1/"]["enforced"] is True
    assert items["ios_app:1234567890"]["name"] == "Example iOS"
    assert items["android_app:com.example.test.app"]["platform_type"] == "android"
    assert items["other:any other asset owned by example"]["tier"] is None
    assert items["cidr:198.51.100.0/24"]["enforced"] is True
    blog = items["web_host:blog.example.test"]
    assert blog["in_scope"] is False and blog["enforced"] is True
    assert len([k for k in items if k.startswith("web_host:blog")]) == 1  # assets + oos records merge


def test_intigriti_tiered_cards_and_saved_page_reparse(isolated):
    base = scope_dir(isolated)
    write_scope(base, platform="intigriti", assets=[{"name": "tier-2", "targets": [
        {"name": "*.example.test", "uri": "*.example.test", "asset_type": "Wildcard", "category": "wildcard",
         "group": "tier-2", "in_scope": True, "description": ""},
        {"name": "com.example.test.app", "uri": "com.example.test.app", "asset_type": "Android",
         "category": "android", "group": "tier-2", "in_scope": True, "description": ""},
    ]}], in_lines=["*.example.test"])
    inv.write_inventory(base, source="rebuild", program="demo", now=T0)
    items = items_by_key(base)
    assert items["web_wildcard:*.example.test"]["tier"] == "2"
    assert items["android_app:com.example.test.app"]["enforced"] is False

    # assets.json without typed records: the saved rendered page is re-read.
    other = scope_dir(isolated, "pagedemo")
    write_scope(other, platform="intigriti", assets=[], in_lines=["app.example.test"])
    (other / "raw").mkdir()
    (other / "raw" / "intigriti-page.html").write_text(
        '<lib-asset-detail><div class="asset-name"><span>app.example.test</span></div> URL Tier 1</lib-asset-detail>'
        '<lib-asset-detail><div class="asset-name"><span>Example iOS app</span></div> iOS Tier 1</lib-asset-detail>'
    )
    inv.write_inventory(other, source="rebuild", program="pagedemo", now=T0)
    items = items_by_key(other)
    assert items["web_host:app.example.test"]["tier"] == "1"
    assert items["web_host:app.example.test"]["enforced"] is True
    assert items["ios_app:example ios app"]["platform_type"] == "iOS"


def test_untyped_records_classify_from_name(isolated):
    base = scope_dir(isolated)
    names = [
        "https://a.example.test/api/v1", "*.b.example.test", "10.0.0.0/24", "203.0.113.7",
        "3rd party services", "https://play.google.com/store/apps/details?id=com.example.test.app",
        "https://apps.apple.com/us/app/example/id1234567890", "https://github.com/example-test/repo",
        "https://dl.example.test/setup.msi", "Infra - 192.0.2.0/28", "c.example.test",
    ]
    write_scope(base, assets=[{"name": "group", "targets": [{"name": n} for n in names]}],
                in_lines=["c.example.test"])
    inv.write_inventory(base, source="rebuild", program="demo", now=T0)
    assert sorted(items_by_key(base)) == sorted([
        "web_url:https://a.example.test/api/v1", "web_wildcard:*.b.example.test", "cidr:10.0.0.0/24",
        "ip:203.0.113.7", "other:3rd party services", "android_app:com.example.test.app",
        "ios_app:1234567890", "source_code:https://github.com/example-test/repo",
        "executable:https://dl.example.test/setup.msi", "cidr:192.0.2.0/28", "web_host:c.example.test",
    ])
    assert all(item["platform_type"] is None for item in items_by_key(base).values())


def test_hand_made_shapes_and_rule_line_fallback(isolated):
    base = scope_dir(isolated)
    write_scope(base, assets={"program": "demo", "assets": [
        {"type": "URL", "identifier": "app.example.test", "eligible_for_submission": True,
         "eligible_for_bounty": True, "max_severity": "Critical", "instruction": "x" * 900},
        {"type": "GOOGLE_PLAY_APP_ID", "identifier": "com.example.test.app", "eligible_for_submission": False},
    ]}, in_lines=["app.example.test"])
    inv.write_inventory(base, source="rebuild", program="demo", now=T0)
    items = items_by_key(base)
    assert items["web_host:app.example.test"]["max_severity"] == "critical"
    assert len(items["web_host:app.example.test"]["description"]) == 500
    assert items["android_app:com.example.test.app"]["in_scope"] is False

    bare = scope_dir(isolated, "bare")
    write_scope(bare, assets=[], in_lines=["*.example.test", "https://x.example.test/app/*", "Some prose grant"],
                out_lines=["admin.example.test"])
    inv.write_inventory(bare, source="rebuild", program="bare", now=T0)
    items = items_by_key(bare)
    assert items["web_wildcard:*.example.test"]["enforced"] is True
    assert items["web_url:https://x.example.test/app/*"]["in_scope"] is True
    assert items["other:some prose grant"]["enforced"] is False
    assert items["web_host:admin.example.test"]["in_scope"] is False


def test_enforced_only_for_rule_shaped_lines(isolated):
    base = scope_dir(isolated)
    write_scope(base, assets=[{"name": "g", "targets": [
        {"name": "a.example.test", "asset_type": "URL"},
        {"name": "b.example.test", "asset_type": "URL"},
        {"name": "Partner portal", "asset_type": "OTHER"},
    ]}], in_lines=["a.example.test", "Partner portal"])
    inv.write_inventory(base, source="rebuild", program="demo", now=T0)
    items = items_by_key(base)
    assert items["web_host:a.example.test"]["enforced"] is True
    assert items["web_host:b.example.test"]["enforced"] is False
    assert items["other:partner portal"]["enforced"] is False  # prose lines are skipped by the checker


# --------------------------------------------------------------------------
# Keys, first_seen, history


def test_first_seen_preserved_and_last_seen_updated(isolated, monkeypatch):
    monkeypatch.setattr(inv, "utcnow", lambda: T0)
    save_h1()
    base = scope_dir(isolated)
    first = items_by_key(base)
    monkeypatch.setattr(inv, "utcnow", lambda: T0 + timedelta(days=3))
    save_h1()
    second = items_by_key(base)
    assert first.keys() == second.keys()
    for key, item in second.items():
        assert item["first_seen"] == "2026-11-01T10:00:00Z"
        assert item["last_seen"] == "2026-11-04T10:00:00Z"
    assert len(history(base)) == 1  # baseline only; nothing changed


def test_history_baseline_once_then_added_removed_changed(isolated, monkeypatch):
    base = scope_dir(isolated)
    monkeypatch.setattr(inv, "utcnow", lambda: T0)
    save_h1([h1_node("URL", "https://legacy.example.test"), h1_node("URL", "https://status.example.test")])
    lines = history(base)
    assert [line["source"] for line in lines] == ["baseline"]
    assert {entry["key"] for entry in lines[0]["added"]} == {"web_host:legacy.example.test",
                                                            "web_host:status.example.test"}

    save_h1([h1_node("URL", "https://legacy.example.test"), h1_node("URL", "https://status.example.test")])
    assert len(history(base)) == 1  # unchanged pull adds nothing

    monkeypatch.setattr(inv, "utcnow", lambda: T0 + timedelta(days=1))
    save_h1([
        h1_node("URL", "https://status.example.test", submit=False, severity="none"),
        h1_node("APPLE_STORE_APP_ID", "1234567890"),
        h1_node("URL", "https://keep.example.test"),
    ])
    line = history(base)[-1]
    assert line["at"] == "2026-11-02T10:00:00Z" and line["source"] == "pull"
    assert {e["key"] for e in line["added"]} == {"ios_app:1234567890", "web_host:keep.example.test"}
    assert line["removed"] == [{"key": "web_host:legacy.example.test", "kind": "web_host",
                                "name": "https://legacy.example.test", "in_scope": True}]
    assert {"key": "web_host:status.example.test", "field": "in_scope", "from": True, "to": False} in line["changed"]
    assert {"key": "web_host:status.example.test", "field": "max_severity", "from": "critical", "to": "none"} \
        in line["changed"]
    assert line["release_changed"] == []


def test_scope_pull_state_after_pull_and_rebuild(isolated, monkeypatch):
    monkeypatch.setattr(inv, "utcnow", lambda: T0)
    save_h1()
    base = scope_dir(isolated)
    state = json.loads((base / inv.PULL_FILE).read_text())
    assert state["pulled_at"] == state["last_attempt_at"] == "2026-11-01T10:00:00Z"
    assert state["last_attempt_status"] == "ok" and state["last_error"] is None
    assert state["items"] == len(items_by_key(base))
    assert state["platform"] == "hackerone" and state["source_url"] == "https://hackerone.example.test/demo"
    assert len(state["items_hash"]) == 64
    old_hash = state["items_hash"]
    inv.write_inventory(base, source="rebuild", program="demo", now=T0 + timedelta(days=9))
    state = json.loads((base / inv.PULL_FILE).read_text())
    assert state["pulled_at"] == "2026-11-01T10:00:00Z" and state["items_hash"] == old_hash
    assert json.loads((base / inv.ITEMS_FILE).read_text())["source"] == "rebuild"


# --------------------------------------------------------------------------
# Release-changed signal


class FakeHTTP:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, url, method="GET"):
        self.calls.append((method, url))
        for needle, response in self.responses.items():
            if needle in url:
                if isinstance(response, Exception):
                    raise response
                return response
        raise AssertionError(f"unmocked URL {url}")


def itunes(version, date):
    return 200, {}, json.dumps({"resultCount": 1, "results": [
        {"version": version, "currentVersionReleaseDate": date}]}).encode()


def play(date):
    return 200, {}, (f'<div class="a">Updated on</div><div class="b">{date}</div>').encode()


RELEASE_NODES = [
    h1_node("APPLE_STORE_APP_ID", "1234567890"),
    h1_node("GOOGLE_PLAY_APP_ID", "com.example.test.app"),
    h1_node("DOWNLOADABLE_EXECUTABLES", "https://dl.example.test/client.exe"),
    h1_node("DOWNLOADABLE_EXECUTABLES", "Desktop client"),
    h1_node("GOOGLE_PLAY_APP_ID", "com.example.test.oos", submit=False),
    h1_node("URL", "https://app.example.test"),
]


def test_release_signals_recorded_and_changes_logged(isolated, monkeypatch):
    base = scope_dir(isolated)
    fake = FakeHTTP({
        "itunes.apple.com/lookup?id=1234567890": itunes("3.1.0", "2026-10-02T07:00:00Z"),
        "id=com.example.test.app": play("Oct 2, 2026"),
        "dl.example.test/client.exe": (200, {"etag": '"abc"', "content-length": "100"}, b""),
    })
    monkeypatch.setattr(inv, "http_request", fake)
    monkeypatch.setattr(inv, "utcnow", lambda: T0)
    save_h1(RELEASE_NODES, release_check=True)
    items = items_by_key(base)
    ios = items["ios_app:1234567890"]["release"]
    assert ios["method"] == "itunes_lookup" and ios["version"] == "3.1.0"
    assert ios["signal"] == "3.1.0 2026-10-02T07:00:00Z" and ios["changed_at"] is None
    assert items["android_app:com.example.test.app"]["release"]["signal"] == "Updated on Oct 2, 2026"
    head = items["executable:https://dl.example.test/client.exe"]["release"]
    assert head["method"] == "download_head" and head["signal"] == 'etag="abc"; content-length=100'
    no_url = items["executable:desktop client"]["release"]
    assert no_url["method"] is None and no_url["error"] == "no download URL"
    assert items["android_app:com.example.test.oos"]["release"] is None
    assert items["web_host:app.example.test"]["release"] is None
    assert sorted(fake.calls) == sorted([
        ("GET", "https://itunes.apple.com/lookup?id=1234567890"),
        ("GET", "https://play.google.com/store/apps/details?id=com.example.test.app&hl=en_US&gl=US"),
        ("HEAD", "https://dl.example.test/client.exe"),
    ])  # one request per checkable in-scope item

    later = T0 + timedelta(days=20)
    fake.responses["id=com.example.test.app"] = play("Nov 20, 2026")
    fake.calls.clear()
    monkeypatch.setattr(inv, "utcnow", lambda: later)
    save_h1(RELEASE_NODES, release_check=True)
    android = items_by_key(base)["android_app:com.example.test.app"]["release"]
    assert android["signal"] == "Updated on Nov 20, 2026"
    assert android["previous_signal"] == "Updated on Oct 2, 2026"
    assert android["changed_at"] == "2026-11-21T10:00:00Z"
    line = history(base)[-1]
    assert line["added"] == line["removed"] == line["changed"] == []
    assert line["release_changed"] == [{"key": "android_app:com.example.test.app", "name": "com.example.test.app",
                                        "previous": "Updated on Oct 2, 2026", "signal": "Updated on Nov 20, 2026"}]

    # Same signal next time: changed_at and previous_signal are carried, no new line.
    save_h1(RELEASE_NODES, release_check=True)
    assert items_by_key(base)["android_app:com.example.test.app"]["release"]["changed_at"] == "2026-11-21T10:00:00Z"
    assert len(history(base)) == 2


@pytest.mark.parametrize("failure, expected", [
    (socket.timeout("timed out"), "timeout"),
    (urllib.error.HTTPError("https://x", 404, "nf", {}, None), "HTTP 404"),
    (urllib.error.URLError(OSError("refused")), "URLError: OSError"),
])
def test_release_failure_recorded_never_fails_pull(isolated, monkeypatch, failure, expected):
    base = scope_dir(isolated)
    monkeypatch.setattr(inv, "http_request", FakeHTTP({"itunes": itunes("1.0", "2026-09-01T00:00:00Z")}))
    save_h1([h1_node("APPLE_STORE_APP_ID", "1234567890"), h1_node("URL", "https://app.example.test")],
            release_check=True)
    monkeypatch.setattr(inv, "http_request", FakeHTTP({"itunes": failure}))
    save_h1([h1_node("APPLE_STORE_APP_ID", "1234567890"), h1_node("URL", "https://app.example.test")],
            release_check=True)
    release = items_by_key(base)["ios_app:1234567890"]["release"]
    assert release["error"] == expected
    assert release["signal"] == "1.0 2026-09-01T00:00:00Z"  # last known signal kept for the next comparison
    assert "app.example.test" in (base / "in-scope.txt").read_text()


def test_release_parse_errors_and_identifier_rules():
    item = lambda kind, ident: {"kind": kind, "identifier": ident, "key": f"{kind}:{ident}", "name": ident}
    assert inv.release_target(item("ios_app", "com.example.test.ios"))[1].endswith("bundleId=com.example.test.ios")
    assert inv.release_target(item("ios_app", "example ios app"))[2] == "no App Store id"
    assert inv.release_target(item("android_app", "https://dl.example.test/app.apk"))[0] == "download_head"
    assert inv.release_target(item("android_app", "https://www.example.test/android/"))[2] == "no package id"
    assert inv.release_target(item("executable", "desktop client"))[2] == "no download URL"


def test_release_bad_payloads(monkeypatch):
    now = T0
    monkeypatch.setattr(inv, "http_request", FakeHTTP({"lookup": (200, {}, b'{"resultCount": 0, "results": []}'),
                                                       "play.google": (200, {}, b"<html>no date</html>"),
                                                       "dl.example": (200, {}, b"")}))
    ios, event = inv.check_release({"kind": "ios_app", "identifier": "1234567890", "key": "k", "name": "n"}, None, now)
    assert ios["error"] == "ValueError: app not found in iTunes lookup" and event is None
    android, _ = inv.check_release({"kind": "android_app", "identifier": "com.example.test.app", "key": "k",
                                    "name": "n"}, None, now)
    assert "Updated on" in android["error"]
    head, _ = inv.check_release({"kind": "executable", "identifier": "https://dl.example.test/a.exe", "key": "k",
                                 "name": "n"}, None, now)
    assert "ETag" in head["error"]


def test_no_release_check_carries_previous_release(isolated, monkeypatch):
    base = scope_dir(isolated)
    monkeypatch.setattr(inv, "http_request", FakeHTTP({"itunes": itunes("2.0", "2026-10-01T00:00:00Z")}))
    save_h1([h1_node("APPLE_STORE_APP_ID", "1234567890"), h1_node("URL", "https://app.example.test")],
            release_check=True)
    monkeypatch.setattr(inv, "http_request", FakeHTTP({}))
    save_h1([h1_node("APPLE_STORE_APP_ID", "1234567890"), h1_node("URL", "https://app.example.test")],
            release_check=False)
    assert items_by_key(base)["ios_app:1234567890"]["release"]["version"] == "2.0"


# --------------------------------------------------------------------------
# Offline rebuild


def snapshot(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def run_cli(monkeypatch, *argv) -> int:
    monkeypatch.setattr(sys, "argv", ["scope_puller.py", *argv])
    return scope_puller.main()


def test_rebuild_offline_touches_only_inventory_files(isolated, monkeypatch):
    for name in ("alpha", "beta"):
        write_scope(scope_dir(isolated, name), assets=[{"name": "g", "targets": [
            {"name": f"{name}.example.test", "asset_type": "URL", "in_scope": True},
            {"name": "1234567890", "asset_type": "APPLE_STORE_APP_ID", "in_scope": True},
        ]}], in_lines=[f"{name}.example.test"])
    (scope_dir(isolated, "alpha") / "duplicate-intelligence.md").write_text("manual\n")
    os.symlink(scope_dir(isolated, "alpha"), isolated / "Shared" / "scopes" / "alias")
    root = isolated / "Shared" / "scopes"
    before = snapshot(root)
    assert run_cli(monkeypatch, "--rebuild-inventory", "--all") == 0  # network guard would raise
    after = snapshot(root)
    for path, body in before.items():
        assert after[path] == body
    new = {p for p in after if p not in before and not p.startswith("alias/")}
    assert new == {f"{n}/{f}" for n in ("alpha", "beta") for f in inv.INVENTORY_FILES}
    state = json.loads((root / "alpha" / inv.PULL_FILE).read_text())
    assert state["pulled_at"] is None and state["last_attempt_status"] is None
    alpha = items_by_key(root / "alpha")
    assert alpha["ios_app:1234567890"]["release"] is None
    mtime = datetime.fromtimestamp((root / "alpha" / "assets.json").stat().st_mtime, timezone.utc)
    assert alpha["web_host:alpha.example.test"]["first_seen"] == inv.iso(mtime)
    assert [line["source"] for line in history(root / "alpha")] == ["baseline"]

    assert run_cli(monkeypatch, "--rebuild-inventory", "alpha") == 0
    assert len(history(root / "alpha")) == 1  # nothing changed, no new line


def test_rebuild_missing_program_and_bad_args(isolated, monkeypatch):
    assert run_cli(monkeypatch, "--rebuild-inventory", "nope") == 1
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, "--all")
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, "--rebuild-inventory")


# --------------------------------------------------------------------------
# --if-older-than


def saved_state(isolated, *, pulled_at=None, failed_at=None):
    base = scope_dir(isolated)
    write_scope(base, assets=[], in_lines=["app.example.test"])
    state = {"version": 1, "program": "demo", "pulled_at": pulled_at, "last_attempt_status": "ok"}
    if failed_at:
        state.update(last_attempt_status="failed", last_failed_at=failed_at, last_error="boom")
    (base / inv.PULL_FILE).write_text(json.dumps(state))
    return base


def test_if_older_than_fresh_skips_without_writing(isolated, monkeypatch, capsys):
    base = saved_state(isolated, pulled_at="2026-11-20T18:02:11Z")
    monkeypatch.setattr(inv, "utcnow", lambda: datetime(2026, 11, 25, 9, tzinfo=timezone.utc))
    monkeypatch.setattr(scope_puller, "pull_scope", lambda *a, **k: pytest.fail("pulled while fresh"))
    before = snapshot(base)
    assert run_cli(monkeypatch, "demo", "--if-older-than", "7") == 0
    assert "scope fresh (pulled 4 days ago)" in capsys.readouterr().out
    assert snapshot(base) == before


def test_if_older_than_falls_back_to_file_mtime(isolated, monkeypatch, capsys):
    base = scope_dir(isolated)
    write_scope(base, assets=[], in_lines=["app.example.test"])
    old = (datetime.now(timezone.utc) - timedelta(days=10)).timestamp()
    os.utime(base / "assets.json", (old, old))
    called = []
    monkeypatch.setattr(scope_puller, "pull_scope", lambda *a, **k: called.append(k) or {})
    assert run_cli(monkeypatch, "demo", "--if-older-than", "7", "--no-release-check") == 0
    assert called == [{"use_api": False, "release_check": False, "slug": "demo"}]
    called.clear()
    assert run_cli(monkeypatch, "demo", "--if-older-than", "30") == 0
    assert called == [] and "scope fresh (pulled 10 days ago)" in capsys.readouterr().out


def test_if_older_than_failed_pull_keeps_files_and_exits_zero(isolated, monkeypatch, capsys):
    base = saved_state(isolated, pulled_at="2026-11-01T00:00:00Z")
    now = datetime(2026, 11, 25, 9, tzinfo=timezone.utc)
    monkeypatch.setattr(inv, "utcnow", lambda: now)

    def fail(*_a, **_k):
        raise RuntimeError("HackerOne GraphQL error: rate limited")

    monkeypatch.setattr(scope_puller, "pull_scope", fail)
    before = {k: v for k, v in snapshot(base).items() if k != inv.PULL_FILE}
    assert run_cli(monkeypatch, "demo", "--if-older-than", "7") == 0
    out = capsys.readouterr().out
    assert "scope refresh failed" in out and "continuing with saved scope (24 days old)" in out
    assert {k: v for k, v in snapshot(base).items() if k != inv.PULL_FILE} == before
    state = json.loads((base / inv.PULL_FILE).read_text())
    assert state["last_attempt_status"] == "failed" and "rate limited" in state["last_error"]
    assert state["pulled_at"] == "2026-11-01T00:00:00Z" and state["last_failed_at"] == inv.iso(now)

    # Within 24 h: no new attempt.
    monkeypatch.setattr(inv, "utcnow", lambda: now + timedelta(hours=5))
    monkeypatch.setattr(scope_puller, "pull_scope", lambda *a, **k: pytest.fail("retried inside backoff"))
    assert run_cli(monkeypatch, "demo", "--if-older-than", "7") == 0
    assert "not retrying before 2026-11-26T09:00:00Z" in capsys.readouterr().out
    state = json.loads((base / inv.PULL_FILE).read_text())
    assert state["last_attempt_status"] == "skipped_backoff" and state["last_failed_at"] == inv.iso(now)

    # After 24 h it tries again; a fetch that returns nothing also counts as failed.
    monkeypatch.setattr(inv, "utcnow", lambda: now + timedelta(hours=25))
    monkeypatch.setattr(scope_puller, "pull_scope", lambda *a, **k: None)
    assert run_cli(monkeypatch, "demo", "--if-older-than", "7") == 0
    state = json.loads((base / inv.PULL_FILE).read_text())
    assert state["last_attempt_status"] == "failed" and state["last_error"] == "failed to fetch program page"


def test_if_older_than_missing_dir_is_a_normal_first_pull(isolated, monkeypatch):
    called = []
    monkeypatch.setattr(scope_puller, "pull_scope", lambda *a, **k: called.append(a) or {})
    assert run_cli(monkeypatch, "newprog", "--if-older-than", "7") == 0
    assert called == [("newprog", None)]
    monkeypatch.setattr(scope_puller, "pull_scope", lambda *a, **k: None)
    assert run_cli(monkeypatch, "newprog", "--if-older-than", "7") == 1  # nothing saved to fall back on
    assert not (isolated / "Shared" / "scopes" / "newprog").exists()


def test_successful_pull_clears_failure_state(isolated, monkeypatch):
    base = saved_state(isolated, pulled_at="2026-10-01T00:00:00Z", failed_at="2026-11-20T00:00:00Z")
    monkeypatch.setattr(inv, "utcnow", lambda: datetime(2026, 11, 25, tzinfo=timezone.utc))
    monkeypatch.setattr(scope_puller, "pull_scope", lambda *a, **k: save_h1() or {})
    assert run_cli(monkeypatch, "demo", "--if-older-than", "7") == 0
    state = json.loads((base / inv.PULL_FILE).read_text())
    assert state["last_attempt_status"] == "ok" and state["last_failed_at"] is None
    assert state["pulled_at"] == "2026-11-25T00:00:00Z"


# --------------------------------------------------------------------------
# Atomic writes and failure isolation


def test_atomic_write_leaves_old_file_on_crash(tmp_path, monkeypatch):
    path = tmp_path / "scope-items.json"
    inv.atomic_write_json(path, {"version": 1, "items": []})
    original = path.read_bytes()

    def crash(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr(inv.os, "replace", crash)
    with pytest.raises(OSError):
        inv.atomic_write_json(path, {"version": 1, "items": [{"key": "x"}]})
    assert path.read_bytes() == original
    assert json.loads(original)["items"] == []
    assert [p.name for p in tmp_path.iterdir()] == ["scope-items.json"]


def test_inventory_failure_does_not_fail_saved_scope(isolated, monkeypatch, capsys):
    def boom(*_a, **_k):
        raise ValueError("fixture")

    monkeypatch.setattr(inv, "build_items", boom)
    save_h1()
    base = scope_dir(isolated)
    assert "app.example.test" in (base / "in-scope.txt").read_text()
    assert not (base / inv.ITEMS_FILE).exists()
    assert "scope inventory could not be written" in capsys.readouterr().out


def test_history_lines_are_append_only(isolated, monkeypatch):
    base = scope_dir(isolated)
    monkeypatch.setattr(inv, "utcnow", lambda: T0)
    save_h1([h1_node("URL", "https://a.example.test")])
    first = (base / inv.HISTORY_FILE).read_text()
    save_h1([h1_node("URL", "https://b.example.test")])
    text = (base / inv.HISTORY_FILE).read_text()
    assert text.startswith(first) and text.count("\n") == 2


# --------------------------------------------------------------------------
# Review round 1 regressions


def test_malformed_saved_shapes_do_not_crash_or_explode(isolated, monkeypatch):
    base = scope_dir(isolated)
    write_scope(base, assets={"web": {"hosts": "app.example.test", "url_endpoints": 5}, "mobile": {"ios": 7}},
                in_lines=["app.example.test"])
    assert run_cli(monkeypatch, "--rebuild-inventory", "demo") == 0
    assert list(items_by_key(base)) == ["web_host:app.example.test"]  # rule-line fallback, no per-char junk


def test_reordered_assets_write_no_history_line(isolated):
    base = scope_dir(isolated)
    groups = [
        {"name": "Tier 1", "targets": [{"name": "api.example.test", "category": "api", "group": "Tier 1"}]},
        {"name": "Tier 3", "targets": [{"name": "https://api.example.test", "category": "website",
                                        "group": "Tier 3"}]},
    ]
    write_scope(base, platform="bugcrowd", assets=groups, in_lines=["api.example.test"])
    inv.write_inventory(base, source="pull", program="demo", now=T0)
    first = items_by_key(base)["web_host:api.example.test"]
    write_scope(base, platform="bugcrowd", assets=list(reversed(groups)), in_lines=["api.example.test"])
    inv.write_inventory(base, source="pull", program="demo", now=T0 + timedelta(days=1))
    assert items_by_key(base)["web_host:api.example.test"]["tier"] == first["tier"] == "1"
    assert len(history(base)) == 1


def test_inventory_failure_still_records_pulled_at(isolated, monkeypatch):
    monkeypatch.setattr(inv, "utcnow", lambda: T0)
    monkeypatch.setattr(inv, "build_items", lambda base: (_ for _ in ()).throw(ValueError("fixture")))
    save_h1()
    state = json.loads((scope_dir(isolated) / inv.PULL_FILE).read_text())
    assert state["pulled_at"] == "2026-11-01T10:00:00Z" and state["last_attempt_status"] == "ok"


def test_non_string_first_seen_is_replaced(isolated):
    base = scope_dir(isolated)
    write_scope(base, assets=[{"name": "g", "targets": [{"name": "a.example.test", "asset_type": "URL"}]}],
                in_lines=["a.example.test"])
    (base / inv.ITEMS_FILE).write_text(json.dumps({"items": [{"key": "web_host:a.example.test", "first_seen": 123,
                                                              "kind": "web_host", "name": "a.example.test",
                                                              "in_scope": True}]}))
    inv.write_inventory(base, source="pull", program="demo", now=T0)
    assert items_by_key(base)["web_host:a.example.test"]["first_seen"] == "2026-11-01T10:00:00Z"


# --------------------------------------------------------------------------
# Independent review (BLOCK) regressions


def _origin_dir(isolated, name, platform, source_url=None, pull_platform=None, age_days=30):
    base = scope_dir(isolated, name)
    write_scope(base, assets=[], in_lines=["app.example.test"], platform=platform)
    rules = {"platform": platform}
    if source_url:
        rules["source_url"] = source_url
    (base / "rules-of-engagement.json").write_text(json.dumps(rules))
    if pull_platform:
        (base / inv.PULL_FILE).write_text(json.dumps({"platform": pull_platform, "pulled_at": None}))
    old = (datetime.now(timezone.utc) - timedelta(days=age_days)).timestamp()
    for path in base.iterdir():
        os.utime(path, (old, old))
    return base


def test_refresh_uses_saved_platform_and_source_url(isolated, monkeypatch):
    _origin_dir(isolated, "acme", "bugcrowd", "https://bugcrowd.com/engagements/acme")
    calls = []
    monkeypatch.setattr(scope_puller, "pull_scope", lambda program, platform, **kw: calls.append(
        (program, platform, kw["slug"])) or {})
    assert scope_puller.run_pull("acme", None, use_api=False, release_check=False, if_older_than=7) == 0
    assert scope_puller.run_pull("acme", None, use_api=False, release_check=False) == 0
    assert calls == [("https://bugcrowd.com/engagements/acme", "bugcrowd", "acme")] * 2


def test_scope_pull_platform_wins_over_rules(isolated, monkeypatch):
    _origin_dir(isolated, "acme", "hackerone", "https://hackerone.com/acme", pull_platform="intigriti")
    calls = []
    monkeypatch.setattr(scope_puller, "pull_scope", lambda program, platform, **kw: calls.append(platform) or {})
    assert scope_puller.run_pull("acme", None, use_api=False, release_check=False) == 0
    assert calls == ["intigriti"]


def test_renamed_dir_refresh_queries_recorded_handle_and_writes_same_dir(isolated, monkeypatch):
    base = _origin_dir(isolated, "short", "hackerone", "https://hackerone.com/long_handle/policy_scopes")
    asked = []

    def team(handle):
        asked.append(handle)
        return {"policy": "", "submission_state": "open", "offers_bounties": True,
                **h1_team([h1_node("URL", "https://new.example.test")])}

    monkeypatch.setattr(scope_puller, "fetch_hackerone_team", team)
    assert scope_puller.run_pull("short", None, use_api=False, release_check=False, if_older_than=7) == 0
    assert asked == ["long_handle"]
    assert "new.example.test" in (base / "in-scope.txt").read_text()
    assert not (isolated / "Shared" / "scopes" / "long_handle").exists()
    assert json.loads((base / "rules-of-engagement.json").read_text())["program"] == "short"


def test_explicit_platform_mismatch_refuses_unless_forced(isolated, monkeypatch, capsys):
    base = _origin_dir(isolated, "acme", "bugcrowd", "https://bugcrowd.com/engagements/acme")
    calls = []
    monkeypatch.setattr(scope_puller, "pull_scope", lambda program, platform, **kw: calls.append(
        (program, platform, kw["slug"])) or {})
    before = snapshot(base)
    assert run_cli(monkeypatch, "acme", "--platform", "hackerone", "--if-older-than", "7") == 1
    assert calls == [] and snapshot(base) == before
    assert "refusing --platform hackerone" in capsys.readouterr().out
    assert run_cli(monkeypatch, "acme", "--platform", "hackerone", "--force-platform") == 0
    assert calls == [("acme", "hackerone", None)]
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, "acme", "--force-platform")


def test_unsupported_saved_platform_does_not_pull(isolated, monkeypatch, capsys):
    base = _origin_dir(isolated, "ywh", "yeswehack", "https://yeswehack.example.test/programs/ywh")
    monkeypatch.setattr(scope_puller, "pull_scope", lambda *a, **k: pytest.fail("pulled unsupported platform"))
    before = {k: v for k, v in snapshot(base).items() if k != inv.PULL_FILE}
    assert run_cli(monkeypatch, "ywh", "--if-older-than", "7") == 0
    assert "platform 'yeswehack' is not supported" in capsys.readouterr().out
    state = json.loads((base / inv.PULL_FILE).read_text())
    assert state["last_attempt_status"] == "failed" and "yeswehack" in state["last_error"]
    assert {k: v for k, v in snapshot(base).items() if k != inv.PULL_FILE} == before
    (base / inv.PULL_FILE).unlink()
    assert run_cli(monkeypatch, "ywh") == 1


def _legacy_bugcrowd_dir(isolated, name, code):
    """An older Bugcrowd pull: engagement URL saved as ``source``/``slug``, no ``source_url``."""
    base = _origin_dir(isolated, name, "bugcrowd")
    rules = {"platform": "bugcrowd", "program": name, "slug": code,
             "source": f"https://bugcrowd.com/engagements/{code}"}
    (base / "rules-of-engagement.json").write_text(json.dumps(rules))
    old = (datetime.now(timezone.utc) - timedelta(days=30)).timestamp()
    os.utime(base / "rules-of-engagement.json", (old, old))
    return base


def test_legacy_bugcrowd_source_refreshes_the_engagement_code(isolated, monkeypatch):
    _legacy_bugcrowd_dir(isolated, "acme", "acme-og")
    calls = []
    monkeypatch.setattr(scope_puller, "pull_scope", lambda program, platform, **kw: calls.append(
        (program, platform, kw["slug"])) or {})
    assert scope_puller.run_pull("acme", None, use_api=False, release_check=False, if_older_than=7) == 0
    assert calls == [("https://bugcrowd.com/engagements/acme-og", "bugcrowd", "acme")]


def test_rebuild_records_legacy_source_as_source_url(isolated):
    base = _legacy_bugcrowd_dir(isolated, "acme", "acme-og")
    assert scope_puller.rebuild_inventory("acme") == 0
    state = json.loads((base / inv.PULL_FILE).read_text())
    assert state["source_url"] == "https://bugcrowd.com/engagements/acme-og"
    assert scope_puller.recorded_origin(base) == ("bugcrowd", "https://bugcrowd.com/engagements/acme-og")


def test_saved_dir_without_source_url_is_not_pulled_from_its_name(isolated, monkeypatch, capsys):
    base = _origin_dir(isolated, "acme", "bugcrowd")
    monkeypatch.setattr(scope_puller, "pull_scope", lambda *a, **k: pytest.fail("guessed the handle from the dir name"))
    before = {k: v for k, v in snapshot(base).items() if k != inv.PULL_FILE}
    assert run_cli(monkeypatch, "acme", "--if-older-than", "7") == 0
    assert "records no source URL" in capsys.readouterr().out
    state = json.loads((base / inv.PULL_FILE).read_text())
    assert state["last_attempt_status"] == "failed" and "no source URL" in state["last_error"]
    assert {k: v for k, v in snapshot(base).items() if k != inv.PULL_FILE} == before
    assert run_cli(monkeypatch, "acme") == 1

    calls = []
    monkeypatch.setattr(scope_puller, "pull_scope", lambda program, platform, **kw: calls.append(
        (program, platform, kw["slug"])) or {})
    assert run_cli(monkeypatch, "acme", "--platform", "hackerone", "--force-platform") == 0
    assert calls == [("acme", "hackerone", None)]


def test_bugcrowd_page_without_brief_names_the_url():
    with pytest.raises(RuntimeError, match=r"engagements/klaviyo \(engagement not found or not public\)"):
        scope_puller.parse_bugcrowd_public_engagement("klaviyo", "<html><title>Resource not found 404</title></html>")


def test_release_values_sanitized_and_capped(monkeypatch):
    ios = {"key": "ios_app:123456", "kind": "ios_app", "identifier": "123456", "name": "x"}
    body = json.dumps({"results": [{"version": "1\x1b[31m" + "A" * 5000,
                                    "currentVersionReleaseDate": "2026-01-01\x85T00:00:00Z"}]}).encode()
    monkeypatch.setattr(inv, "http_request", lambda url, method="GET": (200, {}, body))
    release, _ = inv.check_release(ios, None, T0)
    assert len(release["version"]) == 64 and len(release["signal"]) <= 200
    assert not inv._UNSAFE_CHARS.search(release["signal"] + release["version"])

    exe = {"key": "executable:https://dl.example.test/a.exe", "kind": "executable",
           "identifier": "https://dl.example.test/a.exe", "name": "a"}
    monkeypatch.setattr(inv, "http_request", lambda url, method="GET": (200, {"etag": "x" * 20000,
                                                                              "last-modified": "a\x07b"}, b""))
    release, _ = inv.check_release(exe, None, T0)
    assert len(release["signal"]) == 200 and "\x07" not in release["signal"]

    play = {"key": "android_app:com.example.test.app", "kind": "android_app",
            "identifier": "com.example.test.app", "name": "p"}
    monkeypatch.setattr(inv, "http_request", lambda url, method="GET": (
        200, {}, b'<div>Updated on</div><div>Nov\x1b 20, 2026\x7f</div>'))
    release, event = inv.check_release(play, {"signal": "Updated on Nov 20,\x1b 2026"}, T0)
    assert release["signal"] == "Updated on Nov 20, 2026"
    assert event is None  # compared after sanitizing both sides


def test_lost_items_file_resyncs_from_history(isolated, monkeypatch, capsys):
    base = scope_dir(isolated)
    monkeypatch.setattr(inv, "utcnow", lambda: T0)
    save_h1([h1_node("URL", "https://a.example.test"), h1_node("URL", "https://b.example.test")])
    (base / inv.ITEMS_FILE).unlink()
    monkeypatch.setattr(inv, "utcnow", lambda: T0 + timedelta(days=2))
    save_h1([h1_node("URL", "https://a.example.test", submit=False), h1_node("URL", "https://c.example.test")])
    assert "resyncing" in capsys.readouterr().out
    lines = history(base)
    assert [l["source"] for l in lines] == ["baseline", "rebuild"]
    resync = lines[-1]
    assert resync["resync"] is True and resync["items"] == 2
    assert [e["key"] for e in resync["added"]] == ["web_host:c.example.test"]
    assert [e["key"] for e in resync["removed"]] == ["web_host:b.example.test"]
    assert resync["changed"] == [{"key": "web_host:a.example.test", "field": "in_scope", "from": True, "to": False}]
    items = items_by_key(base)
    assert items["web_host:a.example.test"]["first_seen"] == "2026-11-01T10:00:00Z"  # recovered
    assert items["web_host:c.example.test"]["first_seen"] == "2026-11-03T10:00:00Z"

    (base / inv.ITEMS_FILE).write_text("{not json")
    save_h1([h1_node("URL", "https://a.example.test", submit=False), h1_node("URL", "https://c.example.test")])
    assert [l["source"] for l in history(base)].count("baseline") == 1

    # An empty history file still means first inventory.
    other = scope_dir(isolated, "fresh")
    (other / inv.HISTORY_FILE).write_text("")
    write_scope(other, assets=[], in_lines=["x.example.test"])
    inv.write_inventory(other, source="rebuild", program="fresh", now=T0)
    assert [l["source"] for l in history(other)] == ["baseline"]


def test_stale_items_read_does_not_duplicate_history(isolated, monkeypatch):
    base = scope_dir(isolated)
    write_scope(base, assets=[{"name": "g", "targets": [{"name": "app.example.test", "category": "website"}]}],
                in_lines=["app.example.test"])
    inv.write_inventory(base, source="pull", program="demo", now=T0)
    stale = json.loads((base / inv.ITEMS_FILE).read_text())
    write_scope(base, assets=[{"name": "g", "targets": [{"name": "app.example.test", "category": "website"},
                                                         {"name": "new.example.test", "category": "website"}]}],
                in_lines=["app.example.test"])
    inv.write_inventory(base, source="pull", program="demo", now=T0)
    real = inv.read_json
    monkeypatch.setattr(inv, "read_json", lambda p: stale if p.name == inv.ITEMS_FILE else real(p))
    inv.write_inventory(base, source="pull", program="demo", now=T0)
    assert sum("new.example.test" in line for line in (base / inv.HISTORY_FILE).read_text().splitlines()) == 1


def test_inventory_lock_is_outside_scope_dir_and_times_out(isolated, monkeypatch, capsys):
    import fcntl

    monkeypatch.setattr(inv, "lock_dir", lambda: isolated / "locks")
    monkeypatch.setattr(inv, "LOCK_TIMEOUT", 0.3)
    save_h1()
    base = scope_dir(isolated)
    assert not any(p.name.endswith(".lock") for p in base.iterdir())
    (lock,) = (isolated / "locks").iterdir()
    before = {k: v for k, v in snapshot(base).items() if k in inv.INVENTORY_FILES}
    holder = os.open(lock, os.O_RDWR)
    try:
        fcntl.flock(holder, fcntl.LOCK_EX)
        with pytest.raises(inv.InventoryLockTimeout, match="locked by another writer"):
            inv.write_inventory(base, source="rebuild", program="demo")
        with pytest.raises(inv.InventoryLockTimeout):
            inv.record_attempt(base, "failed", error="x")
        save_h1([h1_node("URL", "https://changed.example.test")])  # scope files still save
        assert "changed.example.test" in (base / "in-scope.txt").read_text()
        assert "inventory could not be written" in capsys.readouterr().out
    finally:
        os.close(holder)
    assert {k: v for k, v in snapshot(base).items() if k in inv.INVENTORY_FILES} == before


# Review round 2 (minor): one lock path per user regardless of XDG_RUNTIME_DIR,
# so interactive shells and cron/ssh/systemd jobs contend for the same lock.
def test_lock_dir_is_independent_of_xdg_runtime_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(inv.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(inv, "lock_dir", _REAL_LOCK_DIR)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    with_xdg = inv.lock_dir()
    monkeypatch.delenv("XDG_RUNTIME_DIR")
    assert inv.lock_dir() == with_xdg == tmp_path / ".cache" / "bbh" / "scope-locks"
    d = tmp_path / "acme"
    d.mkdir()
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    with inv.inventory_lock(d):
        monkeypatch.delenv("XDG_RUNTIME_DIR")
        with pytest.raises(inv.InventoryLockTimeout):
            with inv.inventory_lock(d, timeout=0.3):
                pass


# Review round 2 (minor): a refresh through an alias dir records the canonical
# program name, so alternating names never flip the recorded program.
def test_alias_refresh_records_canonical_program(isolated, monkeypatch):
    base = _origin_dir(isolated, "acme_corp", "hackerone", "https://hackerone.com/acme_corp")
    (isolated / "Shared" / "scopes" / "acme").symlink_to("acme_corp")
    calls = []

    def team(handle):
        calls.append(handle)
        return {"policy": "", "submission_state": "open", "offers_bounties": True,
                **h1_team([h1_node("URL", "https://new.example.test")])}

    monkeypatch.setattr(scope_puller, "fetch_hackerone_team", team)
    assert scope_puller.run_pull("acme", None, use_api=False, release_check=False) == 0
    assert calls == ["acme_corp"]
    assert json.loads((base / "rules-of-engagement.json").read_text())["program"] == "acme_corp"
    assert json.loads((base / inv.ITEMS_FILE).read_text())["program"] == "acme_corp"
    assert (isolated / "Shared" / "scopes" / "acme").is_symlink()
