from __future__ import annotations

import json

from agents import scope_puller


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
