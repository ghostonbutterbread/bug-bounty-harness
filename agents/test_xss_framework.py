from __future__ import annotations

import json
from pathlib import Path

from agents.xss_framework import DiscoveredParam, ParameterDiscovery, ReflectedTester, ScreenResult, StoredTester, XSSFramework, XSSScreener


class _Response:
    status_code = 200
    text = "<html><body>nothing reflected</body></html>"


class _Session:
    def get(self, url: str, **kwargs):
        return _Response()


def test_context_classifies_marker_by_actual_html_location() -> None:
    screener = XSSScreener(_Session())
    marker = "XSSUNIQUE"
    assert screener._detect_context(f'<div title="{marker}">text</div>', marker) == "html_attr"
    assert screener._detect_context(f'<a href="/search?q={marker}">link</a>', marker) == "url_param"
    assert screener._detect_context(f'<script>const v = "{marker}";</script>', marker) == "js_string"
    assert screener._detect_context(f'<script>const v = `{marker}`;</script>', marker) == "js_template"
    assert screener._detect_context(f'<!-- {marker} -->', marker) == "comment"
    assert screener._detect_context(f'<p>{marker}</p>', marker) == "html_body"
    assert screener._detect_context('MARKER <p>irrelevant</p>', marker) == "none"


def test_discovery_preserves_same_name_on_distinct_routes() -> None:
    discovery = ParameterDiscovery(_Session())
    params = discovery._dedupe_and_rank([
        DiscoveredParam("q", "url", url="https://example.test/search?q=old", priority=10),
        DiscoveredParam("q", "wayback", url="https://example.test/archive?q=old", priority=7),
        DiscoveredParam("q", "js", url="https://example.test/search", priority=6),
    ])
    assert [(p.name, p.source) for p in params] == [("q", "url"), ("q", "wayback")]

def test_discovery_preserves_render_mode_but_dedupes_probe_value() -> None:
    discovery = ParameterDiscovery(_Session())
    html_url = "https://example.test/search?view=html&q=old"
    json_url = "https://example.test/search?q=other&view=json"
    params = discovery._dedupe_and_rank([
        DiscoveredParam("q", "wayback", url=html_url, priority=7),
        DiscoveredParam("q", "url", url="https://example.test/search?q=new&view=html", priority=10),
        DiscoveredParam("q", "wayback", url=json_url, priority=7),
    ])
    assert [(p.source, p.url) for p in params] == [
        ("url", "https://example.test/search?q=new&view=html"),
        ("wayback", json_url),
    ]

def test_context_classifies_unquoted_attributes_and_script_comment_text() -> None:
    screener = XSSScreener(_Session())
    marker = "XSSUNIQUE"
    assert screener._detect_context(f'<input value={marker}>', marker) == "html_attr"
    assert screener._detect_context(f'<a href=/search?q={marker}>', marker) == "url_param"
    assert screener._detect_context(f'<script>const v = "<!-- {marker} -->";</script>', marker) == "js_string"
    assert screener._detect_context(f'<!-- <script>{marker}</script> -->', marker) == "comment"


def test_screener_probes_discovered_route_not_base_target(monkeypatch) -> None:
    class Session:
        urls = []
        def get(self, url, **kwargs):
            self.urls.append(url)
            return type("Response", (), {"text": "<p>XSSMARKER</p>", "status_code": 200})()

    session = Session()
    monkeypatch.setattr("agents.xss_framework.time.sleep", lambda _: None)
    monkeypatch.setattr("agents.xss_framework.uuid4", lambda: type("UUID", (), {"hex": "marker"})())
    results = XSSScreener(session).screen("https://example.test/root", [
        DiscoveredParam("q", "wayback", url="https://example.test/archive?q=old")
    ])
    assert results[0].url.startswith("https://example.test/archive?q=")
    assert session.urls[-1].startswith("https://example.test/archive?q=")


def test_http_reflection_never_claims_browser_execution() -> None:
    payload = "<img src=x onerror=alert(1)>"
    class Session:
        def __init__(self, text):
            self.text = text
        def get(self, url, **kwargs):
            return type("Response", (), {"text": self.text, "status_code": 200})()

    screen = ScreenResult("q", "https://example.test/route?q=marker", True, "html_body", "", False, "MED")
    escaped = ReflectedTester(Session("<p>&lt;img src=x onerror=alert(1)&gt;</p>"))
    assert escaped._send(screen.url, "q", payload)["reflected_intact"] is False
    raw = ReflectedTester(Session(f"<p>{payload}</p>"))
    assert raw._send(screen.url, "q", payload)["executed"] is False
    assert raw._send(screen.url, "q", payload)["reflected_intact"] is True
    stored = StoredTester(Session(f"<p>{payload}</p>"))
    assert stored._check_execution(screen.url, payload, "token")["executed"] is False


def test_reflected_probe_retains_route_and_records_reflection_not_execution(monkeypatch) -> None:
    from agents.xss_framework import REFLECTED_PAYLOADS

    class Session:
        urls = []
        def get(self, url, **kwargs):
            self.urls.append(url)
            return type("Response", (), {"text": "<img src=x onerror=alert(1)>", "status_code": 200})()

    session = Session()
    records = []
    monkeypatch.setattr("agents.xss_framework.time.sleep", lambda _: None)
    monkeypatch.setitem(REFLECTED_PAYLOADS, "standard", ["<img src=x onerror=alert(1)>"])
    tester = ReflectedTester(session, attempt_recorder=records.append)
    tester.TIERS = ["standard"]
    result = tester.test("https://example.test/root", ScreenResult(
        "q", "https://example.test/archive?q=marker", True, "html_body", "", False, "MED"
    ))
    assert len(result) == 1
    assert result[0].url.startswith("https://example.test/archive?q=")
    assert result[0].confirmed is False
    assert session.urls == [result[0].url]
    assert records[0]["outcome"] == "reflected_intact"

def test_reflected_comment_echo_is_not_a_finding_but_escape_is(monkeypatch) -> None:
    from agents.xss_framework import REFLECTED_PAYLOADS
    from urllib.parse import parse_qs, urlsplit

    class Session:
        def get(self, url, **kwargs):
            payload = parse_qs(urlsplit(url).query)["q"][0]
            body = f"<!-- {payload} -->"
            return type("Response", (), {"text": body, "status_code": 200})()

    monkeypatch.setattr("agents.xss_framework.time.sleep", lambda _: None)
    payload = "<img src=x onerror=alert(1)>"
    breakout = "--><img src=x onerror=alert(1)>"
    monkeypatch.setitem(REFLECTED_PAYLOADS, "standard", [payload, breakout])
    screen = ScreenResult("q", "https://example.test/search?q=marker", True, "comment", "", False, "MED")
    records = []
    tester = ReflectedTester(Session(), attempt_recorder=records.append)
    tester.TIERS = ["standard"]
    findings = tester.test(screen.url, screen)
    assert [f.payload for f in findings] == [breakout]
    assert findings[0].confirmed is False
    assert [row["outcome"] for row in records] == ["reflected_intact", "reflected_intact"]

    monkeypatch.setitem(REFLECTED_PAYLOADS, "standard", [payload])
    assert tester.test(screen.url, screen) == []


def test_comment_delimiters_in_script_and_active_second_echo_are_not_inert() -> None:
    from agents.xss_framework import _only_in_html_comments
    payload = "<img src=x onerror=alert(1)>"
    assert _only_in_html_comments(f"<!-- {payload} -->", payload)
    assert not _only_in_html_comments(f"<!-- {payload} -->\n<div>{payload}</div>", payload)
    assert not _only_in_html_comments(f'<script>const text = "<!--"; {payload}</script>', payload)

def test_blocked_echo_is_not_finding_and_deeper_tier_is_tried(monkeypatch) -> None:
    from agents.xss_framework import REFLECTED_PAYLOADS
    from urllib.parse import parse_qs, urlsplit

    class Session:
        def __init__(self):
            self.urls = []
        def get(self, url, **kwargs):
            self.urls.append(url)
            status = 200 if "deep-probe" in url else 403
            payload = parse_qs(urlsplit(url).query)["q"][0]
            return type("Response", (), {"text": payload, "status_code": status})()

    monkeypatch.setattr("agents.xss_framework.time.sleep", lambda _: None)
    for tier in ("standard", "encoding", "alternative_tags"):
        monkeypatch.setitem(REFLECTED_PAYLOADS, tier, [f"<{tier}-probe>"])
    monkeypatch.setitem(REFLECTED_PAYLOADS, "attribute_break", ["<deep-probe>"])
    session = Session()
    records = []
    tester = ReflectedTester(session, attempt_recorder=records.append)
    tester.TIERS = ["standard", "encoding", "alternative_tags", "attribute_break"]
    findings = tester.test("https://example.test/search?q=old", ScreenResult(
        "q", "https://example.test/search?q=marker", True, "html_body", "", False, "MED"
    ))
    assert len(session.urls) == 4
    assert len(findings) == 1
    assert findings[0].payload == "<deep-probe>"
    assert findings[0].confirmed is False
    assert [row["outcome"] for row in records] == ["blocked"] * 3 + ["reflected_intact"]

def test_final_dedupe_preserves_route_provenance() -> None:
    from agents.xss_framework import XSSFinding
    framework = XSSFramework("https://example.test/root", skip_scope=True)
    try:
        def finding(route):
            return XSSFinding("reflected", route, "q", "<probe>", "html_body", "reflection", route, "P2", "standard", "echo")
        first = finding("https://example.test/search?q=%3Cprobe%3E")
        second = finding("https://example.test/archive?q=%3Cprobe%3E")
        assert framework._dedupe([first, first, second]) == [first, second]
    finally:
        framework.close()

def test_all_blocked_echoes_are_only_attempts(monkeypatch) -> None:
    from agents.xss_framework import REFLECTED_PAYLOADS
    monkeypatch.setattr("agents.xss_framework.time.sleep", lambda _: None)
    monkeypatch.setitem(REFLECTED_PAYLOADS, "standard", ["<probe>"])
    records = []
    class Session:
        def get(self, url, **kwargs):
            return type("Response", (), {"text": "<probe>", "status_code": 403})()
    tester = ReflectedTester(Session(), attempt_recorder=records.append)
    tester.TIERS = ["standard"]
    assert tester.test("https://example.test/route", ScreenResult(
        "q", "https://example.test/route?q=marker", True, "html_body", "", False, "MED"
    )) == []
    assert records[0]["outcome"] == "blocked"
    assert records[0]["stop_reason"] == "response_blocked"


def test_screener_returns_structured_cold_result_when_marker_is_absent() -> None:
    result = XSSScreener(_Session())._test_reflection(
        "https://example.test/search?q=baseline",
        "q",
        "XSSMARKER",
        "",
    )

    assert isinstance(result, ScreenResult)
    assert result.reflected is False
    assert result.context == "none"
    assert result.priority == "LOW"



def test_framework_resolves_default_attempts_in_xss_lane(tmp_path: Path, monkeypatch) -> None:
    calls: dict[str, object] = {}

    def resolve(program: str, **kwargs: object) -> Path:
        calls["program"] = program
        calls.update(kwargs)
        return tmp_path / "attempts.jsonl"

    monkeypatch.setattr("agents.xss_framework.resolve_attempts_path", resolve)
    XSSFramework(
        target="https://example.test/search?q=baseline",
        program="Example Program",
        mode="reflected",
        skip_scope=True,
    )

    assert calls["program"] == "Example Program"
    assert calls["lane"] == "xss"
    assert isinstance(calls["run_id"], str)


def test_framework_records_cold_selected_vector_without_running_payload_tiers(tmp_path: Path) -> None:
    attempts_path = tmp_path / "attempts.jsonl"
    framework = XSSFramework(
        target="https://example.test/search?q=baseline",
        program="adhoc",
        mode="reflected",
        skip_scope=True,
        attempts_path=attempts_path,
    )
    framework.discovery.run = lambda target: [DiscoveredParam(name="q", source="url", url=target)]
    framework.screener.screen = lambda target, params: [
        ScreenResult(
            param="q",
            url="https://example.test/search?q=XSSMARKER",
            reflected=False,
            context="none",
            location="",
            near_sink=False,
            priority="LOW",
        )
    ]
    framework.reflected_tester.test = lambda target, candidate: (_ for _ in ()).throw(AssertionError("cold vector must not enter payload tiers"))
    framework._save_report = lambda: None
    framework._print_summary = lambda: None

    try:
        assert framework.run() == []
    finally:
        framework.close()

    rows = [json.loads(line) for line in attempts_path.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1
    row = rows[0]
    assert row["schema_version"] == 1
    assert row["attempt_id"].startswith("A-")
    assert row["producer"] == row["tool"] == "xss_framework"
    assert row["subject"] == row["target"] == "https://example.test/search?q=XSSMARKER"
    assert row["reason"] == row["stop_reason"] == "raw_response_only_inconclusive"
    assert row["outcome"] == "cold"
    assert row["param"] == "q"
    assert row["context"] == "none"
    assert row["raw_response_evidence"] == "marker_absent"
    assert row["recommended_follow_up"] == "browser_rendered_reflection_or_stored_xss"


def test_reflected_tester_records_each_payload_as_an_experimental_probe(monkeypatch) -> None:
    from agents.xss_framework import REFLECTED_PAYLOADS, ReflectedTester

    class _PayloadResponse:
        status_code = 200
        text = "<html><body>encoded or absent</body></html>"

    class _PayloadSession:
        def get(self, url: str, **kwargs):
            return _PayloadResponse()

    records: list[dict] = []
    monkeypatch.setattr("agents.xss_framework.time.sleep", lambda _: None)
    monkeypatch.setitem(REFLECTED_PAYLOADS, "standard", ["<probe-marker>"])

    tester = ReflectedTester(_PayloadSession(), rate_limit=100, attempt_recorder=records.append)
    tester.TIERS = ["standard"]
    findings = tester.test(
        "https://example.test/search?q=baseline",
        ScreenResult(
            param="q",
            url="https://example.test/search?q=XSSMARKER",
            reflected=True,
            context="html_text",
            location="body",
            near_sink=False,
            priority="MED",
        ),
    )

    assert findings == []
    assert records == [
        {
            "event_type": "probe",
            "vuln_class": "xss",
            "target": "https://example.test/search?q=%3Cprobe-marker%3E",
            "outcome": "not_reflected",
            "stop_reason": "payload_did_not_reflect_intact",
            "payload": "<probe-marker>",
            "payload_family": "standard",
            "param": "q",
            "context": "html_text",
            "http_status": 200,
        }
    ]


def test_adaptive_bypass_records_every_base_and_variant_payload(tmp_path: Path, monkeypatch) -> None:
    from agents.xss_framework import REFLECTED_PAYLOADS

    class _Response:
        def __init__(self, status_code: int, text: str) -> None:
            self.status_code = status_code
            self.text = text

    class _Session:
        def __init__(self) -> None:
            self.responses = [_Response(403, "blocked"), _Response(200, "not reflected")]

        def get(self, url: str, **kwargs):
            return self.responses.pop(0)

        def close(self) -> None:
            pass

    monkeypatch.setattr("agents.xss_framework.time.sleep", lambda _: None)
    monkeypatch.setitem(REFLECTED_PAYLOADS, "standard", ["<base-probe>"])
    attempts_path = tmp_path / "attempts.jsonl"
    framework = XSSFramework(
        target="https://example.test/search?q=baseline",
        program="adhoc",
        mode="reflected",
        skip_scope=True,
        attempts_path=attempts_path,
    )
    framework.session = _Session()
    framework.bypass_engine.detect_block_type = lambda body, status: "WAF"
    framework.bypass_engine.adapt = lambda payload, block_type: ["<variant-probe>"]

    try:
        assert framework._adaptive_bypass(
            ScreenResult(
                param="q",
                url="https://example.test/search?q=XSSMARKER",
                reflected=True,
                context="html_text",
                location="body",
                near_sink=False,
                priority="HIGH",
            )
        ) == []
    finally:
        framework.close()

    rows = [json.loads(line) for line in attempts_path.read_text(encoding="utf-8").splitlines()]
    assert [row["payload"] for row in rows] == ["<base-probe>", "<variant-probe>"]
    assert all(row["event_type"] == "probe" for row in rows)
    assert all(row["vuln_class"] == "xss" for row in rows)


def test_adaptive_bypass_does_not_promote_comment_only_variant(tmp_path: Path, monkeypatch) -> None:
    from agents.xss_framework import REFLECTED_PAYLOADS
    from urllib.parse import parse_qs, urlsplit

    class Session:
        def get(self, url, **kwargs):
            payload = parse_qs(urlsplit(url).query)["q"][0]
            status = 403 if payload == "<base-probe>" else 200
            return type("Response", (), {"status_code": status, "text": f"<!-- {payload} -->"})()
        def close(self):
            pass

    monkeypatch.setattr("agents.xss_framework.time.sleep", lambda _: None)
    monkeypatch.setitem(REFLECTED_PAYLOADS, "standard", ["<base-probe>"])
    framework = XSSFramework("https://example.test/search?q=old", skip_scope=True, attempts_path=tmp_path / "attempts.jsonl")
    framework.session = Session()
    framework.bypass_engine.detect_block_type = lambda body, status: "WAF"
    framework.bypass_engine.adapt = lambda payload, block_type: ["<img src=x onerror=alert(1)>"]
    try:
        screen = ScreenResult("q", framework.target, True, "comment", "", False, "HIGH")
        assert framework._adaptive_bypass(screen) == []
    finally:
        framework.close()
