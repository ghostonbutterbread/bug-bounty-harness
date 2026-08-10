from __future__ import annotations

import json
from pathlib import Path

from agents.xss_framework import DiscoveredParam, ScreenResult, XSSFramework, XSSScreener


class _Response:
    status_code = 200
    text = "<html><body>nothing reflected</body></html>"


class _Session:
    def get(self, url: str, **kwargs):
        return _Response()


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
