from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from agents.target_intel import (
    TargetIntelConfig,
    build_recommendations,
    match_advisory,
    read_advisory_fixture,
    read_company_pattern_fixture,
    read_stack_path,
    run_target_intel,
)


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_stack_text_and_json_parsing_normalizes_components(tmp_path: Path) -> None:
    text_stack = tmp_path / "tech_stack.txt"
    text_stack.write_text("nginx 1.22.1\nReact: 18.2.0\n# ignored\n", encoding="utf-8")
    json_stack = tmp_path / "stack.json"
    json_stack.write_text(
        json.dumps({"technologies": [{"name": "Apache Struts", "version": "2.5.30", "ecosystem": "maven"}]}),
        encoding="utf-8",
    )

    context = type("Context", (), {"sources": [], "warnings": []})()
    records = read_stack_path(text_stack, "example.com", context) + read_stack_path(json_stack, "example.com", context)
    by_name = {record.normalized_name: record for record in records}

    assert by_name["nginx"].version == "1.22.1"
    assert by_name["react"].fingerprint_method == "text-stack"
    assert by_name["apache struts"].ecosystem == "maven"
    assert all(not record.active_probe for record in records)


def test_advisory_matching_distinguishes_exact_and_fuzzy_metadata(tmp_path: Path) -> None:
    stack_path = tmp_path / "stack.json"
    stack_path.write_text(
        json.dumps(
            [
                {"name": "Apache Struts", "version": "2.5.30"},
                {"name": "Acme Portal Framework", "version": "1.0.0"},
            ]
        ),
        encoding="utf-8",
    )
    advisory_path = tmp_path / "advisories.json"
    advisory_path.write_text(
        json.dumps(
            [
                {
                    "id": "CVE-2026-0001",
                    "title": "Struts RCE",
                    "products": ["Apache Struts"],
                    "affected_versions": ["< 2.5.33"],
                    "severity": "critical",
                },
                {
                    "id": "CVE-2026-0002",
                    "title": "Portal framework bug",
                    "products": ["Acme Portal"],
                    "severity": "high",
                },
            ]
        ),
        encoding="utf-8",
    )
    context = type("Context", (), {"sources": [], "warnings": []})()
    stack = read_stack_path(stack_path, "example.com", context)
    advisories = read_advisory_fixture(advisory_path, context)

    exact = match_advisory(advisories[0], stack)
    fuzzy = match_advisory(advisories[1], stack)

    assert exact[0][1] == "exact-stack"
    assert exact[0][2]["version_match"] is True
    assert fuzzy[0][1] == "fuzzy-name"


def test_company_pattern_fixture_and_scoring_uses_untested_surface(tmp_path: Path) -> None:
    pattern_path = tmp_path / "patterns.jsonl"
    pattern_path.write_text(
        json.dumps(
            {
                "vuln_class": "IDOR",
                "surface": "/api/users/{id}",
                "source_url": "https://hackerone.com/reports/123",
                "platform": "hackerone",
                "relevance": 0.9,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    context = type("Context", (), {"sources": [], "warnings": []})()
    patterns = read_company_pattern_fixture(pattern_path, context)

    assert patterns[0].vuln_class == "idor"
    assert patterns[0].source_url == "https://hackerone.com/reports/123"


def test_report_output_writes_lane_local_intel_artifacts(tmp_path: Path) -> None:
    stack = tmp_path / "tech_stack.txt"
    stack.write_text("Apache Struts 2.5.30\n", encoding="utf-8")
    advisories = tmp_path / "advisories.json"
    advisories.write_text(
        json.dumps(
            {
                "id": "CVE-2026-0001",
                "title": "Struts RCE",
                "products": ["Apache Struts"],
                "affected_versions": ["< 2.5.33"],
                "severity": "critical",
                "cvss": 9.8,
                "known_exploited": "true",
                "vuln_class": "rce",
                "references": ["https://vendor.example/advisory"],
            }
        ),
        encoding="utf-8",
    )
    surface_map = tmp_path / "surface_map.jsonl"
    surface_map.write_text(
        json.dumps(
            {
                "surface_id": "surface:1",
                "family": "api-endpoint-operation",
                "subtype": "rest-api",
                "entry_vector": "https://app.example.com/api/upload",
                "scope_status": "in-scope",
                "coverage_hints": ["untested"],
                "candidate_child_skills": ["waf"],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    asset_graph = tmp_path / "asset_graph.jsonl"
    asset_graph.write_text(
        json.dumps({"kind": "url", "normalized_value": "https://other.test/admin", "scope_status": "out-of-scope"})
        + "\n",
        encoding="utf-8",
    )

    intel_json = run_target_intel(
        TargetIntelConfig(
            program="demo",
            target="example.com",
            root=tmp_path / "shared",
            stack_paths=[stack],
            advisory_fixture_paths=[advisories],
            surface_map_paths=[surface_map],
            asset_graph_paths=[asset_graph],
            offline=True,
            run_date="2026-06-01",
        )
    )
    summary = json.loads(intel_json.read_text(encoding="utf-8"))

    assert intel_json == tmp_path / "shared" / "web_bounty" / "demo" / "web" / "intel" / "2026-06-01" / "intel.json"
    assert summary["counts"]["promoted_findings"] == 0
    assert summary["recommendations"][0]["match_type"] == "exact-stack"
    assert summary["recommendations"][0]["scope_status"] == "unknown"
    assert summary["recommendations"][0]["metadata"]["match"]["version_match"] is True
    assert summary["recommendations"][0]["metadata"]["advisory"]["known_exploited"] is True
    assert (intel_json.parent / "intel.md").exists()
    assert read_jsonl(intel_json.parent / "recommendations.jsonl")
    assert read_jsonl(intel_json.parent / "stack_fingerprints.jsonl")[0]["name"] == "Apache Struts"


def test_cli_offline_json_output(tmp_path: Path) -> None:
    stack = tmp_path / "tech_stack.txt"
    stack.write_text("nginx 1.22.1\n", encoding="utf-8")
    advisories = tmp_path / "advisories.jsonl"
    advisories.write_text(
        json.dumps({"id": "CVE-2026-0003", "products": ["nginx"], "severity": "high", "affected_versions": ["1.22.1"]})
        + "\n",
        encoding="utf-8",
    )

    cmd = [
        sys.executable,
        "agents/target_intel.py",
        "demo",
        "--target",
        "example.com",
        "--offline",
        "--root",
        str(tmp_path / "shared"),
        "--stack",
        str(stack),
        "--advisory-fixture",
        str(advisories),
        "--run-date",
        "2026-06-01",
        "--json",
    ]
    result = subprocess.run(cmd, cwd=Path(__file__).resolve().parents[1], text=True, capture_output=True, check=True)
    summary = json.loads(result.stdout)

    assert summary["tool"] == "target-intel"
    assert summary["mode"] == "offline"
    assert summary["counts"]["recommendations"] == 1
    assert summary["recommendations"][0]["advisory_id"] == "CVE-2026-0003"
