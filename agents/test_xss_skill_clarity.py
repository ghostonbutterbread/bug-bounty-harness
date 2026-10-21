"""XSS entry guidance remains clear, progressive, and evidence-led."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
XSS = ROOT / "skills/xss/SKILL.md"
SOURCE = ROOT / "skills/xss/references/source-acquisition.md"
BLIND = ROOT / "skills/blind-xss/SKILL.md"


def test_xss_router_has_one_cold_start_and_no_observation_quota() -> None:
    text = XSS.read_text(encoding="utf-8")
    assert "references/opening-and-knowledge.md" in text
    assert "current input and render context" in text
    assert "3-5 fresh" not in text
    assert "notes/summary.md" not in text
    assert "before deep payload work" not in text
    assert "Do not delay investigation of an existing source-to-sink path" in text


def test_xss_route_preserves_pressure_without_automatic_pivot_on_one_inert_probe() -> None:
    text = XSS.read_text(encoding="utf-8")
    assert "plausible executable consumer" in text
    assert "context-appropriate discovery pass" in text
    assert "pending" in text and "missing artifact" in text
    assert "account-testing-policy" in text
    assert "injection-testing-policy" in text
    assert "references/source-acquisition.md" in text
    assert SOURCE.is_file()
    assert "docs/xss-blocker-deepening" not in text


def test_xss_record_and_proof_contract_has_one_owner() -> None:
    text = XSS.read_text(encoding="utf-8")
    assert "attempt-recording-policy" in text
    assert "xss-payload-engineering" in text
    assert "browser or equivalent execution evidence" in text
    assert "bare collector hit" in text
    assert "planted executable payload" in text
    assert "tested context" in text
    assert "## Evidence Standard" not in text
    assert "Typical XSS pressure ladder" not in text


def test_xss_pairs_named_inputs_and_sinks_without_rigid_census_gate() -> None:
    router = XSS.read_text(encoding="utf-8")
    reference = SOURCE.read_text(encoding="utf-8")
    script_map = (ROOT / "skills/xss/scripts/README.md").read_text(encoding="utf-8")
    assert "source_sites" in router and "sink_sites" in router
    assert "parameter-mining" in router and "recon_bus.py query" in reference
    assert "params.txt" in reference and "name-only" in reference
    assert "untested" in reference and "truncated" in reference
    assert "not a taint trace" in reference
    assert "xss_source_sites.py" in script_map
    assert "Do not delay investigation of an existing source-to-sink path" in router


def test_xss_routes_live_js_loading_and_stack_specific_source_sink_review() -> None:
    router = XSS.read_text(encoding="utf-8")
    reference = SOURCE.read_text(encoding="utf-8")
    source_script = ROOT / "agents/xss_source_sites.py"
    sink_script = ROOT / "agents/xss_sink_sites.py"
    assert source_script.is_file() and sink_script.is_file()
    for route in ("browser-session-policy", "chromium-test", "js-pull", "js-hunt"):
        assert route in router and route in reference
    for cue in ("Network", "Sources", "lazy-loaded", "forms", "hidden inputs"):
        assert cue in router
    assert "--page` fetches linked scripts" in reference
    assert "--input <scoped-js-url-list>" in " ".join(reference.split())
    assert "agents/xss_source_sites.py" in reference
    assert "agents/xss_sink_sites.py" in reference
    assert "unloaded" in reference and "server-rendered templates" in reference
    assert "not separate live scanners" in router
    assert "not a taint trace" in router
    script_map = (ROOT / "skills/xss/scripts/README.md").read_text(encoding="utf-8")
    assert "## `agents/xss_source_sites.py`" in script_map
    assert "## `agents/xss_sink_sites.py`" in script_map
    assert "scan_source_sites" in script_map and "scan_sink_sites" in script_map


def test_blind_lane_uses_the_same_confirmed_evidence_threshold() -> None:
    router = XSS.read_text(encoding="utf-8")
    blind = BLIND.read_text(encoding="utf-8")
    for text in (router, blind):
        assert "planted executable payload" in text
        assert "bare collector hit" in text
        assert "Confirmed" in text
    assert "jumps straight to `Confirmed`" not in blind
    assert "last-resort execution" not in blind
    assert "proves script execution" not in blind
    assert "can support `Confirmed` **if**" in blind
    assert "full GET is retained and correlated" in " ".join(blind.split())
    assert "A bare collector hit remains `Pending-OOB`" in blind
    image_line = next(line for line in blind.splitlines() if '<img src onerror=' in line)
    assert "WEBHOOK_URL?probe=" in image_line
    assert "location.href" in image_line
    assert "document.cookie" not in image_line
    assert "Do not automatically resubmit to a staff queue" in blind
