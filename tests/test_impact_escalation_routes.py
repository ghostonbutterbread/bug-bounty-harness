from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "agents/index.md"
OVERLAY = ROOT / "skills/xss-escalation/SKILL.md"
SSRF_OVERLAY = ROOT / "skills/ssrf-impact-escalation/SKILL.md"


def test_finding_to_report_route_keeps_initial_capture_first():
    entry = ENTRY.read_text(encoding="utf-8")
    capture = (ROOT / "skills/manual-hunter/SKILL.md").read_text(encoding="utf-8")
    reporting = (ROOT / "skills/security-reporting/SKILL.md").read_text(encoding="utf-8")
    assert entry.index("After recording a proven FID") < entry.index("load `impact-escalation`")
    assert entry.index("load `impact-escalation`") < entry.index("Load the standalone `bunny-report-and-triage`")
    assert capture.index("ingest it promptly") < capture.index("Then load `impact-escalation`")
    assert "same FID" in reporting


def test_xss_overlay_routes_to_guard_owner_and_checks_effect():
    overlay = OVERLAY.read_text(encoding="utf-8")
    xss = (ROOT / "skills/xss/SKILL.md").read_text(encoding="utf-8")
    assert "`xss-escalation`" in xss
    for phrase in ("`assumption-testing`", "Old-password, OTP", "server enforcement", "independently usable", "owned accounts", "same FID"):
        assert phrase in overlay
    assert "this overlay supplies **impact ideas**" in overlay


def test_ssrf_overlay_routed_after_capture_and_requires_verified_effect():
    overlay = SSRF_OVERLAY.read_text(encoding="utf-8")
    ssrf = (ROOT / "skills/ssrf/SKILL.md").read_text(encoding="utf-8")
    assert overlay.startswith("---\nname: ssrf-impact-escalation\n")
    assert ssrf.index("captured in the findings ledger with an FID") < ssrf.index("`ssrf-impact-escalation` overlay")
    for phrase in ("IMDSv2", "GET-only", "GCP and Azure", "`assumption-testing`", "independent read-back", "same FID", "report-only"):
        assert phrase in overlay
    assert "sensitive files" in overlay.lower()
    assert "public callback alone" in overlay.lower()
    assert "does not authorize credential use" in overlay


def test_bbh_maintainer_guide_routes_new_overlays_to_canonical_registry():
    guidance = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    assert "When adding, renaming, or retiring a vulnerability-class escalation skill" in guidance
    assert "class-overlay route list at the bottom" in guidance
    assert "`impact-escalation` skill in AI Policies" in guidance
    assert "Verify the listed skill resolves" in guidance
