from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "agents/index.md"
OVERLAY = ROOT / "skills/xss-escalation/SKILL.md"


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


def test_bbh_maintainer_guide_routes_new_overlays_to_canonical_registry():
    guidance = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    assert "When adding, renaming, or retiring a vulnerability-class escalation skill" in guidance
    assert "class-overlay route list at the bottom" in guidance
    assert "`impact-escalation` skill in AI Policies" in guidance
    assert "Verify the listed skill resolves" in guidance
