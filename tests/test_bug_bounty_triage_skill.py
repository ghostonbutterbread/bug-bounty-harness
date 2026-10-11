"""Contract checks for the upstream-derived BBH triage workflow."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/bug-bounty-triage/SKILL.md"


def test_upstream_attribution_and_discovery():
    text = SKILL.read_text(encoding="utf-8")
    assert text.startswith("---\nname: bug-bounty-triage\n")
    assert "Sequester-AG/bug-bounty-triage" in text
    assert "9684e1bfc876e841f9c789f0b258902b43d461e4" in text
    assert "Copyright (c) 2026 Sequester-AG" in (SKILL.parent / "LICENSE").read_text()
    assert "skills/bug-bounty-triage/SKILL.md" in (ROOT / "SKILL_REGISTRY.md").read_text()


def test_existing_owners_remain_canonical():
    text = SKILL.read_text(encoding="utf-8")
    for marker in (
        "security-reporting", "reports/<FID>/EVIDENCE.md", "REPORT.md",
        "reports/<FID>/SUBMISSION.md", "bbh agents/finding_submission.py",
        "--evidence-pointer", "bounty-storage", "bounty-directory-structure-policy",
        "five-section", "Summary", "Technical details", "How to reproduce",
        "Impact", "Remediation", "report-only assignment must not launch live tests",
        "independent judge", "No internal triage scorecard",  # checked case-insensitively below
    ):
        assert marker.lower() in text.lower(), marker
    assert "SUBMISSION_SECTIONS = (\"Summary\", \"Technical details\", \"How to reproduce\", \"Impact\", \"Remediation\")" in (ROOT / "agents/finding_submission.py").read_text()


def test_testing_mail_and_privacy_routes():
    text = SKILL.read_text(encoding="utf-8")
    for marker in (
        "general-security-testing-policy", "live-testing-policy", "chromium-test",
        "browser_provisioner.py request", "task-scoped MITM", "Never", "agent-browser",
        "account-testing-policy", "email-access-policy", "Composio", "mail",
        "temporary-email", "never redact", "owned fixtures", "GREEN", "YELLOW", "RED",
        "original versus", "cleanup status",
    ):
        assert marker.lower() in text.lower(), marker
    assert "Write a file called `<target-domain>" not in text
    assert "agent-email create\n" not in text


def test_verified_unrecorded_finding_gets_fid_before_reporting():
    text = SKILL.read_text(encoding="utf-8")
    assert "verified finding without a FID" in text
    assert "manual-hunter` ingest in the canonical program/lane" in text
    assert "unproven candidate remains a lead" in text
    assert "assigned FID and populate its generated `EVIDENCE.md` and rough `REPORT.md`" in text
    assert "exact existing ledger FID and populated packet" in text


def test_triage_hands_off_submission_authorship():
    text = SKILL.read_text(encoding="utf-8")
    assert "coordinator assigns the **reporting agent**" in text
    assert "reporting agent, not this triage-only worker" in text
    assert "explicitly assigned both triage and reporting" in text
    assert "follow `security-reporting`'s gates" in text
