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
