"""The XSS router distinguishes an absent consumer from a defended one."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def text(relative: str) -> str:
    return " ".join((ROOT / relative).read_text(encoding="utf-8").split())


def test_router_loads_consumer_classifier_only_on_missing_mount() -> None:
    router = text("skills/xss/SKILL.md")
    reference = ROOT / "skills/xss/references/consumer-reach.md"
    assert reference.is_file()
    assert "claimed consumer does not mount" in router
    assert "references/consumer-reach.md" in router
    assert "do not infer that a sanitizer held" in router
    assert "references/defense-chain.md" in router


def test_classifier_preserves_owners_and_distinct_ingress_paths() -> None:
    reach = text("skills/xss/references/consumer-reach.md")
    for phrase in (
        "Defense", "Reachability", "Policy", "Distinct ingress question",
        "assumption-testing", "account-testing-policy", "captcha-policy",
        "blockers", "source-acquisition.md", "xss-lifecycle",
        "server-side write or denial", "response code or client flag alone",
        "writer, validation, filter, storage, and decode stages",
        "external", "remediation evidence", "wake condition",
        "selected lane decides proof and disposition",
    ):
        assert phrase in reach
    assert "do not bypass a challenge to sustain unrelated testing" in reach
    assert "a reachable sibling path may merit its own context-matched probes" in reach.lower()
    assert "a paid plan or an internal-only cohort is not a default test fixture" in reach.lower()
