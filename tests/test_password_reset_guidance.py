"""Documentation contracts; semantic navigation is independently reviewed."""
from pathlib import Path
import re

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/password-reset"


def assert_recipient_routes(skill: Path) -> None:
    main = (skill / "SKILL.md").read_text()
    patterns = (skill / "references/ato-patterns.md").read_text()
    assert "references/recipient-parsing.md" in main
    assert "(recipient-parsing.md)" in patterns
    assert (skill / "references/recipient-parsing.md").is_file()


def test_recipient_reference_is_discoverable_and_packaged() -> None:
    assert_recipient_routes(SKILL)
    frontmatter = (SKILL / "SKILL.md").read_text().split("---", 2)[1]
    assert yaml.safe_load(frontmatter)["name"] == "password-reset"
    assert "/password-reset" in (ROOT / "skills/ato/SKILL.md").read_text()
    reference = SKILL / "references/recipient-parsing.md"
    for target in re.findall(r"\]\(([^)]+\.md)\)", reference.read_text()):
        assert (reference.parent / target).is_file(), target


def test_missing_recipient_reference_fails_route_check(tmp_path: Path) -> None:
    (tmp_path / "references").mkdir()
    for relative in ("SKILL.md", "references/ato-patterns.md"):
        (tmp_path / relative).write_text((SKILL / relative).read_text())
    with pytest.raises(AssertionError):
        assert_recipient_routes(tmp_path)


def test_each_mechanism_teaches_a_control_and_limit() -> None:
    text = (SKILL / "references/recipient-parsing.md").read_text()
    headings = (
        "Whitespace and decoding order",
        "Multiple recipients and secondary-address recovery",
        "Duplicate parameters and merged input sources",
        "JSON shape and field precedence",
        "Mailbox grammar and encoded-word parsing",
    )
    for heading in headings:
        section = text.split(f"## {heading}\n", 1)[1].split("\n## ", 1)[0]
        for label in ("Signal / mechanism", "Comparison / control", "Falsifier / limit"):
            assert f"**{label}:**" in section, (heading, label)
    for source in ("CVE-2023-7028", "WSTG-INJT-04", "splitting-the-email-atom"):
        assert source in text


def test_existing_payload_examples_remain_available() -> None:
    text = (SKILL / "references/ato-patterns.md").read_text()
    for example in (
        '{"email":["owned-a@example.com","owned-b@example.com"]}',
        "email=owned-a@example.com|owned-b@example.com",
        "email=owned-a@example.com%0aowned-b@example.com",
        "email=owned-a@example.com%0d%0aCc:owned-b@example.com",
        "email=owned-a@example.com&email=owned-b@example.com",
        "email=owned-b@example.com&email=owned-a@example.com",
        "email=owned-a@example.com&email[]=owned-b@example.com",
        '{"email":"owned-a@example.com","backup_email":"owned-b@example.com"}',
    ):
        assert example in text


def assert_auth_recovery_routes(ato: str, reset: str, recipient: str) -> None:
    """Check routing and retained boundaries, not the quality of agent reasoning."""
    ato, reset, recipient = (" ".join(text.split()) for text in (ato, reset, recipient))
    for phrase in (
        "Understand and question authority", "/assumption-testing", "/password-reset",
        "another account, purpose, session, transaction", "missing delivery, authority, binding",
        "/attempt-recording-policy", "/map-store", "/hypothesis-ledger", "/bounty-storage",
        "brute-forcing codes/tokens",
    ):
        assert phrase in ato, phrase
    for phrase in (
        "Recipient confusion", "JSON objects/arrays", "Link/code construction and binding",
        "Proof and final reset", "Lifecycle and alternate paths", "Delivery and exposure",
        "references/recipient-parsing.md", "references/ato-patterns.md",
        "research-knowledge-management", "/data-store-guidance", "/attempt-recording-policy",
        "brute forcing tokens/codes", "If a baseline cannot yet be observed",
    ):
        assert phrase in reset, phrase
    for phrase in (
        "Generate a distinct parser hypothesis", "decoding order", "duplicate precedence",
        "strongest benign explanation", "expected recipient and final account", "falsify",
        "no fixed idea cap", "not proof of a reset takeover",
    ):
        assert phrase in recipient, phrase
    assert "/ghost/ato/" not in ato
    assert "/ghost/password-reset/" not in reset


def assert_advanced_route(reset: str, skill: Path) -> None:
    paragraph = next(
        p for p in reset.split("\n\n")
        if p.startswith("When an observed parser, representation, or stack")
    )
    assert "references/recipient-parsing.md" in paragraph
    assert (skill / "references/recipient-parsing.md").is_file()


def test_auth_recovery_routes_and_mechanism_depth() -> None:
    assert_auth_recovery_routes(
        (ROOT / "skills/ato/SKILL.md").read_text(),
        (SKILL / "SKILL.md").read_text(),
        (SKILL / "references/recipient-parsing.md").read_text(),
    )
    assert_advanced_route((SKILL / "SKILL.md").read_text(), SKILL)


def test_missing_advanced_recipient_route_is_rejected() -> None:
    reset = (SKILL / "SKILL.md").read_text()
    route = "use `references/recipient-parsing.md` to derive distinct stage disagreements"
    assert reset.count(route) == 1
    missing = reset.replace(route, "use `missing-reference.md` to derive distinct stage disagreements")
    assert missing != reset
    with pytest.raises(AssertionError):
        assert_advanced_route(missing, SKILL)
