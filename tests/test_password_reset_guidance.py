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
