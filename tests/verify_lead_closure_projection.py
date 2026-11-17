"""Verify closure routes against an explicitly selected policy projection.

Usage: python tests/verify_lead_closure_projection.py POLICY_SKILLS_ROOT
The root contains general-security-testing-policy/ and browser-session-policy/.
Negative checks operate only on a temporary copy of the selected policy files.
"""
from pathlib import Path
import shutil
import sys
import tempfile

from test_lead_closure_guidance import ROOT, skill, validate_closure_route


def verify_browser_route(text, policy_root):
    assert "`browser-session-policy`" in text
    assert (policy_root / "browser-session-policy" / "SKILL.md").is_file()


def expect_failure(fn):
    try:
        fn()
    except AssertionError:
        return
    raise AssertionError("missing route or policy target unexpectedly passed")


def main(policy_root):
    entries = {name: skill(name) for name in ("coverage", "leads")}
    for text in entries.values():
        validate_closure_route(text, policy_root)
    verify_browser_route(entries["coverage"], policy_root)

    with tempfile.TemporaryDirectory(prefix="closure-route-") as temporary:
        root = Path(temporary)
        for name in ("general-security-testing-policy", "browser-session-policy"):
            shutil.copytree(policy_root / name, root / name)
        for text in entries.values():
            validate_closure_route(text, root)
            route = "`general-security-testing-policy`"
            assert text.count(route) == 1
            expect_failure(lambda: validate_closure_route(text.replace(route, "removed", 1), root))
        owner = root / "general-security-testing-policy/SKILL.md"
        original_owner = owner.read_bytes()
        owner.unlink()
        for text in entries.values():
            expect_failure(lambda: validate_closure_route(text, root))
        owner.write_bytes(original_owner)
        reference = root / "general-security-testing-policy/references/testing-posture.md"
        reference.unlink()
        for text in entries.values():
            expect_failure(lambda: validate_closure_route(text, root))
        browser = root / "browser-session-policy/SKILL.md"
        browser.unlink()
        expect_failure(lambda: verify_browser_route(entries["coverage"], root))
        browser_route = "`browser-session-policy`"
        assert entries["coverage"].count(browser_route) == 1
        # Restore only the synthetic file so this case fails on the removed route.
        browser.write_text("fixture")
        expect_failure(lambda: verify_browser_route(
            entries["coverage"].replace(browser_route, "removed", 1), root))
    print(f"verified closure and browser routes against {policy_root}; negative cases passed")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    main(Path(sys.argv[1]).resolve(strict=True))
