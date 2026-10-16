"""Focused regression checks for the canonical BBH skill triage."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.scope_seed_files import recon_scope_file_lines

SKILLS = ROOT / "skills"


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_new_skills_have_discoverable_routes_and_no_local_runtime_path() -> None:
    registry = text("SKILL_REGISTRY.md")
    jwt = text("skills/jwt-auth/SKILL.md")
    requests = text("skills/request-exploration/SKILL.md")
    for name in ("cookie-session-analysis", "form-submission-testing"):
        skill = (SKILLS / name / "SKILL.md").read_text(encoding="utf-8")
        assert skill.startswith(f"---\nname: {name}\n")
        assert f"| **{name}** |" in registry
        assert "/home/ryushe/.hermes" not in skill
    assert "/cookie-session-analysis" in jwt
    assert "opaque server-side session IDs" in jwt
    assert "/form-submission-testing" in requests
    assert requests.index("/form-submission-testing") < requests.index("Capture the valid baseline request")


def test_cookie_and_form_testing_preserve_safety_contracts() -> None:
    cookie = text("skills/cookie-session-analysis/SKILL.md")
    form = text("skills/form-submission-testing/SKILL.md")
    for phrase in ("`-cookie` passes its value in process arguments", "synthetic", "isolated", "offline"):
        assert phrase in cookie
    assert "`-url` issues a live HTTP request" in cookie  # no live replay from this offline route
    assert "present runnable workflow does not accept live bearer cookies" in cookie
    assert "stop and request a separately reviewed isolated secret-handling adapter" in cookie
    for phrase in ("valid", "baseline", "conditional", "account-testing-policy", "CAPTCHA"):
        assert phrase in form


def test_scope_merge_is_small_and_not_a_duplicate_recon_router() -> None:
    recon = " ".join(text("skills/recon/SKILL.md").split())
    assert "every eligible root host" in recon
    assert "one-host smoke" in recon
    assert "path-scoped repository/package URL" in recon
    assert "does **not** enforce scheme or port" in recon
    assert "do not run" in recon and "active `exact-urls`" in recon
    assert "distinct `--remote-project` for each host" in recon
    assert "previous detached job has completed" in recon
    assert "per project" in recon and "not an aggregate concurrent limiter" in recon
    assert not (SKILLS / "scope-aware-recon").exists()
    assert not (SKILLS / "triager-poc-authoring").exists()
    for obsolete in ("finding-ingestion", "offline-agent-analysis", "severity-recording-contract"):
        assert not (SKILLS / obsolete).exists()


def test_exact_url_scope_file_is_only_a_host_filter() -> None:
    lines, deferred = recon_scope_file_lines(
        ["https://portal.example.test:8443/", "https://docs.example.test/package/x"]
    )
    assert lines == ["portal.example.test"]  # scheme and port cannot survive
    assert deferred == ["https://docs.example.test/package/x"]
    recon = text("skills/recon/SKILL.md")
    assert "post-run artifact filtering cannot undo an out-of-scope request" in recon
    assert "request-level destinations" in recon
