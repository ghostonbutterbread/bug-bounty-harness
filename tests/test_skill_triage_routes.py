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
    assert "non-authentic synthetic fixture" in jwt
    assert "do not pass a live cookie value in chat or CLI" in jwt
    assert "{nonsecret-synthetic-fixture-ref}" in registry
    assert "{owned-cookie-fixture}" not in registry
    assert "never supply a cookie value in chat" in registry
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


def test_mandatory_recon_ry_child_route_preserves_exact_host_stop_gate() -> None:
    child = " ".join(text("skills/recon-ry/SKILL.md").split())
    playbook = " ".join(text("prompts/recon-ry-playbook.md").split())
    assert "Read `prompts/recon-ry-playbook.md`" in child
    assert "host-granular scope file does not enforce scheme, port, or path" in child
    assert "one distinct project per eligible host" in child
    assert "A grant limited to one origin or path does not authorize that active profile" in child
    assert "A URL limited to one scheme/port or an allowed path is **not** a host-wide grant" in playbook
    assert "do not run active `exact-urls` stages" in playbook.lower()
    assert "--remote-project /home/ryushe/bounties/<program>/exact/<host-key>" in playbook
    assert "do not launch the next host until the prior PID has completed" in playbook
    assert "not** an aggregate concurrent cap" in playbook
    assert "Run it once per exact scoped host" not in playbook
    assert "launch Recon-Ry once as the durable broad collector" not in child


def test_mixed_scope_full_profile_is_not_implicitly_safe() -> None:
    lines, deferred = recon_scope_file_lines(
        ["*.example.test", "https://limited.other.test:8443/"]
    )
    assert lines == ["*.example.test", "limited.other.test"]
    assert deferred == []  # the restricted origin becomes a host filter
    recon = " ".join(text("skills/recon/SKILL.md").split())
    playbook = " ".join(text("prompts/recon-ry-playbook.md").split())
    entry = " ".join(text("prompts/recon-playbook.md").split())
    child = " ".join(text("skills/recon-ry/SKILL.md").split())
    assert "wildcard hosts **and** a restricted exact origin/path" in recon
    assert "Do not launch `full` on the mixed set" in recon
    assert "This preflight applies to **every** active profile, including `full`" in playbook
    assert "reduce the exact URL to a host" in playbook
    assert "Do not launch that mixed set" in playbook
    assert "mixed-scope preflight before `full`" in child
    assert "wildcard scope alongside an origin/path-limited exact URL" in entry
    assert "Stop the active run" in entry
    assert "verified request-level confinement" in entry
    assert "use `exact-urls` once per eligible host" in entry
    assert "exact-urls` per approved origin" not in entry
