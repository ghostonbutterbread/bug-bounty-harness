"""Offline routing and safety checks for the Mullvad entry skill."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/mullvad/SKILL.md"
PLAYBOOK = ROOT / "prompts/mullvad-playbook.md"


def normalized(text):
    return " ".join(text.split())


def section(text, start, end=None):
    result = text.split(start, 1)[1]
    return result.split(end, 1)[0] if end else result


def test_preflight_preserves_manager_and_fresh_setup_is_guarded():
    skill = SKILL.read_text()
    preflight = normalized(section(skill, "## Preflight", "## Suspected IP-related incident"))
    for command in ("`tailscale get exit-node`", "`tailscale status --json`", "`mullvad status -v`"):
        assert command in preflight
    assert "A failed status command does not prove a manager absent" in preflight
    assert "or managers conflict, stop external traffic and ask Ryushe" in preflight
    assert "Never silently use ISP egress" in preflight
    assert "Never clear a selected Tailscale exit" in preflight
    assert "public DNS/egress probe only after local manager status" in preflight
    assert "`egress_inspect.py`" in preflight and "read-only IPv4 local snapshot" in preflight
    fresh = section(preflight, "**Fresh setup exception:**", "For remote changes")
    for gate in ("explicitly directs a fresh setup", "verified absent or disconnected", "no selected, saved or effective exit", "mismatch or inaccessible state", "public probes behind the gate"):
        assert gate in fresh
    assert "independently tested recovery proven to survive the change" in preflight
    assert "pre-switch LAN SSH alone is insufficient" in preflight


def test_conditional_procedures_exist_and_fresh_setup_does_not_probe_first():
    skill = SKILL.read_text()
    playbook = PLAYBOOK.read_text()
    routes = normalized(section(skill, "## Conditional procedures and verification"))
    for heading in ("Choose the path on each host", "Directed fresh setup", "Preflight gate for a remote handoff", "Tailscale rotation", "Standalone CLI fallback / rotation", "Boot/restart checks", "Failure and rollback boundary", "Scoped connectivity recovery"):
        assert heading in routes
        assert any(line.startswith("## " + heading) for line in playbook.splitlines())
    fresh = normalized(section(playbook, "## Directed fresh setup", "## Preflight gate"))
    for gate in ("may only pass after selection", "authenticated and online", "live-listed", "privilege and workload safety", "inspect lockdown", "daemon auto-connect off", "GUI Auto-connect", "post-selection probe gate"):
        assert gate in fresh
    remote = normalized(section(playbook, "## Preflight gate", "## One-time move"))
    assert "only after the skill's local route and DNS probe gate permits them" in remote
    assert "proven to remain usable with the selected exit" in remote
    startup = normalized(section(playbook, "## Boot/restart checks", "## Failure and rollback boundary"))
    assert "daemon and independent GUI Auto-connect are off" in startup
    assert "daemon auto-connect on" in startup
    assert "effective route lookup and an independent check of the LAN access path in use" in startup
    assert "test LAN SSH independently when it is used" in startup
    assert "If LAN access is used, also verify its effective return route" in startup
    assert "when LAN access is used, verify its effective return route" in normalized(skill)
    assert "bbh --print-command prompts/mullvad-playbook.md" in routes
    assert "bbh --root" in routes and "lanes differ" in routes
    assert "../../prompts/" not in skill


def test_direct_registry_entry_routes_to_incident_owner():
    registry = normalized((ROOT / "SKILL_REGISTRY.md").read_text())
    assert "| **mullvad** | `/mullvad` | `prompts/mullvad-playbook.md` |" in registry
    entry = normalized(section(PLAYBOOK.read_text(), "## Entry and incident route", "## How the traffic flows"))
    for requirement in ("load the `mullvad` skill", "Suspected IP-related incident", "record the incident", "preflight permits the host-direct probe", "`record KEY`", "`check KEY` or `refresh KEY` is optional", "Do not bypass an unavailable baseline with manual rotation", "reading them does not require restarting the incident workflow"):
        assert requirement in entry, requirement


def test_remote_standalone_absent_tailscale_keeps_recovery_gates():
    playbook = PLAYBOOK.read_text()
    choose = normalized(section(playbook, "## Choose the path", "## Directed fresh setup"))
    fresh = normalized(section(playbook, "## Directed fresh setup", "## Preflight gate"))
    remote = normalized(section(playbook, "## Preflight gate", "## One-time move"))
    standalone = normalized(section(playbook, "## Standalone CLI fallback / rotation", "## Boot/restart checks"))
    for requirement in ("If Tailscale is installed", "Skip a manager's checks only if verified absent", "unknown presence or inaccessible state requires operator recovery"):
        assert requirement in choose, requirement
    for requirement in ("directed fresh standalone setup", "Tailscale is verified absent", "remote handoff gate", "do not perform Tailscale-only setup or privilege checks"):
        assert requirement in fresh, requirement
    for requirement in ("if Tailscale is installed compare", "Skip those checks only if Tailscale is verified absent", "presence or state is uncertain or inaccessible, stop for operator recovery", "When a Tailscale operation is planned", "a privilege error is a stop", "safe workload change window", "rehearsed rollback", "With only pre-switch LAN SSH and no independent recovery, stop", "or standalone tunnel as applicable", "health of each affected browser, agent, proxy, container and service", "local route and DNS probe gate"):
        assert requirement in remote, requirement
    assert "When Tailscale is absent and no selection could have been stored, skip this step" in standalone
    assert "installed but its CLI/daemon is inaccessible" in standalone


def test_remote_access_is_required_only_when_relevant():
    skill = normalized(SKILL.read_text())
    verify = section(skill, "After any change, including incident refresh")
    for requirement in ("independent remote access where relevant", "required for a remotely managed host", "not for a local host with no relevant remote access"):
        assert requirement in verify, requirement
    rotation = normalized(section(PLAYBOOK.read_text(), "## Tailscale rotation", "## Standalone CLI fallback"))
    assert "required for a remotely managed host, not a local host with no relevant remote access" in rotation


def test_remote_standalone_console_without_lan_preserves_independent_recovery():
    remote = normalized(section(PLAYBOOK.read_text(), "## Preflight gate", "## One-time move"))
    for requirement in (
        "tested out-of-band console or an independently verified control/rollback path",
        "or standalone tunnel as applicable",
        "rehearsed rollback that does not depend on the route being changed",
        "A standalone remote host using an independent console does not require LAN or SSH",
        "When SSH is an access path in use, test another client's SSH to the host",
        "When LAN access is in use, independently test LAN control after selection",
        "`ip -4 route get <LAN-peer-IP>` selects the LAN interface",
    ):
        assert requirement in remote, requirement


def test_local_tailnet_without_lan_or_magicdns_and_applicable_tailscale_lan():
    rotation = normalized(section(PLAYBOOK.read_text(), "## Tailscale rotation", "## Standalone CLI fallback"))
    for requirement in (
        "required for a remotely managed host, not a local host with no relevant remote access",
        "When LAN access is in use, check `ip -4 route get <LAN-peer-IP>` and require the LAN interface",
        "test tailnet peer access when used and tailnet/MagicDNS resolution when used",
        "A local host using neither LAN access nor MagicDNS does not need those tests",
        "Verify public DNS separately",
        "a successful direct-IP HTTPS call does **not** clear the DNS failure",
    ):
        assert requirement in rotation, requirement


def test_projected_skill_and_launcher_resolve_the_same_lane():
    with tempfile.TemporaryDirectory() as directory:
        check_projected_skill_and_launcher_resolve_the_same_lane(Path(directory))


def check_projected_skill_and_launcher_resolve_the_same_lane(tmp_path):
    for lane in ("stable", "beta"):
        root = tmp_path / lane
        (root / "scripts").mkdir(parents=True)
        (root / "prompts").mkdir()
        (root / "skills/mullvad").mkdir(parents=True)
        shutil.copyfile(ROOT / "scripts/bbh.py", root / "scripts/bbh.py")
        (root / "prompts/mullvad-playbook.md").write_text(lane)
        shutil.copyfile(SKILL, root / "skills/mullvad/SKILL.md")
    projected = tmp_path / "projected/mullvad"
    projected.parent.mkdir()
    projected.symlink_to(tmp_path / "stable/skills/mullvad", target_is_directory=True)
    source_root = (projected / "SKILL.md").resolve().parents[2]
    for lane in ("stable", "beta"):
        result = subprocess.run([sys.executable, str(tmp_path / lane / "scripts/bbh.py"), "--print-command", "prompts/mullvad-playbook.md"], text=True, capture_output=True, check=True)
        path = Path(result.stdout.strip())
        assert path.read_text() == lane
        assert (path.parents[1] == source_root) == (lane == "stable")
    (tmp_path / "stable/prompts/mullvad-playbook.md").unlink()
    missing = subprocess.run([sys.executable, str(tmp_path / "stable/scripts/bbh.py"), "--print-command", "prompts/mullvad-playbook.md"], text=True, capture_output=True)
    assert missing.returncode != 0 and "missing from this checkout" in missing.stderr


def load_tests(loader, tests, pattern):
    # Preserve the prior unittest discovery/CLI entry point as well as pytest.
    return unittest.TestSuite(unittest.FunctionTestCase(fn) for name, fn in sorted(globals().items()) if name.startswith("test_") and callable(fn))


if __name__ == "__main__":
    unittest.main()
