"""Offline contracts for proxy routing and the promoted host diagnostic."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def normalized(path):
    return " ".join(path.read_text().split())


def test_target_traffic_stays_on_proxy():
    text = normalized(ROOT / "skills/agent-proxy/SKILL.md")
    assert "host-direct IP diagnostic" in text
    assert "`proxy-routing-policy`" in text
    assert "does not authorize sending target traffic outside the task proxy" in text
    assert "browser: --proxy-server=http://127.0.0.1:<leased-port>" in text


def test_incident_record_precedes_optional_same_manager_refresh():
    text = normalized(ROOT / "skills/mullvad/SKILL.md")
    incident = text.split("## Suspected IP-related incident", 1)[1].split("## Conditional procedures", 1)[0]
    for requirement in (
        "A CAPTCHA or 403 alone is not an IP-block classification",
        "regardless of whether a host baseline can be captured",
        "non-secret incident context in the run record",
        "`egress_snapshot.py`", "Load General Skills `script-manager`",
        "actual egress host using authorized remote control", "no `--host`",
        'python3 "$HOME/.hermes/synced-skills/script-manager/scripts/egress_snapshot.py"',
        "stable, private, opaque run-owned incident key", "baseline is unknown",
        "Do not substitute another public-IP probe", "Continue other permitted investigation",
        "`already_refreshed`", "same-city West Coast exit of the current manager",
        "not automatic, guaranteed to switch, or a manager change",
        "same UID and shared filesystem view, not other users or VPN tools",
        "uncertain or interrupted switch can leave a persistent latch",
        "do not remove it or retry speculatively",
        "point-in-time post-block host-direct IPv4 observation",
        "cannot establish the blocked IP if a switch preceded capture",
        "accept an arbitrary program-specific IP", "whether a remote proxy path changed",
        "deduplicates only the host-direct path", "not that the target unblocked",
        "`same` or `unknown` is not permission to rotate", "Do not force rotation",
    ):
        assert requirement.lower() in incident.lower(), requirement
    assert incident.index("After preflight") < incident.index("`record KEY`")
    assert incident.index("`record KEY`") < incident.index("may use `refresh KEY` with the same key")
    assert "never rotate to get past a CAPTCHA or active `operator_review`" in incident
    assert "Optionally run `check KEY` first with the same key" in incident


def test_all_changes_require_private_full_path_verification():
    text = normalized(ROOT / "skills/mullvad/SKILL.md")
    verification = text.split("After any change, including incident refresh", 1)[1]
    for requirement in ("manager, relay, intended route, public DNS", "relevant IPv6", "independent remote access where relevant", "required for a remotely managed host", "not for a local host with no relevant remote access", "affected workloads", "rule out the ISP address", "do not place raw addresses or provider output in transcripts or logs", "arrange operator verification", "local route and DNS gate", "stop traffic if verification fails"):
        assert requirement.lower() in verification.lower(), requirement
    playbook = normalized(ROOT / "prompts/mullvad-playbook.md")
    assert "agent/tool transcripts or logs" in playbook
    standalone = playbook.split("## Standalone CLI fallback / rotation", 1)[1].split("## Boot/restart checks", 1)[0]
    assert "public IP is not the normal ISP IP" in standalone
    assert "`mullvad_exit_ip: true`" in standalone
    assert "curl -4fsS --max-time 10 https://ip.me" not in playbook


def test_scoped_retest_cannot_bypass_task_proxy():
    playbook = normalized(ROOT / "prompts/mullvad-playbook.md")
    recovery = playbook.split("## Scoped connectivity recovery", 1)[1]
    for requirement in (
        "existing leased task-MITM listener from `agent-proxy`",
        "curl -I --max-time 15 --proxy http://127.0.0.1:<leased-port> https://<in-scope-host>/",
        "with the task CA", "browser reload through that same task proxy",
        "Never bypass the proxy for target traffic", "host's own DNS path",
        "not the proxy's DNS result", "host-direct IP diagnostic is separate",
        "is not a target request", "incident, manager, scope and safety gates",
    ):
        assert requirement in recovery, requirement
    assert "curl -I --max-time 15 https://<in-scope-host>/" not in recovery


def load_tests(loader, tests, pattern):
    # Preserve the prior unittest discovery/CLI entry point as well as pytest.
    return unittest.TestSuite(unittest.FunctionTestCase(fn) for name, fn in sorted(globals().items()) if name.startswith("test_") and callable(fn))


if __name__ == "__main__":
    unittest.main()
