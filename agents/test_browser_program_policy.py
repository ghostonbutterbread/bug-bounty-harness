"""Program browser admission defaults: isolated SQLite, no live browsers."""
import argparse
import json

import pytest

from agents.test_browser_lease_recovery import provisioner  # establishes local script import path
import browser_profile_lease as profiles


def request(state, program, key, agent):
    return profiles.cmd_acquire(argparse.Namespace(
        program=program, account="anon", auth_domain="local.test", agent_id=agent,
        run_id=agent, purpose="policy fixture", ttl_seconds=60,
        state_dir=str(state), recover_profile=False, instance_key=key,
        manager_id="manager"))


def set_program(state, program="alpha", mode="single", evidence="observed-session-limit"):
    return profiles.cmd_set_program_policy(argparse.Namespace(
        state_dir=str(state), program=program, mode=mode, source="agent", evidence=evidence))


def test_program_isolation_and_policy_precedence(tmp_path):
    state = tmp_path / "state"
    assert request(state, "alpha", "one", "a")["status"] == "leased"
    assert request(state, "beta", "one", "b")["status"] == "leased"
    set_program(state)
    assert request(state, "alpha", "two", "c")["status"] == "locked"
    assert request(state, "beta", "two", "d")["status"] == "leased"
    narrow = argparse.Namespace(state_dir=str(state), program="beta", account="anon",
                                auth_domain="local.test", mode="single")
    assert profiles.cmd_policy(narrow)["status"] == "policy-set"
    set_program(state, "beta", "multiple", "observed-parallel-sessions")
    assert request(state, "beta", "three", "e")["status"] == "locked"
    narrow.mode = "multiple"
    profiles.cmd_policy(narrow)
    assert request(state, "beta", "three", "e")["status"] == "leased"
    # Exact policy multiple cannot relax program single.
    narrow.program = "alpha"
    profiles.cmd_policy(narrow)
    assert request(state, "alpha", "three", "f")["status"] == "locked"


def test_readback_and_active_leases_untouched(tmp_path):
    state = tmp_path / "state"
    before = request(state, "alpha", "one", "a")["lease"]
    other = request(state, "alpha", "two", "b")["lease"]
    assert profiles.cmd_show_program_policy(argparse.Namespace(state_dir=str(state), program="alpha"))["policy"] is None
    receipt = set_program(state)
    assert receipt["effect"] == "future-acquisitions-only" and receipt["automatic_auth_retry"] is False
    shown = profiles.cmd_show_program_policy(argparse.Namespace(state_dir=str(state), program="alpha"))
    assert {k: shown["policy"][k] for k in ("mode", "source", "evidence")} == {
        "mode": "single", "source": "agent", "evidence": "observed-session-limit"}
    with profiles.connect(state / "browser_profile_leases.sqlite") as conn:
        rows = conn.execute("SELECT lease_id, status, profile_dir FROM browser_profile_leases ORDER BY lease_id").fetchall()
    assert {(r["lease_id"], r["status"], r["profile_dir"]) for r in rows} == {
        (lease["lease_id"], "active", lease["profile_dir"]) for lease in (before, other)}
    assert request(state, "alpha", "three", "c")["status"] == "locked"


def test_legacy_unknown_policy_and_passive_logout(tmp_path):
    state = tmp_path / "state"
    assert request(state, "alpha", "one", "a")["status"] == "leased"
    with profiles.connect(state / "browser_profile_leases.sqlite") as conn:
        assert profiles.single_browser_policy(conn, "alpha", "anon", "local.test") is False
    assert request(state, "alpha", "two", "b")["status"] == "leased"
    with profiles.connect(state / "browser_profile_leases.sqlite") as conn:
        profiles.init_resource_policy(conn)
        conn.execute("INSERT INTO browser_program_concurrency_policy VALUES(?,?,?,?,?)",
                     ("alpha", "unknown", "agent", "program-rules", 0))
        assert profiles.single_browser_policy(conn, "alpha", "anon", "local.test") is False
    lease = request(state, "alpha", "three", "c")["lease"]
    result = profiles.cmd_report_logout(argparse.Namespace(state_dir=str(state),
        lease_id=lease["lease_id"], agent_id="c", reason="session-rejected"))
    assert result["policy_changed"] is False and result["automatic_auth_retry"] is False
    assert profiles.cmd_show_program_policy(argparse.Namespace(state_dir=str(state), program="alpha"))["policy"]["mode"] == "unknown"
    assert request(state, "alpha", "four", "d")["status"] == "leased"


def test_cli_set_show_readback(tmp_path, capsys):
    prefix = ["--state-dir", str(tmp_path / "state")]
    assert profiles.main(prefix + ["set-program-browser-policy", "alpha", "--mode", "single",
                                   "--source", "agent", "--evidence", "program-rules"]) == 0
    assert json.loads(capsys.readouterr().out)["mode"] == "single"
    assert profiles.main(prefix + ["show-program-browser-policy", "alpha"]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["policy"]["evidence"] == "program-rules"
    assert profiles.main(prefix + ["show-program-browser-policy", "beta"]) == 0
    assert json.loads(capsys.readouterr().out)["policy"] is None


def test_invalid_metadata_never_persisted_or_echoed(tmp_path, capsys):
    state = tmp_path / "state"
    secret = "secret-cookie-session-value"
    for field in ("source", "evidence"):
        command = ["--state-dir", str(state), "set-program-browser-policy", "alpha",
                   "--mode", "single", "--source", "agent", "--evidence", "program-rules"]
        command[command.index("--" + field) + 1] = secret
        with pytest.raises(SystemExit) as exc:
            profiles.main(command)
        assert exc.value.code == 2
        assert secret not in capsys.readouterr().err
    assert profiles.cmd_show_program_policy(argparse.Namespace(state_dir=str(state), program="alpha"))["policy"] is None
    assert not (state / "browser_profile_leases.sqlite").read_bytes().count(secret.encode())
