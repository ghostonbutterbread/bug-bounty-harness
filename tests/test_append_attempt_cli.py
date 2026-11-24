"""Offline tests for the shell Attempts writer (`bbh scripts/append_attempt.py`)."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import bounty_core
import pytest

from agents.attempts import REQUIRED_ATTEMPT_FIELDS
from agents.storage_resolver import resolve_storage

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "append_attempt.py"
ATTEMPT = {
    "tool": "xss-probe",
    "target": "https://app.example/search?q=REDACTED",
    "outcome": "inert",
    "stop_reason": "marker HTML-encoded",
    "vuln_class": "xss",
    "payload_family": "html-break",
}


def _shared(tmp_path: Path, program: str = "example", lane: str = "web") -> Path:
    shared = tmp_path / "shared"
    resolve_storage(program, lane=lane, root_override=shared, create=True)
    return shared


def _run(args: list[str], tmp_path: Path, *, stdin: str | None = None, env: dict | None = None,
         command: list[str] | None = None) -> subprocess.CompletedProcess:
    environment = {**os.environ, "HOME": str(tmp_path / "home"), "PYTHONDONTWRITEBYTECODE": "1"}
    environment.update(env or {})
    return subprocess.run(
        [*(command or [sys.executable, str(SCRIPT)]), *args],
        input=stdin if stdin is not None else "",
        capture_output=True, text=True, check=False, env=environment, cwd=tmp_path,
    )


def _resolver_args(shared: Path, run_id: str = "xss-search-20261124") -> list[str]:
    return ["--program", "example", "--lane", "web", "--run-id", run_id, "--root", str(shared)]


def test_records_attempt_into_resolved_run_stream(tmp_path: Path) -> None:
    shared = _shared(tmp_path)
    result = _run(
        [*_resolver_args(shared), "--timestamp-now", "--agent-id", "hunter", "--model-id", "model-x"],
        tmp_path, stdin=json.dumps(ATTEMPT),
    )

    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    expected = shared / "web_bounty/example/web/attempts/_runs/xss-search-20261124/attempts.jsonl"
    assert receipt["path"] == str(expected)
    assert receipt["run_id"] == "xss-search-20261124"
    assert receipt["attempt_id"].startswith("A-")
    rows = [json.loads(line) for line in expected.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1
    row = rows[0]
    assert all(str(row[field]).strip() for field in REQUIRED_ATTEMPT_FIELDS)
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", row["timestamp"])
    assert (row["attempt_id"], row["run_id"], row["vuln_class"]) == (receipt["attempt_id"], "xss-search-20261124", "xss")
    assert row["producer"] == "xss-probe" and row["ai_reviewed_by"]


def test_json_option_with_explicit_timestamp_and_secret_redaction(tmp_path: Path) -> None:
    shared = _shared(tmp_path)
    attempt = {
        **ATTEMPT,
        "timestamp": "2026-11-24T00:00:00Z",
        "target": "https://app.example/search?q=needle&nonce=secret-nonce",
        "request_headers": {"Cookie": "session=secret-cookie"},
        "body_snippet": "password=hunter2; token: bearer-token",
    }
    result = _run([*_resolver_args(shared), "--json", json.dumps(attempt)], tmp_path)

    assert result.returncode == 0, result.stderr
    stored = Path(json.loads(result.stdout)["path"]).read_text(encoding="utf-8")
    assert json.loads(stored)["timestamp"] == "2026-11-24T00:00:00Z"
    for secret in ("secret-nonce", "secret-cookie", "hunter2", "bearer-token"):
        assert secret not in stored
        assert secret not in result.stdout + result.stderr


def test_missing_required_fields_are_rejected_without_writing(tmp_path: Path) -> None:
    shared = _shared(tmp_path)
    incomplete = {key: value for key, value in ATTEMPT.items() if key != "stop_reason"}
    result = _run(_resolver_args(shared), tmp_path, stdin=json.dumps(incomplete))

    assert result.returncode == 2
    assert "attempt missing required fields: timestamp, stop_reason" in result.stderr
    assert "--timestamp-now" in result.stderr
    assert "Traceback" not in result.stderr
    assert not (shared / "web_bounty/example/web/attempts").exists()


@pytest.mark.parametrize(
    ("args", "stdin", "message"),
    [
        (["--timestamp-now"], json.dumps({**ATTEMPT, "timestamp": "2026-11-24T00:00:00Z"}), "conflicts"),
        ([], "{not json", "not valid JSON"),
        ([], json.dumps([ATTEMPT]), "one JSON object"),
    ],
)
def test_malformed_input_is_rejected_without_writing(tmp_path: Path, args, stdin, message) -> None:
    shared = _shared(tmp_path)
    result = _run([*_resolver_args(shared), *args], tmp_path, stdin=stdin)

    assert result.returncode == 2
    assert message in result.stderr
    assert not (shared / "web_bounty/example/web/attempts").exists()


def test_uninitialized_program_lane_is_refused_without_creating_it(tmp_path: Path) -> None:
    shared = _shared(tmp_path)
    args = ["--program", "exmaple", "--lane", "web", "--run-id", "run-1", "--root", str(shared), "--timestamp-now"]
    result = _run(args, tmp_path, stdin=json.dumps(ATTEMPT))

    assert result.returncode == 2
    assert "program lane not found" in result.stderr
    assert "bbh scripts/program_init.py exmaple --lane web" in result.stderr
    assert not (shared / "web_bounty" / "exmaple").exists()


def test_exact_path_mode_and_destination_option_errors(tmp_path: Path) -> None:
    stream = tmp_path / "lane/attempts/_runs/packet-run/attempts.jsonl"
    result = _run(["--path", str(stream), "--timestamp-now"], tmp_path, stdin=json.dumps(ATTEMPT))
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["run_id"] == "packet-run"
    assert json.loads(stream.read_text(encoding="utf-8"))["run_id"] == "packet-run"

    conflict = _run(["--path", str(stream), "--program", "example", "--timestamp-now"], tmp_path,
                    stdin=json.dumps(ATTEMPT))
    assert conflict.returncode == 2 and "--path cannot be combined with --program" in conflict.stderr

    missing = _run(["--program", "example", "--lane", "web", "--timestamp-now"], tmp_path, stdin=json.dumps(ATTEMPT))
    assert missing.returncode == 2 and "missing --run-id" in missing.stderr
    assert len(stream.read_text(encoding="utf-8").splitlines()) == 1


def _tree(root: Path) -> list[str]:
    return sorted(str(path.relative_to(root)) for path in root.rglob("*")) if root.exists() else []


def test_json_run_id_must_match_destination_run(tmp_path: Path) -> None:
    shared = _shared(tmp_path)
    runs = shared / "web_bounty/example/web/attempts/_runs"
    conflict = _run([*_resolver_args(shared, "run-a"), "--timestamp-now"], tmp_path,
                    stdin=json.dumps({**ATTEMPT, "run_id": "run-b"}))
    assert conflict.returncode == 2
    assert "does not match the destination run 'run-a'" in conflict.stderr
    assert not runs.exists()

    stream = tmp_path / "lane/attempts/_runs/packet-run/attempts.jsonl"
    path_conflict = _run(["--path", str(stream), "--timestamp-now"], tmp_path,
                         stdin=json.dumps({**ATTEMPT, "run_id": "other"}))
    assert path_conflict.returncode == 2 and "does not match" in path_conflict.stderr
    assert not stream.exists()

    for run_id in ("run-a", None, ""):
        ok = _run([*_resolver_args(shared, "run-a"), "--timestamp-now"], tmp_path,
                  stdin=json.dumps({**ATTEMPT, "run_id": run_id}))
        assert ok.returncode == 0, ok.stderr
    rows = [json.loads(line) for line in (runs / "run-a/attempts.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [row["run_id"] for row in rows] == ["run-a"] * 3
    assert [path.name for path in runs.iterdir()] == ["run-a"]


@pytest.mark.parametrize("flag", ["--program", "--lane"])
@pytest.mark.parametrize("value", [".", "..", " .. ", "", "a/b", "..\\x"])
def test_path_like_program_or_lane_is_rejected_before_storage_access(tmp_path: Path, flag, value) -> None:
    shared = _shared(tmp_path)
    before = _tree(shared)
    values = {"--program": "example", "--lane": "web", flag: value}
    for root_args in (["--root", str(shared)], []):  # explicit root and the HOME default
        args = ["--program", values["--program"], "--lane", values["--lane"], "--run-id", "run-1", *root_args]
        result = _run([*args, "--timestamp-now"], tmp_path, stdin=json.dumps(ATTEMPT))
        assert result.returncode == 2
        assert f"{flag} must be a plain name" in result.stderr
    assert _tree(shared) == before
    assert not (tmp_path / "home").exists()


def test_closed_or_empty_stdin_reports_missing_input(tmp_path: Path) -> None:
    shared = _shared(tmp_path)
    closed = _run([*_resolver_args(shared), "--timestamp-now"], tmp_path,
                  command=["sh", "-c", 'exec "$@" <&-', "sh", sys.executable, str(SCRIPT)])
    empty = _run([*_resolver_args(shared), "--timestamp-now"], tmp_path, stdin="  \n")
    blank_json = _run([*_resolver_args(shared), "--timestamp-now", "--json", " "], tmp_path)
    for result in (closed, empty, blank_json):
        assert result.returncode == 2
        assert "no attempt JSON; pass --json or a quoted heredoc" in result.stderr
        assert "Traceback" not in result.stderr and "JSON" not in result.stdout
    assert not (shared / "web_bounty/example/web/attempts").exists()


def test_null_timestamp_is_absent_and_null_or_nonstring_required_fields_are_rejected(tmp_path: Path) -> None:
    shared = _shared(tmp_path)
    ok = _run([*_resolver_args(shared), "--timestamp-now"], tmp_path, stdin=json.dumps({**ATTEMPT, "timestamp": None}))
    assert ok.returncode == 0, ok.stderr
    assert json.loads(Path(json.loads(ok.stdout)["path"]).read_text(encoding="utf-8"))["timestamp"]

    bad = {**ATTEMPT, "tool": None, "target": 5, "outcome": [], "stop_reason": {}}
    result = _run([*_resolver_args(shared, "run-bad"), "--timestamp-now"], tmp_path, stdin=json.dumps(bad))
    assert result.returncode == 2
    assert "attempt missing required fields: tool, target, outcome, stop_reason" in result.stderr
    assert "required nonempty string fields" in result.stderr
    assert not (shared / "web_bounty/example/web/attempts/_runs/run-bad").exists()


def test_receipt_path_is_absolute_and_normalized(tmp_path: Path) -> None:
    result = _run(["--path", "x/../rel/attempts/_runs/run-a/attempts.jsonl", "--timestamp-now"], tmp_path,
                  stdin=json.dumps(ATTEMPT))
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["path"] == str(tmp_path / "rel/attempts/_runs/run-a/attempts.jsonl")
    assert receipt["run_id"] == "run-a" and Path(receipt["path"]).is_file()


@pytest.mark.parametrize("run_id", ["token=hunter2", "Bearer hunter2", ".hunter2", "user:hunter2@x"])
def test_secret_looking_run_ids_are_rejected_unechoed(tmp_path: Path, run_id: str) -> None:
    shared = _shared(tmp_path)
    by_flag = _run([*_resolver_args(shared, run_id), "--timestamp-now"], tmp_path, stdin=json.dumps(ATTEMPT))
    by_path = _run(["--path", str(tmp_path / f"lane/attempts/_runs/{run_id}/attempts.jsonl"), "--timestamp-now"],
                   tmp_path, stdin=json.dumps(ATTEMPT))
    for result in (by_flag, by_path):
        assert result.returncode == 2
        assert "never put secrets in a run ID" in result.stderr
        assert "hunter2" not in result.stdout + result.stderr
    assert not (shared / "web_bounty/example/web/attempts").exists()
    assert not (tmp_path / "lane").exists()


def test_recording_does_not_rescaffold_lane_or_rewrite_target_profile(tmp_path: Path) -> None:
    shared = _shared(tmp_path)
    lane = shared / "web_bounty/example/web"
    profile = lane / "context/target_profile.json"
    profile.write_text('{"sentinel": "operator-owned"}\n', encoding="utf-8")
    shutil.rmtree(lane / "reports")
    before = _tree(lane)

    result = _run([*_resolver_args(shared, "run-a"), "--timestamp-now"], tmp_path, stdin=json.dumps(ATTEMPT))

    assert result.returncode == 0, result.stderr
    assert profile.read_text(encoding="utf-8") == '{"sentinel": "operator-owned"}\n'
    added = sorted(set(_tree(lane)) - set(before))
    assert added == ["attempts", "attempts/_runs", "attempts/_runs/run-a", "attempts/_runs/run-a/attempts.jsonl"]


def test_missing_custom_lane_does_not_suggest_program_init(tmp_path: Path) -> None:
    shared = _shared(tmp_path)
    result = _run(["--program", "example", "--lane", "xss", "--family", "web_bounty", "--run-id", "run-1",
                   "--root", str(shared), "--timestamp-now"], tmp_path, stdin=json.dumps(ATTEMPT))
    assert result.returncode == 2
    assert "program lane not found" in result.stderr and "custom lanes are created by the tool" in result.stderr
    assert "program_init" not in result.stderr
    assert not (shared / "web_bounty/example/xss").exists()


def _fake_runtime_checkout(tmp_path: Path) -> Path:
    """A selected checkout whose runtime interpreter sees only its own Core."""
    checkout = tmp_path / "runtime-beta"
    (checkout / "scripts").mkdir(parents=True)
    for name in ("bbh", "bbh.py", "append_attempt.py"):
        shutil.copy2(ROOT / "scripts" / name, checkout / "scripts" / name)
    (checkout / "agents").symlink_to(ROOT / "agents", target_is_directory=True)
    python = checkout / ".venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    core_parent = Path(bounty_core.__file__).resolve().parents[1]
    python.write_text(
        f'#!/bin/sh\nPYTHONPATH="$PYTHONPATH:{core_parent}" exec "{sys.executable}" "$@"\n', encoding="utf-8"
    )
    python.chmod(0o755)
    return checkout


def _stale_core(tmp_path: Path, *, importable_package: bool = True) -> Path:
    """A bounty-core clone that predates provenance.py, as found on Hoster."""
    stale = tmp_path / ("stale-bounty-core" if importable_package else "broken-bounty-core")
    shutil.copytree(
        Path(bounty_core.__file__).resolve().parent, stale / "bounty_core",
        ignore=shutil.ignore_patterns("provenance.py", "__pycache__"),
    )
    if importable_package:
        # An older package __init__ does not reference provenance; only the writer's import fails.
        (stale / "bounty_core" / "__init__.py").write_text('"""Stale Bounty Core."""\n', encoding="utf-8")
    return stale


def test_bbh_dispatch_records_attempt_despite_stale_pythonpath(tmp_path: Path) -> None:
    shared = _shared(tmp_path)
    checkout = _fake_runtime_checkout(tmp_path)
    stale = _stale_core(tmp_path)
    launcher = tmp_path / "bin" / "bbh"
    launcher.parent.mkdir()
    launcher.symlink_to(checkout / "scripts" / "bbh")
    env = {"PYTHONPATH": str(stale), "HARNESS_ROOT": "/definitely/not/the-selected-checkout"}

    # Papercut reproduction: the improvised interpreter/PYTHONPATH fails, actionably.
    direct = _run([*_resolver_args(shared), "--timestamp-now"], tmp_path, stdin=json.dumps(ATTEMPT), env=env,
                  command=[sys.executable, str(checkout / "scripts" / "append_attempt.py")])
    assert direct.returncode != 0
    assert "bounty_core.provenance" in direct.stderr
    assert str(stale / "bounty_core") in direct.stderr
    assert "bbh scripts/append_attempt.py" in direct.stderr and "--install-python-deps" in direct.stderr
    assert "Traceback" not in direct.stderr

    dispatched = _run([*_resolver_args(shared), "--timestamp-now"], tmp_path, stdin=json.dumps(ATTEMPT), env=env,
                      command=[str(launcher), "scripts/append_attempt.py"])
    assert dispatched.returncode == 0, dispatched.stderr
    stream = Path(json.loads(dispatched.stdout)["path"])
    assert stream.is_relative_to(shared / "web_bounty/example/web/attempts/_runs")
    assert json.loads(stream.read_text(encoding="utf-8"))["outcome"] == "inert"


@pytest.mark.parametrize("importable_package", [True, False])
def test_library_import_failure_names_runtime_and_remedy(tmp_path: Path, importable_package: bool) -> None:
    stale = _stale_core(tmp_path, importable_package=importable_package)
    result = subprocess.run(
        [sys.executable, "-c", "import agents.attempts"],
        capture_output=True, text=True, check=False, cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": f"{stale}{os.pathsep}{ROOT}", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert result.returncode != 0
    # Type and module name are preserved for callers that catch ImportError subclasses.
    assert "ModuleNotFoundError: agents.attempts cannot load" in result.stderr
    assert "bounty_core.provenance" in result.stderr
    assert sys.executable in result.stderr
    assert str(stale / "bounty_core" / "__init__.py") in result.stderr
    assert "bbh scripts/append_attempt.py" in result.stderr and "--install-python-deps" in result.stderr


def test_documented_commands_use_only_supported_options() -> None:
    spec = importlib.util.spec_from_file_location("append_attempt_cli", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    supported = {option for action in module.build_parser()._actions for option in action.option_strings}
    commands = [
        line
        for doc in ("docs/attempt-recording-contract.md", "docs/bbh-launcher.md", "scripts/README.md")
        for line in (ROOT / doc).read_text(encoding="utf-8").splitlines()
        if "bbh scripts/append_attempt.py --" in line
    ]
    assert len(commands) >= 3
    for line in commands:
        used = set(re.findall(r"(?<![\w-])--[a-z][a-z-]*", line.split("append_attempt.py", 1)[1]))
        assert used and used <= supported, (line, used - supported)
