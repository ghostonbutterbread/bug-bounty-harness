from __future__ import annotations

import base64
import json
import multiprocessing
import threading
from pathlib import Path
from typing import Any

import pytest

from agents.dynamic_validation import cli
from agents.dynamic_validation.models import (
    EvidenceRecord,
    ValidationAction,
    ValidationTask,
    ValidationVerdict,
)
from agents.dynamic_validation.policy import PolicyGate
from agents.dynamic_validation.queue import ScopedTaskQueue
from agents.dynamic_validation.report_ingest import (
    ingest_execute_action_task,
    ingest_lifecycle_tasks,
    ingest_report_task,
    ingest_scout_task,
)
from agents.dynamic_validation.report_layout import (
    assert_no_legacy_status_first_dirs,
    legacy_status_first_dirs,
)
from agents.dynamic_validation.reporting import (
    live_validation_lock_root,
    write_live_validation_artifacts,
)
from agents.dynamic_validation.transports.cdp import CDPTransportError, ElectronCDPTransport
from agents.storage_resolver import resolve_storage


def _file_lock_worker(lock_root: str, release_event, started_event, events) -> None:
    queue = ScopedTaskQueue()
    task = ValidationTask(
        run_id="run",
        program="canva",
        family="binaries",
        lane="exe",
        target="canva",
        account="acct",
        vm="vm1",
    )
    with queue.acquire(task, lock_root=Path(lock_root)):
        events.put("start")
        started_event.set()
        release_event.wait(timeout=2.0)
        events.put("end")


def _storage(tmp_path: Path):
    return resolve_storage(
        "canva",
        family="binaries",
        lane="exe",
        root_override=tmp_path,
        create=True,
    )


def _finding(fid: str = "D01", **overrides: Any) -> dict[str, object]:
    finding: dict[str, object] = {
        "fid": fid,
        "title": "Renderer bridge probe",
        "type": "Renderer bridge probe",
        "status": "dormant",
        "review_tier": "DORMANT_ACTIVE",
        "severity": "HIGH",
        "report_path": "",
    }
    finding.update(overrides)
    return finding


def _write_ledger(storage, finding: dict[str, object]) -> None:
    storage.ledgers_root.mkdir(parents=True, exist_ok=True)
    (storage.ledgers_root / "ledger.json").write_text(
        json.dumps({"version": 2, "findings": [finding]}, indent=2) + "\n",
        encoding="utf-8",
    )


def test_policy_allows_read_only_and_sandbox_local_user_actions_and_denies_vendor_impact() -> None:
    gate = PolicyGate()

    read_only = gate.evaluate(ValidationAction(kind="cdp_version", description="read version"))
    local_file = gate.evaluate(
        ValidationAction(kind="open_controlled_local_file", description="open a local fixture")
    )
    private_doc = gate.evaluate(
        ValidationAction(kind="private_document_create", description="create a private test document")
    )
    live_ipc = gate.evaluate(
        ValidationAction(kind="live_ipc_interaction", description="call a bounded local IPC method")
    )
    denied = gate.evaluate(
        ValidationAction(
            kind="publish_content",
            description="publish a design",
            vendor_impact=True,
        )
    )

    assert read_only.decision == "allow"
    assert local_file.decision == "allow"
    assert private_doc.decision == "allow"
    assert live_ipc.decision == "allow"
    assert denied.decision == "deny"


def test_policy_allows_private_workflow_ai_templates_and_store_apps_by_default() -> None:
    gate = PolicyGate()

    workflow_action = ValidationAction(
        kind="private_workflow_create",
        description="create one private workflow",
    )
    chat_action = ValidationAction(
        kind="canva_ai_private_chat",
        description="open one private Canva AI chat",
    )
    template_action = ValidationAction(
        kind="use_template",
        description="use a template in a private test document",
    )
    app_action = ValidationAction(
        kind="install_store_app",
        description="install a free Canva app in the test account",
    )

    assert gate.evaluate(workflow_action).decision == "allow"
    assert gate.evaluate(chat_action).decision == "allow"
    assert gate.evaluate(template_action).decision == "allow"
    assert gate.evaluate(app_action).decision == "allow"


def test_policy_still_denies_public_support_billing_and_bulk_actions() -> None:
    gate = PolicyGate()
    denied_kinds = [
        "public_share",
        "contact_support",
        "send_support_request",
        "send_message",
        "send_invite",
        "modify_billing",
        "delete_account",
        "bulk_create_assets",
        "generate_large_traffic",
    ]

    for kind in denied_kinds:
        assert gate.evaluate(ValidationAction(kind=kind, description=kind)).decision == "deny"


def test_queue_serializes_same_scope() -> None:
    queue = ScopedTaskQueue()
    task_one = ValidationTask(
        run_id="run-1",
        program="canva",
        family="binaries",
        lane="exe",
        target="canva",
        account="acct",
        vm="vm1",
    )
    task_two = ValidationTask(
        run_id="run-2",
        program="canva",
        family="binaries",
        lane="exe",
        target="canva",
        account="acct",
        vm="vm1",
    )
    order: list[str] = []
    release_first = threading.Event()
    second_finished = threading.Event()

    def worker(task: ValidationTask) -> None:
        with queue.acquire(task):
            order.append(f"start:{task.run_id}")
            if task.run_id == "run-1":
                release_first.wait(timeout=1.0)
            order.append(f"end:{task.run_id}")
        if task.run_id == "run-2":
            second_finished.set()

    first = threading.Thread(target=worker, args=(task_one,))
    second = threading.Thread(target=worker, args=(task_two,))
    first.start()
    second.start()
    second_finished.wait(timeout=0.05)
    assert order == ["start:run-1"]
    release_first.set()
    first.join()
    second.join()

    assert order == ["start:run-1", "end:run-1", "start:run-2", "end:run-2"]


def test_queue_file_lock_serializes_same_scope_across_processes(tmp_path: Path) -> None:
    ctx = multiprocessing.get_context("fork")
    lock_root = tmp_path / "locks"
    release_first = ctx.Event()
    release_second = ctx.Event()
    first_started = ctx.Event()
    second_started = ctx.Event()
    events = ctx.Queue()

    first = ctx.Process(
        target=_file_lock_worker,
        args=(str(lock_root), release_first, first_started, events),
    )
    second = ctx.Process(
        target=_file_lock_worker,
        args=(str(lock_root), release_second, second_started, events),
    )

    first.start()
    assert first_started.wait(timeout=1.0)
    second.start()

    assert not second_started.wait(timeout=0.1)
    assert events.get(timeout=1.0) == "start"

    release_first.set()
    assert second_started.wait(timeout=1.0)
    assert events.get(timeout=1.0) == "end"
    assert events.get(timeout=1.0) == "start"
    release_second.set()
    assert events.get(timeout=1.0) == "end"

    first.join(timeout=1.0)
    second.join(timeout=1.0)

    assert first.exitcode == 0
    assert second.exitcode == 0


def test_cdp_transport_parses_version_and_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    payloads = {
        "http://127.0.0.1:9222/json/version": {"Browser": "Chrome/146.0.0", "Protocol-Version": "1.3"},
        "http://127.0.0.1:9222/json/list": [
            {
                "id": "page-1",
                "type": "page",
                "title": "Canva",
                "url": "https://www.canva.com/",
                "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/page-1",
            }
        ],
    }

    class FakeResponse:
        def __init__(self, url: str) -> None:
            self.url = url

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return json.dumps(payloads[self.url]).encode("utf-8")

    monkeypatch.setattr(
        "agents.dynamic_validation.transports.cdp.request.urlopen",
        lambda url, timeout=0: FakeResponse(url),
    )

    transport = ElectronCDPTransport("http://127.0.0.1:9222")

    assert transport.json_version()["Browser"] == "Chrome/146.0.0"
    assert transport.target_snapshots()[0]["title"] == "Canva"
    assert transport.build_read_only_evaluate("window.location.href")["method"] == "Runtime.evaluate"
    assert transport.build_screenshot_command()["method"] == "Page.captureScreenshot"


def test_cdp_transport_runtime_evaluate_over_websocket(monkeypatch: pytest.MonkeyPatch) -> None:
    messages: list[str] = []
    state = {"closed": False, "timeout": None, "suppress_origin": None}

    class FakeConnection:
        def settimeout(self, timeout: float) -> None:
            state["timeout"] = timeout

        def send(self, message: str) -> None:
            messages.append(message)

        def recv(self) -> str:
            if len(messages) == 1:
                payload = json.loads(messages[0])
                if not state.get("event_sent"):
                    state["event_sent"] = True
                    return json.dumps({"method": "Runtime.executionContextCreated", "params": {}})
                return json.dumps(
                    {
                        "id": payload["id"],
                        "result": {
                            "result": {
                                "type": "object",
                                "value": {"href": "https://www.canva.com/", "title": "Canva"},
                            }
                        },
                    }
                )
            raise AssertionError("recv called before send")

        def close(self) -> None:
            state["closed"] = True

    def fake_create_connection(url: str, timeout: float = 0, **kwargs: Any) -> FakeConnection:
        _ = url
        _ = timeout
        state["suppress_origin"] = kwargs.get("suppress_origin")
        return FakeConnection()

    monkeypatch.setattr(
        "agents.dynamic_validation.transports.cdp.websocket.create_connection",
        fake_create_connection,
    )

    transport = ElectronCDPTransport("http://127.0.0.1:9222", timeout=3.0)
    response = transport.runtime_evaluate(
        "ws://127.0.0.1:9222/devtools/page/page-1",
        "window.location.href",
    )

    sent_payload = json.loads(messages[0])
    assert sent_payload["method"] == "Runtime.evaluate"
    assert sent_payload["params"]["returnByValue"] is True
    assert response["result"]["result"]["value"]["href"] == "https://www.canva.com/"
    assert state["timeout"] == 3.0
    assert state["suppress_origin"] is True
    assert state["closed"] is True


def test_cdp_transport_capture_screenshot_over_websocket(monkeypatch: pytest.MonkeyPatch) -> None:
    messages: list[str] = []

    class FakeConnection:
        def send(self, message: str) -> None:
            messages.append(message)

        def recv(self) -> str:
            payload = json.loads(messages[0])
            return json.dumps(
                {
                    "id": payload["id"],
                    "result": {
                        "data": "c2NyZWVuc2hvdA==",
                    },
                }
            )

        def close(self) -> None:
            return None

    monkeypatch.setattr(
        "agents.dynamic_validation.transports.cdp.websocket.create_connection",
        lambda url, timeout=0, **kwargs: FakeConnection(),
    )

    transport = ElectronCDPTransport("http://127.0.0.1:9222")
    response = transport.capture_screenshot("ws://127.0.0.1:9222/devtools/page/page-1")

    sent_payload = json.loads(messages[0])
    assert sent_payload["method"] == "Page.captureScreenshot"
    assert response["result"]["data"] == "c2NyZWVuc2hvdA=="


def test_cdp_transport_rejects_non_list_json(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return b"{\"oops\": true}"

    monkeypatch.setattr(
        "agents.dynamic_validation.transports.cdp.request.urlopen",
        lambda url, timeout=0: FakeResponse(),
    )
    transport = ElectronCDPTransport("http://127.0.0.1:9222")

    with pytest.raises(CDPTransportError):
        transport.json_list()


def test_cdp_transport_wraps_read_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def raising_urlopen(url, timeout=0):
        raise OSError("connection refused")

    monkeypatch.setattr(
        "agents.dynamic_validation.transports.cdp.request.urlopen",
        raising_urlopen,
    )
    transport = ElectronCDPTransport("http://127.0.0.1:9222")

    with pytest.raises(CDPTransportError, match="failed to read"):
        transport.json_version()


def test_report_ingest_from_fid_and_canonical_report_path(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    report_path = storage.reports_root / "findings" / "dormant" / "D01 - HIGH - Renderer bridge probe.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("# Renderer bridge probe\n", encoding="utf-8")
    finding = _finding()
    finding["report_path"] = str(report_path)
    _write_ledger(storage, finding)

    fid_task = ingest_report_task(
        "canva",
        fid="D01",
        family="binaries",
        lane="exe",
        root_override=tmp_path,
    )
    path_task = ingest_report_task(
        "canva",
        report_path=report_path,
        family="binaries",
        lane="exe",
        root_override=tmp_path,
    )
    lifecycle_tasks = ingest_lifecycle_tasks(
        "canva",
        "dormant",
        family="binaries",
        lane="exe",
        root_override=tmp_path,
    )

    assert fid_task.fid == "D01"
    assert fid_task.report_path == report_path
    assert fid_task.review_tier == "DORMANT_ACTIVE"
    assert path_task.fid == "D01"
    assert len(lifecycle_tasks) == 1


def test_report_ingest_rejects_noncanonical_report_paths(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    outside_path = tmp_path / "D01 - HIGH - Renderer bridge probe.md"
    outside_path.write_text("# Outside\n", encoding="utf-8")

    invalid_lifecycle = storage.reports_root / "findings" / "pending-review" / "D01 - HIGH - Renderer bridge probe.md"
    invalid_lifecycle.parent.mkdir(parents=True, exist_ok=True)
    invalid_lifecycle.write_text("# Invalid\n", encoding="utf-8")

    with pytest.raises(ValueError, match="report_path must be under"):
        ingest_report_task(
            "canva",
            report_path=outside_path,
            family="binaries",
            lane="exe",
            root_override=tmp_path,
        )

    with pytest.raises(ValueError, match="unsupported report lifecycle"):
        ingest_report_task(
            "canva",
            report_path=invalid_lifecycle,
            family="binaries",
            lane="exe",
            root_override=tmp_path,
        )


def test_scout_ingest_creates_no_report_task(tmp_path: Path) -> None:
    task = ingest_scout_task(
        "canva",
        family="binaries",
        lane="exe",
        root_override=tmp_path,
        cdp_url="http://127.0.0.1:9222",
        account="acct",
        vm="vm1",
        playbook="canva-electron",
    )

    assert task.fid == "SCOUT"
    assert task.report_path is None
    assert task.status == "scout"
    assert task.metadata["source"] == "no_report"
    assert task.metadata["report_source"] == "none"


def test_execute_action_ingest_creates_direct_action_task_without_report(tmp_path: Path) -> None:
    task = ingest_execute_action_task(
        "canva",
        family="binaries",
        lane="exe",
        root_override=tmp_path,
        cdp_url="http://127.0.0.1:9222",
        account="acct",
        vm="vm1",
        playbook="electron-base",
    )

    assert task.fid == ""
    assert task.report_path is None
    assert task.status == "execute-action"
    assert task.dry_run is False
    assert task.metadata["mode"] == "execute-action"
    assert task.metadata["report_source"] == "none"


def test_report_ingest_preserves_review_semantics_for_ledger_and_path_fallback(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    dormant_path = storage.reports_root / "findings" / "dormant" / "D01 - HIGH - Renderer bridge probe.md"
    novel_path = storage.reports_root / "findings" / "novel" / "D02 - HIGH - Renderer bridge probe.md"
    raw_path = storage.reports_root / "findings" / "raw" / "D03 - MEDIUM - Renderer bridge probe.md"
    for path in (dormant_path, novel_path, raw_path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {path.stem}\n", encoding="utf-8")

    _write_ledger(
        storage,
        _finding(
            report_path=str(dormant_path),
            status="dormant",
            review_tier="DORMANT_ACTIVE",
        ),
    )

    ledger_task = ingest_report_task(
        "canva",
        report_path=dormant_path,
        family="binaries",
        lane="exe",
        root_override=tmp_path,
    )
    novel_task = ingest_report_task(
        "canva",
        report_path=novel_path,
        family="binaries",
        lane="exe",
        root_override=tmp_path,
    )
    raw_task = ingest_report_task(
        "canva",
        report_path=raw_path,
        family="binaries",
        lane="exe",
        root_override=tmp_path,
    )

    assert ledger_task.status == "dormant"
    assert ledger_task.review_tier == "DORMANT_ACTIVE"
    assert novel_task.status == "novel"
    assert novel_task.review_tier == "NOVEL"
    assert raw_task.status == "raw"
    assert raw_task.review_tier == "INCONCLUSIVE"


def test_report_ingest_preserves_novel_and_inconclusive_status_from_ledger(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    novel_finding = _finding(
        fid="D02",
        status="",
        review_tier="NOVEL",
        report_path="",
    )
    inconclusive_finding = _finding(
        fid="D03",
        status="",
        review_tier="INCONCLUSIVE",
        report_path="",
    )
    storage.ledgers_root.mkdir(parents=True, exist_ok=True)
    (storage.ledgers_root / "ledger.json").write_text(
        json.dumps({"version": 2, "findings": [novel_finding, inconclusive_finding]}, indent=2) + "\n",
        encoding="utf-8",
    )

    novel_task = ingest_report_task(
        "canva",
        fid="D02",
        family="binaries",
        lane="exe",
        root_override=tmp_path,
    )
    inconclusive_task = ingest_report_task(
        "canva",
        fid="D03",
        family="binaries",
        lane="exe",
        root_override=tmp_path,
    )

    assert novel_task.status == "novel"
    assert inconclusive_task.status == "raw"


def test_reporting_writes_live_validation_artifacts_and_keeps_legacy_dirs_unused(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    report_path = storage.reports_root / "findings" / "confirmed" / "D01 - HIGH - Renderer bridge probe.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("# Before\n", encoding="utf-8")
    task = ValidationTask(
        run_id="dvh-test",
        program="canva",
        family="binaries",
        lane="exe",
        target="canva",
        account="acct",
        vm="vm1",
        fid="D01",
        report_path=report_path,
    )
    verdict = ValidationVerdict(
        state="blocked",
        summary="Dry run only",
        run_id=task.run_id,
        fid=task.fid,
        report_path=task.report_path,
        evidence=[EvidenceRecord(kind="cdp_snapshot", name="cdp_snapshot.json", data={"targets": []})],
    )

    root = write_live_validation_artifacts(storage, task, verdict, after_report_text="# After\n")

    assert (root / "input" / "D01.before.md").exists()
    assert (root / "output" / "D01.after.md").exists()
    assert (root / "evidence" / "cdp_snapshot.json").exists()
    assert (root / "diff.patch").exists()
    assert (root / "verdict.json").exists()
    assert legacy_status_first_dirs(storage.reports_root) == []


def test_canva_playbook_collects_n03_evidence_from_type_match() -> None:
    task = ValidationTask(
        run_id="dvh-n03",
        program="canva",
        family="binaries",
        lane="exe",
        target="canva",
        account="acct",
        vm="vm1",
        fid="D01",
        cdp_url="http://127.0.0.1:9222",
        playbook="canva-electron",
        metadata={
            "title": "Desktop notification issue",
            "type": "Toast XML notification injection",
        },
    )

    class FakeTransport:
        def json_version(self) -> dict[str, Any]:
            return {"Browser": "Chrome/146.0.0"}

        def target_snapshots(self) -> list[dict[str, Any]]:
            return [
                {
                    "id": "page-1",
                    "type": "page",
                    "title": "Canva",
                    "url": "https://www.canva.com/",
                    "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/page-1",
                },
                {
                    "id": "worker-1",
                    "type": "service_worker",
                    "title": "Canva background",
                    "url": "https://www.canva.com/sw.js",
                    "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/worker-1",
                },
            ]

        def snapshot(self) -> dict[str, Any]:
            return {
                "version": self.json_version(),
                "targets": self.target_snapshots(),
            }

        def runtime_evaluate(self, websocket_url: str, expression: str, *, await_promise: bool = False) -> dict[str, Any]:
            _ = await_promise
            if "matchedSurfaceCount" in expression:
                value = {
                    "targetUrl": websocket_url,
                    "matchedSurfaceCount": 2,
                    "matchedSurfaces": [{"name": "NotificationBridge"}, {"name": "desktopNotifications"}],
                }
            else:
                value = {
                    "targetUrl": websocket_url,
                    "href": "https://www.canva.com/",
                    "title": "Canva",
                    "notificationType": "function",
                }
            return {"result": {"result": {"type": "object", "value": value}}}

    evidence = cli.CanvaElectronPlaybook().collect_preflight(task, FakeTransport())
    names = [record.name for record in evidence]
    runtime_payload = next(record.data for record in evidence if record.name == "cdp_runtime_context.json")
    probe_payload = next(record.data for record in evidence if record.name == "n03_read_only_probe.json")

    assert "cdp_version.json" in names
    assert "cdp_runtime_context.json" in names
    assert "n03_read_only_probe.json" in names
    assert [target["target"]["type"] for target in runtime_payload["targets"]] == ["page", "service_worker"]
    assert probe_payload["targets"][0]["evaluation"]["matchedSurfaceCount"] == 2


def test_reporting_rejects_evidence_path_traversal(tmp_path: Path) -> None:
    storage = _storage(tmp_path)
    task = ValidationTask(
        run_id="dvh-evidence",
        program="canva",
        family="binaries",
        lane="exe",
        target="canva",
        account="acct",
        vm="vm1",
        fid="D01",
    )
    verdict = ValidationVerdict(
        state="blocked",
        summary="Dry run only",
        run_id=task.run_id,
        evidence=[EvidenceRecord(kind="notes", name="../escape.md", data="bad")],
    )

    with pytest.raises(ValueError, match="unsafe evidence name"):
        write_live_validation_artifacts(storage, task, verdict)


def test_live_validation_guard_rejects_legacy_status_first_dirs(tmp_path: Path) -> None:
    reports_root = tmp_path / "reports"
    legacy_path = reports_root / "confirmed" / "finding.md"
    legacy_path.parent.mkdir(parents=True)
    legacy_path.write_text("# legacy body\n", encoding="utf-8")

    with pytest.raises(RuntimeError):
        assert_no_legacy_status_first_dirs(reports_root)


def test_cli_validate_report_dry_run_writes_artifacts(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    storage = _storage(tmp_path)
    report_path = storage.reports_root / "findings" / "dormant" / "D01 - HIGH - Renderer bridge probe.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("# Renderer bridge probe\n", encoding="utf-8")
    finding = _finding()
    finding["report_path"] = str(report_path)
    _write_ledger(storage, finding)

    exit_code = cli.main(
        [
            "validate-report",
            "--target",
            "canva",
            "--lane",
            "exe",
            "--family",
            "binaries",
            "--root",
            str(tmp_path),
            "--fid",
            "D01",
        ]
    )

    out = capsys.readouterr().out
    payload = json.loads(out)

    assert exit_code == 0
    assert payload["status"] == "ok"
    artifact_root = Path(payload["artifact_root"])
    assert (artifact_root / "verdict.json").exists()
    verdict_payload = json.loads((artifact_root / "verdict.json").read_text(encoding="utf-8"))
    assert verdict_payload["dry_run"] is True
    assert verdict_payload["state"] == "planned"
    assert artifact_root.parent.name == "live_validation"
    assert live_validation_lock_root(storage).parent == artifact_root.parent


def test_cli_scout_writes_no_report_artifacts_and_no_legacy_dirs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = _storage(tmp_path)

    class FakeTransport:
        def __init__(self, base_url: str) -> None:
            self.base_url = base_url

        def json_version(self) -> dict[str, Any]:
            return {"Browser": "Chrome/146.0.0"}

        def target_snapshots(self) -> list[dict[str, Any]]:
            return [{"id": "page-1", "title": "Canva", "url": "https://www.canva.com/"}]

        def snapshot(self) -> dict[str, Any]:
            return {
                "version": self.json_version(),
                "targets": self.target_snapshots(),
            }

    monkeypatch.setattr(cli, "ElectronCDPTransport", FakeTransport)

    exit_code = cli.main(
        [
            "scout",
            "--target",
            "canva",
            "--lane",
            "exe",
            "--family",
            "binaries",
            "--root",
            str(tmp_path),
            "--cdp",
            "http://127.0.0.1:9222",
            "--allow-private-workflow-ai",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    artifact_root = Path(payload["artifact_root"])
    verdict_payload = json.loads((artifact_root / "verdict.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert payload["fid"] == "SCOUT"
    assert artifact_root.parent.name == "live_validation"
    assert (artifact_root / "evidence" / "action_plan.md").exists()
    assert (artifact_root / "evidence" / "policy_decisions.json").exists()
    assert (artifact_root / "evidence" / "cdp_version.json").exists()
    assert (artifact_root / "evidence" / "cdp_target_list.json").exists()
    assert (artifact_root / "evidence" / "cdp_snapshot.json").exists()
    assert verdict_payload["state"] == "planned"
    assert verdict_payload["metadata"]["mode"] == "scout"
    assert verdict_payload["metadata"]["report_source"] == "none"
    assert sorted(verdict_payload["metadata"]["operator_approved_actions"]) == [
        "canva_ai_private_chat",
        "private_workflow_create",
    ]
    assert verdict_payload["metadata"]["task"]["report_path"] is None
    assert verdict_payload["metadata"]["task"]["fid"] == "SCOUT"
    assert legacy_status_first_dirs(storage.reports_root) == []
    assert not (storage.ledgers_root / "ledger.json").exists()


def test_cli_policy_block_skips_preflight_and_transport(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = _storage(tmp_path)
    report_path = storage.reports_root / "findings" / "dormant" / "D01 - HIGH - Renderer bridge probe.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("# Renderer bridge probe\n", encoding="utf-8")
    _write_ledger(storage, _finding(report_path=str(report_path)))

    state = {"preflight_called": False, "transport_called": False}

    class BlockingPlaybook:
        name = "blocking-playbook"

        def plan(self, task: ValidationTask) -> list[ValidationAction]:
            return [
                ValidationAction(
                    kind="contact_support",
                    description="Denied support-contact flow",
                )
            ]

        def collect_preflight(self, task, transport):
            state["preflight_called"] = True
            return []

    def fake_transport(*args, **kwargs):
        state["transport_called"] = True
        raise AssertionError("transport should not be constructed when policy blocks preflight")

    monkeypatch.setattr(cli, "_playbook_for", lambda name, target: BlockingPlaybook())
    monkeypatch.setattr(cli, "ElectronCDPTransport", fake_transport)

    exit_code = cli.main(
        [
            "validate-report",
            "--target",
            "canva",
            "--lane",
            "exe",
            "--family",
            "binaries",
            "--root",
            str(tmp_path),
            "--fid",
            "D01",
            "--cdp",
            "http://127.0.0.1:9222",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    artifact_root = Path(payload["artifact_root"])
    verdict_payload = json.loads((artifact_root / "verdict.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert state == {"preflight_called": False, "transport_called": False}
    assert verdict_payload["state"] == "blocked"
    assert verdict_payload["summary"] == "Dry run blocked by dynamic validation policy before preflight."
    assert verdict_payload["policy_decisions"][0]["decision"] == "deny"


def test_cli_cdp_error_persists_blocked_verdict(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = _storage(tmp_path)
    report_path = storage.reports_root / "findings" / "dormant" / "D01 - HIGH - Renderer bridge probe.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("# Renderer bridge probe\n", encoding="utf-8")
    _write_ledger(storage, _finding(report_path=str(report_path)))

    class FailingTransport:
        def __init__(self, base_url: str) -> None:
            self.base_url = base_url

        def json_version(self) -> dict[str, Any]:
            raise CDPTransportError("boom")

        def target_snapshots(self) -> list[dict[str, Any]]:
            raise AssertionError("target_snapshots should not run after json_version failure")

    monkeypatch.setattr(cli, "ElectronCDPTransport", FailingTransport)

    exit_code = cli.main(
        [
            "validate-report",
            "--target",
            "canva",
            "--lane",
            "exe",
            "--family",
            "binaries",
            "--root",
            str(tmp_path),
            "--fid",
            "D01",
            "--cdp",
            "http://127.0.0.1:9222",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    artifact_root = Path(payload["artifact_root"])
    verdict_payload = json.loads((artifact_root / "verdict.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert verdict_payload["state"] == "blocked"
    assert verdict_payload["summary"] == "Dry run blocked by CDP preflight error."
    assert verdict_payload["metadata"]["error"] == "boom"
    assert verdict_payload["evidence"][0]["name"] == "cdp_error.json"


def test_cli_validate_report_persists_canva_n03_probe_evidence(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = _storage(tmp_path)
    report_path = storage.reports_root / "findings" / "dormant" / "N03 - HIGH - Toast XML notification injection.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("# Toast XML notification injection\n", encoding="utf-8")
    _write_ledger(
        storage,
        _finding(
            fid="N03",
            title="Toast XML notification injection",
            type="Toast XML notification injection",
            report_path=str(report_path),
        ),
    )

    class FakeTransport:
        def __init__(self, base_url: str) -> None:
            self.base_url = base_url

        def json_version(self) -> dict[str, Any]:
            return {"Browser": "Chrome/146.0.0"}

        def target_snapshots(self) -> list[dict[str, Any]]:
            return [
                {
                    "id": "page-1",
                    "type": "page",
                    "title": "Canva",
                    "url": "https://www.canva.com/",
                    "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/page-1",
                }
            ]

        def snapshot(self) -> dict[str, Any]:
            return {
                "version": self.json_version(),
                "targets": self.target_snapshots(),
            }

        def runtime_evaluate(self, websocket_url: str, expression: str, *, await_promise: bool = False) -> dict[str, Any]:
            _ = await_promise
            value = {
                "targetUrl": websocket_url,
                "surface": "runtime-context" if "navigatorUserAgent" in expression else "notification-surface",
            }
            return {"result": {"result": {"type": "object", "value": value}}}

    monkeypatch.setattr(cli, "ElectronCDPTransport", FakeTransport)

    exit_code = cli.main(
        [
            "validate-report",
            "--target",
            "canva",
            "--lane",
            "exe",
            "--family",
            "binaries",
            "--root",
            str(tmp_path),
            "--fid",
            "N03",
            "--cdp",
            "http://127.0.0.1:9222",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    artifact_root = Path(payload["artifact_root"])
    runtime_context = json.loads((artifact_root / "evidence" / "cdp_runtime_context.json").read_text(encoding="utf-8"))
    read_only_probe = json.loads((artifact_root / "evidence" / "n03_read_only_probe.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert runtime_context["fid"] == "N03"
    assert runtime_context["targets"][0]["evaluation"]["surface"] == "runtime-context"
    assert read_only_probe["targets"][0]["evaluation"]["surface"] == "notification-surface"
    verdict_payload = json.loads((artifact_root / "verdict.json").read_text(encoding="utf-8"))
    assert verdict_payload["state"] == "planned"


def test_cli_execute_action_policy_block_skips_transport(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = {"transport_called": False}

    def fake_transport(*args, **kwargs):
        state["transport_called"] = True
        raise AssertionError("transport should not be constructed for denied execute-action requests")

    monkeypatch.setattr(cli, "ElectronCDPTransport", fake_transport)

    exit_code = cli.main(
        [
            "execute-action",
            "--target",
            "canva",
            "--lane",
            "exe",
            "--family",
            "binaries",
            "--root",
            str(tmp_path),
            "--cdp",
            "http://127.0.0.1:9222",
            "--action-kind",
            "contact_support",
            "--description",
            "Denied support contact attempt",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    artifact_root = Path(payload["artifact_root"])
    verdict_payload = json.loads((artifact_root / "verdict.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert state["transport_called"] is False
    assert verdict_payload["state"] == "blocked"
    assert verdict_payload["dry_run"] is False
    assert verdict_payload["summary"] == "Execute-action request was blocked by dynamic validation policy before transport."
    assert (artifact_root / "evidence" / "action.json").exists()
    assert (artifact_root / "evidence" / "policy_decisions.json").exists()


def test_cli_execute_action_records_plan_without_ui_improvisation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = {"transport_called": False}

    def fake_transport(*args, **kwargs):
        state["transport_called"] = True
        raise AssertionError("transport should not be constructed for plan-only execute-action requests")

    monkeypatch.setattr(cli, "ElectronCDPTransport", fake_transport)

    exit_code = cli.main(
        [
            "execute-action",
            "--target",
            "canva",
            "--lane",
            "exe",
            "--family",
            "binaries",
            "--root",
            str(tmp_path),
            "--cdp",
            "http://127.0.0.1:9222",
            "--action-kind",
            "private_document_create",
            "--description",
            "Plan one private document creation step",
            "--metadata-json",
            json.dumps({"scope": "private"}),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    artifact_root = Path(payload["artifact_root"])
    verdict_payload = json.loads((artifact_root / "verdict.json").read_text(encoding="utf-8"))
    step_plan = (artifact_root / "evidence" / "step_plan.md").read_text(encoding="utf-8")

    assert exit_code == 0
    assert state["transport_called"] is False
    assert verdict_payload["state"] == "planned"
    assert verdict_payload["metadata"]["stop_reason"] == (
        "action requires an explicit supported primitive before live execution"
    )
    assert "runtime_evaluate" in step_plan
    assert "do not improvise" in step_plan


def test_cli_execute_action_runtime_evaluate_writes_report_copies_and_evidence(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = _storage(tmp_path)
    report_path = storage.reports_root / "findings" / "dormant" / "D01 - HIGH - Renderer bridge probe.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("# Renderer bridge probe\n", encoding="utf-8")
    _write_ledger(storage, _finding(report_path=str(report_path)))

    class FakeTransport:
        def __init__(self, base_url: str) -> None:
            self.base_url = base_url
            self.snapshot_calls = 0

        def target_snapshots(self) -> list[dict[str, Any]]:
            self.snapshot_calls += 1
            title = "Canva" if self.snapshot_calls == 1 else "Canva updated"
            return [
                {
                    "id": "page-1",
                    "type": "page",
                    "title": title,
                    "url": "https://www.canva.com/design",
                    "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/page-1",
                }
            ]

        def runtime_evaluate(self, websocket_url: str, expression: str, *, await_promise: bool = False) -> dict[str, Any]:
            _ = await_promise
            return {
                "result": {
                    "result": {
                        "type": "object",
                        "value": {
                            "websocket_url": websocket_url,
                            "expression": expression,
                            "ok": True,
                        },
                    }
                }
            }

        def build_screenshot_command(self, *, image_format: str = "png", from_surface: bool = True) -> dict[str, Any]:
            return {
                "id": 9,
                "method": "Page.captureScreenshot",
                "params": {"format": image_format, "fromSurface": from_surface},
            }

        def capture_screenshot(
            self,
            websocket_url: str,
            *,
            image_format: str = "png",
            from_surface: bool = True,
        ) -> dict[str, Any]:
            _ = websocket_url
            _ = image_format
            _ = from_surface
            return {"result": {"data": "c2NyZWVuc2hvdA=="}}

    monkeypatch.setattr(cli, "ElectronCDPTransport", FakeTransport)

    exit_code = cli.main(
        [
            "execute-action",
            "--target",
            "canva",
            "--lane",
            "exe",
            "--family",
            "binaries",
            "--root",
            str(tmp_path),
            "--fid",
            "D01",
            "--cdp",
            "http://127.0.0.1:9222",
            "--action-kind",
            "live_ipc_interaction",
            "--description",
            "Evaluate one IPC-related expression without clicking",
            "--target-ref",
            "Canva",
            "--metadata-json",
            json.dumps(
                {
                    "primitive": "runtime_evaluate",
                    "safe_expression_id": "location_summary",
                }
            ),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    artifact_root = Path(payload["artifact_root"])
    verdict_payload = json.loads((artifact_root / "verdict.json").read_text(encoding="utf-8"))
    runtime_payload = json.loads((artifact_root / "evidence" / "runtime_evaluate_result.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert verdict_payload["state"] == "executed"
    assert verdict_payload["dry_run"] is False
    assert verdict_payload["metadata"]["executed_primitive"] == "runtime_evaluate"
    assert (artifact_root / "input" / "D01.before.md").exists()
    assert (artifact_root / "output" / "D01.after.md").exists()
    assert (artifact_root / "evidence" / "cdp_targets_before.json").exists()
    assert (artifact_root / "evidence" / "cdp_targets_after.json").exists()
    assert (artifact_root / "evidence" / "selected_target.json").exists()
    assert (artifact_root / "evidence" / "screenshot_command.json").exists()
    assert (artifact_root / "evidence" / "runtime_evaluate_screenshot.png").read_bytes() == b"screenshot"
    assert runtime_payload["action_kind"] == "live_ipc_interaction"
    assert runtime_payload["result"]["ok"] is True


def test_cli_execute_action_capture_screenshot_uses_transport_helper(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = {"capture_called": False}

    class FakeTransport:
        def __init__(self, base_url: str) -> None:
            self.base_url = base_url

        def target_snapshots(self) -> list[dict[str, Any]]:
            return [
                {
                    "id": "page-1",
                    "type": "page",
                    "title": "Canva",
                    "url": "https://www.canva.com/",
                    "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/page-1",
                }
            ]

        def build_screenshot_command(self, *, image_format: str = "png", from_surface: bool = True) -> dict[str, Any]:
            return {
                "id": 1,
                "method": "Page.captureScreenshot",
                "params": {"format": image_format, "fromSurface": from_surface},
            }

        def capture_screenshot(
            self,
            websocket_url: str,
            *,
            image_format: str = "png",
            from_surface: bool = True,
        ) -> dict[str, Any]:
            _ = websocket_url
            _ = image_format
            _ = from_surface
            state["capture_called"] = True
            return {"result": {"data": "c2NyZWVuc2hvdA=="}}

    monkeypatch.setattr(cli, "ElectronCDPTransport", FakeTransport)

    exit_code = cli.main(
        [
            "execute-action",
            "--target",
            "canva",
            "--lane",
            "exe",
            "--family",
            "binaries",
            "--root",
            str(tmp_path),
            "--cdp",
            "http://127.0.0.1:9222",
            "--action-kind",
            "cdp_capture_screenshot",
            "--description",
            "Capture one bounded screenshot",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    artifact_root = Path(payload["artifact_root"])
    verdict_payload = json.loads((artifact_root / "verdict.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert state["capture_called"] is True
    assert verdict_payload["state"] == "executed"
    assert verdict_payload["metadata"]["executed_primitive"] == "cdp_capture_screenshot"
    assert (artifact_root / "evidence" / "screenshot_command.json").exists()
    assert (artifact_root / "evidence" / "screenshot.png").read_bytes() == b"screenshot"


def test_cli_execute_action_rejects_arbitrary_runtime_expression_before_evaluation(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeTransport:
        def __init__(self, base_url: str) -> None:
            self.base_url = base_url

        def target_snapshots(self) -> list[dict[str, Any]]:
            return [
                {
                    "id": "page-1",
                    "type": "page",
                    "title": "Canva",
                    "url": "https://www.canva.com/",
                    "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/page-1",
                }
            ]

        def runtime_evaluate(self, websocket_url: str, expression: str, *, await_promise: bool = False) -> dict[str, Any]:
            raise AssertionError("arbitrary expressions must be rejected before Runtime.evaluate")

    monkeypatch.setattr(cli, "ElectronCDPTransport", FakeTransport)

    exit_code = cli.main(
        [
            "execute-action",
            "--target",
            "canva",
            "--lane",
            "exe",
            "--family",
            "binaries",
            "--root",
            str(tmp_path),
            "--cdp",
            "http://127.0.0.1:9222",
            "--action-kind",
            "live_ipc_interaction",
            "--description",
            "Try a mutating runtime expression",
            "--metadata-json",
            json.dumps({"primitive": "runtime_evaluate", "expression": "fetch('/api/share', {method:'POST'})"}),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    artifact_root = Path(payload["artifact_root"])
    verdict_payload = json.loads((artifact_root / "verdict.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert verdict_payload["state"] == "blocked"
    assert "safe_expression_id" in verdict_payload["metadata"]["error"]


def test_cli_execute_action_requires_unique_exact_target_selector(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeTransport:
        def __init__(self, base_url: str) -> None:
            self.base_url = base_url

        def target_snapshots(self) -> list[dict[str, Any]]:
            return [
                {
                    "id": "page-1",
                    "type": "page",
                    "title": "Canva",
                    "url": "https://www.canva.com/design/one",
                    "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/page-1",
                },
                {
                    "id": "page-2",
                    "type": "page",
                    "title": "Canva",
                    "url": "https://www.canva.com/design/two",
                    "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/page-2",
                },
            ]

        def runtime_evaluate(self, websocket_url: str, expression: str, *, await_promise: bool = False) -> dict[str, Any]:
            raise AssertionError("ambiguous targets must be rejected before Runtime.evaluate")

    monkeypatch.setattr(cli, "ElectronCDPTransport", FakeTransport)

    exit_code = cli.main(
        [
            "execute-action",
            "--target",
            "canva",
            "--lane",
            "exe",
            "--family",
            "binaries",
            "--root",
            str(tmp_path),
            "--cdp",
            "http://127.0.0.1:9222",
            "--action-kind",
            "live_ipc_interaction",
            "--description",
            "Inspect one exact target",
            "--metadata-json",
            json.dumps({"primitive": "runtime_evaluate", "safe_expression_id": "location_summary"}),
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    artifact_root = Path(payload["artifact_root"])
    verdict_payload = json.loads((artifact_root / "verdict.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert verdict_payload["state"] == "blocked"
    assert "multiple page-like CDP targets" in verdict_payload["metadata"]["error"]


def test_cdp_transport_websockets_sync_fallback_uses_recv_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    messages: list[str] = []
    state = {"recv_timeout": None, "origin": "unset"}

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def send(self, message: str) -> None:
            messages.append(message)

        def recv(self, timeout=None) -> str:
            state["recv_timeout"] = timeout
            payload = json.loads(messages[0])
            return json.dumps({"id": payload["id"], "result": {"result": {"type": "string", "value": "ok"}}})

    def fake_connect(url: str, *, open_timeout: float, close_timeout: float, origin=None):
        _ = url
        assert open_timeout == 2.5
        assert close_timeout == 2.5
        state["origin"] = origin
        return FakeConnection()

    monkeypatch.setattr("agents.dynamic_validation.transports.cdp.websocket", None)
    monkeypatch.setattr("agents.dynamic_validation.transports.cdp.websockets_sync_connect", fake_connect)

    transport = ElectronCDPTransport("http://127.0.0.1:9222", timeout=2.5)
    response = transport.runtime_evaluate("ws://127.0.0.1:9222/devtools/page/page-1", "typeof location")

    assert response["result"]["result"]["value"] == "ok"
    assert state["recv_timeout"] == 2.5
    assert state["origin"] is None
