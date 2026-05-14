"""Shared runtime, tracing, and orchestration helpers for BaseTeam-backed teams."""

from __future__ import annotations

import json
import shlex
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Sequence

SpawnFn = Callable[[str, str, Path], subprocess.Popen[Any]]
WaitFn = Callable[[dict[str, subprocess.Popen[Any]], int], dict[str, tuple[str, int]]]
CollectFindingsFn = Callable[[Any, Path | None], list[dict[str, Any]]]
DedupFn = Callable[[list[dict[str, Any]], dict[str, Any]], list[dict[str, Any]]]
ReviewFn = Callable[[list[dict[str, Any]], Path], tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]]
CoverageFn = Callable[[str, str, int], None]
WriteTracesFn = Callable[[list[dict[str, Any]]], None]
CleanupHandleFn = Callable[[subprocess.Popen[Any]], None]
ReadLogFn = Callable[[subprocess.Popen[Any]], str]
PersistPartialFn = Callable[[], None]
SelectSpecsFn = Callable[[Sequence[Any], Sequence[Any]], list[Any]]
GenerateDynamicFn = Callable[[Path, bool], list[Any]]
LoadSharedBrainFn = Callable[[], dict[str, Any]]
LoadLedgerFn = Callable[[], dict[str, Any]]
UpdateReviewedFn = Callable[[list[dict[str, Any]]], list[dict[str, Any]]]
RenderPromptFn = Callable[[Any], str]
TimestampIsoFn = Callable[[], str]
TraceTimestampFn = Callable[[], str]
SlugFn = Callable[[str], str]
EnsureParentFn = Callable[[Path], None]


def spawn_agent(
    prompt: str,
    agent_name: str,
    log_path: Path,
    *,
    ensure_parent: EnsureParentFn,
    team_dir: Path,
    workdir: Path,
    target_path: Path,
    active_handles: dict[str, subprocess.Popen[Any]],
    write_traces: WriteTracesFn,
    slug: SlugFn,
) -> subprocess.Popen[Any]:
    """Spawn a codex subprocess and capture its output to the provided log."""
    ensure_parent(log_path)

    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=team_dir,
        prefix=f".prompt_{slug(agent_name)}_",
        suffix=".txt",
        delete=False,
    ) as handle:
        handle.write(prompt)
        handle.write("\n")
        prompt_file = Path(handle.name)

    command = (
        "codex exec -s read-only --skip-git-repo-check "
        f"--cd {shlex.quote(str(workdir))} < {shlex.quote(str(prompt_file))}"
    )

    log_handle = log_path.open("ab")
    process = subprocess.Popen(
        ["bash", "-lc", command],
        cwd=str(workdir),
        stdin=subprocess.DEVNULL,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
    )
    setattr(process, "_bbh_log_path", str(log_path))
    setattr(process, "_bbh_prompt_path", str(prompt_file))
    setattr(process, "_bbh_agent_name", str(agent_name))
    setattr(process, "_bbh_log_handle", log_handle)
    active_handles[agent_name] = process

    write_traces(
        [
            {
                "event": "spawn",
                "agent_name": agent_name,
                "log_path": str(log_path),
                "prompt_path": str(prompt_file),
                "pid": process.pid,
                "command": command,
                "target_path": str(target_path),
            }
        ]
    )
    return process


def wait_for_agents(
    handles: dict[str, subprocess.Popen[Any]],
    timeout: int,
    *,
    sigterm_received: Callable[[], bool],
    read_log_for_handle: ReadLogFn,
    cleanup_handle: CleanupHandleFn,
    write_traces: WriteTracesFn,
) -> dict[str, tuple[str, int]]:
    """Wait for spawned agents, respecting a global timeout."""
    deadline = time.monotonic() + max(1, int(timeout))
    pending = dict(handles)
    completed: dict[str, tuple[str, int]] = {}

    while pending:
        if sigterm_received():
            break

        for agent_name, handle in list(pending.items()):
            returncode = handle.poll()
            if returncode is None:
                continue
            completed[agent_name] = (read_log_for_handle(handle), returncode)
            cleanup_handle(handle)
            pending.pop(agent_name, None)

        if not pending:
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(0.2)

    for agent_name, handle in pending.items():
        try:
            handle.terminate()
            handle.wait(timeout=5)
        except subprocess.TimeoutExpired:
            handle.kill()
            handle.wait(timeout=5)
        except OSError:
            pass
        completed[agent_name] = (read_log_for_handle(handle), -9)
        cleanup_handle(handle)
        write_traces(
            [
                {
                    "event": "timeout",
                    "agent_name": agent_name,
                    "pid": handle.pid,
                    "timeout_seconds": int(timeout),
                }
            ]
        )

    return completed


def write_traces(
    events: list[dict[str, Any]],
    *,
    traces_dir: Path,
    ensure_parent: EnsureParentFn,
    trace_timestamp: TraceTimestampFn,
    timestamp_iso: TimestampIsoFn,
    program: str,
    team_type: str,
) -> None:
    """Append JSONL trace events to a timestamped trace file."""
    if not events:
        return
    trace_path = traces_dir / f"{trace_timestamp()}.jsonl"
    ensure_parent(trace_path)
    with trace_path.open("a", encoding="utf-8") as handle:
        for event in events:
            payload = dict(event)
            payload.setdefault("timestamp", timestamp_iso())
            payload.setdefault("program", program)
            payload.setdefault("team_type", team_type)
            handle.write(json.dumps(payload, sort_keys=True))
            handle.write("\n")


def install_signal_handlers(
    *,
    signal_handlers_installed: Callable[[], bool],
    set_sigterm_received: Callable[[bool], None],
    persist_partial_results: PersistPartialFn,
    set_signal_handlers_installed: Callable[[bool], None],
    write_traces: WriteTracesFn | None = None,
) -> None:
    if signal_handlers_installed():
        return

    def _handle_sigterm(signum: int, _frame: Any) -> None:
        set_sigterm_received(True)
        if write_traces is not None:
            write_traces([{"event": "signal", "signal": signum}])
        try:
            persist_partial_results()
        finally:
            raise SystemExit(128 + int(signum))

    signal.signal(signal.SIGTERM, _handle_sigterm)
    signal.signal(signal.SIGINT, _handle_sigterm)
    set_signal_handlers_installed(True)


def orchestrate(
    *,
    parallel: bool,
    agents_mode: str,
    install_signal_handlers: Callable[[], None],
    set_partial_findings: Callable[[list[dict[str, Any]]], None],
    get_static_profiles: Callable[[], list[Any]],
    generate_dynamic_agents: GenerateDynamicFn,
    target_path: Path,
    force_preflight: bool,
    select_specs: SelectSpecsFn,
    load_shared_brain: LoadSharedBrainFn,
    load_ledger: LoadLedgerFn,
    set_last_loaded_ledger: Callable[[dict[str, Any]], None],
    findings_path: Path,
    write_traces: WriteTracesFn,
    snapshot_id: Callable[[], str | None],
    spawn_agent: SpawnFn,
    agents_dir: Path,
    slug: SlugFn,
    trace_timestamp: TraceTimestampFn,
    sigterm_received: Callable[[], bool],
    read_log_for_handle: ReadLogFn,
    cleanup_handle: CleanupHandleFn,
    collect_agent_findings: CollectFindingsFn,
    agent_timeout: int,
    deduplicate_findings: DedupFn,
    stage2_review: ReviewFn,
    update_reviewed_findings: UpdateReviewedFn,
    update_coverage: CoverageFn,
    get_last_review_error: Callable[[], str | None],
    active_handles: dict[str, subprocess.Popen[Any]],
    persist_partial_results: PersistPartialFn,
    render_prompt: RenderPromptFn,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Run the full team lifecycle."""
    if agents_mode not in {"static", "dynamic", "all"}:
        raise ValueError("agents_mode must be one of: static, dynamic, all")

    install_signal_handlers()
    set_partial_findings([])

    static_specs = get_static_profiles() if agents_mode in {"static", "all"} else []
    dynamic_specs = generate_dynamic_agents(target_path, force_preflight) if agents_mode in {"dynamic", "all"} else []
    selected_specs = select_specs(static_specs, dynamic_specs)
    shared_brain = load_shared_brain()
    ledger = load_ledger()
    set_last_loaded_ledger(ledger)
    findings_path.write_text("", encoding="utf-8")

    write_traces(
        [
            {
                "event": "preflight",
                "agents_mode": agents_mode,
                "parallel": bool(parallel),
                "static_count": len(static_specs),
                "dynamic_count": len(dynamic_specs),
                "selected_count": len(selected_specs),
                "snapshot_id": snapshot_id(),
                "shared_brain_files": len((shared_brain.get("files") or {})),
            }
        ]
    )

    raw_findings: list[dict[str, Any]] = []
    findings_by_agent: dict[str, list[dict[str, Any]]] = {}

    try:
        if parallel:
            handles: dict[str, subprocess.Popen[Any]] = {}
            log_paths: dict[str, Path] = {}
            for spec in selected_specs:
                rendered = render_prompt(spec)
                timestamp = trace_timestamp()
                log_path = agents_dir / f"agent_{slug(spec.key)}_{timestamp}.log"
                log_paths[spec.key] = log_path
                handles[spec.key] = spawn_agent(rendered, spec.key, log_path)

            pending = dict(handles)
            deadline = time.monotonic() + max(1, int(agent_timeout))

            while pending:
                if sigterm_received():
                    break

                for agent_name, handle in list(pending.items()):
                    returncode = handle.poll()
                    if returncode is None:
                        continue
                    _ = read_log_for_handle(handle)
                    cleanup_handle(handle)
                    pending.pop(agent_name, None)

                    spec = next((s for s in selected_specs if s.key == agent_name), None)
                    if spec is not None:
                        agent_findings = collect_agent_findings(spec, log_paths.get(agent_name))
                        findings_by_agent[agent_name] = agent_findings
                        raw_findings.extend(agent_findings)
                        set_partial_findings(list(raw_findings))
                        write_traces(
                            [
                                {
                                    "event": "agent_complete",
                                    "agent_name": agent_name,
                                    "surface": spec.surface,
                                    "returncode": returncode,
                                    "finding_count": len(agent_findings),
                                }
                            ]
                        )

                if not pending:
                    break
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.2)

            for agent_name, handle in pending.items():
                try:
                    handle.terminate()
                    handle.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    handle.kill()
                    handle.wait(timeout=5)
                except OSError:
                    pass
                _ = read_log_for_handle(handle)
                cleanup_handle(handle)

                spec = next((s for s in selected_specs if s.key == agent_name), None)
                if spec is not None:
                    agent_findings = collect_agent_findings(spec, log_paths.get(agent_name))
                    findings_by_agent[agent_name] = agent_findings
                    raw_findings.extend(agent_findings)
                    set_partial_findings(list(raw_findings))
                    write_traces(
                        [
                            {
                                "event": "timeout",
                                "agent_name": agent_name,
                                "surface": spec.surface,
                                "pid": handle.pid,
                                "timeout_seconds": int(agent_timeout),
                                "finding_count": len(agent_findings),
                            }
                        ]
                    )
        else:
            for spec in selected_specs:
                if sigterm_received():
                    break
                rendered = render_prompt(spec)
                timestamp = trace_timestamp()
                log_path = agents_dir / f"agent_{slug(spec.key)}_{timestamp}.log"
                handle = spawn_agent(rendered, spec.key, log_path)
                wait_for_agents(
                    {spec.key: handle},
                    agent_timeout,
                    sigterm_received=sigterm_received,
                    read_log_for_handle=read_log_for_handle,
                    cleanup_handle=cleanup_handle,
                    write_traces=write_traces,
                )
                agent_findings = collect_agent_findings(spec, log_path)
                findings_by_agent[spec.key] = agent_findings
                raw_findings.extend(agent_findings)
                set_partial_findings(list(raw_findings))
                write_traces(
                    [
                        {
                            "event": "agent_complete",
                            "agent_name": spec.key,
                            "surface": spec.surface,
                            "returncode": handle.returncode,
                            "finding_count": len(agent_findings),
                        }
                    ]
                )

        set_partial_findings(list(raw_findings))
        new_findings = deduplicate_findings(raw_findings, ledger)
        confirmed, dormant, novel = stage2_review(new_findings, target_path)
        reviewed_findings = confirmed + dormant + novel
        reviewed_findings = update_reviewed_findings(reviewed_findings)

        for spec in selected_specs:
            update_coverage(
                agent_name=spec.key,
                surface=spec.surface,
                finding_count=len(findings_by_agent.get(spec.key, [])),
            )

        write_traces(
            [
                {
                    "event": "review_complete",
                    "confirmed": len(confirmed),
                    "dormant": len(dormant),
                    "novel": len(novel),
                    "review_error": get_last_review_error(),
                }
            ]
        )
        return confirmed, dormant, novel
    except SystemExit:
        raise
    except BaseException:
        persist_partial_results()
        raise
    finally:
        for handle in list(active_handles.values()):
            if handle.poll() is None:
                try:
                    handle.terminate()
                except OSError:
                    pass
            cleanup_handle(handle)
        active_handles.clear()
