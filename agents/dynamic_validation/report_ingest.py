"""Build dynamic validation tasks from canonical reports or ledger findings."""

from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Any

from agents.ledger import read_team_findings
from agents.storage_resolver import REPORT_STATES, resolve_family_lane, resolve_storage

from .models import ValidationTask

REPORT_FILENAME_RE = re.compile(
    r"^(?P<fid>[A-Za-z]\d+)\s+-\s+(?P<severity>[^-]+?)\s+-\s+(?P<title>.+)\.md$"
)
ALLOWED_FINDING_LIFECYCLES = frozenset(REPORT_STATES)
LIFECYCLE_REVIEW_TIER_DEFAULTS = {
    "confirmed": "CONFIRMED",
    "novel": "NOVEL",
    "raw": "INCONCLUSIVE",
}


def default_run_id(prefix: str = "dvh") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def _root_override_path(root_override: str | Path | None) -> Path | None:
    if root_override is None:
        return None
    return Path(root_override).expanduser().resolve(strict=False)


def _normalize_report_path(value: Any) -> Path | None:
    if not value:
        return None
    return Path(str(value)).expanduser().resolve(strict=False)


def _finding_review_tier(finding: dict[str, Any]) -> str:
    current = finding.get("current")
    if isinstance(current, dict):
        tier = str(current.get("review_tier") or current.get("tier") or "").strip()
        if tier:
            return tier
    return str(finding.get("review_tier") or finding.get("tier") or "").strip()


def _finding_status(finding: dict[str, Any]) -> str:
    status = str(finding.get("status") or "").strip()
    if status:
        return status
    tier = _finding_review_tier(finding).upper()
    if tier == "CONFIRMED":
        return "confirmed"
    if tier.startswith("DORMANT"):
        return "dormant"
    if tier == "NOVEL":
        return "novel"
    if tier == "INCONCLUSIVE":
        return "raw"
    return "active"


def _finding_to_task(
    finding: dict[str, Any],
    *,
    program: str,
    family: str,
    lane: str,
    cdp_url: str | None,
    account: str,
    vm: str,
    playbook: str,
    dry_run: bool,
    run_id: str | None,
) -> ValidationTask:
    task_run_id = run_id or default_run_id()
    report_path = _normalize_report_path(finding.get("report_path"))
    fid = str(finding.get("fid") or "").strip()
    return ValidationTask(
        run_id=task_run_id,
        program=program,
        family=family,
        lane=lane,
        target=program,
        account=account,
        vm=vm,
        fid=fid,
        report_path=report_path,
        status=_finding_status(finding),
        review_tier=_finding_review_tier(finding),
        cdp_url=cdp_url,
        playbook=playbook,
        dry_run=dry_run,
        metadata={
            "title": str(
                finding.get("title")
                or finding.get("type")
                or finding.get("vulnerability_name")
                or ""
            ).strip(),
            "type": str(finding.get("type") or finding.get("vulnerability_name") or "").strip(),
            "severity": str(finding.get("severity") or "").strip(),
            "source": "ledger",
        },
    )


def load_finding_by_fid(
    program: str,
    fid: str,
    *,
    family: str | None = None,
    lane: str | None = None,
    root_override: str | Path | None = None,
) -> dict[str, Any]:
    findings = read_team_findings(
        program,
        family=family,
        lane=lane,
        root_override=_root_override_path(root_override),
    )
    for finding in findings:
        if str(finding.get("fid") or "").strip().upper() == fid.strip().upper():
            return finding
    raise FileNotFoundError(f"no finding found for fid {fid}")


def _resolve_canonical_report_path(
    report_path: str | Path,
    *,
    reports_root: Path,
) -> tuple[Path, str]:
    resolved = Path(report_path).expanduser().resolve(strict=False)
    findings_root = (reports_root / "findings").resolve(strict=False)
    try:
        relative = resolved.relative_to(findings_root)
    except ValueError as exc:
        raise ValueError(
            f"report_path must be under {findings_root}"
        ) from exc
    if len(relative.parts) != 2:
        raise ValueError(
            "report_path must match reports/findings/<lifecycle>/<canonical-filename>.md"
        )
    lifecycle, _ = relative.parts
    if lifecycle not in ALLOWED_FINDING_LIFECYCLES:
        raise ValueError(f"unsupported report lifecycle: {lifecycle}")
    return resolved, lifecycle


def _parse_report_path(report_path: Path, *, lifecycle: str) -> dict[str, Any]:
    match = REPORT_FILENAME_RE.match(report_path.name)
    if not match:
        raise ValueError(f"unsupported canonical report filename: {report_path.name}")
    return {
        "fid": match.group("fid"),
        "severity": match.group("severity").strip(),
        "title": match.group("title").strip(),
        "status": lifecycle,
        "review_tier": LIFECYCLE_REVIEW_TIER_DEFAULTS.get(lifecycle, ""),
        "report_path": str(report_path),
    }


def load_finding_by_report_path(
    program: str,
    report_path: str | Path,
    *,
    family: str | None = None,
    lane: str | None = None,
    root_override: str | Path | None = None,
) -> dict[str, Any]:
    storage = resolve_storage(
        program,
        family=family,
        lane=lane,
        root_override=_root_override_path(root_override),
        create=False,
    )
    resolved, lifecycle = _resolve_canonical_report_path(
        report_path,
        reports_root=storage.reports_root,
    )
    findings = read_team_findings(
        program,
        family=family,
        lane=lane,
        root_override=_root_override_path(root_override),
    )
    for finding in findings:
        finding_path = _normalize_report_path(finding.get("report_path"))
        if finding_path is not None and finding_path == resolved:
            return finding
    parsed = _parse_report_path(resolved, lifecycle=lifecycle)
    parsed["source"] = "report_path"
    return parsed


def ingest_report_task(
    program: str,
    *,
    fid: str | None = None,
    report_path: str | Path | None = None,
    family: str | None = None,
    lane: str | None = None,
    root_override: str | Path | None = None,
    cdp_url: str | None = None,
    account: str = "default",
    vm: str = "default",
    playbook: str = "electron-base",
    dry_run: bool = True,
    run_id: str | None = None,
) -> ValidationTask:
    resolved_family, resolved_lane = resolve_family_lane(family=family, lane=lane, hunt_type="source")
    _ = resolve_storage(
        program,
        family=resolved_family,
        lane=resolved_lane,
        root_override=_root_override_path(root_override),
        create=False,
    )
    if fid:
        finding = load_finding_by_fid(
            program,
            fid,
            family=resolved_family,
            lane=resolved_lane,
            root_override=root_override,
        )
    elif report_path is not None:
        finding = load_finding_by_report_path(
            program,
            report_path,
            family=resolved_family,
            lane=resolved_lane,
            root_override=root_override,
        )
    else:
        raise ValueError("either fid or report_path is required")
    return _finding_to_task(
        finding,
        program=program,
        family=resolved_family,
        lane=resolved_lane,
        cdp_url=cdp_url,
        account=account,
        vm=vm,
        playbook=playbook,
        dry_run=dry_run,
        run_id=run_id,
    )


def ingest_scout_task(
    program: str,
    *,
    family: str | None = None,
    lane: str | None = None,
    root_override: str | Path | None = None,
    cdp_url: str | None = None,
    account: str = "default",
    vm: str = "default",
    playbook: str = "electron-base",
    dry_run: bool = True,
    run_id: str | None = None,
) -> ValidationTask:
    resolved_family, resolved_lane = resolve_family_lane(family=family, lane=lane, hunt_type="source")
    _ = resolve_storage(
        program,
        family=resolved_family,
        lane=resolved_lane,
        root_override=_root_override_path(root_override),
        create=True,
    )
    return ValidationTask(
        run_id=run_id or default_run_id(prefix="scout"),
        program=program,
        family=resolved_family,
        lane=resolved_lane,
        target=program,
        account=account,
        vm=vm,
        fid="SCOUT",
        report_path=None,
        status="scout",
        review_tier="",
        cdp_url=cdp_url,
        playbook=playbook,
        dry_run=dry_run,
        metadata={
            "mode": "scout",
            "source": "no_report",
            "report_source": "none",
            "title": "Dynamic validation scout rehearsal",
            "severity": "",
        },
    )


def ingest_execute_action_task(
    program: str,
    *,
    fid: str | None = None,
    report_path: str | Path | None = None,
    family: str | None = None,
    lane: str | None = None,
    root_override: str | Path | None = None,
    cdp_url: str | None = None,
    account: str = "default",
    vm: str = "default",
    playbook: str = "electron-base",
    dry_run: bool = False,
    run_id: str | None = None,
) -> ValidationTask:
    resolved_family, resolved_lane = resolve_family_lane(family=family, lane=lane, hunt_type="source")
    if fid or report_path is not None:
        task = ingest_report_task(
            program,
            fid=fid,
            report_path=report_path,
            family=resolved_family,
            lane=resolved_lane,
            root_override=root_override,
            cdp_url=cdp_url,
            account=account,
            vm=vm,
            playbook=playbook,
            dry_run=dry_run,
            run_id=run_id or default_run_id(prefix="exec"),
        )
        task.metadata = {
            **task.metadata,
            "mode": "execute-action",
            "report_source": task.metadata.get("source", ""),
        }
        return task

    _ = resolve_storage(
        program,
        family=resolved_family,
        lane=resolved_lane,
        root_override=_root_override_path(root_override),
        create=True,
    )
    return ValidationTask(
        run_id=run_id or default_run_id(prefix="exec"),
        program=program,
        family=resolved_family,
        lane=resolved_lane,
        target=program,
        account=account,
        vm=vm,
        fid="",
        report_path=None,
        status="execute-action",
        review_tier="",
        cdp_url=cdp_url,
        playbook=playbook,
        dry_run=dry_run,
        metadata={
            "mode": "execute-action",
            "source": "direct_action",
            "report_source": "none",
            "title": "Dynamic validation one-step action",
            "severity": "",
        },
    )


def ingest_lifecycle_tasks(
    program: str,
    lifecycle: str,
    *,
    family: str | None = None,
    lane: str | None = None,
    root_override: str | Path | None = None,
    cdp_url: str | None = None,
    account: str = "default",
    vm: str = "default",
    playbook: str = "electron-base",
    dry_run: bool = True,
) -> list[ValidationTask]:
    resolved_family, resolved_lane = resolve_family_lane(family=family, lane=lane, hunt_type="source")
    storage = resolve_storage(
        program,
        family=resolved_family,
        lane=resolved_lane,
        root_override=_root_override_path(root_override),
        create=False,
    )
    reports_dir = storage.reports_root / "findings" / lifecycle
    tasks: list[ValidationTask] = []
    if not reports_dir.is_dir():
        return tasks
    for path in sorted(reports_dir.glob("*.md")):
        tasks.append(
            ingest_report_task(
                program,
                report_path=path,
                family=resolved_family,
                lane=resolved_lane,
                root_override=root_override,
                cdp_url=cdp_url,
                account=account,
                vm=vm,
                playbook=playbook,
                dry_run=dry_run,
            )
        )
    return tasks
