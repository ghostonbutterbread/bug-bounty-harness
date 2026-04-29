"""Shared reviewed-finding promotion flow for procedural BaseTeam-backed teams."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .reporting_compat import is_placeholder_finding
from .reports import write_report_indexes
from .review import (
    _render_confirmed_report,
    _render_dormant_report,
    _render_novel_findings_report,
)

UpdateFindingFn = Callable[..., dict[str, Any]]
PromotedHook = Callable[[dict[str, Any], str, str], None]
LogSpanFn = Callable[..., None]


def promote_reviewed_findings(
    *,
    program: str,
    storage: Any,
    reviewed_groups: Mapping[str, Sequence[dict[str, Any]]],
    snapshot_identity: Mapping[str, Any],
    run_id: str | None,
    agent: str,
    root_override: str | Path | None,
    update_finding: UpdateFindingFn,
    log_span: LogSpanFn | None = None,
    on_promoted: PromotedHook | None = None,
    verbose: bool = False,
    ledger_path: Any | None = None,
) -> dict[str, Any]:
    """Promote reviewed findings, then write dated report indexes from promoted rows.

    This keeps the team flow linear and traceable:
    review output -> FID patch/update -> promoted groups -> report indexes.
    Findings without a reserved FID, placeholders, or failed ledger updates are not
    included in report indexes.
    """

    promoted: dict[str, list[dict[str, Any]]] = {
        "confirmed": [],
        "dormant": [],
        "novel": [],
    }
    ledger_updates = 0

    for bucket in ("confirmed", "dormant", "novel"):
        for raw_finding in reviewed_groups.get(bucket, []):
            finding = dict(raw_finding)
            title = str(finding.get("vulnerability_name") or finding.get("type") or "").strip() or "untitled"
            if is_placeholder_finding(finding):
                print(f"[ledger] REJECTED placeholder finding: {title}", flush=True)
                continue

            fid = str(finding.get("fid", "")).strip()
            if not fid:
                print(f"[ledger] SKIPPED finding without reserved fid; skipping report index entry: {title}", flush=True)
                continue

            try:
                updated = update_finding(
                    program,
                    finding,
                    snapshot_id=str(snapshot_identity.get("snapshot_id") or ""),
                    version_label=str(snapshot_identity.get("version_label") or ""),
                    run_id=run_id,
                    agent=agent,
                    family=storage.family,
                    lane=storage.lane,
                    root_override=root_override,
                    write_report=True,
                    refresh=True,
                    update_current=False,
                    update_sighting=False,
                )
            except Exception as exc:
                print(f"[ledger] FAILED update {fid}; skipping report index entry: {exc}", flush=True)
                continue

            promoted[bucket].append(updated)
            ledger_updates += 1
            if verbose:
                ledger_target = ledger_path or getattr(storage, "ledgers_root", "ledger")
                print(f"[ledger] UPDATED {fid} via {ledger_target}")

            if on_promoted is not None:
                on_promoted(updated, fid, title)

            if log_span is not None:
                log_span(
                    span_type="finding",
                    level="RESULT",
                    message=f"Finding: {fid or title}",
                    finding_fid=fid or title,
                    review_tier=str(updated.get("review_tier") or updated.get("severity") or "UNKNOWN"),
                    duplicate=False,
                    finding_reward=0,
                    allocated_pte_lite=0,
                )

    report_paths = write_report_indexes(
        storage,
        confirmed=promoted["confirmed"],
        dormant=promoted["dormant"],
        novel=promoted["novel"],
        render_confirmed=_render_confirmed_report,
        render_dormant=_render_dormant_report,
        render_novel=_render_novel_findings_report,
    )

    reviewed = promoted["confirmed"] + promoted["dormant"] + promoted["novel"]
    return {
        "confirmed": promoted["confirmed"],
        "dormant": promoted["dormant"],
        "novel": promoted["novel"],
        "reviewed": reviewed,
        "ledger_updates": ledger_updates,
        "report_paths": report_paths,
    }
