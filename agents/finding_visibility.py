"""Finding visibility rules for default work-selection surfaces."""

from __future__ import annotations

from typing import Any

SUBMISSION_STATES = frozenset({"not_submitted", "submitted", "dropped"})
SUBMISSION_RESULTS = frozenset({"valid", "duplicate"})


def normalize_submission(
    value: Any,
    *,
    report: str | None = None,
    result: str | None = None,
) -> dict[str, str]:
    """Return the small, operator-owned submission record for one finding."""
    incoming = value if isinstance(value, dict) else {}
    state = str(incoming.get("state") or "not_submitted").strip().lower()
    if state not in SUBMISSION_STATES:
        raise ValueError(f"invalid submission state: {state}; use one of {sorted(SUBMISSION_STATES)}")
    normalized = {"state": state}
    report_value = str((incoming.get("report") if report is None else report) or "").strip()
    if report_value:
        normalized["report"] = report_value
    result_value = str((incoming.get("result") if result is None else result) or "").strip().lower()
    if result_value:
        if result_value not in SUBMISSION_RESULTS:
            raise ValueError(f"invalid submission result: {result_value}; use one of {sorted(SUBMISSION_RESULTS)}")
        normalized["result"] = result_value
    return normalized


def submission_state(finding: dict[str, Any]) -> str:
    return normalize_submission(finding.get("submission")).get("state", "not_submitted")


def is_closed_finding(finding: dict[str, Any]) -> bool:
    """True when a finding is visible for lookup/dedupe, not default new work."""
    status = str(finding.get("status") or "").strip().lower()
    current = finding.get("current")
    current_status = str(current.get("status") or "").strip().lower() if isinstance(current, dict) else ""
    review_tier = str(finding.get("review_tier") or finding.get("tier") or "").strip().upper()
    return status == "confirmed" or current_status == "confirmed" or review_tier == "CONFIRMED" or submission_state(finding) != "not_submitted"


def visible_for_default_work(findings: list[dict[str, Any]], *, include_closed: bool = False) -> list[dict[str, Any]]:
    if include_closed:
        return list(findings)
    return [finding for finding in findings if not is_closed_finding(finding)]
