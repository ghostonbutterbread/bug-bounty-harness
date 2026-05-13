"""Dataclasses for dynamic validation tasks and outputs."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


PolicyDecisionKind = str
VerdictState = str


def _jsonify(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (bytes, bytearray)):
        return {"__bytes__": len(value)}
    if isinstance(value, list):
        return [_jsonify(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonify(item) for key, item in value.items()}
    return value


@dataclass(slots=True)
class ValidationAction:
    kind: str
    description: str
    target: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    target_impact: bool = False
    vendor_impact: bool = False

    def to_dict(self) -> dict[str, Any]:
        return _jsonify(asdict(self))


@dataclass(slots=True)
class PolicyDecision:
    action_kind: str
    decision: PolicyDecisionKind
    reason: str
    action: ValidationAction | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = _jsonify(asdict(self))
        if self.action is not None:
            payload["action"] = self.action.to_dict()
        return payload


@dataclass(slots=True)
class EvidenceRecord:
    kind: str
    name: str
    data: Any = None
    path: Path | None = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _jsonify(asdict(self))


@dataclass(slots=True)
class ValidationTask:
    run_id: str
    program: str
    family: str
    lane: str
    target: str
    account: str
    vm: str
    fid: str = ""
    report_path: Path | None = None
    status: str = ""
    review_tier: str = ""
    cdp_url: str | None = None
    playbook: str = "electron-base"
    dry_run: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)
    actions: list[ValidationAction] = field(default_factory=list)

    def queue_key(self) -> str:
        return f"{self.target}:{self.lane}:{self.account}:{self.vm}"

    def to_dict(self) -> dict[str, Any]:
        payload = _jsonify(asdict(self))
        payload["actions"] = [action.to_dict() for action in self.actions]
        return payload


@dataclass(slots=True)
class ValidationVerdict:
    state: VerdictState
    summary: str
    run_id: str
    fid: str = ""
    report_path: Path | None = None
    dry_run: bool = True
    evidence: list[EvidenceRecord] = field(default_factory=list)
    policy_decisions: list[PolicyDecision] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = _jsonify(asdict(self))
        payload["evidence"] = [record.to_dict() for record in self.evidence]
        payload["policy_decisions"] = [decision.to_dict() for decision in self.policy_decisions]
        return payload
