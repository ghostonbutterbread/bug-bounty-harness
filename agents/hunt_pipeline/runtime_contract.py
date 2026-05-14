from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Mapping, Sequence

CONTRACT_SCHEMA_VERSION = 1
CONTRACT_STATUS_BLOCKED = "blocked"
PROMOTION_PROTOCOL_SCHEMA_VERSION = 1
PROMOTION_PROTOCOL_STATUS_DRAFT = "draft"


@dataclass(frozen=True, slots=True)
class RuntimeHandoffGate:
    id: str
    description: str
    required: bool = True


@dataclass(frozen=True, slots=True)
class RuntimeHandoffGateResult:
    gate_id: str
    required: bool
    passed: bool
    status: str
    details: str


@dataclass(frozen=True, slots=True)
class RuntimeHandoffContract:
    schema_version: int
    status: str
    required_gates: tuple[dict[str, Any], ...]
    gate_results: tuple[dict[str, Any], ...]
    promotion_allowed: bool = False
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RuntimePromotionProtocol:
    schema_version: int
    status: str
    promotion_enabled: bool
    required_approvals: tuple[dict[str, Any], ...]
    adapter_ownership_boundaries: tuple[dict[str, Any], ...]
    ledger_review_ownership_boundaries: tuple[dict[str, Any], ...]
    rollback_stop_semantics: dict[str, Any]
    future_promotion_steps: tuple[dict[str, Any], ...]
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


GateEvaluator = Callable[[Mapping[str, Any]], RuntimeHandoffGateResult]


def default_runtime_handoff_gates() -> tuple[RuntimeHandoffGate, ...]:
    return (
        RuntimeHandoffGate(
            "runtime_handoff_contract_present",
            "pipeline_plan.json carries a runtime_handoff_contract artifact",
        ),
        RuntimeHandoffGate(
            "runtime_adapter_non_live",
            "runtime adapter is conversion-only with spawning and ledger writes disabled",
        ),
        RuntimeHandoffGate(
            "static_team_invocation_disabled",
            "static team handoffs are metadata-only and cannot invoke teams",
        ),
        RuntimeHandoffGate(
            "dynamic_validation_disabled",
            "dynamic validation queue is disabled and empty",
        ),
        RuntimeHandoffGate(
            "safety_flags_non_live",
            "dry-run safety flags disable spawning, live validation, and ledger writes",
        ),
        RuntimeHandoffGate(
            "promotion_protocol_non_live",
            "runtime promotion protocol is present, draft-only, and cannot enable live execution",
        ),
        RuntimeHandoffGate(
            "explicit_contract_promotion",
            "future operator promotion has explicitly enabled live execution",
        ),
    )


def build_runtime_handoff_contract(
    plan: Mapping[str, Any],
    *,
    gates: Sequence[RuntimeHandoffGate] | None = None,
) -> RuntimeHandoffContract:
    configured_gates = tuple(gates or default_runtime_handoff_gates())
    results = tuple(_evaluate_gate(gate, plan) for gate in configured_gates)
    return RuntimeHandoffContract(
        schema_version=CONTRACT_SCHEMA_VERSION,
        status=CONTRACT_STATUS_BLOCKED,
        required_gates=tuple(asdict(gate) for gate in configured_gates),
        gate_results=tuple(asdict(result) for result in results),
        promotion_allowed=False,
        notes=(
            "Live execution remains disabled in this slice.",
            "A future promotion path must update this contract before --execute-live can spawn agents.",
        ),
    )


def build_runtime_promotion_protocol(
    *,
    status: str = PROMOTION_PROTOCOL_STATUS_DRAFT,
    promotion_enabled: bool = False,
    required_approvals: Sequence[Mapping[str, Any]] | None = None,
    adapter_ownership_boundaries: Sequence[Mapping[str, Any]] | None = None,
    ledger_review_ownership_boundaries: Sequence[Mapping[str, Any]] | None = None,
    rollback_stop_semantics: Mapping[str, Any] | None = None,
    future_promotion_steps: Sequence[Mapping[str, Any]] | None = None,
    notes: Sequence[str] | None = None,
) -> RuntimePromotionProtocol:
    """Build the design-only protocol artifact for a future live promotion."""

    return RuntimePromotionProtocol(
        schema_version=PROMOTION_PROTOCOL_SCHEMA_VERSION,
        status=str(status or PROMOTION_PROTOCOL_STATUS_DRAFT).strip() or PROMOTION_PROTOCOL_STATUS_DRAFT,
        promotion_enabled=bool(promotion_enabled is True),
        required_approvals=tuple(dict(item) for item in (required_approvals or _default_required_approvals())),
        adapter_ownership_boundaries=tuple(
            dict(item) for item in (adapter_ownership_boundaries or _default_adapter_ownership_boundaries())
        ),
        ledger_review_ownership_boundaries=tuple(
            dict(item) for item in (ledger_review_ownership_boundaries or _default_ledger_review_boundaries())
        ),
        rollback_stop_semantics=dict(rollback_stop_semantics or _default_rollback_stop_semantics()),
        future_promotion_steps=tuple(dict(item) for item in (future_promotion_steps or _default_future_promotion_steps())),
        notes=tuple(str(item) for item in (notes or _default_promotion_protocol_notes())),
    )


def evaluate_runtime_handoff_contract(plan: Mapping[str, Any]) -> dict[str, Any]:
    """Return current gate results from the plan without trusting stored results."""

    return build_runtime_handoff_contract(plan).to_dict()


def evaluate_runtime_promotion_protocol(plan: Mapping[str, Any]) -> dict[str, Any]:
    """Return a conservative summary of the stored promotion protocol artifact."""

    protocol = plan.get("runtime_promotion_protocol")
    if not isinstance(protocol, Mapping):
        return {
            "schema_version": 0,
            "status": "missing",
            "promotion_enabled": False,
            "valid": False,
            "details": "runtime_promotion_protocol is missing",
        }
    schema_version = _schema_version(protocol.get("schema_version"))
    required_approvals = protocol.get("required_approvals")
    adapter_boundaries = protocol.get("adapter_ownership_boundaries")
    ledger_review_boundaries = protocol.get("ledger_review_ownership_boundaries")
    rollback = protocol.get("rollback_stop_semantics")
    future_steps = protocol.get("future_promotion_steps")
    status = str(protocol.get("status") or "").strip()
    promotion_enabled = bool(protocol.get("promotion_enabled") is True)
    valid = (
        schema_version >= PROMOTION_PROTOCOL_SCHEMA_VERSION
        and status in {"draft", "blocked"}
        and promotion_enabled is False
        and _non_empty_mapping_sequence(required_approvals)
        and _non_empty_mapping_sequence(adapter_boundaries)
        and _non_empty_mapping_sequence(ledger_review_boundaries)
        and isinstance(rollback, Mapping)
        and _non_empty_mapping_sequence(future_steps)
    )
    if valid:
        details = "runtime_promotion_protocol is design-only and promotion_enabled is false"
    elif promotion_enabled:
        details = "runtime_promotion_protocol cannot enable promotion in this slice"
    else:
        details = "runtime_promotion_protocol is missing required draft-only structure"
    return {
        "schema_version": schema_version,
        "status": status or "malformed",
        "promotion_enabled": False,
        "stored_promotion_enabled": promotion_enabled,
        "valid": valid,
        "details": details,
    }


def promotion_allowed(plan: Mapping[str, Any]) -> bool:
    return bool(evaluate_runtime_handoff_contract(plan).get("promotion_allowed") is True)


def failed_required_gates(contract: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        dict(result)
        for result in contract.get("gate_results", ())
        if isinstance(result, Mapping)
        and bool(result.get("required", True))
        and not bool(result.get("passed", False))
    ]


def _evaluate_gate(gate: RuntimeHandoffGate, plan: Mapping[str, Any]) -> RuntimeHandoffGateResult:
    evaluators: dict[str, GateEvaluator] = {
        "runtime_handoff_contract_present": _gate_contract_present,
        "runtime_adapter_non_live": _gate_runtime_adapter_non_live,
        "static_team_invocation_disabled": _gate_static_team_invocation_disabled,
        "dynamic_validation_disabled": _gate_dynamic_validation_disabled,
        "safety_flags_non_live": _gate_safety_flags_non_live,
        "promotion_protocol_non_live": _gate_promotion_protocol_non_live,
        "explicit_contract_promotion": _gate_explicit_contract_promotion,
    }
    evaluator = evaluators.get(gate.id)
    if evaluator is None:
        return RuntimeHandoffGateResult(
            gate_id=gate.id,
            required=gate.required,
            passed=False,
            status="unknown",
            details="no evaluator is registered for this gate",
        )
    result = evaluator(plan)
    return RuntimeHandoffGateResult(
        gate_id=result.gate_id,
        required=gate.required,
        passed=result.passed,
        status=result.status,
        details=result.details,
    )


def _gate_contract_present(plan: Mapping[str, Any]) -> RuntimeHandoffGateResult:
    contract = plan.get("runtime_handoff_contract")
    passed = isinstance(contract, Mapping) and _schema_version(contract.get("schema_version")) >= CONTRACT_SCHEMA_VERSION
    return _result(
        "runtime_handoff_contract_present",
        passed,
        "runtime_handoff_contract schema_version is present"
        if passed
        else "runtime_handoff_contract is missing or has no supported schema_version",
    )


def _gate_runtime_adapter_non_live(plan: Mapping[str, Any]) -> RuntimeHandoffGateResult:
    adapter = plan.get("runtime_adapter_availability") if isinstance(plan.get("runtime_adapter_availability"), Mapping) else {}
    passed = (
        bool(adapter.get("conversion_only") is True)
        and bool(adapter.get("spawn_enabled") is False)
        and bool(adapter.get("ledger_writes_enabled") is False)
    )
    return _result(
        "runtime_adapter_non_live",
        passed,
        "adapter reports conversion-only non-live behavior"
        if passed
        else "adapter availability does not prove conversion-only non-live behavior",
    )


def _gate_static_team_invocation_disabled(plan: Mapping[str, Any]) -> RuntimeHandoffGateResult:
    handoffs = plan.get("static_team_handoffs") if isinstance(plan.get("static_team_handoffs"), Mapping) else {}
    planned = handoffs.get("planned") if isinstance(handoffs.get("planned"), list | tuple) else ()
    planned_shape_valid = isinstance(handoffs.get("planned", []), list | tuple)
    statuses = [
        item.get("invocation_status")
        for item in planned
        if isinstance(item, Mapping) and item.get("invocation_status") is not None
    ]
    passed = (
        planned_shape_valid
        and bool(handoffs.get("enabled") is False)
        and bool(handoffs.get("invocation_enabled") is False)
        and all(status == "planned-only" for status in statuses)
    )
    return _result(
        "static_team_invocation_disabled",
        passed,
        "static team handoffs are planned-only metadata"
        if passed
        else "static team handoff metadata could allow invocation",
    )


def _gate_dynamic_validation_disabled(plan: Mapping[str, Any]) -> RuntimeHandoffGateResult:
    queue = plan.get("dynamic_validation_queue") if isinstance(plan.get("dynamic_validation_queue"), Mapping) else {}
    queued = queue.get("queued") if isinstance(queue.get("queued"), list | tuple) else ()
    queued_shape_valid = isinstance(queue.get("queued", []), list | tuple)
    passed = queued_shape_valid and bool(queue.get("enabled") is False) and len(queued) == 0
    return _result(
        "dynamic_validation_disabled",
        passed,
        "dynamic validation is disabled and empty"
        if passed
        else "dynamic validation appears enabled or has queued work",
    )


def _gate_safety_flags_non_live(plan: Mapping[str, Any]) -> RuntimeHandoffGateResult:
    safety = plan.get("safety") if isinstance(plan.get("safety"), Mapping) else {}
    passed = (
        bool(safety.get("dry_run_only") is True)
        and bool(safety.get("spawn_agents") is False)
        and bool(safety.get("live_dynamic_validation") is False)
        and bool(safety.get("ledger_writes") is False)
    )
    return _result(
        "safety_flags_non_live",
        passed,
        "safety flags enforce dry-run-only execution"
        if passed
        else "safety flags do not enforce dry-run-only execution",
    )


def _gate_promotion_protocol_non_live(plan: Mapping[str, Any]) -> RuntimeHandoffGateResult:
    protocol = evaluate_runtime_promotion_protocol(plan)
    passed = bool(protocol.get("valid") is True and protocol.get("promotion_enabled") is False)
    return _result(
        "promotion_protocol_non_live",
        passed,
        "promotion protocol is present and draft-only"
        if passed
        else str(protocol.get("details") or "promotion protocol is not a valid draft-only artifact"),
    )


def _gate_explicit_contract_promotion(plan: Mapping[str, Any]) -> RuntimeHandoffGateResult:
    stored = plan.get("runtime_handoff_contract") if isinstance(plan.get("runtime_handoff_contract"), Mapping) else {}
    requested = bool(stored.get("promotion_requested") is True or stored.get("promotion_allowed") is True)
    return RuntimeHandoffGateResult(
        gate_id="explicit_contract_promotion",
        required=True,
        passed=False,
        status="not_promoted",
        details=(
            "promotion signal is present but promotion is not implemented in this slice"
            if requested
            else "contract has not been explicitly promoted for live execution"
        ),
    )


def _schema_version(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _result(gate_id: str, passed: bool, details: str) -> RuntimeHandoffGateResult:
    return RuntimeHandoffGateResult(
        gate_id=gate_id,
        required=True,
        passed=passed,
        status="passed" if passed else "failed",
        details=details,
    )


def _default_required_approvals() -> tuple[dict[str, Any], ...]:
    return (
        {
            "approval": "operator_live_execution_approval",
            "owner": "human-operator",
            "required": True,
            "evidence": "explicit command/config change outside the non-live slice",
        },
        {
            "approval": "runtime_contract_update_review",
            "owner": "hunt-pipeline-maintainer",
            "required": True,
            "evidence": "runtime_handoff_contract gates updated and reviewed",
        },
        {
            "approval": "ledger_review_owner_assignment",
            "owner": "findings-review-owner",
            "required": True,
            "evidence": "ledger, review, and report ownership documented before writes",
        },
    )


def _default_adapter_ownership_boundaries() -> tuple[dict[str, Any], ...]:
    return (
        {
            "owner": "hunt_pipeline.runtime_adapter",
            "owns": ["packet-to-spec conversion", "scheduler-decision-to-spec conversion"],
            "does_not_own": ["agent spawning", "live target mutation", "ledger writes"],
        },
        {
            "owner": "future live runtime adapter",
            "owns": ["spawn orchestration after promotion", "bounded execution status collection"],
            "activation": "must be introduced in a future slice with tests and explicit approval",
        },
    )


def _default_ledger_review_boundaries() -> tuple[dict[str, Any], ...]:
    return (
        {
            "owner": "base_team.review",
            "owns": ["finding review semantics", "review tier decisions"],
            "activation": "review-only until live ledger write path is promoted",
        },
        {
            "owner": "base_team.promotion/findings ledger",
            "owns": ["confirmed/dormant/novel report promotion", "durable ledger writes"],
            "activation": "disabled in this slice; requires explicit future owner handoff",
        },
    )


def _default_rollback_stop_semantics() -> dict[str, Any]:
    return {
        "stop_command": "hunt_pipeline stop",
        "pause_command": "hunt_pipeline pause",
        "rollback_behavior": "disable future live waves, preserve existing artifacts for review, do not delete ledgers",
        "active_wave_behavior": "future implementation must define whether active subprocesses are drained or killed",
        "default_on_protocol_error": "block promotion and keep execute-live rejected",
    }


def _default_future_promotion_steps() -> tuple[dict[str, Any], ...]:
    return (
        {
            "step": "land_live_runtime_adapter",
            "status": "future",
            "requires": ["adapter ownership boundaries", "spawn tests", "stop/pause behavior tests"],
        },
        {
            "step": "wire_static_team_invocation",
            "status": "future",
            "requires": ["operator approval", "bounded team allowlist", "no implicit static bundle execution"],
        },
        {
            "step": "wire_dynamic_validation",
            "status": "future",
            "requires": ["queue ownership", "transport policy", "target safety review"],
        },
        {
            "step": "wire_ledger_writes",
            "status": "future",
            "requires": ["review owner", "report promotion owner", "rollback semantics"],
        },
        {
            "step": "flip_promotion_enabled",
            "status": "blocked",
            "requires": ["all prior steps", "runtime_handoff_contract promotion gate update"],
        },
    )


def _default_promotion_protocol_notes() -> tuple[str, ...]:
    return (
        "This artifact is a promotion design protocol only.",
        "promotion_enabled=false is required; malformed or missing protocol data cannot imply promotion.",
        "--execute-live remains blocked by runtime_handoff_contract.",
    )


def _non_empty_mapping_sequence(value: Any) -> bool:
    return isinstance(value, list | tuple) and bool(value) and all(isinstance(item, Mapping) for item in value)
