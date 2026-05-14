from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Mapping, Sequence

CONTRACT_SCHEMA_VERSION = 1
CONTRACT_STATUS_BLOCKED = "blocked"


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


def evaluate_runtime_handoff_contract(plan: Mapping[str, Any]) -> dict[str, Any]:
    """Return current gate results from the plan without trusting stored results."""

    return build_runtime_handoff_contract(plan).to_dict()


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
