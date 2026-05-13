"""Single-step bounded execution helpers for dynamic validation."""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from .models import EvidenceRecord, ValidationAction
from .transports import CDPTransportError


PLAN_ONLY_ACTIONS = frozenset(
    {
        "live_ipc_interaction",
        "local_ui_interaction",
        "private_document_create",
        "private_document_edit",
        "private_workflow_create",
        "canva_ai_private_chat",
        "use_template",
        "install_store_app",
        "offline_user_equivalent_action",
    }
)
SUPPORTED_PRIMITIVES = frozenset({"runtime_evaluate"})
PAGE_LIKE_TARGET_TYPES = frozenset({"page", "webview"})

SAFE_RUNTIME_EXPRESSIONS = {
    "location_summary": """
(() => ({
  href: typeof location === "object" && location ? location.href : null,
  origin: typeof location === "object" && location ? location.origin : null,
  title: typeof document === "object" && document ? document.title : null,
  readyState: typeof document === "object" && document ? document.readyState : null
}))()
""".strip(),
    "bridge_type_summary": """
(() => ({
  electronBridgeType: typeof ElectronBridge,
  hostRpcType: typeof HostRpc,
  notificationType: typeof Notification,
  processType: typeof process,
  requireType: typeof require
}))()
""".strip(),
    "desktop_surface_inventory": """
(() => {
  const pattern = /(toast|notification|desktop|bridge|electron|ipc|native|host|shell)/i;
  const matches = [];
  for (const name of Object.getOwnPropertyNames(globalThis).sort()) {
    if (!pattern.test(name)) continue;
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, name);
    if (!descriptor) continue;
    matches.push({
      name,
      enumerable: !!descriptor.enumerable,
      configurable: !!descriptor.configurable,
      valueType: descriptor.get || descriptor.set ? "accessor" : typeof descriptor.value
    });
  }
  return { matchedSurfaceCount: matches.length, matchedSurfaces: matches };
})()
""".strip(),
}


def action_requires_transport(action: ValidationAction) -> bool:
    if action.kind in {"cdp_version", "cdp_list_targets", "cdp_target_snapshot", "cdp_capture_screenshot"}:
        return True
    if action.kind == "cdp_evaluate_read_only":
        return True
    if action.kind in PLAN_ONLY_ACTIONS and str(action.metadata.get("primitive") or "").strip() in SUPPORTED_PRIMITIVES:
        return True
    return False


def execute_action(
    action: ValidationAction,
    *,
    transport,
) -> tuple[str, str, list[EvidenceRecord], dict[str, Any]]:
    if action.kind == "cdp_version":
        if transport is None:
            raise CDPTransportError("cdp_version requires a CDP transport")
        version = transport.json_version()
        return (
            "executed",
            "Collected CDP version metadata for the requested action.",
            [
                EvidenceRecord(
                    kind="cdp_version",
                    name="cdp_version.json",
                    data=version,
                    note="CDP version metadata for the execute-action run.",
                )
            ],
            {"executed_primitive": "json_version"},
        )
    if action.kind == "cdp_list_targets":
        if transport is None:
            raise CDPTransportError("cdp_list_targets requires a CDP transport")
        targets = transport.target_snapshots()
        return (
            "executed",
            "Collected CDP target metadata for the requested action.",
            [
                EvidenceRecord(
                    kind="cdp_list_targets",
                    name="cdp_target_list.json",
                    data=targets,
                    note="CDP target enumeration for the execute-action run.",
                )
            ],
            {"executed_primitive": "target_snapshots"},
        )
    if action.kind == "cdp_target_snapshot":
        if transport is None:
            raise CDPTransportError("cdp_target_snapshot requires a CDP transport")
        snapshot = transport.snapshot()
        return (
            "executed",
            "Collected a CDP target snapshot for the requested action.",
            [
                EvidenceRecord(
                    kind="cdp_target_snapshot",
                    name="cdp_snapshot.json",
                    data=snapshot,
                    note="CDP snapshot for the execute-action run.",
                )
            ],
            {"executed_primitive": "snapshot"},
        )
    if action.kind == "cdp_capture_screenshot":
        if transport is None:
            raise CDPTransportError("cdp_capture_screenshot requires a CDP transport")
        state, summary, evidence, metadata = _capture_screenshot_action(transport, action)
        return state, summary, evidence, metadata
    if action.kind == "cdp_evaluate_read_only":
        if transport is None:
            raise CDPTransportError("cdp_evaluate_read_only requires a CDP transport")
        state, summary, evidence, metadata = _runtime_evaluate_action(
            transport,
            action,
            executed_primitive="cdp_evaluate_read_only",
        )
        return state, summary, evidence, metadata
    if action.kind in PLAN_ONLY_ACTIONS:
        primitive = str(action.metadata.get("primitive") or "").strip()
        if primitive == "runtime_evaluate":
            if transport is None:
                raise CDPTransportError(f"{action.kind} with runtime_evaluate requires a CDP transport")
            state, summary, evidence, metadata = _runtime_evaluate_action(
                transport,
                action,
                executed_primitive="runtime_evaluate",
            )
            return state, summary, evidence, metadata
        return (
            "planned",
            "Recorded a bounded executable step plan only; no live UI action ran.",
            [
                EvidenceRecord(
                    kind="plan",
                    name="step_plan.md",
                    data=_render_step_plan(action),
                    note="Executable step plan captured without live UI improvisation.",
                )
            ],
            {
                "executed_primitive": "",
                "supported_primitives": sorted(SUPPORTED_PRIMITIVES),
                "stop_reason": "action requires an explicit supported primitive before live execution",
            },
        )
    return (
        "planned",
        "Recorded the requested action metadata, but this MVP does not execute that action kind yet.",
        [
            EvidenceRecord(
                kind="plan",
                name="step_plan.md",
                data=_render_step_plan(action),
                note="Action recorded for bounded follow-up without improvisation.",
            )
        ],
        {
            "executed_primitive": "",
            "supported_primitives": sorted(SUPPORTED_PRIMITIVES),
            "stop_reason": "action kind is not executable in the MVP",
        },
    )


def _render_step_plan(action: ValidationAction) -> str:
    metadata_json = json.dumps(action.metadata, indent=2, sort_keys=True)
    return "\n".join(
        [
            "# Execute Action Plan",
            "",
            f"- Action kind: `{action.kind}`",
            f"- Description: {action.description}",
            f"- Target ref: `{action.target or 'unspecified'}`",
            "- Supported explicit primitives in this MVP: `runtime_evaluate`",
            "- Stop condition: do not improvise clicks, typing, navigation, or multi-step UI workflows.",
            "",
            "## Action metadata",
            "",
            "```json",
            metadata_json,
            "```",
            "",
        ]
    )


def _runtime_evaluate_action(
    transport,
    action: ValidationAction,
    *,
    executed_primitive: str,
) -> tuple[str, str, list[EvidenceRecord], dict[str, Any]]:
    expression, expression_id = _safe_runtime_expression(action)
    pre_targets = transport.target_snapshots()
    selected_target = _select_target(pre_targets, action)
    websocket_url = str(selected_target.get("webSocketDebuggerUrl") or "").strip()
    if not websocket_url:
        raise CDPTransportError("selected target does not expose webSocketDebuggerUrl")
    response = transport.runtime_evaluate(websocket_url, expression)
    evaluation = _extract_evaluate_value(response)
    evidence = [
        EvidenceRecord(
            kind="cdp_target_snapshot",
            name="cdp_targets_before.json",
            data=pre_targets,
            note="CDP targets before the runtime evaluation step.",
        ),
        EvidenceRecord(
            kind="target",
            name="selected_target.json",
            data=_target_summary(selected_target),
            note="CDP target selected for the runtime evaluation step.",
        ),
        EvidenceRecord(
            kind="cdp_evaluate_read_only",
            name="runtime_evaluate_result.json",
            data={
                "action_kind": action.kind,
                "description": action.description,
                "safe_expression_id": expression_id,
                "expression": expression,
                "target": _target_summary(selected_target),
                "result": evaluation,
            },
            note="Runtime.evaluate result for the execute-action run.",
        ),
    ]
    evidence.extend(_optional_screenshot_evidence(transport, selected_target))
    post_targets = transport.target_snapshots()
    evidence.append(
        EvidenceRecord(
            kind="cdp_target_snapshot",
            name="cdp_targets_after.json",
            data=post_targets,
            note="CDP targets after the runtime evaluation step.",
        )
    )
    return (
        "executed",
        "Executed one bounded runtime evaluation step against the selected CDP target.",
        evidence,
        {
            "executed_primitive": executed_primitive,
            "target": _target_summary(selected_target),
        },
    )


def _capture_screenshot_action(
    transport,
    action: ValidationAction,
) -> tuple[str, str, list[EvidenceRecord], dict[str, Any]]:
    pre_targets = transport.target_snapshots()
    selected_target = _select_target(pre_targets, action)
    websocket_url = str(selected_target.get("webSocketDebuggerUrl") or "").strip()
    if not websocket_url:
        raise CDPTransportError("selected target does not expose webSocketDebuggerUrl")
    command = transport.build_screenshot_command()
    payload = transport.capture_screenshot(websocket_url)
    result = payload.get("result")
    if not isinstance(result, dict):
        raise CDPTransportError("Page.captureScreenshot did not return a result object")
    data = result.get("data")
    if not isinstance(data, str) or not data.strip():
        raise CDPTransportError("Page.captureScreenshot did not return screenshot data")
    image_format = str(command.get("params", {}).get("format") or "png").strip() or "png"
    try:
        screenshot_bytes = base64.b64decode(data.encode("utf-8"))
    except binascii.Error as exc:
        raise CDPTransportError("Page.captureScreenshot returned invalid base64 data") from exc
    post_targets = transport.target_snapshots()
    evidence = [
        EvidenceRecord(
            kind="cdp_target_snapshot",
            name="cdp_targets_before.json",
            data=pre_targets,
            note="CDP targets before the screenshot step.",
        ),
        EvidenceRecord(
            kind="target",
            name="selected_target.json",
            data=_target_summary(selected_target),
            note="CDP target selected for the screenshot step.",
        ),
        EvidenceRecord(
            kind="command",
            name="screenshot_command.json",
            data=command,
            note="Page.captureScreenshot command issued for the execute-action run.",
        ),
        EvidenceRecord(
            kind="screenshot",
            name=f"screenshot.{image_format}",
            data=screenshot_bytes,
            note="Captured screenshot evidence from the selected CDP target.",
        ),
        EvidenceRecord(
            kind="cdp_target_snapshot",
            name="cdp_targets_after.json",
            data=post_targets,
            note="CDP targets after the screenshot step.",
        ),
    ]
    return (
        "executed",
        "Captured one bounded screenshot from the selected CDP target.",
        evidence,
        {
            "executed_primitive": "cdp_capture_screenshot",
            "target": _target_summary(selected_target),
        },
    )


def _optional_screenshot_evidence(transport, target: dict[str, Any]) -> list[EvidenceRecord]:
    websocket_url = str(target.get("webSocketDebuggerUrl") or "").strip()
    if not websocket_url:
        return []
    command = transport.build_screenshot_command()
    evidence = [
        EvidenceRecord(
            kind="command",
            name="screenshot_command.json",
            data=command,
            note="Best-effort screenshot command associated with the runtime evaluation step.",
        )
    ]
    try:
        payload = transport.capture_screenshot(websocket_url)
        result = payload.get("result")
        if not isinstance(result, dict):
            raise CDPTransportError("Page.captureScreenshot did not return a result object")
        data = result.get("data")
        if not isinstance(data, str) or not data.strip():
            raise CDPTransportError("Page.captureScreenshot did not return screenshot data")
        image_format = str(command.get("params", {}).get("format") or "png").strip() or "png"
        try:
            screenshot_bytes = base64.b64decode(data.encode("utf-8"))
        except binascii.Error as exc:
            raise CDPTransportError("Page.captureScreenshot returned invalid base64 data") from exc
        evidence.append(
            EvidenceRecord(
                kind="screenshot",
                name=f"runtime_evaluate_screenshot.{image_format}",
                data=screenshot_bytes,
                note="Best-effort screenshot captured after the runtime evaluation step.",
            )
        )
    except Exception as exc:
        evidence.append(
            EvidenceRecord(
                kind="warning",
                name="screenshot_error.json",
                data={"message": str(exc)},
                note="Best-effort screenshot capture failed after runtime evaluation.",
            )
        )
    return evidence


def _select_target(targets: list[dict[str, Any]], action: ValidationAction) -> dict[str, Any]:
    websocket_targets = [target for target in targets if str(target.get("webSocketDebuggerUrl") or "").strip()]
    selectors = {
        "id": str(action.metadata.get("target_id") or "").strip(),
        "title": str(action.metadata.get("target_title") or action.metadata.get("title") or "").strip(),
        "url": str(action.metadata.get("target_url") or action.metadata.get("url") or "").strip(),
        "type": str(action.metadata.get("target_type") or action.metadata.get("type") or "").strip(),
    }
    if any(selectors.values()):
        matches = [target for target in websocket_targets if _matches_target(target, selectors)]
        return _unique_target(matches, "requested selectors")
    target_ref = str(action.target or "").strip()
    if target_ref:
        matches = []
        for target in websocket_targets:
            for key in ("id", "title", "url", "type"):
                value = str(target.get(key) or "").strip()
                if value and value == target_ref:
                    matches.append(target)
                    break
        return _unique_target(matches, "target-ref")
    page_like_targets = [
        target for target in websocket_targets if str(target.get("type") or "").strip().lower() in PAGE_LIKE_TARGET_TYPES
    ]
    if len(websocket_targets) == 1:
        return websocket_targets[0]
    if len(page_like_targets) > 1:
        raise CDPTransportError("multiple page-like CDP targets are available; provide an exact target selector")
    if websocket_targets:
        raise CDPTransportError("multiple CDP targets are available; provide an exact target selector")
    raise CDPTransportError("no CDP targets with webSocketDebuggerUrl are available")


def _matches_target(target: dict[str, Any], selectors: dict[str, str]) -> bool:
    if selectors["id"] and str(target.get("id") or "").strip() != selectors["id"]:
        return False
    if selectors["title"]:
        title = str(target.get("title") or "").strip()
        needle = selectors["title"]
        if title != needle:
            return False
    if selectors["url"]:
        url = str(target.get("url") or "").strip()
        needle = selectors["url"]
        if url != needle:
            return False
    if selectors["type"]:
        target_type = str(target.get("type") or "").strip().lower()
        if target_type != selectors["type"].lower():
            return False
    return True


def _unique_target(matches: list[dict[str, Any]], selector_name: str) -> dict[str, Any]:
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise CDPTransportError(f"no CDP target matched the {selector_name}")
    raise CDPTransportError(f"multiple CDP targets matched the {selector_name}; provide a unique selector")


def _safe_runtime_expression(action: ValidationAction) -> tuple[str, str]:
    expression_id = str(action.metadata.get("safe_expression_id") or "").strip()
    if expression_id:
        expression = SAFE_RUNTIME_EXPRESSIONS.get(expression_id)
        if expression is None:
            raise CDPTransportError(f"unsupported safe_expression_id: {expression_id}")
        return expression, expression_id

    expression = str(action.metadata.get("expression") or "").strip()
    if expression in SAFE_RUNTIME_EXPRESSIONS.values():
        for known_id, known_expression in SAFE_RUNTIME_EXPRESSIONS.items():
            if expression == known_expression:
                return expression, known_id

    raise CDPTransportError(
        "runtime evaluation requires metadata.safe_expression_id from the built-in safe expression allowlist"
    )


def _extract_evaluate_value(payload: dict[str, Any]) -> Any:
    result = payload.get("result", {})
    remote = result.get("result", {})
    if "value" in remote:
        return remote["value"]
    return remote


def _target_summary(target: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": target.get("id", ""),
        "type": target.get("type", ""),
        "title": target.get("title", ""),
        "url": target.get("url", ""),
        "webSocketDebuggerUrl": target.get("webSocketDebuggerUrl", ""),
    }
