"""Canva-specific Electron validation skeleton."""

from __future__ import annotations

from typing import Any

from ..models import EvidenceRecord, ValidationAction, ValidationTask
from .electron_base import ElectronBasePlaybook


CANVA_READ_ONLY_PROBES = (
    ("host-rpc", "Document HostRpc or bridge objects without invoking them"),
    ("native-image", "Inspect renderer-visible nativeImage exposure surfaces"),
    ("download-paths", "Check download or file handling surface exposure"),
    ("custom-protocols", "Document deep-link and custom protocol registration state"),
)

N03_REPORT_MARKERS = (
    "toast xml notification injection",
    "toast xml",
    "notification injection",
)

CANVA_RUNTIME_CONTEXT_EXPRESSION = """
(() => {
  const hasDocument = typeof document === "object" && document !== null;
  const hasLocation = typeof location === "object" && location !== null;
  const hasNavigator = typeof navigator === "object" && navigator !== null;
  const hasProcess = typeof process === "object" && process !== null;
  const versions = hasProcess && process.versions ? process.versions : null;
  return {
    targetKind: hasDocument ? "renderer" : "background",
    href: hasLocation ? location.href : null,
    origin: hasLocation ? location.origin : null,
    title: hasDocument ? document.title : null,
    readyState: hasDocument ? document.readyState : null,
    globalTag: Object.prototype.toString.call(globalThis),
    notificationType: typeof Notification,
    requireType: typeof require,
    processType: typeof process,
    navigatorUserAgent: hasNavigator ? navigator.userAgent : null,
    processVersions: versions ? {
      electron: versions.electron || null,
      chrome: versions.chrome || null,
      node: versions.node || null
    } : null
  };
})()
""".strip()

CANVA_NOTIFICATION_SURFACE_EXPRESSION = """
(() => {
  const globalNames = Object.getOwnPropertyNames(globalThis).sort();
  const pattern = /(toast|notification|desktop|bridge|electron|ipc|native|host|shell)/i;
  const matches = [];
  for (const name of globalNames) {
    if (!pattern.test(name)) {
      continue;
    }
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, name);
    if (!descriptor) {
      continue;
    }
    const entry = {
      name,
      enumerable: !!descriptor.enumerable,
      configurable: !!descriptor.configurable,
      hasGetter: typeof descriptor.get === "function",
      hasSetter: typeof descriptor.set === "function",
      valueType: descriptor.get || descriptor.set ? "accessor" : typeof descriptor.value
    };
    if ("value" in descriptor && descriptor.value && (typeof descriptor.value === "object" || typeof descriptor.value === "function")) {
      try {
        entry.ownKeys = Object.getOwnPropertyNames(descriptor.value).sort().slice(0, 50);
      } catch (error) {
        entry.ownKeysError = String(error && error.message ? error.message : error);
      }
    }
    matches.push(entry);
  }
  return {
    targetKind: typeof document === "object" && document !== null ? "renderer" : "background",
    matchedSurfaceCount: matches.length,
    matchedSurfaces: matches
  };
})()
""".strip()


class CanvaElectronPlaybook(ElectronBasePlaybook):
    name = "canva-electron"

    def plan(self, task: ValidationTask) -> list[ValidationAction]:
        actions = super().plan(task)
        for hypothesis, description in CANVA_READ_ONLY_PROBES:
            actions.append(
                ValidationAction(
                    kind="cdp_evaluate_read_only",
                    description=description,
                    target=task.cdp_url or "no-cdp-url",
                    metadata={"hypothesis": hypothesis},
                )
            )
        if task.metadata.get("mode") == "scout":
            actions.extend(
                [
                    ValidationAction(
                        kind="private_workflow_create",
                        description="Plan a single private workflow creation rehearsal without publishing",
                        target="private-workflow",
                        metadata={
                            "scope": "private",
                            "rehearsal_only": True,
                        },
                    ),
                    ValidationAction(
                        kind="canva_ai_private_chat",
                        description="Plan a bounded private Canva AI chat rehearsal without sharing or posting",
                        target="canva-ai-private-chat",
                        metadata={
                            "scope": "private",
                            "rehearsal_only": True,
                        },
                    ),
                ]
            )
        return actions

    def collect_preflight(
        self,
        task: ValidationTask,
        transport,
    ) -> list[EvidenceRecord]:
        evidence = super().collect_preflight(task, transport)
        if transport is None or not self._should_collect_n03_evidence(task):
            return evidence
        targets = self._select_probe_targets(transport.target_snapshots())
        runtime_context: list[dict[str, Any]] = []
        read_only_probe: list[dict[str, Any]] = []
        for target in targets:
            websocket_url = str(target.get("webSocketDebuggerUrl") or "").strip()
            if not websocket_url:
                continue
            runtime_context.append(
                {
                    "target": self._target_summary(target),
                    "evaluation": self._extract_evaluate_value(
                        transport.runtime_evaluate(websocket_url, CANVA_RUNTIME_CONTEXT_EXPRESSION)
                    ),
                }
            )
            read_only_probe.append(
                {
                    "target": self._target_summary(target),
                    "evaluation": self._extract_evaluate_value(
                        transport.runtime_evaluate(websocket_url, CANVA_NOTIFICATION_SURFACE_EXPRESSION)
                    ),
                }
            )
        evidence.extend(
            [
                EvidenceRecord(
                    kind="cdp_runtime_context",
                    name="cdp_runtime_context.json",
                    data={
                        "fid": task.fid,
                        "title": task.metadata.get("title", ""),
                        "type": task.metadata.get("type", ""),
                        "targets": runtime_context,
                    },
                    note="Read-only Runtime.evaluate context capture for Canva N03 validation.",
                ),
                EvidenceRecord(
                    kind="cdp_evaluate_read_only",
                    name="n03_read_only_probe.json",
                    data={
                        "fid": task.fid,
                        "title": task.metadata.get("title", ""),
                        "type": task.metadata.get("type", ""),
                        "targets": read_only_probe,
                    },
                    note="Read-only Runtime.evaluate probe for renderer-accessible notification and desktop bridge surfaces.",
                ),
            ]
        )
        return evidence

    @staticmethod
    def _should_collect_n03_evidence(task: ValidationTask) -> bool:
        if task.fid.strip().upper() == "N03":
            return True
        haystack = " ".join(
            [
                str(task.metadata.get("title") or ""),
                str(task.metadata.get("type") or ""),
            ]
        ).strip().lower()
        return any(marker in haystack for marker in N03_REPORT_MARKERS)

    @staticmethod
    def _select_probe_targets(targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
        selected: list[dict[str, Any]] = []
        renderer = None
        background = None
        for target in targets:
            if not str(target.get("webSocketDebuggerUrl") or "").strip():
                continue
            target_type = str(target.get("type") or "").strip().lower()
            if renderer is None and target_type in {"page", "webview"}:
                renderer = target
            if background is None and target_type in {"background_page", "service_worker", "shared_worker", "worker"}:
                background = target
        if renderer is not None:
            selected.append(renderer)
        if background is not None and background is not renderer:
            selected.append(background)
        return selected

    @staticmethod
    def _extract_evaluate_value(payload: dict[str, Any]) -> Any:
        result = payload.get("result", {})
        remote = result.get("result", {})
        if "value" in remote:
            return remote["value"]
        return remote

    @staticmethod
    def _target_summary(target: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": target.get("id", ""),
            "type": target.get("type", ""),
            "title": target.get("title", ""),
            "url": target.get("url", ""),
            "webSocketDebuggerUrl": target.get("webSocketDebuggerUrl", ""),
        }
