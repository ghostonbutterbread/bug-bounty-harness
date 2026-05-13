"""Reusable Electron playbook primitives."""

from __future__ import annotations

from ..models import EvidenceRecord, ValidationAction, ValidationTask
from .base import ValidationPlaybook
from .typing import TransportLike


class ElectronBasePlaybook(ValidationPlaybook):
    name = "electron-base"

    def plan(self, task: ValidationTask) -> list[ValidationAction]:
        cdp_target = task.cdp_url or "no-cdp-url"
        return [
            ValidationAction(
                kind="cdp_version",
                description="Collect Electron and Chromium version metadata",
                target=cdp_target,
            ),
            ValidationAction(
                kind="cdp_list_targets",
                description="List available CDP targets",
                target=cdp_target,
            ),
            ValidationAction(
                kind="cdp_target_snapshot",
                description="Persist a basic CDP target snapshot",
                target=cdp_target,
            ),
        ]

    def collect_preflight(
        self,
        task: ValidationTask,
        transport: TransportLike | None,
    ) -> list[EvidenceRecord]:
        if transport is None:
            return [
                EvidenceRecord(
                    kind="notes",
                    name="notes.md",
                    data=f"# Dry Run\n\nNo CDP endpoint provided for `{task.program}`.\n",
                )
            ]
        version = transport.json_version()
        targets = transport.target_snapshots()
        snapshot = {
            "version": version,
            "targets": targets,
        }
        return [
            EvidenceRecord(
                kind="cdp_version",
                name="cdp_version.json",
                data=version,
                note="Read-only CDP version preflight",
            ),
            EvidenceRecord(
                kind="cdp_list_targets",
                name="cdp_target_list.json",
                data=targets,
                note="Read-only CDP target enumeration",
            ),
            EvidenceRecord(
                kind="cdp_snapshot",
                name="cdp_snapshot.json",
                data=snapshot,
                note="Read-only CDP preflight snapshot",
            )
        ]
