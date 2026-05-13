"""Base playbook interfaces."""

from __future__ import annotations

from .typing import TransportLike
from ..models import EvidenceRecord, ValidationAction, ValidationTask


class ValidationPlaybook:
    name = "base"

    def plan(self, task: ValidationTask) -> list[ValidationAction]:
        return []

    def collect_preflight(
        self,
        task: ValidationTask,
        transport: TransportLike | None,
    ) -> list[EvidenceRecord]:
        _ = task
        _ = transport
        return []
