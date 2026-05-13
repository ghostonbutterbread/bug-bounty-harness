"""Safety gate for dynamic validation actions."""

from __future__ import annotations

from .models import PolicyDecision, ValidationAction


DEFAULT_ALLOWED_ACTIONS = {
    "cdp_version",
    "cdp_list_targets",
    "cdp_target_snapshot",
    "cdp_evaluate_read_only",
    "cdp_capture_screenshot",
    "collect_console_logs",
    "live_ipc_interaction",
    "local_ui_interaction",
    "open_controlled_local_file",
    "private_document_create",
    "private_document_edit",
    "private_workflow_create",
    "canva_ai_private_chat",
    "use_template",
    "install_store_app",
    "offline_user_equivalent_action",
    "vm_command_read_only",
}

DEFAULT_REQUIRES_APPROVAL_ACTIONS = {
}

DEFAULT_DENIED_ACTIONS = {
    "change_account_settings",
    "delete_account",
    "delete_data",
    "modify_account",
    "publish_content",
    "post_public_comment",
    "public_share",
    "contact_support",
    "send_support_request",
    "purchase_asset",
    "send_message",
    "send_invite",
    "bulk_create_assets",
    "modify_team",
    "modify_billing",
    "trigger_payment",
    "scrape_private_data",
    "vm_command_destructive",
    "generate_large_traffic",
}


class PolicyGate:
    """Evaluate whether a validation action is safe to execute."""

    def __init__(
        self,
        *,
        allowed_actions: set[str] | None = None,
        requires_approval_actions: set[str] | None = None,
        denied_actions: set[str] | None = None,
        operator_approved_actions: set[str] | None = None,
    ) -> None:
        self.operator_approved_actions = set(operator_approved_actions or ())
        self.allowed_actions = set(allowed_actions or DEFAULT_ALLOWED_ACTIONS) | self.operator_approved_actions
        self.requires_approval_actions = (
            set(requires_approval_actions or DEFAULT_REQUIRES_APPROVAL_ACTIONS) - self.operator_approved_actions
        )
        self.denied_actions = set(denied_actions or DEFAULT_DENIED_ACTIONS)

    def evaluate(self, action: ValidationAction) -> PolicyDecision:
        if action.vendor_impact:
            return PolicyDecision(
                action_kind=action.kind,
                decision="deny",
                reason="vendor-impacting actions are denied by default",
                action=action,
            )
        if action.kind in self.denied_actions:
            return PolicyDecision(
                action_kind=action.kind,
                decision="deny",
                reason="action is denied by the dynamic validation safety policy",
                action=action,
            )
        if action.kind in self.operator_approved_actions:
            return PolicyDecision(
                action_kind=action.kind,
                decision="allow",
                reason="action is operator-approved for this bounded dynamic validation run",
                action=action,
            )
        if action.kind in self.allowed_actions:
            return PolicyDecision(
                action_kind=action.kind,
                decision="allow",
                reason="action is allowed inside the bounded local test-user sandbox",
                action=action,
            )
        if action.kind in self.requires_approval_actions:
            return PolicyDecision(
                action_kind=action.kind,
                decision="requires_approval",
                reason="action is bounded but still requires explicit operator approval",
                action=action,
            )
        return PolicyDecision(
            action_kind=action.kind,
            decision="deny",
            reason="unknown dynamic action kind is denied by default",
            action=action,
        )

    def evaluate_actions(self, actions: list[ValidationAction]) -> list[PolicyDecision]:
        return [self.evaluate(action) for action in actions]
