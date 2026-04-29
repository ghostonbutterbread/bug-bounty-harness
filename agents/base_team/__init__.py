"""Shared BaseTeam package for storage, reports, runtime, and review helpers."""

from .apk_compat import load_findings, run_agent_session
from .compat import AgentSession, ensure_directory, pretty_print_findings, reset_findings_store, summarize_findings, write_chainable_findings_input
from .findings import (
    extract_findings_from_log,
    finding_identity,
    normalize_finding,
    normalize_relpath,
    read_findings_jsonl,
    safe_int,
)
from .ledger import load_ledger, save_ledger
from .reports import dated_report_index_paths, write_report_indexes
from .review import (
    build_review_prompt,
    normalize_review_tier,
    review_single_finding,
    run_review_cli,
    stage2_ghost_review,
    stage2_review,
)
from .reporting_compat import display_file_reference, is_placeholder_finding, split_file_reference
from .runtime import install_signal_handlers, orchestrate, spawn_agent, wait_for_agents, write_traces
from .storage import resolve_team_storage

# Compatibility re-export layer:
# The repo currently uses the package namespace `agents.base_team` as the
# stable public surface, while the main implementation class still lives in
# `agents.base_team_core` during the incremental extraction.
from agents.base_team_core import AgentSpec, BaseTeam  # type: ignore

__all__ = [
    "AgentSpec",
    "BaseTeam",
    "AgentSession",
    "build_review_prompt",
    "dated_report_index_paths",
    "ensure_directory",
    "extract_findings_from_log",
    "finding_identity",
    "display_file_reference",
    "install_signal_handlers",
    "is_placeholder_finding",
    "load_findings",
    "load_ledger",
    "normalize_finding",
    "normalize_relpath",
    "normalize_review_tier",
    "orchestrate",
    "pretty_print_findings",
    "read_findings_jsonl",
    "reset_findings_store",
    "resolve_team_storage",
    "review_single_finding",
    "run_agent_session",
    "run_review_cli",
    "safe_int",
    "save_ledger",
    "spawn_agent",
    "split_file_reference",
    "stage2_ghost_review",
    "stage2_review",
    "summarize_findings",
    "wait_for_agents",
    "write_chainable_findings_input",
    "write_report_indexes",
    "write_traces",
]
