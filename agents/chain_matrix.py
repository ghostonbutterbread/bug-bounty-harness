"""Capability-based exploit-chain matrix for reviewed findings."""

from __future__ import annotations

from typing import Any, Literal, cast
import re


Capability = Literal[
    "renderer_js_execution",
    "node_api_access",
    "ipc_bridge_invocation",
    "privileged_file_read",
    "privileged_file_write",
    "privileged_file_delete",
    "internal_http_request",
    "internal_http_response_read",
    "serialized_payload_control",
    "os_command_execution",
    "prototype_control",
    "native_memory_corruption",
]
RoleName = Literal["endpoint", "stepping_stone", "both"]

GRANTS: dict[str, list[Capability]] = {
    "dom-xss": ["renderer_js_execution"],
    "node-integration": ["node_api_access"],
    "ipc-trust-boundary": ["ipc_bridge_invocation", "privileged_file_read", "privileged_file_write"],
    "path-traversal": ["privileged_file_read", "privileged_file_write", "privileged_file_delete"],
    "prototype-pollution": ["prototype_control"],
    "unsafe-deserialization": ["os_command_execution"],
    "ssrf": ["internal_http_request", "internal_http_response_read", "serialized_payload_control"],
    "exec-sink-reachability": ["os_command_execution"],
    "native-module-abuse": ["os_command_execution", "privileged_file_read", "privileged_file_write"],
    "memory-unsafe-parser": ["native_memory_corruption", "os_command_execution"],
    "idor": ["privileged_file_read", "privileged_file_write"],
    "auth-bypass": [],
    "csrf": [],
    "session-fixation": [],
}

REQUIRES: dict[str, list[Capability]] = {
    "dom-xss": [],
    "node-integration": ["renderer_js_execution"],
    "ipc-trust-boundary": ["renderer_js_execution"],
    "prototype-pollution": [],
    "unsafe-deserialization": ["serialized_payload_control"],
    "ssrf": [],
    "exec-sink-reachability": ["renderer_js_execution", "node_api_access"],
    "native-module-abuse": ["renderer_js_execution", "node_api_access"],
    "memory-unsafe-parser": [],
    "path-traversal": [],
    "idor": [],
    "auth-bypass": [],
    "csrf": [],
    "session-fixation": [],
}

ROLE: dict[str, RoleName] = {
    "dom-xss": "stepping_stone",
    "node-integration": "stepping_stone",
    "ipc-trust-boundary": "both",
    "prototype-pollution": "stepping_stone",
    "unsafe-deserialization": "endpoint",
    "ssrf": "both",
    "exec-sink-reachability": "endpoint",
    "native-module-abuse": "endpoint",
    "memory-unsafe-parser": "endpoint",
    "path-traversal": "endpoint",
    "idor": "endpoint",
    "auth-bypass": "endpoint",
    "csrf": "endpoint",
    "session-fixation": "endpoint",
}

GRANT_INFERENCE_PATTERNS: list[tuple[re.Pattern[str], list[Capability]]] = [
    (re.compile(r"arbitrary (js|javascript|code) execution in renderer", re.IGNORECASE), ["renderer_js_execution"]),
    (re.compile(r"nodeIntegration|node integration enabled", re.IGNORECASE), ["node_api_access"]),
    (re.compile(r"preload|contextBridge|ipcRenderer", re.IGNORECASE), ["ipc_bridge_invocation"]),
    (re.compile(r"read.*file|file.*read|access.*filesystem", re.IGNORECASE), ["privileged_file_read"]),
    (re.compile(r"write.*file|file.*write|create.*file|plant.*file", re.IGNORECASE), ["privileged_file_write"]),
    (re.compile(r"delete.*file|remove.*file|unlink", re.IGNORECASE), ["privileged_file_delete"]),
    (re.compile(r"ssrf|server-side request|internal.*http|fetch.*internal", re.IGNORECASE), ["internal_http_request"]),
    (
        re.compile(r"response.*body|read.*response|deserialize|unserialize", re.IGNORECASE),
        ["internal_http_response_read", "serialized_payload_control"],
    ),
    (re.compile(r"rce|remote code execution|os command|shell|exec\(", re.IGNORECASE), ["os_command_execution"]),
    (re.compile(r"prototype.*pollution|__proto__|constructor\.prototype", re.IGNORECASE), ["prototype_control"]),
]


def build_chain_graph(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a chainability graph from confirmed and dormant reviewed findings."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    for finding in findings:
        tier = _review_tier(finding)
        if tier not in {"CONFIRMED", "DORMANT"}:
            continue
        vuln_class = _finding_vuln_class(finding)
        unknown_class = vuln_class not in ROLE
        grants = sorted(_infer_grants(finding, vuln_class))
        requires = sorted(set(REQUIRES.get(vuln_class, [])))
        role = ROLE.get(vuln_class, "endpoint")
        node_id = _finding_id(finding, len(nodes))
        nodes.append(
            {
                "id": node_id,
                "finding": finding,
                "vuln_class": vuln_class,
                "grants": grants,
                "requires": requires,
                "role": role,
                "unknown_class": unknown_class,
                "incoming": [],
                "outgoing": [],
            }
        )

    for source in nodes:
        source_grants = set(cast(list[Capability], source["grants"]))
        if not source_grants:
            continue
        for target in nodes:
            if source["id"] == target["id"]:
                continue
            target_requires = set(cast(list[Capability], target["requires"]))
            overlap = sorted(source_grants & target_requires)
            if not overlap:
                continue
            edge = {"from": source["id"], "to": target["id"], "via": overlap}
            edges.append(edge)
            source["outgoing"].append(edge)
            target["incoming"].append(edge)

    return {
        "nodes": nodes,
        "edges": edges,
        "chainable_node_ids": _chainable_node_ids(nodes),
    }


def get_chainable_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return reviewed findings worth sending to the exploit chainer."""
    graph = build_chain_graph(findings)
    chainable_ids = set(graph["chainable_node_ids"])
    chainable: list[dict[str, Any]] = []
    for node in graph["nodes"]:
        if node["id"] in chainable_ids:
            chainable.append(cast(dict[str, Any], node["finding"]))
    return chainable


def _review_tier(finding: dict[str, Any]) -> str:
    return str(finding.get("review_tier") or finding.get("tier") or "").strip().upper()


def _finding_vuln_class(finding: dict[str, Any]) -> str:
    class_name = str(finding.get("class_name", "")).strip().lower()
    if class_name and class_name != "novel":
        return class_name
    agent = str(finding.get("agent", "")).strip().lower()
    return agent or "unknown"


def _finding_id(finding: dict[str, Any], index: int) -> str:
    fid = str(finding.get("fid", "")).strip()
    if fid:
        return fid
    file_ref = str(finding.get("file", "")).strip() or f"finding-{index + 1}"
    finding_type = str(finding.get("type", "")).strip() or "finding"
    return f"{index + 1}:{file_ref}:{finding_type}"


def _infer_grants(finding: dict[str, Any], vuln_class: str) -> set[Capability]:
    grants: set[Capability] = set(GRANTS.get(vuln_class, []))
    haystack = " ".join(
        str(finding.get(key, "")).strip()
        for key in (
            "type",
            "description",
            "context",
            "source",
            "sink",
            "trust_boundary",
            "flow_path",
            "exploitability",
            "impact",
            "blocked_reason",
            "chain_requirements",
            "review_notes",
        )
    )
    for pattern, inferred_caps in GRANT_INFERENCE_PATTERNS:
        if pattern.search(haystack):
            grants.update(inferred_caps)
    return grants


def _chainable_node_ids(nodes: list[dict[str, Any]]) -> list[str]:
    if len(nodes) == 1:
        node = nodes[0]
        if node.get("unknown_class") or node.get("role") in {"endpoint", "both"}:
            return [str(node["id"])]
        return []

    chainable: list[str] = []
    for node in nodes:
        if node.get("unknown_class"):
            chainable.append(str(node["id"]))
            continue
        role = str(node.get("role", "endpoint"))
        incoming_count = len(node.get("incoming", []))
        outgoing_count = len(node.get("outgoing", []))
        if role == "stepping_stone" and outgoing_count == 0:
            continue
        if role in {"endpoint", "both"} and incoming_count > 0:
            chainable.append(str(node["id"]))
    return chainable
