#!/usr/bin/env python3
"""Read-only static analysis for remote code execution primitives."""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import textwrap
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


SEVERITY_ORDER = {
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}

LANGUAGE_EXTENSIONS = {
    "python": {".py"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"},
    "c": {".c", ".h"},
    "cpp": {".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx"},
}

USER_CONTROLLED_NAME_RE = re.compile(
    r"(?:user|input|request|req|param|query|body|form|json|payload|data|cmd|command|expr|code|template)",
    re.IGNORECASE,
)

WEB_INPUT_RE = re.compile(
    r"(?:req|request|ctx|context|params|query|body|argv|location|cookie|headers|input)",
    re.IGNORECASE,
)

ROUTE_DECORATORS = {
    "route",
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "options",
    "head",
}

# Downstream agent templates interpolate {program} and {vuln_type}; keep these
# placeholders literal so follow-on agents can generate target-aware comments.


@dataclass(slots=True)
class Finding:
    rule_id: str
    vuln_type: str
    severity: str
    language: str
    file: str
    line: int
    sink: str
    description: str
    exploit_scenario: str
    snippet: str
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "language": self.language,
            "file": self.file,
            "line": self.line,
            "sink": self.sink,
            "description": self.description,
            "exploit_scenario": self.exploit_scenario,
            "snippet": self.snippet,
            "tags": self.tags,
            "comment_template": "Review {program} for {vuln_type} exposure at this sink.",
        }


@dataclass(slots=True)
class FunctionContext:
    name: str
    route_handler: bool
    user_controlled: set[str]


class PythonAnalyzer(ast.NodeVisitor):
    """AST-backed Python analyzer focused on RCE primitives."""

    def __init__(self, path: Path, source: str):
        self.path = path
        self.source = source
        self.lines = source.splitlines()
        self.findings: list[Finding] = []
        self._dedupe: set[tuple[str, int, str]] = set()
        self._contexts: list[FunctionContext] = []
        self._imports: dict[str, str] = {}

    def analyze(self) -> list[Finding]:
        tree = ast.parse(self.source, filename=str(self.path))
        self.visit(tree)
        return self.findings

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        ctx = self._current_context()
        if ctx and self._expr_uses_user_input(node.value, ctx):
            for target in node.targets:
                for name in self._extract_target_names(target):
                    ctx.user_controlled.add(name)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        ctx = self._current_context()
        if ctx and node.value and self._expr_uses_user_input(node.value, ctx):
            for name in self._extract_target_names(node.target):
                ctx.user_controlled.add(name)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._imports[alias.asname or alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            imported_name = f"{module}.{alias.name}".strip(".")
            self._imports[alias.asname or alias.name] = imported_name
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        ctx = self._current_context()
        call_name = self._call_name(node.func)
        if not call_name:
            self.generic_visit(node)
            return

        self._check_python_rce_calls(node, call_name, ctx)
        self.generic_visit(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        route_handler = any(self._is_route_decorator(decorator) for decorator in node.decorator_list)
        user_controlled = {arg.arg for arg in node.args.args}
        if node.args.vararg:
            user_controlled.add(node.args.vararg.arg)
        if node.args.kwarg:
            user_controlled.add(node.args.kwarg.arg)
        if route_handler:
            user_controlled.add("request")

        self._contexts.append(
            FunctionContext(
                name=node.name,
                route_handler=route_handler,
                user_controlled=user_controlled,
            )
        )
        self.generic_visit(node)
        self._contexts.pop()

    def _check_python_rce_calls(
        self,
        node: ast.Call,
        call_name: str,
        ctx: FunctionContext | None,
    ) -> None:
        first_arg = node.args[0] if node.args else None
        arg_is_user_controlled = bool(first_arg is not None and ctx and self._expr_uses_user_input(first_arg, ctx))
        arg_is_dynamic = bool(first_arg is not None and self._is_dynamic_string(first_arg))
        in_route = bool(ctx and ctx.route_handler)

        if call_name in {"eval", "builtins.eval", "exec", "builtins.exec"}:
            if arg_is_user_controlled or arg_is_dynamic or in_route:
                self._add_finding(
                    node=node,
                    rule_id="python-eval-user-input",
                    vuln_type="code_injection",
                    severity="CRITICAL" if (arg_is_user_controlled or in_route) else "HIGH",
                    sink=call_name,
                    description="Dynamic Python evaluation reaches a web-facing or user-influenced string.",
                    scenario="User-controlled content may be executed as Python code, which can become full server-side RCE.",
                    tags=["python", "rce", "eval", "web-rce" if in_route else "static-analysis"],
                )
            return

        if call_name in {"compile", "builtins.compile", "__import__", "builtins.__import__"}:
            if arg_is_user_controlled or arg_is_dynamic:
                self._add_finding(
                    node=node,
                    rule_id="python-dynamic-import-compile",
                    vuln_type="code_injection",
                    severity="CRITICAL" if in_route else "HIGH",
                    sink=call_name,
                    description="Dynamic code compilation or importing uses a user-controlled string.",
                    scenario="An attacker who can influence module names or compiled source may redirect execution into arbitrary code paths.",
                    tags=["python", "rce", "code-injection"],
                )
            return

        if call_name in {"os.system", "os.popen", "commands.getoutput", "commands.getstatusoutput"}:
            if arg_is_user_controlled or arg_is_dynamic or in_route:
                self._add_finding(
                    node=node,
                    rule_id="python-os-command-injection",
                    vuln_type="command_injection",
                    severity="CRITICAL" if (arg_is_user_controlled or in_route) else "HIGH",
                    sink=call_name,
                    description="OS command execution consumes a dynamic or user-controlled string.",
                    scenario="Unsanitized request data may be interpreted by the shell and lead to arbitrary command execution.",
                    tags=["python", "rce", "command-injection", "web-rce" if in_route else "static-analysis"],
                )
            return

        if call_name in {
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
        }:
            shell_true = any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            )
            if shell_true and (arg_is_user_controlled or arg_is_dynamic or in_route):
                self._add_finding(
                    node=node,
                    rule_id="python-subprocess-shell-true",
                    vuln_type="command_injection",
                    severity="CRITICAL",
                    sink=call_name,
                    description="`subprocess` is invoked with `shell=True` and a dynamic command source.",
                    scenario="Shell metacharacters in request-controlled arguments may pivot into arbitrary command execution.",
                    tags=["python", "rce", "command-injection", "web-rce" if in_route else "static-analysis"],
                )
            elif shell_true:
                self._add_finding(
                    node=node,
                    rule_id="python-subprocess-shell-true-review",
                    vuln_type="os_command_injection",
                    severity="HIGH",
                    sink=call_name,
                    description="`subprocess` uses `shell=True`; verify the command string never incorporates external input.",
                    scenario="Even indirect string concatenation or future refactors can turn this shell invocation into a reachable command-injection sink.",
                    tags=["python", "rce", "shell-true"],
                )
            return

        if call_name == "pickle.loads":
            self._add_finding(
                node=node,
                rule_id="python-pickle-loads",
                vuln_type="deserialization",
                severity="CRITICAL" if (arg_is_user_controlled or in_route) else "HIGH",
                sink=call_name,
                description="`pickle.loads()` deserializes attacker-influenced bytes.",
                scenario="Python pickle opcodes can trigger object construction and code execution during deserialization.",
                tags=["python", "rce", "deserialization", "web-rce" if in_route else "static-analysis"],
            )
            return

        if call_name == "yaml.load":
            loader_keyword = next((keyword for keyword in node.keywords if keyword.arg == "Loader"), None)
            safe_loader = loader_keyword and "SafeLoader" in ast.unparse(loader_keyword.value)
            if not safe_loader:
                self._add_finding(
                    node=node,
                    rule_id="python-yaml-load-unsafe",
                    vuln_type="deserialization",
                    severity="CRITICAL" if (arg_is_user_controlled or in_route) else "HIGH",
                    sink=call_name,
                    description="`yaml.load()` is used without `SafeLoader`.",
                    scenario="Unsafe YAML constructors may instantiate attacker-chosen objects and reach code execution paths.",
                    tags=["python", "rce", "deserialization"],
                )
            return

        if call_name == "json.loads" and (arg_is_user_controlled or in_route):
            self._add_finding(
                node=node,
                rule_id="python-json-loads-review",
                vuln_type="deserialization",
                severity="MEDIUM",
                sink=call_name,
                description="`json.loads()` accepts user-controlled data. This is rarely direct RCE but is worth tracing for sink chaining.",
                scenario="Decoded attacker-controlled objects can become dangerous if later passed into `eval`, templates, shell commands, or unsafe deserializers.",
                tags=["python", "deserialization", "review"],
            )
            return

        if call_name in {"flask.render_template_string", "render_template_string"}:
            if arg_is_user_controlled or arg_is_dynamic or in_route:
                self._add_finding(
                    node=node,
                    rule_id="python-render-template-string",
                    vuln_type="template_injection",
                    severity="CRITICAL" if (arg_is_user_controlled and in_route) else "HIGH",
                    sink=call_name,
                    description="Runtime template rendering uses a dynamic string source.",
                    scenario="If template text is attacker-controlled, SSTI may expose server objects and sometimes reach code execution.",
                    tags=["python", "ssti", "web-rce", "template-injection"],
                )

    def _is_route_decorator(self, decorator: ast.AST) -> bool:
        if isinstance(decorator, ast.Call):
            return self._is_route_decorator(decorator.func)
        if isinstance(decorator, ast.Attribute):
            return decorator.attr in ROUTE_DECORATORS
        if isinstance(decorator, ast.Name):
            return decorator.id in ROUTE_DECORATORS
        return False

    def _expr_uses_user_input(self, expr: ast.AST, ctx: FunctionContext) -> bool:
        for node in ast.walk(expr):
            if isinstance(node, ast.Name):
                if node.id in ctx.user_controlled or USER_CONTROLLED_NAME_RE.search(node.id):
                    return True
            elif isinstance(node, ast.Attribute):
                dotted = self._call_name(node)
                if dotted.startswith("request.") or dotted.startswith("flask.request."):
                    return True
                if dotted in {"sys.argv", "sys.stdin", "sys.stdin.readline"}:
                    return True
            elif isinstance(node, ast.Call):
                call_name = self._call_name(node.func)
                if call_name in {
                    "input",
                    "sys.stdin.readline",
                    "request.args.get",
                    "request.form.get",
                    "request.values.get",
                    "request.headers.get",
                    "request.cookies.get",
                    "request.get_json",
                }:
                    return True
        return False

    def _is_dynamic_string(self, expr: ast.AST) -> bool:
        if isinstance(expr, ast.JoinedStr):
            return True
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            return True
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
            return expr.func.attr == "format"
        return False

    def _extract_target_names(self, target: ast.AST) -> set[str]:
        names: set[str] = set()
        for node in ast.walk(target):
            if isinstance(node, ast.Name):
                names.add(node.id)
        return names

    def _call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self._imports.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self._call_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return ""

    def _add_finding(
        self,
        *,
        node: ast.AST,
        rule_id: str,
        vuln_type: str,
        severity: str,
        sink: str,
        description: str,
        scenario: str,
        tags: Iterable[str],
    ) -> None:
        line = getattr(node, "lineno", 1)
        key = (rule_id, line, sink)
        if key in self._dedupe:
            return
        self._dedupe.add(key)
        snippet = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        self.findings.append(
            Finding(
                rule_id=rule_id,
                vuln_type=vuln_type,
                severity=severity,
                language="python",
                file=str(self.path),
                line=line,
                sink=sink,
                description=description,
                exploit_scenario=scenario,
                snippet=snippet[:240],
                tags=[tag for tag in tags if tag],
            )
        )

    def _current_context(self) -> FunctionContext | None:
        return self._contexts[-1] if self._contexts else None


class ZeroDayHunter:
    """Language-aware static analysis for RCE primitives and memory hazards."""

    def __init__(self, *, severity: str = "MEDIUM", lang: str = "all"):
        self.minimum_severity = severity
        self.lang_filter = lang

    def scan_file(self, path: Path) -> tuple[int, list[Finding]]:
        language = self._detect_language(path)
        if not language or not self._language_selected(language):
            return 0, []

        source = path.read_text(encoding="utf-8", errors="replace")
        findings: list[Finding]
        if language == "python":
            findings = PythonAnalyzer(path, source).analyze()
        elif language == "javascript":
            findings = self._scan_javascript(path, source)
        else:
            findings = self._scan_c_family(path, source, language)

        return 1, self._filter_findings(findings)

    def scan_directory(self, directory: Path) -> tuple[int, list[Finding]]:
        findings: list[Finding] = []
        files_scanned = 0
        for path in sorted(directory.rglob("*")):
            if not path.is_file():
                continue
            scanned, file_findings = self.scan_file(path)
            files_scanned += scanned
            findings.extend(file_findings)
        return files_scanned, findings

    def build_report(
        self,
        *,
        target: Path,
        files_scanned: int,
        findings: list[Finding],
    ) -> dict[str, object]:
        severity_counts = Counter(finding.severity for finding in findings)
        return {
            "scanner": "zero_day_hunter",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": str(target),
            "files_scanned": files_scanned,
            "filters": {
                "severity": self.minimum_severity,
                "lang": self.lang_filter,
            },
            "summary": {
                "finding_count": len(findings),
                "severity_counts": {key: severity_counts.get(key, 0) for key in ("CRITICAL", "HIGH", "MEDIUM")},
            },
            "findings": [finding.to_dict() for finding in findings],
        }

    def _language_selected(self, language: str) -> bool:
        return self.lang_filter == "all" or self.lang_filter == language

    def _detect_language(self, path: Path) -> str | None:
        suffix = path.suffix.lower()
        for language, extensions in LANGUAGE_EXTENSIONS.items():
            if suffix in extensions:
                return language
        return None

    def _filter_findings(self, findings: list[Finding]) -> list[Finding]:
        threshold = SEVERITY_ORDER[self.minimum_severity]
        findings = [finding for finding in findings if SEVERITY_ORDER[finding.severity] >= threshold]
        findings.sort(
            key=lambda finding: (
                -SEVERITY_ORDER[finding.severity],
                finding.file,
                finding.line,
                finding.rule_id,
            )
        )
        return findings

    def _scan_javascript(self, path: Path, source: str) -> list[Finding]:
        masked = _mask_c_like_source(source)
        findings: list[Finding] = []
        dedupe: set[tuple[str, int, str]] = set()
        raw_lines = source.splitlines()
        masked_lines = masked.splitlines()

        patterns = [
            (
                "js-eval-user-input",
                "code_injection",
                "CRITICAL",
                re.compile(r"\beval\s*\("),
                "JavaScript `eval()` appears on a live code path.",
                "If request-controlled data reaches `eval()`, it can execute arbitrary server-side or client-side code depending on runtime context.",
                "eval",
                True,
            ),
            (
                "js-function-constructor",
                "code_injection",
                "HIGH",
                re.compile(r"\b(?:new\s+)?Function\s*\("),
                "Dynamic function construction is present.",
                "User-controlled input passed into the Function constructor can become executable code.",
                "Function",
                True,
            ),
            (
                "js-child-process-exec",
                "command_injection",
                "CRITICAL",
                re.compile(r"\bchild_process\.(?:exec|execSync)\s*\("),
                "Node.js command execution API is used.",
                "If attacker input controls any portion of the command string, the host may execute arbitrary shell commands.",
                "child_process.exec",
                True,
            ),
            (
                "js-child-process-shell",
                "command_injection",
                "CRITICAL",
                re.compile(r"\bchild_process\.(?:spawn|spawnSync)\s*\("),
                "Node.js process spawning is present; review for shell-like command composition.",
                "Dynamic arguments or shell options can turn process spawning into a command-injection path.",
                "child_process.spawn",
                True,
            ),
            (
                "js-vm-run",
                "code_injection",
                "CRITICAL",
                re.compile(r"\bvm\.runIn(?:New|This)Context\s*\("),
                "The Node `vm` module executes dynamic code.",
                "Feeding user-controlled strings into VM execution can create a direct code-injection primitive.",
                "vm.runInContext",
                True,
            ),
            (
                "js-template-ssti",
                "template_injection",
                "HIGH",
                re.compile(r"\b(?:twig|nunjucks)\.render(?:String)?\s*\("),
                "Template rendering uses a potentially dynamic template string.",
                "If a request parameter can shape the template body, SSTI may expose server internals or code-execution gadgets.",
                "template.render",
                True,
            ),
            (
                "js-res-render-user-template",
                "template_injection",
                "HIGH",
                re.compile(r"\bres\.render\s*\("),
                "A web handler renders a template path or template name dynamically.",
                "Supplying template names or expressions from request data can open template traversal or SSTI-style execution flows.",
                "res.render",
                True,
            ),
        ]

        for line_no, (raw_line, masked_line) in enumerate(zip(raw_lines, masked_lines), start=1):
            lowered_raw = raw_line.lower()
            for rule_id, vuln_type, severity, pattern, description, scenario, sink, needs_input in patterns:
                if not pattern.search(masked_line):
                    continue
                if needs_input and not WEB_INPUT_RE.search(lowered_raw):
                    if rule_id not in {"js-child-process-shell", "js-template-ssti"}:
                        continue
                if rule_id == "js-child-process-shell" and "shell" not in lowered_raw and not WEB_INPUT_RE.search(lowered_raw):
                    continue
                if rule_id == "js-res-render-user-template" and not WEB_INPUT_RE.search(lowered_raw):
                    continue
                key = (rule_id, line_no, sink)
                if key in dedupe:
                    continue
                dedupe.add(key)
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        vuln_type=vuln_type,
                        severity=severity,
                        language="javascript",
                        file=str(path),
                        line=line_no,
                        sink=sink,
                        description=description,
                        exploit_scenario=scenario,
                        snippet=raw_line.strip()[:240],
                        tags=["javascript", "rce", vuln_type.replace("_", "-")],
                    )
                )

        return findings

    def _scan_c_family(self, path: Path, source: str, language: str) -> list[Finding]:
        masked = _mask_c_like_source(source)
        findings: list[Finding] = []
        raw_lines = source.splitlines()
        masked_lines = masked.splitlines()
        dedupe: set[tuple[str, int, str]] = set()

        def add_finding(
            line_no: int,
            *,
            rule_id: str,
            vuln_type: str,
            severity: str,
            sink: str,
            description: str,
            scenario: str,
        ) -> None:
            key = (rule_id, line_no, sink)
            if key in dedupe:
                return
            dedupe.add(key)
            findings.append(
                Finding(
                    rule_id=rule_id,
                    vuln_type=vuln_type,
                    severity=severity,
                    language=language,
                    file=str(path),
                    line=line_no,
                    sink=sink,
                    description=description,
                    exploit_scenario=scenario,
                    snippet=raw_lines[line_no - 1].strip()[:240],
                    tags=[language, "memory-safety", vuln_type.replace("_", "-")],
                )
            )

        freed_vars: dict[str, int] = {}

        for line_no, (raw_line, masked_line) in enumerate(zip(raw_lines, masked_lines), start=1):
            stripped = masked_line.strip()
            if not stripped:
                continue

            if re.search(r"\bgets\s*\(", stripped):
                add_finding(
                    line_no,
                    rule_id="c-gets",
                    vuln_type="buffer_overflow",
                    severity="CRITICAL",
                    sink="gets",
                    description="`gets()` reads unbounded input into a fixed buffer.",
                    scenario="Any oversized input can overrun stack memory and may become code execution on vulnerable builds.",
                )

            for sink_name in ("strcpy", "strcat", "sprintf", "vsprintf"):
                if re.search(rf"\b{sink_name}\s*\(", stripped):
                    add_finding(
                        line_no,
                        rule_id=f"c-{sink_name}",
                        vuln_type="buffer_overflow",
                        severity="HIGH",
                        sink=sink_name,
                        description=f"`{sink_name}()` performs unsafe copying or formatting without inherent bounds enforcement.",
                        scenario="If destination sizing assumptions break, attacker-controlled data can overflow stack or heap buffers.",
                    )

            if re.search(r"\b(?:s|f|v)?scanf\s*\(", stripped) and _scanf_without_width(raw_line):
                add_finding(
                    line_no,
                    rule_id="c-scanf-unbounded",
                    vuln_type="buffer_overflow",
                    severity="HIGH",
                    sink="scanf",
                    description="`scanf`-style input uses `%s` without a field width.",
                    scenario="A long token can exceed the destination buffer and corrupt adjacent memory.",
                )

            if re.search(r"\bmemcpy\s*\(", stripped):
                args = _extract_call_args(raw_line, "memcpy")
                if len(args) >= 3 and _suspicious_length_expression(args[2]):
                    add_finding(
                        line_no,
                        rule_id="c-memcpy-length",
                        vuln_type="buffer_overflow",
                        severity="HIGH",
                        sink="memcpy",
                        description="`memcpy()` uses a length expression that should be checked against the destination capacity.",
                        scenario="If the computed length exceeds the allocated destination, the copy can corrupt memory and become exploitable.",
                    )

            for sink_name, arg_index in (("printf", 0), ("fprintf", 1), ("sprintf", 1), ("snprintf", 2)):
                if re.search(rf"\b{sink_name}\s*\(", stripped):
                    args = _extract_call_args(raw_line, sink_name)
                    if len(args) > arg_index and _looks_non_literal(args[arg_index]):
                        add_finding(
                            line_no,
                            rule_id=f"c-{sink_name}-format-string",
                            vuln_type="format_string",
                            severity="HIGH",
                            sink=sink_name,
                            description=f"`{sink_name}()` appears to use a non-literal format string.",
                            scenario="An attacker-controlled format string can leak memory, write arbitrary values, or redirect execution.",
                        )

            if re.search(r"\balloca\s*\(", stripped) or re.search(r"\b(?:char|wchar_t|uint8_t|int)\s+\w+\s*\[\s*[A-Za-z_]\w*\s*\]", stripped):
                add_finding(
                    line_no,
                    rule_id="c-stack-dynamic-allocation",
                    vuln_type="stack_overflow_indicator",
                    severity="HIGH",
                    sink="stack-allocation",
                    description="Dynamic stack allocation or a variable-length array is present.",
                    scenario="If the size derives from external input or large integers, stack exhaustion or overwrite conditions can follow.",
                )

            if re.search(r"\b(?:malloc|calloc|realloc)\s*\([^)]*[*+][^)]*\)", stripped) or re.search(r"\bnew\s+\w+\s*\[[^\]]*[*+][^\]]*\]", stripped):
                add_finding(
                    line_no,
                    rule_id="c-integer-overflow-allocation",
                    vuln_type="integer_overflow",
                    severity="MEDIUM",
                    sink="allocation-size",
                    description="Allocation size arithmetic is performed inline.",
                    scenario="Unchecked integer overflow can shrink the allocation and set up a later heap overflow during copy or initialization.",
                )

            free_match = re.search(r"\bfree\s*\(\s*([A-Za-z_]\w*)\s*\)", stripped)
            delete_match = re.search(r"\bdelete(?:\s*\[\])?\s+([A-Za-z_]\w*)", stripped)
            if free_match or delete_match:
                var_name = (free_match or delete_match).group(1)
                if var_name in freed_vars:
                    add_finding(
                        line_no,
                        rule_id="c-double-free",
                        vuln_type="double_free",
                        severity="HIGH",
                        sink="free",
                        description=f"`{var_name}` appears to be freed more than once.",
                        scenario="Repeated frees can corrupt allocator metadata and may become a reliable code-execution primitive in native targets.",
                    )
                freed_vars[var_name] = line_no
                continue

            for var_name, free_line in list(freed_vars.items()):
                if re.search(rf"\b{re.escape(var_name)}\s*=", stripped):
                    freed_vars.pop(var_name, None)
                    continue
                if re.search(rf"\b{re.escape(var_name)}\b", stripped) and not re.search(r"\bNULL\b|\bnullptr\b", stripped):
                    add_finding(
                        line_no,
                        rule_id="c-use-after-free",
                        vuln_type="use_after_free",
                        severity="HIGH",
                        sink=var_name,
                        description=f"`{var_name}` is referenced after being released at line {free_line}.",
                        scenario="Using a dangling pointer can corrupt reused heap objects or redirect control flow through stale memory.",
                    )
                    freed_vars.pop(var_name, None)

        return findings


def _mask_c_like_source(source: str) -> str:
    """Blank comments and strings while preserving line numbers."""

    result: list[str] = []
    i = 0
    state = "code"
    quote = ""
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""

        if state == "code":
            if ch == "/" and nxt == "/":
                result.extend("  ")
                i += 2
                state = "line_comment"
                continue
            if ch == "/" and nxt == "*":
                result.extend("  ")
                i += 2
                state = "block_comment"
                continue
            if ch in {"'", '"', "`"}:
                result.append(" ")
                i += 1
                quote = ch
                state = "string"
                continue
            result.append(ch)
            i += 1
            continue

        if state == "line_comment":
            if ch == "\n":
                result.append("\n")
                state = "code"
            else:
                result.append(" ")
            i += 1
            continue

        if state == "block_comment":
            if ch == "*" and nxt == "/":
                result.extend("  ")
                i += 2
                state = "code"
            else:
                result.append("\n" if ch == "\n" else " ")
                i += 1
            continue

        if state == "string":
            if ch == "\\":
                result.append(" ")
                if nxt:
                    result.append(" " if nxt != "\n" else "\n")
                i += 2
                continue
            if ch == quote:
                result.append(" ")
                i += 1
                state = "code"
                quote = ""
                continue
            result.append("\n" if ch == "\n" else " ")
            i += 1

    return "".join(result)


def _extract_call_args(line: str, function_name: str) -> list[str]:
    match = re.search(rf"\b{re.escape(function_name)}\s*\(", line)
    if not match:
        return []

    args: list[str] = []
    current: list[str] = []
    depth = 1
    i = match.end()
    in_string = False
    quote = ""

    while i < len(line):
        ch = line[i]
        if in_string:
            current.append(ch)
            if ch == "\\" and i + 1 < len(line):
                current.append(line[i + 1])
                i += 2
                continue
            if ch == quote:
                in_string = False
                quote = ""
            i += 1
            continue

        if ch in {"'", '"'}:
            in_string = True
            quote = ch
            current.append(ch)
            i += 1
            continue

        if ch == "(":
            depth += 1
            current.append(ch)
            i += 1
            continue

        if ch == ")":
            depth -= 1
            if depth == 0:
                fragment = "".join(current).strip()
                if fragment:
                    args.append(fragment)
                break
            current.append(ch)
            i += 1
            continue

        if ch == "," and depth == 1:
            args.append("".join(current).strip())
            current = []
            i += 1
            continue

        current.append(ch)
        i += 1

    return args


def _scanf_without_width(line: str) -> bool:
    for function_name, format_index in (("scanf", 0), ("fscanf", 1), ("sscanf", 1)):
        args = _extract_call_args(line, function_name)
        if not args:
            continue
        if len(args) <= format_index:
            return False
        format_arg = args[format_index]
        return "%s" in format_arg and not re.search(r"%\d+s", format_arg)
    return False


def _suspicious_length_expression(expr: str) -> bool:
    normalized = expr.replace(" ", "")
    if "sizeof" in normalized and any(token in normalized for token in ("dest", "dst", "buf", "buffer")):
        return False
    return bool(re.search(r"(?:len|size|count|argc|argv|input|user|strlen|\*)", normalized, re.IGNORECASE))


def _looks_non_literal(expr: str) -> bool:
    expr = expr.strip()
    if not expr:
        return False
    return not (expr.startswith('"') and expr.endswith('"')) and not (expr.startswith("'") and expr.endswith("'"))


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=textwrap.dedent(
            """\
            Zero-day RCE hunter for read-only source analysis.

            Detects:
              - Command and code injection primitives
              - Unsafe deserialization and template execution
              - Native memory-safety patterns that commonly lead to RCE
            """
        ),
        epilog=textwrap.dedent(
            """\
            Examples:
              python3 agents/zero_day_hunter.py --file app.py
              python3 agents/zero_day_hunter.py --dir src --severity HIGH --lang python
              python3 agents/zero_day_hunter.py --dir . --output findings.json
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--file", help="Single file to analyze")
    target_group.add_argument("--dir", help="Directory to scan recursively")
    parser.add_argument(
        "--severity",
        choices=("CRITICAL", "HIGH", "MEDIUM"),
        default="MEDIUM",
        help="Minimum severity to include in output",
    )
    parser.add_argument(
        "--lang",
        choices=("c", "cpp", "python", "javascript", "all"),
        default="all",
        help="Restrict analysis to a language family",
    )
    parser.add_argument("--output", help="Write JSON results to a file")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    hunter = ZeroDayHunter(severity=args.severity, lang=args.lang)

    try:
        if args.file:
            target = Path(args.file).expanduser().resolve()
            if not target.is_file():
                raise FileNotFoundError(f"File not found: {target}")
            files_scanned, findings = hunter.scan_file(target)
        else:
            target = Path(args.dir).expanduser().resolve()
            if not target.is_dir():
                raise NotADirectoryError(f"Directory not found: {target}")
            files_scanned, findings = hunter.scan_directory(target)
    except Exception as exc:
        print(json.dumps({"error": str(exc), "exit_code": 2}, indent=2), file=sys.stderr)
        return 2

    report = hunter.build_report(target=target, files_scanned=files_scanned, findings=findings)
    payload = json.dumps(report, indent=2)

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.write_text(f"{payload}\n", encoding="utf-8")

    print(payload)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
