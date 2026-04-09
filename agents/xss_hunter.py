"""Main XSS harness implementation."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import html
import json
import math
import sys
from pathlib import Path
import re
import time
from typing import Iterable
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit, urlunsplit
from uuid import uuid4

import httpx

sys.path.insert(0, str(Path.home() / "projects" / "bounty-tools"))
try:
    from subagent_logger import SubagentLogger, compute_pte_lite
except ImportError:  # pragma: no cover
    SubagentLogger = None

    def compute_pte_lite(**kwargs) -> int:
        return (
            int(kwargs.get("prompt_tokens") or 0)
            + int(kwargs.get("completion_tokens") or 0)
            + int(kwargs.get("tool_output_tokens") or 0)
        )

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    BeautifulSoup = None

try:
    from .bypass_generator import BypassGenerator
    from .context_detector import ContextDetector, ContextType, InjectionContext
    from .deep_mode_agent import Attempt, DeepModeAgent
    from .framework_fingerprinter import FrameworkFingerprinter, FrameworkInfo
    from .payload_sets import get_payloads_for_context
    from .sink_detector import Sink, SinkDetector
except ImportError:  # pragma: no cover
    from bypass_generator import BypassGenerator
    from context_detector import ContextDetector, ContextType, InjectionContext
    from deep_mode_agent import Attempt, DeepModeAgent
    from framework_fingerprinter import FrameworkFingerprinter, FrameworkInfo
    from payload_sets import get_payloads_for_context
    from sink_detector import Sink, SinkDetector


@dataclass
class ScanResult:
    url: str
    param: str
    payload: str
    reflected: bool
    blocked: bool
    truncated: bool
    likely_executable: bool
    status_code: int
    context: str
    sink: str = ""
    filter_type: str = "NO_BLOCK"
    response_evidence: str = ""
    reflected_fragment: str = ""


@dataclass
class XSSFinding:
    type: str
    url: str
    param: str
    payload: str
    context: str
    sink: str
    poc: str
    severity: str
    response_evidence: str


class XSSHunter:
    """Main XSS testing harness."""

    def __init__(self, target_url: str, params: dict | None = None, program: str | None = None, rate_limit: float = 5.0, scan_depth: str = "shallow"):
        self.target_url = target_url
        self.params = self._normalize_params(params)
        self.program = program or "adhoc"
        self.rate_limit = rate_limit
        self.scan_depth = scan_depth
        self.session = httpx.Client(
            timeout=30,
            follow_redirects=True,
            headers={"User-Agent": "XSSHunter/1.0"},
        )
        self.framework: FrameworkInfo | None = None
        self.context: InjectionContext | None = None
        self.sinks: list[Sink] = []
        self.findings: list[XSSFinding] = []

        self.context_detector = ContextDetector()
        self.framework_fingerprinter = FrameworkFingerprinter()
        self.sink_detector = SinkDetector()
        self.bypass_generator = BypassGenerator()
        self.deep_mode_agent = DeepModeAgent()
        self.log = None
        if SubagentLogger is not None:
            try:
                self.log = SubagentLogger("xss_hunter", self.program, f"xss_{uuid4().hex[:8]}")
                self.log.start(target=self.target_url)
            except Exception:
                self.log = None

        self._baseline_response: httpx.Response | None = None
        self._base_params = self._extract_url_params()
        if self.params:
            self._base_params.update(self.params)

    def scan(self, mode: str = "standard") -> list[XSSFinding]:
        """Run the XSS scan."""
        self.findings = []
        self._baseline_response = self._make_request(self._base_params)
        self.framework = self.framework_fingerprinter.fingerprint(self._baseline_response)
        self.sinks = self._collect_sinks(self._baseline_response)

        if mode == "deep":
            findings = self._deep_scan()
        else:
            findings = self._standard_scan()

        self._save_outputs(findings, mode)
        return findings

    def _standard_scan(self) -> list[XSSFinding]:
        """Standard scan: probe reflection and apply context payload sets."""
        findings: list[XSSFinding] = []
        for param in self._scan_params():
            baseline = self._make_request(self._base_params)
            context = self._probe_param(param, baseline)
            self.context = context

            payloads = get_payloads_for_context(context.type)
            for payload in payloads:
                result = self._submit_payload_for_param(param, payload, baseline)
                if self._is_finding(result):
                    findings.append(self._build_finding(result))

        self.findings = self._dedupe_findings(findings)
        return self.findings

    def _deep_scan(self) -> list[XSSFinding]:
        """Deep scan: AI-driven contextual analysis."""
        findings: list[XSSFinding] = []
        for param in self._scan_params():
            baseline = self._make_request(self._base_params)
            context = self._probe_param(param, baseline)
            self.context = context

            attempts: list[Attempt] = []
            standard_payloads = get_payloads_for_context(context.type)
            for payload in standard_payloads:
                result = self._submit_payload_for_param(param, payload, baseline)
                attempts.append(self._attempt_from_result(result))
                if self._is_finding(result):
                    findings.append(self._build_finding(result))

            _model_start = time.time()
            bypass_payload = asyncio.run(
                self.deep_mode_agent.analyze(
                    target=self.target_url,
                    framework=self.framework or FrameworkInfo(name="vanilla"),
                    context=context,
                    sinks=self.sinks,
                    attempt_history=attempts,
                )
            )
            try:
                response_text = json.dumps(getattr(bypass_payload, "payloads", []), sort_keys=True)
                prompt_basis = json.dumps(
                    {
                        "target": self.target_url,
                        "framework": getattr(self.framework, "name", "unknown"),
                        "context": getattr(context, "type", ""),
                        "sinks": [getattr(sink, "name", "") for sink in self.sinks],
                        "attempts": [asdict(attempt) for attempt in attempts],
                    },
                    sort_keys=True,
                    default=str,
                )
                prompt_tokens = max(0, math.ceil(len(prompt_basis.encode("utf-8", errors="replace")) / 4))
                completion_tokens = max(0, math.ceil(len(response_text.encode("utf-8", errors="replace")) / 4))
                output_bytes = len(response_text.encode("utf-8", errors="replace"))
                tool_output_tokens = max(0, math.ceil(output_bytes / 4))
                if self.log is not None:
                    self.log.log_span(
                        span_type="model",
                        level="STEP",
                        message="Model call: deep_mode_agent",
                        model_name="deep_mode_agent",
                        prompt_tokens=prompt_tokens,
                        completion_tokens=completion_tokens,
                        context_tokens_before=prompt_tokens,
                        context_tokens_after=prompt_tokens + completion_tokens,
                        tool_output_tokens=tool_output_tokens,
                        pte_lite=compute_pte_lite(
                            prompt_tokens=prompt_tokens,
                            completion_tokens=completion_tokens,
                            tool_output_tokens=tool_output_tokens,
                            context_tokens_after=prompt_tokens + completion_tokens,
                        ),
                        output_bytes=output_bytes,
                        latency_ms=int((time.time() - _model_start) * 1000),
                        success=True,
                    )
            except Exception:
                pass

            for payload in bypass_payload.payloads:
                result = self._submit_payload_for_param(param, payload, baseline)
                attempts.append(self._attempt_from_result(result))
                if self._is_finding(result):
                    findings.append(self._build_finding(result, finding_type="dom" if self._dom_style_sink(result.sink) else "reflected"))

        self.findings = self._dedupe_findings(findings)
        return self.findings

    def submit_payload(self, payload: str, context: str, param: str | None = None) -> ScanResult:
        """Submit a single payload and return reflection/blocking metadata."""
        param_name = param or next(iter(self._scan_params()), "q")
        baseline = self._baseline_response or self._make_request(self._base_params)
        return self._submit_payload_for_param(param_name, payload, baseline, context_hint=context)

    def close(self) -> None:
        self.session.close()

    def _probe_param(self, param: str, baseline: httpx.Response) -> InjectionContext:
        marker = f"XSSHUNTER_{uuid4().hex[:12]}"
        probe_response = self._make_request(self._params_with(param, marker))
        return self.context_detector.detect(baseline, probe_response, marker)

    def _submit_payload_for_param(
        self,
        param: str,
        payload: str,
        baseline: httpx.Response,
        context_hint: str | None = None,
    ) -> ScanResult:
        response = self._make_request(self._params_with(param, payload))
        context = self.context_detector.detect(baseline, response, payload)
        if context_hint and context.type == ContextType.NO_REFLECTION:
            context.type = context_hint

        reflected_fragment = context.reflected_fragment
        filter_type = self.bypass_generator.detect_filter_type(payload, reflected_fragment, response.text)
        truncated = bool(reflected_fragment) and len(reflected_fragment) < len(payload)
        likely_executable = self._looks_executable(context.type, reflected_fragment or payload)
        blocked = filter_type != "NO_BLOCK" and not likely_executable

        return ScanResult(
            url=str(response.url),
            param=param,
            payload=payload,
            reflected=context.reflected,
            blocked=blocked,
            truncated=truncated,
            likely_executable=likely_executable,
            status_code=response.status_code,
            context=context.type,
            sink=self._select_sink(context.type),
            filter_type=filter_type,
            response_evidence=context.surrounding_text or self._response_snippet(response.text, payload),
            reflected_fragment=reflected_fragment,
        )

    def _make_request(self, params: dict[str, str]) -> httpx.Response:
        start = time.time()
        response = self.session.get(self._base_url(), params=params)
        response.raise_for_status()
        try:
            output_bytes = len(response.text.encode("utf-8", errors="replace"))
            if self.log is not None:
                self.log.log_span(
                    span_type="tool",
                    level="STEP",
                    message=f"Tool: GET {response.url}",
                    tool_name="httpx.get",
                    tool_category="http_request",
                    input_bytes=len(json.dumps(params, sort_keys=True).encode("utf-8", errors="replace")),
                    output_bytes=output_bytes,
                    latency_ms=int((time.time() - start) * 1000),
                    output_tokens_est=max(0, math.ceil(output_bytes / 4)),
                    success=True,
                )
        except Exception:
            pass
        return response

    def _collect_sinks(self, response: httpx.Response) -> list[Sink]:
        sinks: list[Sink] = []
        for script in self._extract_inline_scripts(response.text):
            sinks.extend(self.sink_detector.find_sinks(script))
        for script_url in self._extract_script_urls(response.text):
            try:
                js_response = self.session.get(script_url)
                js_response.raise_for_status()
            except Exception:
                continue
            try:
                output_bytes = len(js_response.text.encode("utf-8", errors="replace"))
                if self.log is not None:
                    self.log.log_span(
                        span_type="tool",
                        level="STEP",
                        message=f"Tool: GET {script_url}",
                        tool_name="httpx.get",
                        tool_category="http_request",
                        input_bytes=len(script_url.encode("utf-8", errors="replace")),
                        output_bytes=output_bytes,
                        output_tokens_est=max(0, math.ceil(output_bytes / 4)),
                        success=True,
                    )
            except Exception:
                pass
            sinks.extend(self.sink_detector.find_sinks(js_response.text))
        return self._dedupe_sinks(sinks)

    def _extract_script_urls(self, html_text: str) -> list[str]:
        if BeautifulSoup is not None:
            soup = BeautifulSoup(html_text, "html.parser")
            urls = []
            for script in soup.find_all("script", src=True):
                urls.append(urljoin(self.target_url, script["src"]))
            return urls[:10]
        return [
            urljoin(self.target_url, match.group(1))
            for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html_text, re.IGNORECASE)
        ][:10]

    def _extract_inline_scripts(self, html_text: str) -> list[str]:
        if BeautifulSoup is not None:
            soup = BeautifulSoup(html_text, "html.parser")
            return [script.get_text() for script in soup.find_all("script") if not script.get("src")]
        return re.findall(r"<script[^>]*>(.*?)</script>", html_text, re.IGNORECASE | re.DOTALL)

    def _looks_executable(self, context_type: str, fragment: str) -> bool:
        lowered = html.unescape(fragment).lower()
        if context_type in {ContextType.HTML_BODY, ContextType.HTML_ATTRIBUTE, ContextType.HTML_COMMENT}:
            return any(token in lowered for token in ("<script", "onerror", "onload", "onfocus", "javascript:", "<svg", "<img", "<iframe"))
        if context_type in {ContextType.JS_STRING, ContextType.JS_TEMPLATE}:
            return any(token in lowered for token in ("alert(", "confirm(", "prompt(", "constructor(", "</script>", "${"))
        if context_type == ContextType.URL_PARAM:
            return "javascript:" in lowered or lowered.startswith("data:text/html")
        if context_type == ContextType.STYLESHEET:
            return "javascript:" in lowered or "@import" in lowered or "</style>" in lowered
        return False

    def _select_sink(self, context_type: str) -> str:
        if self.sinks:
            return self.sinks[0].name
        if context_type == ContextType.URL_PARAM:
            return "URL navigation"
        if self.framework and self.framework.sinks:
            return self.framework.sinks[0]
        return "reflection"

    def _response_snippet(self, response_text: str, value: str, radius: int = 80) -> str:
        candidates = [value, html.escape(value), html.escape(value, quote=True)]
        for candidate in candidates:
            index = response_text.find(candidate)
            if index >= 0:
                left = max(0, index - radius)
                right = min(len(response_text), index + len(candidate) + radius)
                return response_text[left:right].replace("\n", "\\n")
        return response_text[: radius * 2].replace("\n", "\\n")

    def _attempt_from_result(self, result: ScanResult) -> Attempt:
        outcome = "reflected" if result.reflected else "blocked"
        if result.blocked:
            outcome = "blocked"
        elif result.truncated:
            outcome = "truncated"
        elif result.likely_executable:
            outcome = "likely_executable"
        return Attempt(
            payload=result.payload,
            outcome=outcome,
            filter_type=result.filter_type,
            response_preview=result.response_evidence,
            reflected_fragment=result.reflected_fragment,
        )

    def _is_finding(self, result: ScanResult) -> bool:
        if not result.reflected:
            return False
        if result.blocked:
            return False
        if not result.likely_executable:
            return False
        return True

    def _build_finding(self, result: ScanResult, finding_type: str = "reflected") -> XSSFinding:
        severity = self._severity_for(result, finding_type)
        finding = XSSFinding(
            type=finding_type,
            url=result.url,
            param=result.param,
            payload=result.payload,
            context=result.context,
            sink=result.sink,
            poc=self._build_poc(result.param, result.payload),
            severity=severity,
            response_evidence=result.response_evidence,
        )
        try:
            if self.log is not None:
                self.log.log_span(
                    span_type="finding",
                    level="RESULT",
                    message=f"Finding: xss:{result.param}:{finding_type}",
                    finding_fid=f"xss:{result.param}:{finding_type}:{result.url}",
                    review_tier=severity,
                    duplicate=False,
                    finding_reward=0,
                    allocated_pte_lite=0,
                )
        except Exception:
            pass
        return finding

    def _severity_for(self, result: ScanResult, finding_type: str) -> str:
        if finding_type == "stored":
            return "P1"
        if "eval" in result.sink.lower() or "function" in result.sink.lower() or "dangerouslysetinnerhtml" in result.sink.lower():
            return "P1"
        return "P2"

    def _dom_style_sink(self, sink_name: str) -> bool:
        lowered = sink_name.lower()
        return any(token in lowered for token in ("innerhtml", "eval", "function", "render", "ng-bind-html", "dangerouslysetinnerhtml"))

    def _build_poc(self, param: str, payload: str) -> str:
        params = self._params_with(param, payload)
        query = urlencode(params, doseq=False)
        split = urlsplit(self.target_url)
        return urlunsplit((split.scheme, split.netloc, split.path, query, split.fragment))

    def _base_url(self) -> str:
        split = urlsplit(self.target_url)
        return urlunsplit((split.scheme, split.netloc, split.path, "", split.fragment))

    def _extract_url_params(self) -> dict[str, str]:
        split = urlsplit(self.target_url)
        parsed = parse_qs(split.query, keep_blank_values=True)
        normalized: dict[str, str] = {}
        for key, values in parsed.items():
            normalized[key] = values[0] if values else ""
        return normalized

    def _normalize_params(self, params: dict | None) -> dict[str, str]:
        if not params:
            return {}
        normalized: dict[str, str] = {}
        for key, value in params.items():
            if isinstance(value, list):
                normalized[str(key)] = str(value[0]) if value else ""
            else:
                normalized[str(key)] = str(value)
        return normalized

    def _params_with(self, param: str, value: str) -> dict[str, str]:
        params = dict(self._base_params)
        params[param] = value
        return params

    def _scan_params(self) -> Iterable[str]:
        params = self.params or self._base_params
        if params:
            return list(params.keys())
        return ["q"]

    def _save_outputs(self, findings: list[XSSFinding], mode: str) -> None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output_dir = (
            Path.home()
            / "Shared"
            / "bounty_recon"
            / self.program
            / "agent_shared"
            / "findings"
            / "xss"
            / "hunter"
        )
        output_dir.mkdir(parents=True, exist_ok=True)

        report_path = output_dir / f"xss_scan_{mode}_{timestamp}.json"
        report = {
            "target_url": self.target_url,
            "program": self.program,
            "mode": mode,
            "framework": asdict(self.framework) if self.framework else None,
            "context": asdict(self.context) if self.context else None,
            "sinks": [asdict(sink) for sink in self.sinks],
            "findings": [asdict(finding) for finding in findings],
        }
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        note_path = output_dir / f"xss_scan_{timestamp}.md"
        note_lines = [
            f"# XSS Scan - {self.target_url}",
            "",
            f"- Mode: {mode}",
            f"- Framework: {(self.framework.name if self.framework else 'unknown')}",
            f"- Findings: {len(findings)}",
            "",
        ]
        for finding in findings[:10]:
            note_lines.extend(
                [
                    f"## {finding.severity} - {finding.param}",
                    f"- Type: {finding.type}",
                    f"- Context: {finding.context}",
                    f"- Sink: {finding.sink}",
                    f"- Payload: `{finding.payload}`",
                    f"- PoC: `{finding.poc}`",
                    f"- Evidence: `{finding.response_evidence[:300]}`",
                    "",
                ]
            )
        note_path.write_text("\n".join(note_lines), encoding="utf-8")

    def _dedupe_findings(self, findings: list[XSSFinding]) -> list[XSSFinding]:
        deduped: list[XSSFinding] = []
        seen: set[tuple[str, str, str]] = set()
        for finding in findings:
            key = (finding.url, finding.param, finding.payload)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        return deduped

    def _dedupe_sinks(self, sinks: list[Sink]) -> list[Sink]:
        deduped: list[Sink] = []
        seen: set[tuple[str, int, str]] = set()
        for sink in sinks:
            key = (sink.name, sink.line, sink.snippet)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(sink)
        return deduped


def main():
    """CLI entry point for XSS harness."""
    import argparse
    
    parser = argparse.ArgumentParser(description="XSS Hunter - Find XSS vulnerabilities")
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--program", default="test", help="Bug bounty program name")
    parser.add_argument("--rate-limit", type=float, default=5, help="Requests per second")
    parser.add_argument("--depth", choices=["shallow", "deep"], default="shallow", help="Scan depth")
    parser.add_argument("--output", help="Output file for findings (JSON)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Handle URL format
    target = args.target
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    print(f"[*] Starting XSS scan against: {target}")
    print(f"[*] Program: {args.program}")
    print(f"[*] Rate limit: {args.rate_limit}/sec")
    print(f"[*] Depth: {args.depth}")
    print()
    
    try:
        harness = XSSHunter(
            target_url=target,
            program=args.program,
            rate_limit=args.rate_limit,
            scan_depth=args.depth
        )
        
        findings = harness.scan(mode="deep" if args.depth == "deep" else "standard")
        
        print(f"\n[+] Scan complete! Found {len(findings)} XSS candidates")
        
        for f in findings:
            print(f"  - {f.url} | {f.param} | {f.context}")
        
        if args.output:
            output_data = [
                {
                    "url": f.url,
                    "param": f.param,
                    "context": f.context,
                    "payload": f.payload,
                    "poc": f.poc,
                    "sink": f.sink,
                    "evidence": f.response_evidence[:500]
                }
                for f in findings
            ]
            with open(args.output, "w") as out:
                json.dump(output_data, out, indent=2)
            print(f"[+] Results saved to: {args.output}")
        
        return 0 if findings else 1
        
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
