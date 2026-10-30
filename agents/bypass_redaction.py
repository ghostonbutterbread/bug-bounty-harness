"""Restricted output projections for the bypass harness, not secret detection."""
import ast
import re
from dataclasses import dataclass

from agents.attempts import redact_attempt_value


def safe_text(value):
    """Scrub known secrets and withhold query values in free-form output."""
    # Output contexts can include unencoded whitespace in a query value. Once a
    # query begins, its end cannot safely be inferred from a free-form log line.
    value = re.sub(r'\?[\s\S]*', '[query withheld]', str(value))
    value = re.sub(r'(?i)(authorization\s*:\s*)(?:basic|bearer)\s+[^\s,;]+', r'\1REDACTED', value)
    value = re.sub(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b', 'REDACTED', value)
    return str(redact_attempt_value(value))


def _protect_nested(value):
    if isinstance(value, dict):
        return {k: ('REDACTED' if re.search(r'(?i)session', str(k)) else _protect_nested(v))
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_protect_nested(v) for v in value]
    return value


def safe_payload(value):
    """Redact structured headers, including Python-style dict representations."""
    try:
        parsed = ast.literal_eval(value)
    except (ValueError, SyntaxError, TypeError):
        return safe_text(value)
    if isinstance(parsed, (dict, list, tuple)):
        return safe_text(repr(redact_attempt_value(_protect_nested(parsed))))
    return safe_text(value)


@dataclass(frozen=True)
class CORSEvidence:
    reflected: bool
    wildcard: bool
    present: bool
    credentials: bool


@dataclass(frozen=True)
class RaceEvidence:
    baseline: int | None
    counts: dict[int, int]
    errors: int
    body_variants: int


def safe_evidence(value):
    """Only project fixed derived fields; never trust raw response evidence."""
    if isinstance(value, CORSEvidence) and all(type(x) is bool for x in
            (value.reflected, value.wildcard, value.present, value.credentials)):
        return (f"ACAO: {'reflected' if value.reflected else 'wildcard' if value.wildcard else 'other' if value.present else 'absent'}"
                f" | credentials: {str(value.credentials).lower()}")
    if (isinstance(value, RaceEvidence) and
            (value.baseline is None or type(value.baseline) is int and 100 <= value.baseline <= 999) and
            type(value.counts) is dict and all(type(k) is int and 100 <= k <= 999 and
            type(v) is int and v >= 0 for k, v in value.counts.items()) and
            type(value.errors) is int and value.errors >= 0 and
            type(value.body_variants) is int and value.body_variants >= 0):
        counts = ', '.join(f'HTTP {k}: {v}' for k, v in sorted(value.counts.items()))
        baseline = f'HTTP {value.baseline}' if value.baseline is not None else 'unknown'
        return f'Baseline: {baseline} | {counts} | errors: {value.errors} | body variants: {value.body_variants}'
    return '[response evidence withheld]' if value else ''
