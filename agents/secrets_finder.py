"""
Secrets Finder — detect hardcoded secrets, auth material, and sensitive endpoints.

Usage:
    from agents.secrets_finder import SecretsFinder

    finder = SecretsFinder(program="superdrug")
    finder.scan_directory("/tmp/js_dump")
    finder.scan_url_list("/tmp/urls.txt")
    finder.scan_wayback("superdrug.com", limit=10)
    finder.save_results("/tmp/secrets_out")
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, "/home/ryushe/workspace/bug_bounty_harness")
sys.path.insert(0, "/home/ryushe/projects/bounty-tools")

try:
    from scope_validator import ScopeValidator
except ImportError:
    ScopeValidator = None
try:
    from rate_limiter import RateLimiter
except ImportError:
    RateLimiter = None

try:
    from harness_core import CampaignState
except ImportError:  # pragma: no cover - optional integration
    CampaignState = None

try:
    from orchestrator.findings_store import create_finding, save_finding
    from orchestrator.findings_store import (
        SEVERITY_P1,
        SEVERITY_P2,
        SEVERITY_P3,
        SEVERITY_P4,
        SEVERITY_P5,
    )
except ImportError:  # pragma: no cover - optional integration
    create_finding = None
    save_finding = None
    SEVERITY_P1 = "Critical - P1"
    SEVERITY_P2 = "High - P2"
    SEVERITY_P3 = "Medium - P3"
    SEVERITY_P4 = "Low - P4"
    SEVERITY_P5 = "Info - P5"

try:
    from orchestrator.subagent_logger import SubagentLogger
except ImportError:  # pragma: no cover - optional integration
    SubagentLogger = None


SCRIPT_BLOCK_RE = re.compile(r"<script\b[^>]*>(?P<body>.*?)</script>", re.IGNORECASE | re.DOTALL)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


@dataclass(slots=True)
class FindingRecord:
    type: str
    severity: str
    value: str
    source_file: str
    source_path: str
    line_number: int
    line_context: str
    description: str
    impact: str
    source_kind: str
    source_url: str = ""
    pattern_name: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "severity": self.severity,
            "value": self.value,
            "source_file": self.source_file,
            "source_path": self.source_path,
            "line_number": self.line_number,
            "line_context": self.line_context,
            "description": self.description,
            "impact": self.impact,
            "source_kind": self.source_kind,
            "source_url": self.source_url,
            "pattern_name": self.pattern_name or self.type,
        }


class _LoggerAdapter:
    def __init__(self, program: str):
        self._logger = self._build_logger(program)

    @staticmethod
    def _build_logger(program: str):
        if SubagentLogger is not None:
            for kwargs in (
                {"agent_name": "secrets", "target": program},
                {"agent": "secrets", "target": program},
                {},
            ):
                try:
                    return SubagentLogger(**kwargs)
                except TypeError:
                    continue
                except Exception:
                    break

        logger = logging.getLogger(f"agents.secrets_finder.{program}")
        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger

    def _emit(self, level: str, message: str) -> None:
        if hasattr(self._logger, level):
            getattr(self._logger, level)(message)
            return
        if hasattr(self._logger, "log"):
            self._logger.log(message)
            return
        logging.getLogger(__name__).log(getattr(logging, level.upper(), logging.INFO), message)

    def info(self, message: str) -> None:
        self._emit("info", message)

    def warning(self, message: str) -> None:
        self._emit("warning", message)

    def error(self, message: str) -> None:
        self._emit("error", message)

    def log_span(self, **fields: Any) -> None:
        log_span = getattr(self._logger, "log_span", None)
        if callable(log_span):
            try:
                log_span(**fields)
            except Exception:
                pass


class SecretsFinder:
    """
    Scan JavaScript, HTML, text datasets, and Wayback snapshots for secrets.

    Public methods:
      - scan_file(path)
      - scan_directory(dir_path, extensions=...)
      - scan_url_list(params_file)
      - scan_wayback(domain, limit=...)
      - save_results(output_dir)
      - generate_report()
    """

    def __init__(
        self,
        program: str,
        *,
        campaign_id: str | None = None,
        max_workers: int | None = None,
        pattern_filter: str | Iterable[str] | None = None,
        request_timeout: float = 20.0,
        wayback_delay: float = 1.0,
    ):
        self.program = program
        self.campaign_id = campaign_id
        self.max_workers = max_workers or min(16, (os.cpu_count() or 4))
        self.request_timeout = request_timeout
        self.wayback_delay = max(0.0, wayback_delay)
        self.logger = _LoggerAdapter(program)
        self._lock = threading.Lock()
        self.sources_scanned: list[str] = []
        self.findings: list[FindingRecord] = []
        self._seen_findings: set[tuple[str, str, str, int]] = set()
        self.patterns = self._build_patterns()
        self.severity_map = {
            name: spec["severity"]
            for name, spec in self.patterns.items()
        }
        self.pattern_filter = self._normalize_pattern_filter(pattern_filter)
        if self.pattern_filter:
            missing = sorted(self.pattern_filter - set(self.patterns))
            if missing:
                raise ValueError(f"Unknown pattern filter(s): {', '.join(missing)}")
            self.patterns = {
                name: spec for name, spec in self.patterns.items()
                if name in self.pattern_filter
            }
            self.severity_map = {
                name: severity for name, severity in self.severity_map.items()
                if name in self.patterns
            }
        self._compile_patterns()

        # Load scope
        if program and ScopeValidator is not None:
            self.scope = ScopeValidator(program)
        else:
            self.scope = None

        # Setup rate limiter
        self.limiter = RateLimiter(requests_per_second=5) if RateLimiter else None

    def is_in_scope(self, url: str) -> bool:
        """Check if URL is in scope. Skip if no scope loaded."""
        if not self.scope:
            return True
        return self.scope.is_in_scope(url)

    @staticmethod
    def _normalize_pattern_filter(pattern_filter: str | Iterable[str] | None) -> set[str]:
        if pattern_filter is None:
            return set()
        if isinstance(pattern_filter, str):
            parts = [part.strip() for part in pattern_filter.split(",")]
        else:
            parts = [str(part).strip() for part in pattern_filter]
        return {part for part in parts if part}

    def _build_patterns(self) -> dict[str, dict[str, Any]]:
        return {
            "aws_access_key": {
                "pattern": r"\b(?:AKIA|ASIA|AIDA|AROA|AGPA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b",
                "severity": "CRITICAL",
                "description": "AWS access key found in source",
                "impact": "Can expose AWS resources, IAM actions, or pivot paths",
                "example": "AKIAIOSFODNN7EXAMPLE",
            },
            "google_api_key": {
                "pattern": r"AIza[0-9A-Za-z\-_]{35}",
                "severity": "CRITICAL",
                "description": "Google API key found in source — CRITICAL after Gemini API integration (2025)",
                "impact": "If project's Generative Language API is enabled, key can access Gemini AI, read uploaded files, incur massive costs. ~3000 exposed keys found to auth to Gemini as of Nov 2025.",
                "example": "AIzaSyDjacibP1D0jnd4sMlBJF5b2UjLs7zNh_I",
            },
            "google_oauth_client": {
                "pattern": r"\b[0-9]{12,}-[A-Za-z0-9_]{20,}\.apps\.googleusercontent\.com\b",
                "severity": "HIGH",
                "description": "Google OAuth client identifier found",
                "impact": "Can expose OAuth application metadata and auth flows",
                "example": "123456789012-abc123def456ghi789jklmnop.apps.googleusercontent.com",
            },
            "stripe_live_secret": {
                "pattern": r"\bsk_live_[0-9A-Za-z]{16,}\b",
                "severity": "CRITICAL",
                "description": "Stripe live secret key found",
                "impact": "Can allow direct access to live Stripe resources",
                "example": "sk_live_51N....",
            },
            "stripe_live_publishable": {
                "pattern": r"\bpk_live_[0-9A-Za-z]{16,}\b",
                "severity": "MEDIUM",
                "description": "Stripe live publishable key found",
                "impact": "Can reveal live payment environment identifiers and client integration details",
                "example": "pk_live_51N....",
            },
            "stripe_test_secret": {
                "pattern": r"\bsk_test_[0-9A-Za-z]{16,}\b",
                "severity": "HIGH",
                "description": "Stripe test secret key found",
                "impact": "May expose test payment environment and internal integration patterns",
                "example": "sk_test_51N....",
            },
            "stripe_test_publishable": {
                "pattern": r"\bpk_test_[0-9A-Za-z]{16,}\b",
                "severity": "LOW",
                "description": "Stripe test publishable key found",
                "impact": "Signals test payment integration details",
                "example": "pk_test_51N....",
            },
            "github_token": {
                "pattern": r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b",
                "severity": "CRITICAL",
                "description": "GitHub token found in source",
                "impact": "Can permit repository, package, or workflow access",
                "example": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            },
            "slack_token": {
                "pattern": r"\bxox(?:a|b|p|r|s)-[A-Za-z0-9-]{10,120}\b",
                "severity": "HIGH",
                "description": "Slack token found in source",
                "impact": "May allow workspace, bot, or app access",
                "example": "xoxb-XXXX-XXXX-XXXX-FAKEPLACEHOLDER",
            },
            "sendgrid_key": {
                "pattern": r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b",
                "severity": "CRITICAL",
                "description": "SendGrid API key found in source",
                "impact": "Can allow outbound email abuse or mail data access",
                "example": "SG.FAKEPLACEHOLDER.xxxxxxxxxxxxxxxx",
            },
            "twilio_api_key_sid": {
                "pattern": r"\bSK[0-9a-fA-F]{32}\b",
                "severity": "HIGH",
                "description": "Twilio API key SID found",
                "impact": "Can expose Twilio integration details and pair with leaked secrets",
                "example": "SK00000000000000000000000000000000",
            },
            "twilio_account_sid": {
                "pattern": r"\bAC[0-9a-fA-F]{32}\b",
                "severity": "MEDIUM",
                "description": "Twilio account SID found",
                "impact": "Reveals Twilio account identifiers and targetable integrations",
                "example": "AC00000000000000000000000000000000",
            },
            "mailgun_key": {
                "pattern": r"\bkey-[0-9A-Za-z]{32}\b",
                "severity": "HIGH",
                "description": "Mailgun API key found",
                "impact": "Can allow email sending and API access",
                "example": "key-0123456789abcdef0123456789abcdef",
            },
            "aws_secret_key": {
                "pattern": r"(?i)aws.{0,30}['\"][0-9a-zA-Z\/+]{40}['\"]",
                "severity": "CRITICAL",
                "description": "AWS Secret Access Key found — Lostsec high-signal pattern",
                "impact": "Full AWS account access, S3 data exfiltration, EC2 takeover",
                "example": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            },
            "firebase_token": {
                "pattern": r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
                "severity": "CRITICAL",
                "description": "Firebase server token found in JS",
                "impact": "Can send FCM push notifications or access Firebase services",
                "example": "AAAA...:...",
            },
            "django_secret_key": {
                "pattern": r"[a-zA-Z0-9]{10,50}(?:[._-][a-zA-Z0-9]{10,50}){0,5}",
                "severity": "CRITICAL",
                "description": "Django SECRET_KEY found — used for session signing, CSRF tokens, password reset",
                "impact": "Session hijacking, CSRF bypass, account takeover via forged signed tokens",
                "example": "django-insecure-abc123...xyz789",
            },
            "heroku_api_key": {
                "pattern": r"[hH]eroku['\"][0-9a-f]{32}['\"]",
                "severity": "HIGH",
                "description": "Heroku API key found",
                "impact": "Can manage Heroku apps, scales, add-ons, and credentials",
                "example": "heroku12345678abcdef0123456789abcdef",
            },
            "stripe_restricted_key": {
                "pattern": r"\brk_live_[0-9a-zA-Z]{24,}\b",
                "severity": "CRITICAL",
                "description": "Stripe Restricted Live Key found — Lostsec pattern",
                "impact": "Limited but real Stripe account access via REST API",
                "example": "rk_live_51...",
            },
            "shopify_token": {
                "pattern": r"shpat_[a-fA-F0-9]{32}",
                "severity": "HIGH",
                "description": "Shopify private app token found",
                "impact": "Store admin, orders, customer, and product API access",
                "example": "shpat_1234567890abcdef...",
            },
            "mailchimp_key": {
                "pattern": r"[a-f0-9]{32}-us\d{1,2}",
                "severity": "HIGH",
                "description": "Mailchimp API key found",
                "impact": "Email list access, subscriber data, campaign control",
                "example": "abc123...-us1",
            },
            "atlassian_token": {
                "pattern": r"(?i)atlassian['\"][a-zA-Z0-9]{24}['\"]",
                "severity": "HIGH",
                "description": "Atlassian API token found",
                "impact": "Jira, Confluence, Bitbucket access",
                "example": "ATATT3...",
            },
            "generic_long_string": {
                "pattern": r"['\"][A-Za-z0-9_\-=]{32,80}['\"]",
                "severity": "LOW",
                "description": "Long credential-like string (32-80 chars) — Lostsec noise-reduction approach",
                "impact": "May be a key, token, or hash. Manual review needed.",
                "example": "a1b2c3d4e5f6...",
            },
            "mixpanel_token": {
                "pattern": r"(?i)(?:mixpanel(?:\.[a-z_]+)?|project[_-]?token|mixpanel[_-]?token)\s*[=:]\s*[\"']([0-9a-f]{32})[\"']",
                "severity": "MEDIUM",
                "description": "Mixpanel project token found",
                "impact": "Reveals analytics environment and ingestion credentials",
                "example": "0123456789abcdef0123456789abcdef",
                "value_group": 1,
            },
            "jwt_token": {
                "pattern": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b",
                "severity": "HIGH",
                "description": "JWT token found in source",
                "impact": "May expose session, auth, or API bearer material",
                "example": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            },
            "bearer_token": {
                "pattern": r"\bBearer\s+([A-Za-z0-9\-._~+/=]{12,})",
                "severity": "HIGH",
                "description": "Bearer token found in source",
                "impact": "May provide direct API or session access",
                "example": "Bearer eyJ...",
                "value_group": 1,
            },
            "basic_auth_header": {
                "pattern": r"\bBasic\s+([A-Za-z0-9+/]{8,}={0,2})\b",
                "severity": "HIGH",
                "description": "Basic auth credential found in source",
                "impact": "May expose reusable username/password material",
                "example": "Basic YWRtaW46cGFzc3dvcmQ=",
                "value_group": 1,
            },
            "basic_auth_url": {
                "pattern": r"\bhttps?://[^/\s:@]{1,64}:[^/\s@]{1,128}@[^/\s\"'<>]+\b",
                "severity": "HIGH",
                "description": "Credential-bearing URL found",
                "impact": "Exposes credentials embedded directly in a URL",
                "example": "https://user:pass@example.com/private",
            },
            "rsa_private_key": {
                "pattern": r"-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----",
                "severity": "CRITICAL",
                "description": "RSA private key block found",
                "impact": "Can permit decryption, signing, or server impersonation",
                "example": "-----BEGIN RSA PRIVATE KEY-----",
            },
            "ec_private_key": {
                "pattern": r"-----BEGIN EC PRIVATE KEY-----[\s\S]+?-----END EC PRIVATE KEY-----",
                "severity": "CRITICAL",
                "description": "EC private key block found",
                "impact": "Can permit signing, decryption, or service impersonation",
                "example": "-----BEGIN EC PRIVATE KEY-----",
            },
            "dsa_private_key": {
                "pattern": r"-----BEGIN DSA PRIVATE KEY-----[\s\S]+?-----END DSA PRIVATE KEY-----",
                "severity": "CRITICAL",
                "description": "DSA private key block found",
                "impact": "Can permit signing or trust abuse",
                "example": "-----BEGIN DSA PRIVATE KEY-----",
            },
            "openssh_private_key": {
                "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----",
                "severity": "CRITICAL",
                "description": "OpenSSH private key block found",
                "impact": "Can permit SSH access or infrastructure compromise",
                "example": "-----BEGIN OPENSSH PRIVATE KEY-----",
            },
            "worldpay_merchant_key": {
                "pattern": r"(?i)(?:worldpay|visa(?:[\s_-]*checkout)?|merchant(?:Key)?|clientKey|checkoutKey)[^\n\r]{0,120}?[\"']([A-Za-z0-9]{20,64})[\"']",
                "severity": "CRITICAL",
                "description": "WorldPay / Visa Checkout merchant key found in source",
                "impact": "May expose payment processing credentials enabling fraudulent transactions or payment manipulation",
                "example": "Y7I4LZKHZOCYZo6051R921lZq8ewZ9xBVni4YZDA0EJHfH3zk",
                "value_group": 1,
            },
            "generic_api_key": {
                "pattern": r"(?i)(?:api[_-]?key|access[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|merchant[_-]?key|publishable[_-]?key|private[_-]?token|session[_-]?token)\s*[=:]\s*[\"']([A-Za-z0-9_\-]{16,128})[\"']",
                "severity": "HIGH",
                "description": "Generic API key or token assignment found",
                "impact": "May expose reusable credentials for third-party or internal APIs",
                "example": "api_key = \"abcd1234...\"",
                "value_group": 1,
            },
            "hardcoded_password": {
                "pattern": r"(?i)(?:password|passwd|pwd|secret|client_secret|consumer_secret|api_secret)\s*[=:]\s*[\"']([^\"'\\\r\n]{6,128})[\"']",
                "severity": "HIGH",
                "description": "Hardcoded password or secret found",
                "impact": "May expose authentication material or privileged config",
                "example": "password = \"Sup3rS3cret!\"",
                "value_group": 1,
            },
            "custom_auth_header": {
                "pattern": r"(?i)[\"'](?:x-session-id|x-token|x-auth-token|x-api-key|x-client-token|x-access-token)[\"']\s*:\s*[\"']([^\"']{4,256})[\"']",
                "severity": "HIGH",
                "description": "Custom authentication header with literal value found",
                "impact": "May expose reusable session or API header credentials",
                "example": "\"x-session-id\": \"abcdef\"",
                "value_group": 1,
            },
            "custom_auth_header_name": {
                "pattern": r"(?i)[\"'](x-session-id|x-token|x-auth-token|x-api-key|x-client-token|x-access-token)[\"']\s*:",
                "severity": "MEDIUM",
                "description": "Custom authentication header name found in code",
                "impact": "Reveals nonstandard auth scheme and useful attack surface",
                "example": "\"x-session-id\": token",
                "value_group": 1,
            },
            "registration_code": {
                "pattern": r"(?i)(?:registration(?:[_-]?code)?|promo(?:[_-]?code)?|coupon(?:[_-]?code)?|invite(?:[_-]?code)?|referral(?:[_-]?code)?)\s*[=:]\s*[\"']([A-Za-z0-9]{4,16})[\"']",
                "severity": "MEDIUM",
                "description": "Hardcoded registration or promo code found",
                "impact": "May permit unauthorized signup, discounts, or business logic abuse",
                "example": "registrationCode: \"87e7e\"",
                "value_group": 1,
            },
            "payment_session_token": {
                "pattern": r"\bEC-[A-Z0-9]{10,24}\b",
                "severity": "HIGH",
                "description": "Payment session token found",
                "impact": "May expose active payment session material",
                "example": "EC-4K128833T5091234L",
            },
            "azure_hostname": {
                "pattern": r"\b(?:https?://)?[A-Za-z0-9-]+\.azurewebsites\.net(?:/[^\s\"'<>]*)?\b",
                "severity": "MEDIUM",
                "description": "Azure App Service hostname found",
                "impact": "May expose internal or non-public app endpoints",
                "example": "https://uks-api-fn-superdrug01.azurewebsites.net",
            },
            "sap_commerce_hostname": {
                "pattern": r"\b(?:https?://)?[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.commerce\.ondemand\.com(?:/[^\s\"'<>]*)?\b",
                "severity": "MEDIUM",
                "description": "SAP Commerce or Hybris endpoint found",
                "impact": "Reveals backend commerce services and possible integration endpoints",
                "example": "cmb8j9fjhz-emea5aswa1-d1-public.model-t.cc.commerce.ondemand.com",
            },
            "sensitive_service_endpoint": {
                "pattern": r"(?:https?://)(?:"
                r"(?:api|auth|payment|admin|internal|stage|uat|dev)[-.]"   # internal subdomains
                r"|(?:[a-z][a-z0-9-]*\.azurewebsites\.net)"                # Azure
                r"|(?:[a-z][a-z0-9-]*\.commerce\.ondemand\.com)"            # SAP Hybris
                r"|(?:localhost|127\.0\.0\.1)"                               # localhost
                r"|(?:[a-z][a-z0-9-]*\.(?:meddbase|medibase|health)[.][a-z]{2,})"  # healthcare
                r"|(?:[a-z][a-z0-9-]*-fn-[a-z0-9-]+\.azurewebsites\.net)"  # Azure Functions
                r"|(?:[a-z][a-z0-9-]+\.s3[.-][a-z0-9-]+\.amazonaws\.com)"  # AWS S3
                r"|(?:[a-z][a-z0-9-]*\.ddns\.net|[a-z][a-z0-9-]*\.servehttp\.com)"  # exposed home servers
                r"|(?:[a-z][a-z0-9-]*\.ngrok(?:free\.io|io|[0-9]+\.ngrok(?:debug|app|tunnel|dev))?)"  # ngrok tunnels
                r"|(?:[a-z][a-z0-9-]*\.cloak\.stage\.[a-z]|stage-[a-z][a-z0-9-]*\.[a-z]{2,})"  # staging
                r"|(?:[a-z][a-z0-9-]*\.int\.[a-z]{2,})"                     # *.int.* internal
                r"|(?:[a-z][a-z0-9-]*\.corp\.[a-z]{2,})"                    # *.corp.*
                r"|(?:[a-z][a-z0-9-]*\.internal\.[a-z]{2,})"                 # *.internal.*
                r"|(?:[a-z][a-z0-9-]*\.private\.[a-z]{2,})"                  # *.private.*
                r"|(?:0x[0-9a-fA-F]{1,8}[.:])"                              # IP addresses hex
                r")(?:/[^\s\"'<>]*)?",
                "severity": "MEDIUM",
                "description": "Internal or sensitive hostname/URL found",
                "impact": "May reveal internal infrastructure, dev/staging endpoints, or non-public services",
                "example": "https://api.meddbase.com",
            },
            "oauth_token_endpoint": {
                "pattern": r"(?:https?://[A-Za-z0-9._:-]+)?/(?:oauth/token|oauth2/token|connect/token)\b",
                "severity": "MEDIUM",
                "description": "OAuth token endpoint found",
                "impact": "Identifies auth flows worth deeper review for grant abuse or weak controls",
                "example": "/oauth/token",
            },
            "openid_configuration": {
                "pattern": r"(?:https?://[A-Za-z0-9._:-]+)?/(?:\.well-known/openid-configuration|openid-configuration)\b",
                "severity": "LOW",
                "description": "OpenID configuration endpoint found",
                "impact": "Reveals identity provider metadata and supported auth flows",
                "example": "/.well-known/openid-configuration",
            },
            "sensitive_endpoint": {
                "pattern": r"(?:https?://[A-Za-z0-9._:-]+)?/(?:swagger(?:/index\.html)?|api-docs|actuator|graphiql|graphql|internal|admin-api)\b",
                "severity": "LOW",
                "description": "Sensitive application endpoint found",
                "impact": "May expose debugging, documentation, or privileged functionality",
                "example": "/swagger/index.html",
            },
        }

    def _compile_patterns(self) -> None:
        for spec in self.patterns.values():
            flags = spec.get("flags", re.MULTILINE)
            spec["compiled"] = re.compile(spec["pattern"], flags)

    def _register_source(self, source: str) -> None:
        with self._lock:
            if source not in self.sources_scanned:
                self.sources_scanned.append(source)

    def _add_finding(self, finding: FindingRecord) -> None:
        dedupe_key = (finding.type, finding.value, finding.source_path, finding.line_number)
        with self._lock:
            if dedupe_key in self._seen_findings:
                return
            self._seen_findings.add(dedupe_key)
            self.findings.append(finding)
        self.logger.log_span(
            span_type="finding",
            level="RESULT",
            message=f"Finding: secrets:{finding.type}:{finding.source_path}:{finding.line_number}",
            finding_fid=f"secrets:{finding.type}:{finding.source_path}:{finding.line_number}",
            review_tier=finding.severity,
            duplicate=False,
            finding_reward=0,
            allocated_pte_lite=0,
        )

    @staticmethod
    def _read_text(path: Path) -> str:
        raw = path.read_bytes()
        if raw.count(b"\x00") > 32:
            return ""
        return raw.decode("utf-8", errors="ignore")

    @staticmethod
    def _extract_context(content: str, start: int, end: int, radius: int = 1) -> tuple[int, str]:
        line_number = content.count("\n", 0, start) + 1
        lines = content.splitlines()
        if not lines:
            return line_number, ""
        line_index = max(0, line_number - 1)
        ctx_start = max(0, line_index - radius)
        ctx_end = min(len(lines), line_index + radius + 1)
        context = "\n".join(lines[ctx_start:ctx_end]).strip()
        return line_number, context[:1200]

    @staticmethod
    def _normalize_secret_value(value: str) -> str:
        value = value.strip()
        if "PRIVATE KEY" in value and len(value) > 400:
            lines = value.splitlines()
            if len(lines) >= 4:
                return "\n".join(lines[:2] + ["...[truncated]..."] + lines[-2:])
        return value[:2000]

    @staticmethod
    def _looks_placeholder(value: str) -> bool:
        lowered = value.strip().lower()
        if not lowered:
            return True
        exact_placeholders = {
            "changeme",
            "replace_me",
            "replace-me",
            "example",
            "sample",
            "dummy",
            "testtest",
            "password",
            "secret",
            "token",
            "apikey",
            "api_key",
            "<secret>",
            "<token>",
        }
        if lowered in exact_placeholders:
            return True
        if lowered.startswith(("your_", "your-", "insert_", "insert-", "replace_", "replace-")):
            return True
        if "${" in lowered or lowered in {"xxxxx", "xxxxxx"}:
            return True
        if len(set(lowered)) == 1:
            return True
        return False

    # Values known to be code/UI identifiers, not actual secrets
    _KNOWN_FALSE_POSITIVES = frozenset({
        "checkoutpaymentoptionscomponent",
        "sdworldpayvisacheckout",
        "worldpayvisacheckout",
        "redirectfromtopwhenininiframe",
        "paymentmethodsresponse",
        "retrievingfingerprint",
        "forgottenpasswordtokens",
        "resetpassword",
        "showpassword",
        "onetimetoken",
        "account.holdername.label",
        "account.holdername.placeholder",
        "billingaddress.email",
        "defaultpayment",
        "requirehttps",
        "paymentmethods.enabled",
        "method.icons.component",
        "paymentdata",
        "page.edit.basket.enabled",
        "page.back.to.delivery.options.enabled",
        "page.savings.calculation.enabled",
        "creditcard.cardnumber.label",
        "creditcard.cvc.label",
        "creditcard.expiry.label",
        "paypal.error.label",
        "eft.terminal.error.label",
        "eft.generic.error.label",
        "loyalty.info",
        "loyalty.label",
        "savedcard.label",
        "creditcard.label",
        "giftcard.remove.confirmation",
        "giftcard.remove.cancel",
        "giftcard.remove.remove",
        "remove.msg",
        "remove.confirm",
        "remove.cancel",
        "remove.fail",
        "remove.success",
        "missing",
        "additionalpaymentparameters.entry",
        "paypal.title",
        "applepay.session.error",
        "responseend-qa.starttime",
        "ad.indexof",
        "qb.high",
        "rb.laid",
        "kcp.pwd.940",
        "kcp.pwd.941",
        "browserinforequiredfor.includes",
        "authentication.oauthlibconfig.requirehttps",
        "info.missing",
        "selected.error",
        "payments.api.paymentsclient",
        "merchantinfo.merchantid",
        "merchantinfo.merchantname",
        "merchantinfo.softwareinfo",
        "not.selected.error",
        "otherpayments.label",
        "storedpayments.label",
        "billingaddress",
        "tokenizationdata.token",
        "infocardnetwork",
        "devicefingerprintpromise.promise.then",
        "nativelement.pause",
        "nativelement.play",
        "markerclustererm",
        "groundoverlay",
        "checkoutanalytics",
        "checkoutshopper",
    })

    # Patterns that indicate a value is a UI identifier / code path, not a secret
    _UI_PATH_RE = re.compile(
        r"^(?:"
        r"(?:payment|auth|checkout|oauth|config|form|label|placeholder|error|msg|"
        r"enabled|required|info|token|data|key|remove|cancel|confirm|success|fail|"
        r"edit|basket|delivery|options|savings|creditcard|cvc|expiry|eft|loyalty|"
        r"paypal|applepay|addon|promise|element|cluster|ground|analytics|shopper|"
        r"responseend|starttime|indexof|qb|rb|aid|kcp|pwd|selected|missing|additional|"
        r"nativ|device|bank|account|holder|address|billing|default|mode|"
        r"software|merchant|merchantinfo|paymentsclient|inforequiredfor|cardnetwork|"
        r"tokenization|checkoutshopper|checkoutanalytics|requirehttps|"
        r"editbasket|backdelivery|creditlabel|savedlabel)"
        r"(?:[.][a-z][a-z0-9]+)+$"
        r"|"
        r"^(?:test|qa|dev|staging|uat)[.]"  # test.qa.* hostnames only if full URL
        r"|"
        r"^[a-z]+[.][a-z]+[.][a-z]+$"  # too generic like foo.bar.baz
        r"|"
        r"^(?:https?://)?test[.](?:adyen|cdn|worldpay|payment)[.]"  # test.*.adyen.com type URLs
        r"|"
        r"^/?(?:swagger|actuator|graphiql|internal|admin-api|openid-configuration)$"
        r"|"
        r"^(?:registration|promo|coupon|invite|referral)$"
        r"|"
        r"^(?:api|auth|payment|admin|internal)[.]"  # bare api.* hosts without dots
        r"$)",
        re.IGNORECASE,
    )

    def _is_valid_match(self, pattern_name: str, value: str, context: str) -> bool:
        value = value.strip()
        if not value:
            return False

        # --- structural pattern guards ---
        if pattern_name in {
            "generic_api_key",
            "hardcoded_password",
            "custom_auth_header",
            "registration_code",
            "mixpanel_token",
            "bearer_token",
            "basic_auth_header",
        } and self._looks_placeholder(value):
            return False

        # Reject known UI/code false positives
        normalized = value.lower()
        if normalized in self._KNOWN_FALSE_POSITIVES:
            return False
        
        # Additional checks for specific patterns
        # worldpay_merchant_key: reject camelCase values (JS identifiers)
        if pattern_name == "worldpay_merchant_key" and value != value.lower():
            # Has uppercase = JS identifier, not a key
            return False
        
        # hardcoded_password: reject JS method calls
        if pattern_name == "hardcoded_password":
            lower = value.lower()
            if "setattribute" in lower or "getattribute" in lower or "password" in lower and len(value) <= 15:
                return False
            if "+" in value or "(" in value or ")" in value:
                return False
            if len(value) <= 10:
                return False
                
        # registration_code: reject common words
        if pattern_name == "registration_code":
            if len(value) <= 4:
                return False
            if value.lower() in {"code", "token", "pass", "key", "auth", "user", "test", "demo"}:
                return False
                
        # custom_auth_header_name: keep for recon (shows auth scheme)
        # But filter if it's just a header name without value context
        if pattern_name == "custom_auth_header_name":
            # Keep these - they're valuable for understanding auth
            pass

        # Reject UI-path-like values (payment.foo.bar, etc.)
        if self._UI_PATH_RE.match(value):
            return False

        # Specific numeric-keyed fakes like kcp.pwd.940
        if re.match(r"^[a-z]+\.pwd\.\d+$", normalized):
            return False

        # --- type-specific guards ---
        if pattern_name == "registration_code" and len(value) < 4:
            return False
        if pattern_name == "generic_api_key" and len(value) < 16:
            return False
        if pattern_name == "hardcoded_password" and value.lower() in {
            "true", "false", "null", "undefined",
        }:
            return False
        if pattern_name == "basic_auth_header":
            if len(value) % 4 not in (0, 2, 3):
                return False
        if pattern_name == "custom_auth_header_name" and "authorization" in value.lower():
            return False
        if pattern_name == "twilio_account_sid" and "accountsid" in context.lower():
            return True
        if pattern_name in {"oauth_token_endpoint", "openid_configuration", "sensitive_endpoint"}:
            return True
        if pattern_name == "sensitive_service_endpoint":
            lowered = value.lower()
            # Reject localhost/loopback
            if "localhost" in lowered or "127.0.0.1" in lowered:
                return False
            # Reject known public CDNs and services
            public_prefixes = (
                "https://maps.googleapis.com/maps/api/",  # needs key in URL, skip
                "https://www.googletagmanager.com/",
                "https://maps.google.com/",
                "https://fonts.googleapis.com/",
                "https://fonts.gstatic.com/",
                "https://use.typekit.net/",
                "https://player.vimeo.com/",
                "https://img.youtube.com/",
                "https://vimeo.com/api/",
                "https://vzaar.com/api/",
                "https://github.com/",
                "https://bit.ly/",
                "https://redux.js.org/",
                "https://redux-toolkit.js.org/",
                "https://nextjs.org/",
                "https://angular.io/",
                "https://reactjs.org/",
                "https://jquery.com/",
                "https://jqueryui.com/",
                "https://getbootstrap.com/",
                "https://cdn.jsdelivr.net/",
                "https://cdnjs.cloudflare.com/",
                "https://unpkg.com/",
                "https://www.w3.org/",
                "https://schema.org/",
                "https://applepay.cdn-apple.com/",
                "https://pay.google.com/",
                "https://www.paypal.com/",
                "https://developer.apple.com/",
                "https://checkoutshopper-",
                "https://checkoutanalytics-",
                "https://src.mastercard.com/",
                "https://sandbox.src.mastercard.com/",
                "https://assets.secure.checkout.visa.com/",
                "https://sandbox-assets.secure.checkout.visa.com/",
                "https://kp.lib.",
                "https://community.superdrug.com/",  # public community forum
                "https://healthclinics.superdrug.com/",  # these are public marketing pages
                "https://www.superdrug.com/",
                "https://onlinedoctor.superdrug.com/",
                "https://onlinepharmacy.superdrug.com/",
                "https://www.trustpilot.com/",
                "http://www.google.com/intl/",
                "http://n",
                "http://f",
                "https://a/c",
                "https://x",
                "https://x/",
                "https://reactjs.org/",
            )
            for prefix in public_prefixes:
                if lowered.startswith(prefix):
                    return False

        return True

    def _finding_from_match(
        self,
        pattern_name: str,
        match: re.Match[str],
        content: str,
        *,
        source_path: str,
        source_file: str,
        source_kind: str,
        source_url: str = "",
        base_line_number: int = 0,
    ) -> FindingRecord | None:
        spec = self.patterns[pattern_name]
        value_group = spec.get("value_group", 0)
        try:
            raw_value = match.group(value_group)
        except IndexError:
            raw_value = match.group(0)
        value = self._normalize_secret_value(raw_value)
        line_number, context = self._extract_context(content, match.start(), match.end())
        line_number += base_line_number
        if not self._is_valid_match(pattern_name, value, context):
            return None
        return FindingRecord(
            type=pattern_name,
            severity=spec["severity"],
            value=value,
            source_file=source_file,
            source_path=source_path,
            line_number=line_number,
            line_context=context,
            description=spec["description"],
            impact=spec["impact"],
            source_kind=source_kind,
            source_url=source_url,
            pattern_name=pattern_name,
        )

    def _scan_text(
        self,
        content: str,
        *,
        source_path: str,
        source_file: str,
        source_kind: str,
        source_url: str = "",
        base_line_number: int = 0,
    ) -> list[FindingRecord]:
        findings: list[FindingRecord] = []
        if not content:
            return findings
        for pattern_name, spec in self.patterns.items():
            for match in spec["compiled"].finditer(content):
                finding = self._finding_from_match(
                    pattern_name,
                    match,
                    content,
                    source_path=source_path,
                    source_file=source_file,
                    source_kind=source_kind,
                    source_url=source_url,
                    base_line_number=base_line_number,
                )
                if finding is not None:
                    findings.append(finding)
        return findings

    def scan_file(self, path: str | Path) -> list[dict[str, Any]]:
        file_path = Path(path).expanduser().resolve()
        self._register_source(str(file_path))
        if not file_path.exists() or not file_path.is_file():
            self.logger.warning(f"scan_file skipped missing path: {file_path}")
            return []
        try:
            content = self._read_text(file_path)
        except OSError as exc:
            self.logger.warning(f"scan_file failed for {file_path}: {exc}")
            return []

        all_findings = self._scan_text(
            content,
            source_path=str(file_path),
            source_file=file_path.name,
            source_kind=file_path.suffix.lower().lstrip(".") or "file",
        )

        if file_path.suffix.lower() in {".html", ".htm"} or "<script" in content.lower():
            for script_match in SCRIPT_BLOCK_RE.finditer(content):
                script_body = script_match.group("body")
                base_line = content.count("\n", 0, script_match.start("body"))
                all_findings.extend(
                    self._scan_text(
                        script_body,
                        source_path=str(file_path),
                        source_file=file_path.name,
                        source_kind="inline_script",
                        base_line_number=base_line,
                    )
                )

        for finding in all_findings:
            self._add_finding(finding)
        return [finding.to_dict() for finding in all_findings]

    def scan_directory(
        self,
        dir_path: str | Path,
        extensions: Iterable[str] = (".js", ".html", ".txt"),
    ) -> list[dict[str, Any]]:
        root = Path(dir_path).expanduser().resolve()
        if not root.exists() or not root.is_dir():
            raise FileNotFoundError(f"Directory not found: {root}")

        normalized_exts = {
            ext.lower() if ext.startswith(".") else f".{ext.lower()}"
            for ext in extensions
        }
        files = [
            path for path in root.rglob("*")
            if path.is_file() and path.suffix.lower() in normalized_exts
        ]
        for file_path in files:
            self._register_source(str(file_path))

        results: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.scan_file, path): path for path in files}
            for future in as_completed(futures):
                path = futures[future]
                try:
                    results.extend(future.result())
                except Exception as exc:  # pragma: no cover - defensive
                    self.logger.warning(f"scan_directory failed for {path}: {exc}")
        return results

    def scan_url_list(self, params_file: str | Path) -> list[dict[str, Any]]:
        file_path = Path(params_file).expanduser().resolve()
        self._register_source(str(file_path))
        if not file_path.exists() or not file_path.is_file():
            raise FileNotFoundError(f"URL list not found: {file_path}")

        findings: list[FindingRecord] = []
        with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
            for idx, raw_line in enumerate(handle, start=1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                decoded = urllib.parse.unquote(line)
                line_findings = self._scan_text(
                    decoded,
                    source_path=str(file_path),
                    source_file=file_path.name,
                    source_kind="url_list",
                    source_url=line,
                    base_line_number=idx - 1,
                )
                findings.extend(line_findings)

        for finding in findings:
            self._add_finding(finding)
        return [finding.to_dict() for finding in findings]

    def _wayback_cdx_records(self, domain: str, limit: int) -> list[dict[str, str]]:
        encoded = urllib.parse.quote(f"*.{domain}/*.js", safe="*./:")
        cdx_url = (
            "https://web.archive.org/cdx/search/cdx"
            f"?url={encoded}&output=json&fl=original,timestamp,statuscode,mimetype"
            "&filter=statuscode:200&collapse=urlkey"
            f"&limit={int(limit)}"
        )
        if self.limiter:
            self.limiter.wait()
        request = urllib.request.Request(
            cdx_url,
            headers={"User-Agent": "bug-bounty-harness/1.0"},
        )
        start = time.time()
        with urllib.request.urlopen(request, timeout=self.request_timeout) as response:
            payload = json.loads(response.read().decode("utf-8", errors="ignore"))
        payload_bytes = len(json.dumps(payload).encode("utf-8", errors="replace"))
        self.logger.log_span(
            span_type="tool",
            level="STEP",
            message="Tool: wayback_cdx",
            tool_name="wayback_cdx",
            tool_category="http_request",
            input_bytes=len(cdx_url.encode("utf-8", errors="replace")),
            output_bytes=payload_bytes,
            latency_ms=int((time.time() - start) * 1000),
            output_tokens_est=max(0, math.ceil(payload_bytes / 4)),
            success=True,
        )
        if not payload or len(payload) == 1:
            return []
        headers = payload[0]
        records = []
        for row in payload[1:]:
            record = {headers[i]: row[i] for i in range(min(len(headers), len(row)))}
            if record.get("original", "").lower().endswith(".js"):
                records.append(record)
        return records

    def scan_wayback(self, domain: str, limit: int = 25) -> list[dict[str, Any]]:
        domain = domain.strip().lower()
        if not domain:
            raise ValueError("domain is required for scan_wayback")

        findings: list[FindingRecord] = []
        try:
            records = self._wayback_cdx_records(domain, limit)
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as exc:
            self.logger.warning(f"Wayback lookup failed for {domain}: {exc}")
            return []

        for record in records:
            original = record.get("original", "")
            timestamp = record.get("timestamp", "")
            archived_url = f"https://web.archive.org/web/{timestamp}id_/{original}"
            self._register_source(archived_url)
            if self.limiter:
                self.limiter.wait()
            request = urllib.request.Request(
                archived_url,
                headers={"User-Agent": "bug-bounty-harness/1.0"},
            )
            try:
                start = time.time()
                with urllib.request.urlopen(request, timeout=self.request_timeout) as response:
                    body = response.read().decode("utf-8", errors="ignore")
                body_bytes = len(body.encode("utf-8", errors="replace"))
                self.logger.log_span(
                    span_type="tool",
                    level="STEP",
                    message="Tool: wayback_fetch",
                    tool_name="wayback_fetch",
                    tool_category="http_request",
                    input_bytes=len(archived_url.encode("utf-8", errors="replace")),
                    output_bytes=body_bytes,
                    latency_ms=int((time.time() - start) * 1000),
                    output_tokens_est=max(0, math.ceil(body_bytes / 4)),
                    success=True,
                )
            except (urllib.error.URLError, urllib.error.HTTPError) as exc:
                self.logger.warning(f"Wayback fetch failed for {archived_url}: {exc}")
                continue

            source_file = Path(urllib.parse.urlparse(original).path).name or "wayback.js"
            findings.extend(
                self._scan_text(
                    body,
                    source_path=archived_url,
                    source_file=source_file,
                    source_kind="wayback",
                    source_url=original,
                )
            )
            if self.wayback_delay:
                time.sleep(self.wayback_delay)

        for finding in findings:
            self._add_finding(finding)
        return [finding.to_dict() for finding in findings]

    def run_trufflehog(self, path: str | Path, scan_type: str = "filesystem") -> list[dict[str, Any]]:
        """Run trufflehog on a directory or git URL.
        
        Lostsec technique: trufflehog is the gold standard for secret detection.
        It uses entropy analysis + pattern matching for high-accuracy results.
        
        scan_type: 'filesystem' (local dir) or 'git' (remote repo URL)
        """
        import subprocess

        path = str(path)
        binary = "/home/ryushe/go/bin/trufflehog"

        if not Path(binary).exists():
            self.logger.warning(f"trufflehog not found at {binary}")
            return []

        findings: list[dict] = []
        start = time.time()
        try:
            if scan_type == "filesystem":
                cmd = [binary, "filesystem", path, "--json", "--no-update"]
            else:
                cmd = [binary, "git", path, "--json", "--no-update"]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    secret = data.get("Raw", {}).get("Secret", "unknown")
                    findings.append({
                        "type": "trufflehog",
                        "severity": "CRITICAL",
                        "value": secret[:100],
                        "source_file": data.get("SourceName", path),
                        "source_path": data.get("SourceName", path),
                        "line_number": 0,
                        "line_context": data.get("Raw", {}).get("ExtraData", {}).get("commit", ""),
                        "description": f"Trufflehog detected: {data.get('DetectorName', 'unknown')}",
                        "impact": "High-confidence secret detected via entropy + signatures",
                        "source_kind": "trufflehog",
                    })
                except json.JSONDecodeError:
                    continue

        except subprocess.TimeoutExpired:
            self.logger.warning("trufflehog timed out")
        except Exception as e:
            self.logger.warning(f"trufflehog error: {e}")
        output_bytes = len(json.dumps(findings).encode("utf-8", errors="replace"))
        self.logger.log_span(
            span_type="tool",
            level="STEP",
            message="Tool: trufflehog",
            tool_name="trufflehog",
            tool_category="subprocess",
            input_bytes=len(path.encode("utf-8", errors="replace")),
            output_bytes=output_bytes,
            latency_ms=int((time.time() - start) * 1000),
            output_tokens_est=max(0, math.ceil(output_bytes / 4)),
            success=bool(findings),
        )

        return findings

    def run_gitleaks(self, path: str | Path) -> list[dict[str, Any]]:
        """Run gitleaks on a git repository or directory.
        
        Lostsec technique: gitleaks catches secrets in git history.
        Run against both live repos and archived sources.
        """
        import subprocess

        path = str(path)
        gitleaks = next(
            (Path(p) for p in ["/home/linuxbrew/.linuxbrew/bin/gitleaks",
                               "/usr/local/bin/gitleaks",
                               Path.home() / ".local/bin/gitleaks"]
            if Path(p).exists()), None
        )

        if not gitleaks:
            self.logger.warning("gitleaks not found")
            return []

        findings: list[dict] = []
        start = time.time()
        try:
            cmd = [str(gitleaks), "scan", "--report-format", "json", "--no-color", "-p", path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.stdout.strip():
                try:
                    reports = json.loads(result.stdout)
                    if isinstance(reports, dict):
                        reports = [reports]
                    for r in reports:
                        findings.append({
                            "type": "gitleaks",
                            "severity": "HIGH",
                            "value": r.get("Secret", "")[:80],
                            "source_file": r.get("File", ""),
                            "source_path": str(Path(path) / r.get("File", "")),
                            "line_number": r.get("StartLine", 0),
                            "line_context": r.get("Match", ""),
                            "description": f"GitLeaks: {r.get('Description', 'secret')}",
                            "impact": "Secret detected in git-tracked file",
                            "source_kind": "gitleaks",
                        })
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            self.logger.warning(f"gitleaks error: {e}")
        output_bytes = len(json.dumps(findings).encode("utf-8", errors="replace"))
        self.logger.log_span(
            span_type="tool",
            level="STEP",
            message="Tool: gitleaks",
            tool_name="gitleaks",
            tool_category="subprocess",
            input_bytes=len(path.encode("utf-8", errors="replace")),
            output_bytes=output_bytes,
            latency_ms=int((time.time() - start) * 1000),
            output_tokens_est=max(0, math.ceil(output_bytes / 4)),
            success=bool(findings),
        )

        return findings

    def scan_nuclei_creds(self, target: str) -> list[dict[str, Any]]:
        """Run Nuclei with credential-disclosure templates on a target.
        
        Lostsec technique: Nuclei + credential-disclosure templates catches
        exposed credentials, API keys, and config leaks at scale.
        
        Requires nuclei binary and nuclei-templates (or ~300 cred templates).
        """
        import subprocess

        nuclei = next(
            (Path(p) for p in ["/home/linuxbrew/.linuxbrew/bin/nuclei",
                               "/usr/local/bin/nuclei",
                               Path.home() / ".local/bin/nuclei"]
            if Path(p).exists()), None
        )
        templates = next(
            (Path(p) for p in ["/home/ryushe/nuclei-templates/exposed-tokens",
                              "/home/linuxbrew/.nuclei-templates/exposed-tokens",
                              "/opt/nuclei-templates/exposed-tokens"]
            if Path(p).exists()), None
        )

        if not nuclei:
            self.logger.warning("nuclei not found")
            return []

        findings: list[dict] = []
        start = time.time()
        try:
            cmd = [str(nuclei), "-u", target, "-t", "exposed-tokens,exposed-api-keys",
                   "-json", "-silent"]
            if templates:
                cmd.extend(["-dast", "-templates", str(templates)])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    info = data.get("info", {})
                    findings.append({
                        "type": "nuclei_credential_template",
                        "severity": "HIGH",
                        "value": data.get("matched-at", "")[:80],
                        "source_file": data.get("matched-at", ""),
                        "source_path": data.get("matched-at", ""),
                        "line_number": 0,
                        "line_context": info.get("description", ""),
                        "description": f"Nuclei: {info.get('name', 'credential leak')}",
                        "impact": "Exposed credential or API key template match",
                        "source_kind": "nuclei",
                    })
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            self.logger.warning(f"nuclei error: {e}")
        output_bytes = len(json.dumps(findings).encode("utf-8", errors="replace"))
        self.logger.log_span(
            span_type="tool",
            level="STEP",
            message="Tool: nuclei",
            tool_name="nuclei",
            tool_category="subprocess",
            input_bytes=len(target.encode("utf-8", errors="replace")),
            output_bytes=output_bytes,
            latency_ms=int((time.time() - start) * 1000),
            output_tokens_est=max(0, math.ceil(output_bytes / 4)),
            success=bool(findings),
        )

        return findings

    def get_results(self) -> dict[str, Any]:
        findings = [finding.to_dict() for finding in self._sorted_findings()]
        by_severity = {level: 0 for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        by_type: dict[str, int] = {}
        for finding in findings:
            by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
            by_type[finding["type"]] = by_type.get(finding["type"], 0) + 1
        return {
            "program": self.program,
            "scan_date": datetime.now(timezone.utc).date().isoformat(),
            "sources_scanned": list(self.sources_scanned),
            "total_findings": len(findings),
            "summary": {
                "by_severity": by_severity,
                "by_type": dict(sorted(by_type.items(), key=lambda item: (-item[1], item[0]))),
            },
            "findings": findings,
        }

    def _sorted_findings(self) -> list[FindingRecord]:
        severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        return sorted(
            self.findings,
            key=lambda item: (
                severity_rank.get(item.severity, 99),
                item.type,
                item.source_path,
                item.line_number,
            ),
        )

    def generate_report(self) -> str:
        results = self.get_results()
        lines = [
            f"Secrets Finder Report: {results['program']}",
            f"Scan date: {results['scan_date']}",
            f"Sources scanned: {len(results['sources_scanned'])}",
            f"Total findings: {results['total_findings']}",
            "",
            "Severity summary:",
        ]
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            lines.append(f"- {severity}: {results['summary']['by_severity'].get(severity, 0)}")

        if not results["findings"]:
            lines.append("")
            lines.append("No findings detected.")
            return "\n".join(lines)

        lines.append("")
        lines.append("Top findings:")
        for finding in results["findings"][:50]:
            location = f"{finding['source_path']}:{finding['line_number']}"
            lines.append(f"- [{finding['severity']}] {finding['type']} -> {finding['value']} ({location})")
        return "\n".join(lines)

    def _map_findings_store_severity(self, severity: str) -> str:
        return {
            "CRITICAL": SEVERITY_P1,
            "HIGH": SEVERITY_P2,
            "MEDIUM": SEVERITY_P3,
            "LOW": SEVERITY_P4,
        }.get(severity, SEVERITY_P5)

    def save_findings(self) -> list[str]:
        saved_paths: list[str] = []
        if create_finding is None or save_finding is None:
            return saved_paths

        for finding in self._sorted_findings():
            endpoint = finding.source_url or f"{finding.source_path}:{finding.line_number}"
            poc = (
                f"Value: {finding.value}\n"
                f"Source: {finding.source_path}:{finding.line_number}\n"
                f"Context:\n{finding.line_context}"
            )
            description = f"{finding.description}. Impact: {finding.impact}"
            try:
                store_record = create_finding(
                    target=self.program,
                    vuln_type=f"secrets/{finding.type}",
                    endpoint=endpoint,
                    severity=self._map_findings_store_severity(finding.severity),
                    poc=poc,
                    description=description,
                    status="new",
                )
                saved_paths.append(save_finding(store_record))
            except Exception as exc:  # pragma: no cover - optional integration
                self.logger.warning(f"Failed to save finding to findings_store: {exc}")
        return saved_paths

    def save_to_campaign(self) -> int:
        if not self.campaign_id or CampaignState is None:
            return 0
        count = 0
        try:
            state = CampaignState()
        except Exception as exc:  # pragma: no cover - optional integration
            self.logger.warning(f"Campaign state unavailable: {exc}")
            return 0

        for finding in self._sorted_findings():
            payload = finding.to_dict()
            payload["category"] = "secrets"
            try:
                state.add_finding(self.campaign_id, payload, "potential")
                count += 1
            except Exception as exc:  # pragma: no cover - optional integration
                self.logger.warning(f"Failed to save finding to campaign {self.campaign_id}: {exc}")
        return count

    def save_results(self, output_dir: str | Path) -> dict[str, str]:
        out_dir = Path(output_dir).expanduser().resolve()
        out_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        json_path = out_dir / f"secrets_findings_{timestamp}.json"
        report_path = out_dir / f"secrets_report_{timestamp}.txt"

        results = self.get_results()
        with json_path.open("w", encoding="utf-8") as handle:
            json.dump(results, handle, indent=2)

        with report_path.open("w", encoding="utf-8") as handle:
            handle.write(self.generate_report())
            handle.write("\n")

        saved_findings = self.save_findings()
        saved_campaign = self.save_to_campaign()

        meta_path = out_dir / f"secrets_meta_{timestamp}.json"
        with meta_path.open("w", encoding="utf-8") as handle:
            json.dump(
                {
                    "json_results": str(json_path),
                    "report": str(report_path),
                    "findings_store_records": saved_findings,
                    "campaign_findings_saved": saved_campaign,
                },
                handle,
                indent=2,
            )

        return {
            "json": str(json_path),
            "report": str(report_path),
            "meta": str(meta_path),
        }

    def save_notes(
        self,
        notes_base: str | Path = "/home/ryushe/notes",
        dedupe_known: bool = True,
    ) -> dict[str, str]:
        """Write findings as Obsidian markdown notes organized by vulnerability category.

        Categories:
          - api-keys/          → API keys, tokens, secrets
          - information-disclosure/ → Internal hosts, paths, config leaks
          - authentication-secrets/ → Session tokens, hardcoded credentials
          - server-side/        → SSRF, SQLi, RCE, file inclusions
          - client-side/        → XSS, open redirect, CORS misconfig
          - broken-access-control/ → IDOR, auth bypass, privilege escalation

        dedupe_known: skip findings matching known secrets (default True)
        """
        import re

        notes_base = Path(notes_base).expanduser()

        # ── Category map ───────────────────────────────────────────────────
        KEYWORDS: dict[str, list[str]] = {
            "api-keys": [
                "google_api_key", "worldpay_merchant_key", "visa_checkout",
                "github_token", "slack_token", "stripe", "aws_access_key",
                "aws_secret_key", "firebase_token", "django_secret_key",
                "heroku_api_key", "shopify_token", "mailchimp_key",
                "atlassian_token", "sendgrid_key", "twilio",
                "mailgun_key", "mixpanel_token",
            ],
            "authentication-secrets": [
                "hardcoded_password", "custom_auth_header_name",
                "registration_code", "session_token", "bearer_token",
                "basic_auth_header", "jwt_token",
            ],
            "information-disclosure": [
                "sap_commerce_hostname", "sensitive_service_endpoint",
                "oauth_token_endpoint", "azure_hostname",
                "wordpress_exposure", "internal_hostname",
            ],
            "server-side": [
                "sql", "rce", "command_injection", "lfi", "ssti", "ssrf",
            ],
            "client-side": [
                "xss", "open_redirect", "cors", "dom_xss",
            ],
            "broken-access-control": [
                "idor", "auth_bypass", "privilege_escalation",
            ],
        }

        # Known secrets to skip (prevents re-logging known findings)
        KNOWN: set[str] = {
            "AIzaSyDjacibP1D0jnd4sMlBJF5b2UjLs7zNh_I",
            "Y7I4LZKHZOCYZo6051R921lZq8ewZ9xBVni4YZDA0EJHfH3zk",
            "6abe2327-ad69-4158-93e0-a46222507896",
            "87e7e",
            "EC-66G79400Y683272A",
        }

        # ── Deduplicate ────────────────────────────────────────────────────
        findings = []
        seen_vals: set[str] = set()
        for f in self._sorted_findings():
            v = f.value[:80].lower()
            # Skip exact dupes
            if v in seen_vals:
                continue
            # Skip known
            if dedupe_known and any(k.lower() in v or v in k.lower() for k in KNOWN):
                continue
            seen_vals.add(v)
            findings.append(f)

        if not findings:
            return {"status": "no_new_findings", "notes_written": []}

        # ── Group by category ─────────────────────────────────────────────
        grouped: dict[str, list[FindingRecord]] = {cat: [] for cat in KEYWORDS}
        grouped.setdefault("uncategorized", [])

        for f in findings:
            categorized = False
            for cat, keywords in KEYWORDS.items():
                if f.type in keywords:
                    grouped[cat].append(f)
                    categorized = True
                    break
            if not categorized:
                grouped.setdefault("uncategorized", []).append(f)

        # ── Write notes ───────────────────────────────────────────────────
        written: list[str] = []
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        for category, cat_findings in grouped.items():
            if not cat_findings:
                continue
            cat_dir = notes_base / self.program / "findings" / category
            cat_dir.mkdir(parents=True, exist_ok=True)

            # Category index
            idx_path = cat_dir / "_index.md"
            idx_lines = [
                f"# {category.title().replace('-', ' ')} — {self.program.title()}\n",
                f"> Auto-generated by secrets_finder | {timestamp}\n",
                f"\n## Findings ({len(cat_findings)})\n",
                "| Date | Finding | Severity | Value |",
                "|------|---------|----------|-------|",
            ]

            for f in cat_findings:
                slug = re.sub(r"[^a-z0-9]+", "-", f.type.lower())
                fname = f"{slug}.md"
                fpath = cat_dir / fname

                # Skip if already exists (don't overwrite existing notes)
                if fpath.exists():
                    continue

                note = [
                    f"# {f.type.replace('_', ' ').title()} — {self.program.title()}\n",
                    f"> 🔎 {f.severity} | Source: `{f.source_file}`\n",
                    f"\n## Summary",
                    f"{f.description}",
                    f"\n## Details",
                    f"- **Value:** ```{f.value[:80]}```",
                    f"- **Source:** `{f.source_file}`",
                    f"- **Type:** `{f.type}`",
                    f"- **Severity:** {f.severity}",
                    f"\n## Impact",
                    f"{f.impact}",
                    f"\n## Line Context",
                    f"```",
                    f"{f.line_context[:200]}",
                    f"```",
                    f"\n## Status",
                    f"- [ ] Reported",
                    f"- [ ] Triaged",
                    f"- [ ] Bounty Awarded\n",
                    f"---\n",
                    f"*Auto-generated by secrets_finder | {timestamp}*\n",
                ]

                fpath.write_text("\n".join(note), encoding="utf-8")
                written.append(str(fpath))

                # Index entry
                idx_lines.append(
                    f"| {timestamp} | [[{category}/{fname.rstrip('.md')}|{f.type.replace('_', ' ').title()}]] "
                    f"| {f.severity} | ```{f.value[:40]}...``` |"
                )

            # Write / update category index
            idx_path.write_text("\n".join(idx_lines) + "\n", encoding="utf-8")
            written.append(str(idx_path))

        # ── Update master findings index ───────────────────────────────────
        master_idx = notes_base / self.program / "findings" / "_index.md"
        if master_idx.exists():
            original = master_idx.read_text(encoding="utf-8")
            # Just touch it so it shows recent update
            master_idx.write_text(original, encoding="utf-8")

        return {
            "status": "ok",
            "categories_updated": [c for c in grouped if grouped[c]],
            "notes_written": written,
            "total_findings": len(findings),
        }

    def run(
        self,
        *,
        js_dir: str | Path | None = None,
        urls_file: str | Path | None = None,
        wayback: str | None = None,
        source: str = "auto",
        extensions: Iterable[str] = (".js", ".html", ".txt"),
        output_dir: str | Path | None = None,
        wayback_limit: int = 25,
    ) -> dict[str, Any]:
        valid_sources = {"auto", "js_dir", "urls_file", "wayback"}
        if source not in valid_sources:
            raise ValueError(f"source must be one of: {', '.join(sorted(valid_sources))}")

        if source in {"auto", "js_dir"} and js_dir:
            self.logger.info(f"Scanning directory: {js_dir}")
            self.scan_directory(js_dir, extensions=extensions)

        if source in {"auto", "urls_file"} and urls_file:
            self.logger.info(f"Scanning URL list: {urls_file}")
            self.scan_url_list(urls_file)

        if source in {"auto", "wayback"} and wayback:
            self.logger.info(f"Scanning Wayback for: {wayback}")
            self.scan_wayback(wayback, limit=wayback_limit)

        if output_dir:
            self.save_results(output_dir)
        return self.get_results()


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan JS, HTML, URL lists, and Wayback data for secrets.")
    parser.add_argument("--program", required=True, help="Program or target name")
    parser.add_argument("--campaign-id", help="Optional campaign id for harness integration")
    parser.add_argument("--js-dir", help="Directory containing downloaded JS/HTML/TXT artifacts")
    parser.add_argument("--urls-file", help="Text file containing URLs or parameterized endpoints")
    parser.add_argument("--wayback", help="Domain to query from the Wayback Machine")
    parser.add_argument(
        "--source",
        default="auto",
        choices=["auto", "js_dir", "urls_file", "wayback"],
        help="Restrict scanning to a single source type",
    )
    parser.add_argument(
        "--pattern",
        action="append",
        help="Pattern name filter. Repeat or pass comma-separated names.",
    )
    parser.add_argument(
        "--extensions",
        nargs="+",
        default=[".js", ".html", ".txt"],
        help="File extensions to scan when using --js-dir",
    )
    parser.add_argument("--output-dir", help="Directory for JSON and text report output")
    parser.add_argument("--threads", type=int, default=min(16, (os.cpu_count() or 4)))
    parser.add_argument("--wayback-limit", type=int, default=25)
    parser.add_argument("--wayback-delay", type=float, default=1.0)
    parser.add_argument("--json", action="store_true", help="Print JSON results to stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not any([args.js_dir, args.urls_file, args.wayback]):
        parser.error("At least one input source is required: --js-dir, --urls-file, or --wayback")

    finder = SecretsFinder(
        program=args.program,
        campaign_id=args.campaign_id,
        max_workers=args.threads,
        pattern_filter=args.pattern or None,
        wayback_delay=args.wayback_delay,
    )
    results = finder.run(
        js_dir=args.js_dir,
        urls_file=args.urls_file,
        wayback=args.wayback,
        source=args.source,
        extensions=args.extensions,
        output_dir=args.output_dir,
        wayback_limit=args.wayback_limit,
    )

    if args.json:
        print(json.dumps(results, indent=2))
    elif args.output_dir:
        print(finder.generate_report())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
