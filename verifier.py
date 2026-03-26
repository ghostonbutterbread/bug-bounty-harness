"""
Finding Verifier — Reduces false positives by validating findings before submission.

A finding requires evidence before being marked "confirmed." This module
provides structured verification for each vulnerability type.

Usage:
    from verifier import FindingVerifier, verify_idor, verify_auth_bypass

    verifier = FindingVerifier(campaign_id)
    result = verifier.verify_idor(endpoint, baseline_a, baseline_b, test_response)
    if result.confirmed:
        campaign.add_finding(campaign_id, finding, "confirmed")
"""

import json
import re
from dataclasses import dataclass
from typing import Optional
from enum import Enum


class VulnType(Enum):
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    ESCALATION = "escalation"
    SSRF = "ssrf"
    XSS = "xss"
    SQLI = "sqli"
    VERTICAL_ESCALATION = "vertical_escalation"


@dataclass
class VerificationResult:
    confirmed: bool
    confidence: float  # 0.0 - 1.0
    reason: str
    needs_human_review: bool = False
    evidence: dict = None


class FindingVerifier:
    """
    Runs structured verification on potential findings.
    Each vuln type has its own verification logic.
    """

    def __init__(self, campaign_id: str = None):
        self.campaign_id = campaign_id

    def verify(self, vuln_type: VulnType, **kwargs) -> VerificationResult:
        """Dispatch to the right verifier based on vuln type."""
        if vuln_type == VulnType.IDOR:
            return self.verify_idor(**kwargs)
        elif vuln_type == VulnType.AUTH_BYPASS:
            return self.verify_auth_bypass(**kwargs)
        elif vuln_type == VulnType.ESCALATION:
            return self.verify_escalation(**kwargs)
        elif vuln_type == VulnType.VERTICAL_ESCALATION:
            return self.verify_vertical_escalation(**kwargs)
        else:
            return VerificationResult(
                confirmed=False,
                confidence=0.0,
                reason=f"No verifier for vuln type: {vuln_type.value}",
                needs_human_review=True,
            )

    # ─── IDOR Verification ────────────────────────────────────────────────────

    def verify_idor(
        self,
        baseline_a_response: dict,
        baseline_b_response: dict,
        test_response: dict,
        test_endpoint: str,
        test_method: str = "GET",
    ) -> VerificationResult:
        """
        Verify an IDOR finding.

        An IDOR is confirmed when:
        1. The test response differs from baseline A (something changed)
        2. The change is semantically significant (different user data)
        3. Account B's data appears in Account A's session response
        """
        result = VerificationResult(confirmed=False, confidence=0.0, reason="", evidence={})

        if not baseline_a_response or not test_response:
            return VerificationResult(
                confirmed=False, confidence=0.0,
                reason="Missing baseline or test response data"
            )

        base_status = baseline_a_response.get("status_code")
        test_status = test_response.get("status_code")
        base_body = self._get_body(baseline_a_response)
        test_body = self._get_body(test_response)

        evidence = {
            "baseline_status": base_status,
            "test_status": test_status,
            "body_changed": base_body != test_body,
            "body_length_delta": len(test_body) - len(base_body),
        }

        # ── Check 1: Status code anomaly ────────────────────────────────────
        if base_status == 403 and test_status == 200:
            # Classic IDOR: was blocked, now returning data
            evidence["pattern"] = "auth_block_to_success"
            return VerificationResult(
                confirmed=True, confidence=0.95,
                reason="403→200 status change suggests IDOR — unauthorized access succeeded",
                evidence=evidence,
            )

        # ── Check 2: Body content changed significantly ───────────────────────
        if base_body == test_body:
            return VerificationResult(
                confirmed=False, confidence=0.2,
                reason="Response body unchanged — likely not an IDOR",
                evidence=evidence,
            )

        # ── Check 3: Semantic diff — look for user data leakage ─────────────
        try:
            base_json = json.loads(base_body) if base_body else {}
            test_json = json.loads(test_body) if test_body else {}
            evidence["is_json"] = True

            if isinstance(base_json, dict) and isinstance(test_json, dict):
                # Find differing fields
                diff_keys = []
                user_data_keys = ["user_id", "userId", "id", "email", "user_id", "account_id",
                                  "customer_id", "patient_id", "name", "first_name", "last_name",
                                  "address", "phone", "dob", "date_of_birth"]

                for key in set(base_json.keys()) | set(test_json.keys()):
                    if base_json.get(key) != test_json.get(key):
                        diff_keys.append(key)

                evidence["diff_keys"] = diff_keys

                # Check if differing keys contain other user's data
                user_data_leaked = any(k.lower() in [uk.lower() for uk in user_data_keys] for k in diff_keys)

                if user_data_leaked:
                    # Look for ID mismatch — test has B's ID but was made as A
                    if baseline_b_response:
                        b_body = self._get_body(baseline_b_response)
                        try:
                            b_json = json.loads(b_body) if b_body else {}
                            for key in diff_keys:
                                if key in test_json and key in b_json:
                                    if test_json[key] == b_json[key] and test_json[key] != base_json.get(key):
                                        evidence["leaked_field"] = key
                                        evidence["leaked_value"] = test_json[key]
                                        return VerificationResult(
                                            confirmed=True, confidence=0.95,
                                            reason=f"IDOR confirmed: Account B's {key}={test_json[key]} "
                                                   f"returned in Account A's session",
                                            evidence=evidence,
                                        )
                        except (json.JSONDecodeError, TypeError):
                            pass

                    # Heuristic: significant field differences without B baseline
                    if len(diff_keys) >= 2:
                        return VerificationResult(
                            confirmed=True, confidence=0.75,
                            reason=f"IDOR likely: {len(diff_keys)} fields differ — "
                                   f"{', '.join(diff_keys[:5])}",
                            needs_human_review=True,
                            evidence=evidence,
                        )

        except (json.JSONDecodeError, TypeError):
            evidence["is_json"] = False
            # Non-JSON: check for significant length difference
            if abs(len(test_body) - len(base_body)) > 100:
                return VerificationResult(
                    confirmed=True, confidence=0.6,
                    reason=f"Response body changed significantly ({len(base_body)}→{len(test_body)} chars)",
                    needs_human_review=True,
                    evidence=evidence,
                )

        # ── Check 4: 200 on previously 404/401 ──────────────────────────────
        if base_status in (401, 404) and test_status == 200:
            return VerificationResult(
                confirmed=True, confidence=0.85,
                reason=f"Status {base_status}→200 — unauthorized access to resource succeeded",
                evidence=evidence,
            )

        # ── Check 5: Sensitive data in response ─────────────────────────────
        sensitive_patterns = [
            r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",  # Credit card
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
            r"\b\d{9,}\b",  # Long numeric IDs
        ]
        for pattern in sensitive_patterns:
            if re.search(pattern, test_body) and not re.search(pattern, base_body):
                return VerificationResult(
                    confirmed=True, confidence=0.7,
                    reason="Sensitive data (email/CC/id) appears in response that wasn't in baseline",
                    needs_human_review=True,
                    evidence=evidence,
                )

        return VerificationResult(
            confirmed=False, confidence=0.3,
            reason="Response differs but no clear IDOR pattern detected",
            needs_human_review=True,
            evidence=evidence,
        )

    # ─── Auth Bypass Verification ──────────────────────────────────────────

    def verify_auth_bypass(
        self,
        unauth_response: dict,
        auth_response: dict,
        endpoint: str,
    ) -> VerificationResult:
        """
        Verify an auth bypass finding.

        An auth bypass is confirmed when:
        1. An unauthenticated request returns data that should require auth
        2. The data returned is meaningful (not just an error page)
        """
        evidence = {}

        if not unauth_response:
            return VerificationResult(
                confirmed=False, confidence=0.0,
                reason="Missing unauthenticated response"
            )

        unauth_status = unauth_response.get("status_code")
        unauth_body = self._get_body(unauth_response)

        evidence["unauth_status"] = unauth_status
        evidence["unauth_body_length"] = len(unauth_body)

        if auth_response:
            auth_status = auth_response.get("status_code")
            auth_body = self._get_body(auth_response)
            evidence["auth_status"] = auth_status
            evidence["auth_body_length"] = len(auth_body)

            # Same content returned to both — clear bypass
            if unauth_body == auth_body and unauth_status == 200:
                return VerificationResult(
                    confirmed=True, confidence=0.9,
                    reason="Unauthenticated and authenticated requests return identical content — auth not enforced",
                    evidence=evidence,
                )

        # Unauthenticated returns 200 with substantive content
        if unauth_status == 200 and len(unauth_body) > 500:
            # Check it's not just a redirect or error page
            if not self._is_error_page(unauth_body):
                return VerificationResult(
                    confirmed=True, confidence=0.8,
                    reason="Unauthenticated request returns substantive 200 response",
                    needs_human_review=True,
                    evidence=evidence,
                )

        # Unauthenticated returns 200 with sensitive data patterns
        sensitive_leak = self._check_sensitive_data(unauth_body)
        if sensitive_leak:
            return VerificationResult(
                confirmed=True, confidence=0.9,
                reason=f"Sensitive data exposed to unauthenticated user: {sensitive_leak}",
                evidence=evidence,
            )

        return VerificationResult(
            confirmed=False, confidence=0.3,
            reason="No clear auth bypass pattern",
            needs_human_review=True,
            evidence=evidence,
        )

    # ─── Privilege Escalation Verification ─────────────────────────────────

    def verify_escalation(
        self,
        user_auth_response: dict,
        endpoint: str,
        expected_status: int = 403,
    ) -> VerificationResult:
        """
        Verify horizontal privilege escalation (user accessing another user's data).

        vs

        verify_vertical_escalation — regular user accessing admin endpoints.
        """
        evidence = {}

        if not user_auth_response:
            return VerificationResult(
                confirmed=False, confidence=0.0,
                reason="Missing user auth response"
            )

        status = user_auth_response.get("status_code")
        body = self._get_body(user_auth_response)
        evidence["status"] = status
        evidence["body_length"] = len(body)

        if status == 200 and len(body) > 100:
            if not self._is_error_page(body):
                return VerificationResult(
                    confirmed=True, confidence=0.85,
                    reason=f"Regular user accessed {endpoint} — expected {expected_status}, got {status}",
                    needs_human_review=True,
                    evidence=evidence,
                )

        return VerificationResult(
            confirmed=False, confidence=0.2,
            reason=f"Expected {expected_status}, got {status} — likely properly restricted",
            evidence=evidence,
        )

    def verify_vertical_escalation(
        self,
        regular_user_response: dict,
        admin_endpoint: str,
    ) -> VerificationResult:
        """Verify a regular user can access admin functionality."""
        return self.verify_escalation(
            regular_user_response,
            admin_endpoint,
            expected_status=401,
        )

    # ─── Helpers ─────────────────────────────────────────────────────────────

    def _get_body(self, response: dict) -> str:
        """Extract body from response dict (handles both raw and wrapped)."""
        if isinstance(response, dict):
            if "body" in response:
                body = response["body"]
                if isinstance(body, str):
                    return body
                return json.dumps(body)
            if "response" in response:
                return self._get_body(response["response"])
        return str(response) if response else ""

    def _is_error_page(self, body: str) -> bool:
        """Heuristic: does this look like an error/login page?"""
        body_lower = body.lower()
        error_indicators = [
            "login", "sign in", "not found", "404", "403", "forbidden",
            "access denied", "unauthorized", "please log in",
            "<form", "csrf", "captcha", "redirect"
        ]
        matches = sum(1 for ind in error_indicators if ind in body_lower)
        # If most indicators match, probably an error page
        return matches >= 3

    def _check_sensitive_data(self, body: str) -> Optional[str]:
        """Check for sensitive data patterns in body."""
        patterns = {
            "credit_card": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
            "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "phone": r"\b\d{10,}\b",
            "password": r'"(password|passwd|pwd)"\s*:\s*"[^"]{3,}"',
            "api_key": r'"(api[_-]?key|secret|token)"\s*:\s*"[^"]{8,}"',
        }
        for name, pattern in patterns.items():
            if re.search(pattern, body, re.IGNORECASE):
                return name
        return None
