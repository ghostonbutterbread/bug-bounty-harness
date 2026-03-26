"""
Baseline Capture — Captures authenticated request/response pairs per account.

Before running any vulnerability test, we must capture the legitimate
response as each account. This establishes a baseline for comparison.

Usage:
    from baseline_capture import BaselineStore, capture_baseline_for_account
    store = BaselineStore(campaign_id)
    baseline = store.capture("/api/v2/orders/123", "a", "GET", url, headers)
"""

import json
import hashlib
import httpx
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from harness_core import hash_endpoint


# ─── Baseline Store ────────────────────────────────────────────────────────────

class BaselineStore:
    """
    Stores and retrieves authenticated baseline captures per endpoint/account.

    Files are stored at:
        campaigns/{campaign_id}/baselines/{endpoint_hash}_{account}.json
    """

    def __init__(self, campaign_id: str, campaigns_dir: str = None):
        if campaigns_dir:
            base = Path(campaigns_dir)
        else:
            base = Path.home() / "workspace" / "bug_bounty_harness" / "campaigns"
        self.baselines_dir = base / campaign_id / "baselines"
        self.baselines_dir.mkdir(parents=True, exist_ok=True)
        self.campaign_id = campaign_id

    def _key(self, endpoint: str, account: str) -> str:
        """Generate a storage key from endpoint + account."""
        ep_hash = hash_endpoint(endpoint)
        return f"{ep_hash}_{account}"

    def _path(self, endpoint: str, account: str) -> Path:
        return self.baselines_dir / f"{self._key(endpoint, account)}.json"

    def capture(
        self,
        endpoint: str,
        account: str,
        method: str,
        url: str,
        headers: dict,
        params: dict = None,
        body: dict | str = None,
        timeout: float = 10.0,
    ) -> dict:
        """
        Make an authenticated HTTP request and capture request + response.

        Args:
            endpoint: Normalized endpoint path (e.g. /api/v2/orders/{id})
            account: 'a' or 'b' (for multi-account testing)
            method: HTTP method
            url: Full URL
            headers: Request headers (must include auth)
            params: Query parameters
            body: Request body (dict or JSON string)
            timeout: Request timeout in seconds

        Returns:
            The captured baseline dict
        """
        captured = {
            "endpoint": endpoint,
            "account": account,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "campaign_id": self.campaign_id,
            "request": {
                "method": method.upper(),
                "url": url,
                "headers": dict(headers),  # copy to avoid mutation
                "params": params or {},
                "body": body,
            },
            "response": None,
            "error": None,
        }

        try:
            client_kwargs = {
                "method": method.upper(),
                "url": url,
                "headers": headers,
                "timeout": timeout,
            }
            if params:
                client_kwargs["params"] = params
            if body:
                client_kwargs["content"] = (
                    json.dumps(body) if isinstance(body, dict) else body
                )
                if isinstance(body, dict):
                    captured["request"]["headers"]["Content-Type"] = "application/json"

            response = httpx.request(**client_kwargs)

            # Parse response
            try:
                resp_body = response.json()
                resp_body_str = json.dumps(resp_body)
            except Exception:
                resp_body_str = response.text[:10000]  # cap at 10KB

            captured["response"] = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": resp_body_str,
                "body_length": len(resp_body_str),
                "elapsed_ms": response.elapsed.total_seconds() * 1000,
            }

        except httpx.TimeoutException:
            captured["error"] = "TIMEOUT"
        except httpx.ConnectError as e:
            captured["error"] = f"CONNECT_ERROR: {str(e)}"
        except Exception as e:
            captured["error"] = f"ERROR: {type(e).__name__}: {str(e)}"

        # Save to disk
        path = self._path(endpoint, account)
        with open(path, "w") as f:
            json.dump(captured, f, indent=2)

        return captured

    def get(self, endpoint: str, account: str) -> Optional[dict]:
        """Retrieve a stored baseline, or None if not found."""
        path = self._path(endpoint, account)
        if not path.exists():
            return None
        with open(path) as f:
            return json.load(f)

    def get_path(self, endpoint: str, account: str) -> str:
        """Return the file path for a baseline."""
        return str(self._path(endpoint, account))

    def exists(self, endpoint: str, account: str) -> bool:
        """Check if baseline exists for endpoint + account."""
        return self._path(endpoint, account).exists()

    def list_baselines(self) -> list[dict]:
        """List all stored baselines for this campaign."""
        baselines = []
        for path in sorted(self.baselines_dir.glob("*.json")):
            try:
                with open(path) as f:
                    data = json.load(f)
                    baselines.append({
                        "file": path.name,
                        "endpoint": data.get("endpoint"),
                        "account": data.get("account"),
                        "captured_at": data.get("captured_at"),
                        "has_response": data.get("response") is not None,
                        "error": data.get("error"),
                    })
            except Exception:
                continue
        return baselines


# ─── Baseline Comparison ──────────────────────────────────────────────────────

def diff_response(baseline_a: dict, baseline_b: dict, test_response: dict) -> dict:
    """
    Compare a test response against baselines from two accounts.

    This is the core logic for detecting IDOR:
    - Did the test response return data that should belong to Account B?
    - Is it different from what Account A would legitimately see?

    Args:
        baseline_a: Baseline from Account A
        baseline_b: Baseline from Account B (if available)
        test_response: The mutated test response

    Returns:
        dict with keys:
            - changed: bool — did the response change from baseline?
            - semantic_diff: bool — is the change semantically significant?
            - diff_summary: str — human-readable diff summary
            - account_b_data_leaked: bool — does it look like Account B's data?
            - confidence: float — 0.0 to 1.0
    """
    result = {
        "changed": False,
        "semantic_diff": False,
        "diff_summary": "",
        "account_b_data_leaked": False,
        "confidence": 0.0,
    }

    if not baseline_a or not test_response:
        return result

    baseline_resp = baseline_a.get("response")
    if not baseline_resp:
        return result

    test_status = test_response.get("status_code")
    baseline_status = baseline_resp.get("status_code")
    test_body = test_response.get("body", "")
    baseline_body = baseline_resp.get("body", "")

    # Status code changed?
    if test_status != baseline_status:
        result["changed"] = True
        result["diff_summary"] += f"Status {baseline_status}→{test_status}. "

    # Body changed?
    if test_body != baseline_body:
        result["changed"] = True

        # Check for semantic difference in JSON responses
        if test_body and baseline_body:
            try:
                test_json = json.loads(test_body) if isinstance(test_body, str) else test_body
                base_json = json.loads(baseline_body) if isinstance(baseline_body, str) else baseline_body

                if isinstance(test_json, dict) and isinstance(base_json, dict):
                    # Check if response contains data that differs meaningfully
                    all_keys = set(test_json.keys()) | set(base_json.keys())
                    differing_keys = []
                    for key in all_keys:
                        tv = test_json.get(key)
                        bv = base_json.get(key)
                        if tv != bv:
                            differing_keys.append(key)

                    if differing_keys:
                        result["semantic_diff"] = True
                        result["diff_summary"] += f"Differing fields: {', '.join(differing_keys)}. "

                    # Check if it's account B's data (has B's identifiers)
                    # This is a heuristic — we check for user IDs, emails, names
                    # that appear in baseline_b but not in baseline_a's expected data
                    if baseline_b:
                        baseline_b_body = baseline_b.get("response", {}).get("body", "")
                        if baseline_b_body:
                            try:
                                baseline_b_json = json.loads(baseline_b_body) if isinstance(baseline_b_body, str) else baseline_b_body
                                # If test response matches baseline B's structure but with different values
                                # that's a strong signal of IDOR
                                if isinstance(test_json, dict) and isinstance(baseline_b_json, dict):
                                    # Check for user_id or email fields leaking
                                    id_fields = ["user_id", "userId", "id", "email", "account_id"]
                                    for field in id_fields:
                                        if field in test_json and field in baseline_b_json:
                                            if test_json[field] == baseline_b_json[field] and test_json.get(field) != base_json.get(field):
                                                result["account_b_data_leaked"] = True
                                                result["confidence"] = 0.9
                                                result["diff_summary"] += f"Account B data leaked (field: {field}). "
                            except (json.JSONDecodeError, TypeError):
                                pass

            except (json.JSONDecodeError, TypeError):
                # Non-JSON response — do length comparison
                if len(test_body) != len(baseline_body):
                    result["semantic_diff"] = True
                    result["diff_summary"] += f"Body length {len(baseline_body)}→{len(test_body)} chars. "
        else:
            result["semantic_diff"] = True
            result["diff_summary"] += "Body content changed. "

    # Confidence calculation
    if result["account_b_data_leaked"]:
        result["confidence"] = max(result["confidence"], 0.9)
    elif result["changed"] and result["semantic_diff"]:
        result["confidence"] = 0.6
    elif result["changed"]:
        result["confidence"] = 0.3

    if not result["diff_summary"]:
        result["diff_summary"] = "No significant change detected."

    return result


# ─── Convenience Functions ────────────────────────────────────────────────────

def capture_baseline_for_account(
    campaign_state: dict,
    endpoint: str,
    account: str,
    method: str = "GET",
    base_url: str = None,
    auth_headers: dict = None,
    params: dict = None,
) -> dict:
    """
    Capture a baseline for a specific account.

    Args:
        campaign_state: Loaded campaign dict
        endpoint: Endpoint path (e.g. /api/v2/orders/123)
        account: 'a' or 'b'
        method: HTTP method
        base_url: Override base URL (defaults to campaign target)
        auth_headers: Override auth headers
        params: Query params

    Returns:
        Captured baseline dict
    """
    campaign_id = campaign_state["campaign_id"]
    base = campaign_state.get("target", base_url or "")
    url = f"{base.rstrip('/')}/{endpoint.lstrip('/')}" if endpoint else base

    if auth_headers is None:
        auth_type = campaign_state["scope"].get("auth_type", "session_cookie")
        if auth_type == "session_cookie":
            cookie_key = f"account_{account}_cookie"
            cookie = campaign_state["scope"].get(cookie_key) or campaign_state["scope"].get("session_cookie")
            auth_headers = {"Cookie": cookie} if cookie else {}
        elif auth_type == "bearer":
            token_key = f"account_{account}_token"
            token = campaign_state["scope"].get(token_key) or campaign_state["scope"].get("bearer_token", "")
            auth_headers = {"Authorization": f"Bearer {token}"}

    store = BaselineStore(campaign_id)
    return store.capture(endpoint, account, method, url, auth_headers, params)
