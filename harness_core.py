"""
Harness Core — Constraint enforcement and campaign state management.

Enforces scope, rate, and budget constraints on all agent actions.
Manages campaign state persistence across sessions.

Usage:
    from harness_core import CampaignState, HarnessConstraints, HarnessViolation
    state = CampaignState()
    constraints = HarnessConstraints(state.load("my_campaign"))
    constraints.enforce("https://api.target.com/orders/123", "/api/v2/orders/{id}")
"""

import copy
import fcntl
import json
import hashlib
import logging
import subprocess
import os
import re
import time
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ─── Custom Exception ──────────────────────────────────────────────────────────

class HarnessViolation(Exception):
    """Raised when a harness constraint is violated."""
    pass


# ─── Campaign State ───────────────────────────────────────────────────────────

class CampaignState:
    """
    Manages campaign.json — the source of truth across all sessions.
    Handles git commits for clean exit protocol.
    """

    CAMPAIGNS_DIR = Path.home() / "workspace" / "bug_bounty_harness" / "campaigns"

    def __init__(self, campaigns_dir: str = None):
        if campaigns_dir:
            self.CAMPAIGNS_DIR = Path(campaigns_dir)
        self.CAMPAIGNS_DIR.mkdir(parents=True, exist_ok=True)
        self._lock_path = self.CAMPAIGNS_DIR / ".lock"
        self._lock_path.touch(exist_ok=True)

    def _campaign_path(self, campaign_id: str) -> Path:
        return self.CAMPAIGNS_DIR / f"{campaign_id}.json"

    @contextmanager
    def _campaign_lock(self):
        with open(self._lock_path, "a+") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _load_unlocked(self, path: Path) -> dict:
        with open(path) as f:
            return json.load(f)

    def _save_unlocked(self, path: Path, state: dict) -> None:
        tmp = path.with_name(f"{path.name}.tmp")
        with open(tmp, "w") as f:
            json.dump(state, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        tmp.rename(path)

    def load(self, campaign_id: str) -> dict:
        """Load campaign state. Raises if not found."""
        path = self._campaign_path(campaign_id)
        if not path.exists():
            raise FileNotFoundError(f"Campaign not found: {campaign_id}")
        return self._load_unlocked(path)

    def exists(self, campaign_id: str) -> bool:
        return self._campaign_path(campaign_id).exists()

    def save(self, campaign_id: str, state: dict) -> None:
        """Save campaign state atomically."""
        path = self._campaign_path(campaign_id)
        with self._campaign_lock():
            self._save_unlocked(path, state)

    def create(self, campaign_id: str, target: str, scope_domains: list) -> dict:
        """Create a new campaign with default structure."""
        state = {
            "campaign_id": campaign_id,
            "target": target,
            "created": datetime.now(timezone.utc).isoformat(),
            "last_session": datetime.now(timezone.utc).isoformat(),
            "scope": {
                "domains": scope_domains,
                "require_auth": True,
                "auth_type": "session_cookie",
                "account_a": None,
                "account_b": None,
            },
            "stats": {
                "total_requests": 0,
                "requests_this_session": 0,
                "max_requests_per_session": 500,
                "rate_limit_rpm": 30,
                "rate_limit_cooldown_s": 30,
            },
            "test_catalog": [],
            "findings": {
                "confirmed": [],
                "potential": [],
                "false_positive": [],
            },
            "baselines": {},
            "initializer_complete": False,
            "_rate_tracker": {},  # internal: endpoint -> {"count": N, "window_start": ts}
        }
        self.save(campaign_id, state)
        return state

    def update_test_status(self, campaign_id: str, test_id: str, status: str, notes: str = "") -> None:
        """
        Update a test's status: 'pending' -> 'in_progress' -> 'confirmed'/'potential'/'false_positive'
        """
        path = self._campaign_path(campaign_id)
        with self._campaign_lock():
            state = self._load_unlocked(path)
            for test in state["test_catalog"]:
                if test["id"] == test_id:
                    test["status"] = status
                    test["attempts"] = test.get("attempts", 0) + 1
                    test["last_attempt"] = datetime.now(timezone.utc).isoformat()
                    if notes:
                        test["notes"] = notes
                    break
            state["last_session"] = datetime.now(timezone.utc).isoformat()
            self._save_unlocked(path, state)

    def add_finding(self, campaign_id: str, finding: dict, category: str = "potential") -> None:
        """Add a finding to the campaign."""
        if category not in ("confirmed", "potential", "false_positive"):
            category = "potential"
        path = self._campaign_path(campaign_id)
        with self._campaign_lock():
            state = self._load_unlocked(path)
            finding["_added"] = datetime.now(timezone.utc).isoformat()
            state["findings"][category].append(finding)
            state["last_session"] = datetime.now(timezone.utc).isoformat()
            self._save_unlocked(path, state)

    def get_pending_tests(self, campaign_id: str) -> list[dict]:
        """Return all tests with status 'pending'."""
        state = self.load(campaign_id)
        return [t for t in state["test_catalog"] if t["status"] == "pending"]

    def get_next_test(self, campaign_id: str) -> Optional[dict]:
        """
        Return the highest-priority pending test.
        Priority: P0 > P1 > P2. Within same priority, FIFO.
        """
        state = self.load(campaign_id)
        pending = [t for t in state["test_catalog"] if t["status"] == "pending"]
        if not pending:
            return None

        # Sort by priority order, then by id
        priority_order = {"P0": 0, "P1": 1, "P2": 2}
        pending.sort(key=lambda t: (priority_order.get(t.get("priority", "P2"), 3), t["id"]))
        return pending[0]

    def git_commit(self, campaign_id: str, message: str) -> None:
        """Git add + commit for clean exit protocol."""
        harness_dir = Path(__file__).resolve().parent
        try:
            subprocess.run(
                ["git", "add", "."],
                cwd=harness_dir,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["git", "commit", "-m", message],
                cwd=harness_dir,
                check=True,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            logger.warning("git is unavailable for campaign %s: %s", campaign_id, exc)
        except subprocess.CalledProcessError as exc:
            error_output = (exc.stderr or exc.stdout or str(exc)).strip()
            logger.warning(
                "git commit failed for campaign %s: %s",
                campaign_id,
                error_output,
            )


# ─── Harness Constraints ───────────────────────────────────────────────────────

class HarnessConstraints:
    """
    Enforces: scope boundaries, rate limits, request budget.
    All checks raise HarnessViolation on violation — agents cannot bypass.
    """

    def __init__(self, campaign_state: dict):
        self.state = copy.deepcopy(campaign_state)
        self.scope_domains = self.state["scope"]["domains"]
        self.max_requests_session = self.state["stats"]["max_requests_per_session"]
        self.rate_limit_rpm = self.state["stats"]["rate_limit_rpm"]
        self.cooldown_s = self.state["stats"].get("rate_limit_cooldown_s", 30)
        self._rate_tracker = self.state.setdefault("_rate_tracker", {})

    def is_in_scope(self, url: str) -> bool:
        """Check if URL is within scope domains. Returns True/False."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.netloc.lower()
            # Remove port if standard
            host = re.sub(r":(80|443)$", "", host)
            for domain in self.scope_domains:
                domain = domain.lower()
                if host == domain or host.endswith(f".{domain}"):
                    return True
            return False
        except Exception:
            return False

    def check_scope(self, url: str) -> bool:
        """Scope check — returns True if in scope."""
        if not self.is_in_scope(url):
            return False
        return True

    def _get_endpoint_key(self, url: str, method: str = "GET") -> str:
        """Normalize URL to endpoint key for rate tracking."""
        try:
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(url)
            # Strip query params and IDs for rate tracking
            path = re.sub(r"/\d+", "/{id}", parsed.path)
            path = re.sub(r"/[a-f0-9-]{36}", "/{uuid}", path)
            return f"{method.upper()} {parsed.netloc}{path}"
        except Exception:
            return f"{method.upper()} {url}"

    def check_rate(self, url: str, method: str = "GET") -> bool:
        """
        Per-endpoint rate check. Returns True if OK, False if should defer.
        Uses a sliding window: counts requests in last 60 seconds.
        """
        key = self._get_endpoint_key(url, method)
        now = time.time()
        window = 60.0

        if key not in self._rate_tracker:
            self._rate_tracker[key] = {"count": 0, "window_start": now}

        tracker = self._rate_tracker[key]
        # Reset window if expired
        if now - tracker["window_start"] >= window:
            tracker["count"] = 0
            tracker["window_start"] = now

        return tracker["count"] < self.rate_limit_rpm

    def check_budget(self) -> bool:
        """Session request budget check."""
        return self.state["stats"]["requests_this_session"] < self.max_requests_session

    def should_defer(self, url: str, method: str = "GET") -> bool:
        """Returns True if request should be deferred (rate limited)."""
        return not self.check_rate(url, method)

    def record_request(self, url: str, method: str = "GET") -> None:
        """Record a request for rate and budget tracking."""
        key = self._get_endpoint_key(url, method)
        now = time.time()
        stale_after_s = 120.0

        for existing_key, tracker in list(self._rate_tracker.items()):
            window_start = tracker.get("window_start", now)
            if now - window_start > stale_after_s:
                self._rate_tracker.pop(existing_key, None)

        if key not in self._rate_tracker:
            self._rate_tracker[key] = {"count": 0, "window_start": now}

        tracker = self._rate_tracker[key]
        if now - tracker["window_start"] >= 60.0:
            tracker["count"] = 0
            tracker["window_start"] = now

        tracker["count"] += 1
        self.state["stats"]["requests_this_session"] += 1
        self.state["stats"]["total_requests"] += 1

    def enforce(self, url: str, endpoint_hint: str = "", method: str = "GET") -> None:
        """
        Run all constraint checks. Raises HarnessViolation on any violation.
        Call this before every HTTP request.
        """
        if not self.check_scope(url):
            raise HarnessViolation(
                f"SCOPE VIOLATION: {url} is not in scope. "
                f"Allowed: {', '.join(self.scope_domains)}"
            )

        if not self.check_budget():
            raise HarnessViolation(
                f"BUDGET EXHAUSTED: {self.state['stats']['requests_this_session']} "
                f"requests this session (limit: {self.max_requests_session}). "
                f"End session and start a new one."
            )

        if self.should_defer(url, method):
            key = self._get_endpoint_key(url, method)
            tracker = self._rate_tracker[key]
            elapsed = time.time() - tracker["window_start"]
            wait = max(0, 60.0 - elapsed)
            raise HarnessViolation(
                f"RATE LIMITED: {key} — {tracker['count']}/{self.rate_limit_rpm} "
                f"requests in current window. Wait {wait:.0f}s before retry."
            )


# ─── Utility ──────────────────────────────────────────────────────────────────

def hash_endpoint(endpoint: str) -> str:
    """Stable hash for endpoint → filename-safe key."""
    return hashlib.sha1(endpoint.encode()).hexdigest()[:12]


def is_valid_campaign_id(campaign_id: str) -> bool:
    """Validate campaign ID format."""
    return bool(re.match(r"^[a-z0-9_-]+$", campaign_id))
