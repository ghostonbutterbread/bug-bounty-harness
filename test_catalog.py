"""
Test Catalog — Loads bac_checks.py into campaign format.

Reads P0/P1/P2 tests from the bounty-tools bac_checks module
and converts them to the campaign test_catalog format.

Usage:
    from test_catalog import build_test_catalog
    catalog = build_test_catalog("https://api.target.com", discovered_endpoints)
"""

import sys
sys.path.insert(0, "/home/ryushe/projects/bounty-tools")

from bac_checks import P0_TESTS, P1_TESTS, P2_TESTS


# ─── Priority ordering ────────────────────────────────────────────────────────

PRIORITY_MAP = {
    "auth_bypass": "P0",
    "token_misuse": "P0",
    "idor": "P1",
    "escalation": "P1",
    "info": "P2",
}


def _assign_priority(test: dict) -> str:
    """Assign priority based on category from bac_checks."""
    # P0_TESTS = auth_bypass (account takeover related)
    # P1_TESTS = idor, escalation, auth_bypass (HTTP-level)
    # P2_TESTS = idor, escalation, auth_bypass (config/informational)
    # We use position in the original lists as a tiebreaker
    if test in P0_TESTS:
        return "P0"
    elif test in P1_TESTS:
        return "P1"
    elif test in P2_TESTS:
        return "P2"
    return "P2"


def _make_test_id(priority: str, index: int) -> str:
    """Generate unique test ID like 'BAC-P0-001'."""
    return f"BAC-{priority}-{index:03d}"


def _endpoint_matches(endpoint_pattern: str, discovered_endpoints: list) -> bool:
    """
    Check if a test's endpoint pattern could match discovered endpoints.
    This lets us filter the catalog to only tests applicable to the target.

    Patterns can include: /api/v*/users/{user_id}/profile
    We match on path structure, not exact URL.
    """
    import re
    # Normalize pattern — replace glob markers
    pattern = endpoint_pattern.replace("v*", "v\\d+").replace("*", ".*")
    pattern = re.sub(r"\\{[^}]+\\}", ".+", pattern)  # {user_id} → .+
    pattern = pattern.rstrip("/")

    for ep in discovered_endpoints:
        ep_clean = ep.rstrip("/")
        if re.match(f"^{pattern}$", ep_clean, re.IGNORECASE):
            return True
        # Also match if just the path prefix matches
        ep_parts = ep_clean.split("/")
        pat_parts = pattern.split("/")
        if len(pat_parts) <= len(ep_parts):
            # Check if the non-variable parts match
            matches = True
            for pp, ep_p in zip(pat_parts, ep_parts):
                if pp.startswith("{") or pp == ".+":
                    continue
                if pp.lower() != ep_p.lower():
                    matches = False
                    break
            if matches:
                return True
    return True  # Default to include if no endpoints discovered yet


def build_test_catalog(target_url: str, discovered_endpoints: list = None) -> list[dict]:
    """
    Load all P0/P1/P2 tests from bac_checks and format for campaign.json.

    Args:
        target_url: Base URL of target (e.g. https://api.target.com)
        discovered_endpoints: List of endpoint paths discovered during recon

    Returns:
        List of test dicts ready for campaign.json["test_catalog"]
    """
    if discovered_endpoints is None:
        discovered_endpoints = []

    all_tests = P0_TESTS + P1_TESTS + P2_TESTS
    catalog = []

    # Group by priority
    priority_groups = {
        "P0": P0_TESTS,
        "P1": P1_TESTS,
        "P2": P2_TESTS,
    }

    test_counter = {"P0": 1, "P1": 1, "P2": 1}

    for priority, tests in priority_groups.items():
        for test in tests:
            # Filter by discovered endpoints if we have them
            endpoint = test["endpoint"]
            if discovered_endpoints and not _endpoint_matches(endpoint, discovered_endpoints):
                continue

            # Build full URL
            endpoint_filled = endpoint.replace("v*", "v2")
            if endpoint_filled.startswith("/"):
                full_url = f"{target_url.rstrip('/')}{endpoint_filled}"
            else:
                full_url = f"{target_url.rstrip('/')}/{endpoint_filled}"

            test_dict = {
                "id": _make_test_id(priority, test_counter[priority]),
                "category": test["category"],
                "priority": priority,
                "test_name": test["test_name"],
                "description": test["description"],
                "expected": test["expected"],
                "method": test["method"],
                "endpoint_pattern": endpoint,  # original pattern
                "endpoint": full_url,           # filled with v2 etc.
                "poc_steps": test["poc_steps"],
                "references": test.get("refs", []),
                "status": "pending",
                "attempts": 0,
                "last_attempt": None,
                "notes": "",
            }
            catalog.append(test_dict)
            test_counter[priority] += 1

    return catalog


def get_test_by_id(catalog: list[dict], test_id: str) -> dict | None:
    """Find a test by its ID in the catalog."""
    for test in catalog:
        if test["id"] == test_id:
            return test
    return None


def get_tests_by_priority(catalog: list[dict], priority: str) -> list[dict]:
    """Filter catalog by priority: P0, P1, P2."""
    return [t for t in catalog if t["priority"] == priority]


def get_tests_by_category(catalog: list[dict], category: str) -> list[dict]:
    """Filter catalog by category: idor, escalation, auth_bypass."""
    return [t for t in catalog if t["category"] == category]


def get_pending_by_priority(catalog: list[dict]) -> list[dict]:
    """Return pending tests sorted by priority (P0 first)."""
    priority_order = {"P0": 0, "P1": 1, "P2": 2}
    pending = [t for t in catalog if t["status"] == "pending"]
    pending.sort(key=lambda t: (priority_order.get(t["priority"], 3), t["id"]))
    return pending
