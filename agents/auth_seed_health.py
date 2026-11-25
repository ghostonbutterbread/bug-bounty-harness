"""Non-secret auth-seed capture/verification metadata and planning-time usability.

Shared by the account-management resolver/inventory and the Chromium Test lease
coordinator so a planner can see a dead or empty auth seed before assigning
authenticated work. Nothing here reads files or performs requests. Callers pass
an already-loaded seed (to count replayable material) or an inventory account
record (to classify it); only counts, header *names*, timestamps, and short
reason codes come back. Secret values never leave the caller.

Inventory account records may carry a non-secret ``auth_seed_status`` projection::

    {"captured_at": ISO-8601 UTC | null,
     "seed_fingerprint": "<mtime_ns>:<size>",     # file identity for seeds without captured_at
     "auth_material": "present" | "absent",
     "replayable_cookie_count": int,
     "auth_header_names": [str, ...],
     "last_verified_at": ISO-8601 UTC,            # only after a liveness check ran
     "last_verified_result": "live" | "expired" | "unknown",
     "last_verified_reason": short code, e.g. "http-401" or "cached-response",
     "last_verified_check": {"method": str, "url": scheme://host[:port]/path}}

Only the account's declared auth check is recorded (its URL is already in the
inventory). Records without the projection (older inventories and seeds)
classify as ``unverified``, never as usable.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
from urllib.parse import urlsplit

DEFAULT_VERIFICATION_MAX_AGE_HOURS = 24.0
SEED_REF_PREFIXES = ("auth-seed:", "auth_seed:", "file:")
VERIFICATION_FIELDS = (
    "last_verified_at",
    "last_verified_result",
    "last_verified_reason",
    "last_verified_check",
)
# Header names that commonly carry replayable auth. A CSRF/XSRF token alone
# does not authenticate a request. Programs with an unusual auth header declare
# it in auth_check.required_header_names so it counts as material.
AUTH_HEADER_NAME_RE = re.compile(r"auth|token|session|cookie|key|secret|passw|bearer|jwt|credential", re.IGNORECASE)
NON_AUTH_HEADER_NAME_RE = re.compile(r"csrf|xsrf", re.IGNORECASE)
STATIC_DOCUMENT_SUFFIXES = (
    ".html", ".htm", ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg",
    ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".txt", ".xml",
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def parse_utc(value: Any) -> datetime | None:
    """Parse a stored timestamp; unparseable values read as unknown (None)."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def seed_auth_material(seed: dict[str, Any], required_header_names: Iterable[str] = ()) -> dict[str, Any]:
    """Count replayable auth material in a loaded seed without returning values."""
    cookies = seed.get("cookies")
    cookie_count = 0
    if isinstance(cookies, list):
        cookie_count = sum(
            1
            for cookie in cookies
            if isinstance(cookie, dict) and cookie.get("name") and str(cookie.get("value") or "").strip()
        )
    headers = seed.get("headers")
    required = {str(name).lower() for name in required_header_names}
    auth_header_names: list[str] = []
    if isinstance(headers, dict):
        for name, value in headers.items():
            name = str(name)
            if not str(value or "").strip():
                continue
            if name.lower() in required or (
                AUTH_HEADER_NAME_RE.search(name) and not NON_AUTH_HEADER_NAME_RE.search(name)
            ):
                auth_header_names.append(name)
    return {
        "auth_material": "present" if cookie_count or auth_header_names else "absent",
        "replayable_cookie_count": cookie_count,
        "auth_header_names": sorted(auth_header_names),
    }


def seed_status_snapshot(
    seed: dict[str, Any], required_header_names: Iterable[str] = (), *, fingerprint: str | None = None
) -> dict[str, Any]:
    """Non-secret capture snapshot of a loaded seed for the inventory projection.

    ``fingerprint`` is the caller's file identity (``"<mtime_ns>:<size>"``); it
    identifies the capture only for seeds that carry no ``captured_at``.
    """
    captured_at = seed.get("captured_at")
    return {
        "captured_at": captured_at if parse_utc(captured_at) else None,
        "seed_fingerprint": fingerprint,
        **seed_auth_material(seed, required_header_names),
    }


def check_discriminator(method: Any, url: Any) -> dict[str, str] | None:
    """Method plus origin/path of a liveness check; query and fragment are dropped."""
    if not url:
        return None
    parts = urlsplit(str(url))
    try:
        port = parts.port
    except ValueError:
        port = None
    host = (parts.hostname or "") + (f":{port}" if port is not None else "")
    # Userinfo, query, and fragment are dropped; scheme and host are case-normalized.
    return {"method": str(method or "GET").upper(), "url": f"{parts.scheme.lower()}://{host}{parts.path or '/'}"}


def liveness_from_check(check: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any] | None:
    """Map an auth-check result to verification fields; None when no check ran."""
    status = check.get("status")
    if status not in {"passed", "failed", "inconclusive", "error"}:
        return None
    result = {"passed": "live", "failed": "expired"}.get(str(status), "unknown")
    if result == "expired" and check.get("status_code") == 403:
        result = "unknown"  # a WAF or bot block is indistinguishable from an auth refusal
    if check.get("reason"):
        reason = str(check["reason"])
    elif check.get("status_code") is not None:
        reason = f"http-{check['status_code']}"
    elif check.get("error_type"):
        reason = f"error-{check['error_type']}"
    else:
        reason = str(status)
    return {
        "last_verified_at": iso_utc(now or utc_now()),
        "last_verified_result": result,
        "last_verified_reason": reason[:80],
        "last_verified_check": check_discriminator(check.get("method"), check.get("url")),
    }


def same_capture(stored: dict[str, Any], snapshot: dict[str, Any]) -> bool:
    """Whether a recorded result belongs to the seed now on disk.

    ``captured_at`` decides whenever either side has one. Seeds without it
    (hand-written or pre-metadata) fall back to the recorded file fingerprint, so
    a hand-replaced legacy seed never inherits the previous seed's result. A
    missing identity on either side is never treated as a match.
    """
    stored_at, current_at = stored.get("captured_at"), snapshot.get("captured_at")
    if stored_at or current_at:
        return bool(stored_at) and stored_at == current_at
    stored_id, current_id = stored.get("seed_fingerprint"), snapshot.get("seed_fingerprint")
    return bool(stored_id) and stored_id == current_id


def effective_seed_status(stored: Any, snapshot: dict[str, Any] | None) -> dict[str, Any]:
    """Combine a fresh seed snapshot with stored verification that still applies.

    Verification belongs to one capture (see ``same_capture``); a replaced seed
    reads as unverified rather than inheriting the previous result.
    """
    stored = stored if isinstance(stored, dict) else {}
    if snapshot is None:
        return dict(stored)
    merged = dict(snapshot)
    if same_capture(stored, snapshot):
        merged.update({key: stored[key] for key in VERIFICATION_FIELDS if key in stored})
    return merged


def seed_ref_configured(account: dict[str, Any]) -> bool:
    ref = account.get("auth_seed_ref") or account.get("credential_ref")
    if not ref:
        return False
    text = str(ref)
    for prefix in SEED_REF_PREFIXES:
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    return text.startswith(("/", "~"))


def declared_ttl_hours(account: dict[str, Any]) -> float | None:
    value = account.get("auth_session_ttl_hours")
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        return None
    return float(value)


def classify_seed(
    account: dict[str, Any], *, status: dict[str, Any] | None = None, now: datetime | None = None
) -> dict[str, Any]:
    """Planning-time usability of an account's auth seed from non-secret metadata.

    States: ``usable`` (verified live within the window), ``unverified`` (no
    applicable recent live check), ``stale`` (last check expired, or older than
    the declared session TTL without a fresh live check), ``unusable`` (no
    replayable auth material), and ``none`` (no auth-seed reference configured).
    """
    now = now or utc_now()
    if status is None:
        stored = account.get("auth_seed_status")
        status = stored if isinstance(stored, dict) else {}
    summary: dict[str, Any] = {
        key: status.get(key)
        for key in ("captured_at", "last_verified_at", "last_verified_result")
        if status.get(key) is not None
    }

    def verdict(state: str, *reasons: str) -> dict[str, Any]:
        return {"state": state, "reasons": list(reasons), **summary}

    if not seed_ref_configured(account):
        return verdict("none", "no-auth-seed-ref")
    if status.get("auth_material") == "absent":
        return verdict("unusable", "no-replayable-auth-material")
    result = status.get("last_verified_result")
    reason = str(status.get("last_verified_reason") or "unspecified")
    if result == "expired":
        return verdict("stale", f"last-check-expired:{reason}")
    ttl = declared_ttl_hours(account)
    window = ttl if ttl is not None else DEFAULT_VERIFICATION_MAX_AGE_HOURS
    verified = parse_utc(status.get("last_verified_at"))
    # A fresh live check outranks the age estimate from the declared TTL.
    if result == "live" and verified is not None and now - verified <= timedelta(hours=window):
        return verdict("usable", "verified-live")
    captured = parse_utc(status.get("captured_at"))
    if ttl is not None and captured is not None and now - captured > timedelta(hours=ttl):
        return verdict("stale", f"older-than-declared-ttl:{ttl:g}h")
    if not status:
        return verdict("unverified", "no-recorded-seed-status")
    if result is None:
        return verdict("unverified", "never-verified")
    if result == "live":
        return verdict("unverified", f"verification-older-than:{window:g}h")
    return verdict("unverified", f"last-check-inconclusive:{reason}")


def auth_check_url_warning(url: Any) -> str | None:
    """Static warning for a check URL that cannot discriminate auth state."""
    if not url:
        return None
    path = urlsplit(str(url)).path or "/"
    if path == "/" or path.lower().endswith(STATIC_DOCUMENT_SUFFIXES):
        return (
            "auth check URL looks like a static or cacheable document (site root or file); "
            "use an endpoint whose response differs by auth state, such as a JSON API that "
            "returns 401 or a structured auth error when logged out"
        )
    return None
