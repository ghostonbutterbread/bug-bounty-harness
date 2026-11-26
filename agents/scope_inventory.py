#!/usr/bin/env python3
"""Typed scope inventory, change history and release-changed signal.

Writes three files beside the saved scope files in ``<scopes>/<program>/``:

- ``scope-items.json``    current typed inventory (atomic replace)
- ``scope-history.jsonl`` append-only change log
- ``scope-pull.json``     last pull state (atomic replace)

The inventory is always built from the saved scope files (``assets.json``,
``out-of-scope.json``, ``in-scope.txt``, ``out-of-scope.txt``), so a pull and
an offline rebuild share one normalizer. Only ``scope_puller.py`` calls this.
See ``docs/integrations/scope-inventory.md`` for the contract.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

INVENTORY_VERSION = 1
ITEMS_FILE = "scope-items.json"
HISTORY_FILE = "scope-history.jsonl"
PULL_FILE = "scope-pull.json"
INVENTORY_FILES = (ITEMS_FILE, HISTORY_FILE, PULL_FILE)

RELEASE_KINDS = {"android_app", "ios_app", "executable"}
RELEASE_TIMEOUT = 15
RELEASE_MAX_BODY = 3_000_000
DESCRIPTION_MAX = 500
IDENTIFIER_MAX = 200
CHANGE_FIELDS = ("in_scope", "tier", "max_severity", "eligible_for_bounty", "name")
HASH_FIELDS = (
    "key", "kind", "identifier", "name", "in_scope", "tier", "max_severity",
    "eligible_for_bounty", "enforced", "platform_type", "description",
)

HOSTED_SOURCE_HOSTS = {
    "github.com", "www.github.com", "gist.github.com", "gitlab.com", "bitbucket.org",
    "dev.azure.com", "sourceforge.net",
}
EXECUTABLE_EXTENSIONS = (
    ".exe", ".msi", ".msix", ".dmg", ".pkg", ".appimage", ".deb", ".rpm", ".apk",
    ".zip", ".tar.gz", ".tgz", ".jar",
)
PLAY_URL = re.compile(r"play\.google\.com/store/apps/details\?(?:[^#]*&)?id=([A-Za-z0-9_.]+)", re.I)
APPLE_URL = re.compile(r"(?:apps|itunes)\.apple\.com/\S*?/id(\d{5,})", re.I)
PACKAGE_ID = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+")
APPLE_NUMERIC_ID = re.compile(r"(?:id)?(\d{5,})", re.I)
NAMED_RULE = re.compile(r"[^\-]*\S\s+-\s+(\S+)")
WEB_KINDS = {"web_host", "web_wildcard", "web_url", "ip", "cidr"}
APPLE_ID_ANYWHERE = re.compile(r"\bid(\d{6,})\b", re.I)
TIER_PATTERN = re.compile(r"\btier[\s_-]*(\d+)\b", re.I)
PLAY_UPDATED = re.compile(r"Updated on\s*</div>\s*<div[^>]*>\s*([^<]{3,40}?)\s*</div>", re.I)

# Platform type (asset_type / type / scope_type / category), upper-cased with
# spaces turned into underscores, mapped to a kind. "shape" means the value
# decides between web host / wildcard / URL / IP / CIDR; None means infer.
TYPE_KINDS = {
    "URL": "shape", "WEBSITE": "shape", "API": "shape", "WEB": "shape",
    "WEB_APPLICATION": "shape", "WILDCARD": "shape", "CIDR": "shape", "IP": "shape",
    "IP_ADDRESS": "shape", "IP_RANGE": "shape",
    "ANDROID": "android_app", "GOOGLE_PLAY_APP_ID": "android_app", "OTHER_APK": "android_app",
    "GOOGLE_PLAY": "android_app",
    "IOS": "ios_app", "APPLE_STORE_APP_ID": "ios_app", "TESTFLIGHT": "ios_app",
    "APPLE_APP_ID": "ios_app", "APPLE_STORE": "ios_app",
    "EXECUTABLE": "executable", "DOWNLOADABLE_EXECUTABLES": "executable",
    "WINDOWS_APP_STORE_APP_ID": "executable", "DESKTOP": "executable",
    "SOURCE_CODE": "source_code",
    "HARDWARE": "other", "AI_MODEL": "other", "SMART_CONTRACT": "other", "IOT": "other",
}


def _puller():
    try:
        import scope_puller  # type: ignore
    except ModuleNotFoundError:
        from agents import scope_puller  # type: ignore
    return scope_puller


# --------------------------------------------------------------------------
# Time and atomic I/O


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def atomic_write_json(path: Path, data) -> None:
    """Write JSON to a temp file in the same directory, fsync, then replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(data, indent=2, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def append_jsonl(path: Path, record: dict) -> None:
    """Append one complete line in a single write; never rewrite earlier lines."""
    line = json.dumps(record, sort_keys=True, separators=(", ", ": ")) + "\n"
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------------
# Normalization


def _text(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def _norm_other(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().lower()[:IDENTIFIER_MAX]


def _host_kind(host: str) -> str:
    return "web_wildcard" if "*" in host else "web_host"


def infer_from_value(value: str) -> tuple[str, str] | None:
    """Classify one name/uri value by its shape; None when it is prose."""
    value = _text(value)
    if not value:
        return None
    if match := PLAY_URL.search(value):
        return "android_app", match.group(1)
    if match := APPLE_URL.search(value):
        return "ios_app", match.group(1)
    if re.match(r"https?://", value, re.I):
        if any(char.isspace() for char in value):
            return None
        try:
            parsed = urllib.parse.urlparse(value)
            host = (parsed.hostname or "").lower()
            port = parsed.port
        except ValueError:
            return None
        if not host:
            return None
        path = parsed.path or ""
        if host in HOSTED_SOURCE_HOSTS:
            return "source_code", value.rstrip("/").replace(parsed.netloc, parsed.netloc.lower(), 1)
        if path.lower().endswith(EXECUTABLE_EXTENSIONS):
            return "executable", value
        netloc = f"{host}:{port}" if port is not None else host
        if path in ("", "/", "/*") and not parsed.query:
            return _host_kind(host), netloc
        query = f"?{parsed.query}" if parsed.query else ""
        return "web_url", f"{parsed.scheme.lower()}://{netloc}{path}{query}"
    candidate = value[:-2] if value.endswith("/*") else value.rstrip("/")
    if "/" in candidate:
        try:
            return "cidr", str(ipaddress.ip_network(candidate, strict=False))
        except ValueError:
            pass
    else:
        try:
            return "ip", str(ipaddress.ip_address(candidate))
        except ValueError:
            pass
    puller = _puller()
    if puller.SCOPE_DOMAIN_PATTERN.fullmatch(candidate) or re.fullmatch(
        r"[A-Za-z0-9*-]+(?:\.[A-Za-z0-9*-]+)+", candidate
    ) and "*" in candidate:
        return _host_kind(candidate), candidate.lower()
    if host := puller.bugcrowd_descriptive_host(value):
        return "web_host", host
    # The '<words> - <rule>' export shape the scope matcher grants from.
    if (match := NAMED_RULE.fullmatch(value)) and not any(char.isspace() for char in match.group(1)):
        named = infer_from_value(match.group(1))
        if named and named[0] in WEB_KINDS:
            return named
    return None


def _app_identifier(kind: str, values: list[str]) -> str | None:
    for value in values:
        if kind == "android_app":
            if match := PLAY_URL.search(value):
                return match.group(1)
            if PACKAGE_ID.fullmatch(value):
                return value
        else:
            if match := APPLE_URL.search(value):
                return match.group(1)
            if match := APPLE_NUMERIC_ID.fullmatch(value) or APPLE_ID_ANYWHERE.search(value):
                return match.group(1)
            if PACKAGE_ID.fullmatch(value):
                return value
    for value in values:
        if re.match(r"https?://\S+$", value, re.I):
            return value
    return None


def classify_record(platform_type: str | None, values: list[str]) -> tuple[str, str]:
    """Return (kind, identifier) for a record's platform type and its values."""
    values = [v for v in (_text(v) for v in values) if v]
    mapped = TYPE_KINDS.get((platform_type or "").strip().upper().replace(" ", "_"))
    if mapped is None and platform_type and "CLOUD" in platform_type.upper():
        mapped = "cloud"
    if mapped in ("android_app", "ios_app"):
        identifier = _app_identifier(mapped, values)
        return mapped, identifier or _norm_other(values[0] if values else "")
    if mapped == "executable":
        url = next((v for v in values if re.match(r"https?://\S+$", v, re.I)), None)
        return "executable", url or _norm_other(values[0] if values else "")
    if mapped in ("source_code", "cloud"):
        url = next((v for v in values if re.match(r"https?://\S+$", v, re.I)), None)
        return mapped, (url.rstrip("/") if url else _norm_other(values[0] if values else ""))
    other = ("other", _norm_other(values[-1] if values else ""))
    if mapped == "other":
        return other
    inferred = [r for r in (infer_from_value(v) for v in values) if r]
    if mapped == "shape":
        web = [r for r in inferred if r[0] in WEB_KINDS]
        if web:
            return web[0]
        if not inferred:
            # A typed web record the strict shapes refuse (scheme-less
            # host/path, optional-group wildcard pattern): keep it web-typed.
            token = next((v for v in values if "." in v and not any(c.isspace() for c in v)), None)
            if token:
                host, sep, rest = token.partition("/")
                kind = "web_url" if sep and rest not in ("", "*") else _host_kind(host)
                return kind, (host.lower() + (sep + rest if kind == "web_url" else ""))
    return inferred[0] if inferred else other


def _tier(*labels) -> str | None:
    for label in labels:
        if isinstance(label, str) and (match := TIER_PATTERN.search(label)):
            return match.group(1)
    return None


def _platform_type(record: dict) -> str | None:
    for field in ("asset_type", "type", "scope_type", "category"):
        value = record.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _record_values(record: dict) -> list[str]:
    return [
        _text(record.get(field))
        for field in ("uri", "asset_identifier", "identifier", "asset_value", "name")
        if _text(record.get(field))
    ]


def normalize_record(record: dict, *, group: dict | None, default_in_scope: bool,
                     force_out: bool = False) -> dict | None:
    values = _record_values(record)
    if not values:
        return None
    ptype = _platform_type(record)
    kind, identifier = classify_record(ptype, values)
    if not identifier:
        return None
    if force_out:
        in_scope = False
    elif isinstance(record.get("in_scope"), bool):
        in_scope = record["in_scope"]
    elif isinstance(record.get("eligible_for_submission"), bool):
        in_scope = record["eligible_for_submission"]
    elif group is not None and isinstance(group.get("in_scope"), bool):
        in_scope = group["in_scope"]
    else:
        in_scope = default_in_scope
    group_name = record.get("group") if isinstance(record.get("group"), str) else None
    description = _text(record.get("description")) or _text(record.get("instruction")) \
        or _text(record.get("group_description")) or _text((group or {}).get("description"))
    severity = record.get("max_severity")
    bounty = record.get("eligible_for_bounty")
    return {
        "key": f"{kind}:{identifier}",
        "kind": kind,
        "identifier": identifier,
        "name": _text(record.get("name")) or values[0],
        "in_scope": bool(in_scope),
        "tier": _tier(group_name, (group or {}).get("name"), (group or {}).get("group")),
        "max_severity": severity.strip().lower() if isinstance(severity, str) and severity.strip() else None,
        "eligible_for_bounty": bounty if isinstance(bounty, bool) else None,
        "enforced": False,
        "platform_type": ptype,
        "description": description[:DESCRIPTION_MAX],
        "_values": values,
    }


def iter_asset_records(assets):
    """Yield (record, group) for every target-like dict in any saved assets shape."""
    def from_list(entries, group=None):
        for entry in entries or []:
            if isinstance(entry, str):
                yield {"name": entry}, group
            elif isinstance(entry, dict):
                children = entry.get("targets")
                if not isinstance(children, list):
                    children = entry.get("assets") if isinstance(entry.get("assets"), list) else None
                if children is not None:
                    yield from from_list(children, entry)
                else:
                    yield entry, group

    if isinstance(assets, list):
        yield from from_list(assets)
    elif isinstance(assets, dict):
        if isinstance(assets.get("assets"), list):
            yield from from_list(assets["assets"])
        if isinstance(assets.get("target_groups"), list):
            yield from from_list(assets["target_groups"])
        mobile = assets.get("mobile")
        if isinstance(mobile, dict):
            for platform, kind_type in (("android", "android"), ("ios", "ios")):
                entries = mobile.get(platform)
                for entry in entries if isinstance(entries, list) else [entries]:
                    if isinstance(entry, str) and entry.strip():
                        yield {"name": entry, "type": kind_type}, None
        web = assets.get("web")
        if isinstance(web, dict):
            for field in ("hosts", "url_endpoints"):
                for entry in web.get(field) or []:
                    if isinstance(entry, str):
                        yield {"name": entry}, None


def read_rule_lines(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    rules = []
    for line in lines:
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        rules.append(value.split(" | ", 1)[0].strip())
    return rules


def _candidates(item: dict, review: dict[str, str], *, exclusion: bool) -> set[str]:
    puller = _puller()
    out = {item["identifier"].lower()}
    for value in item["_values"]:
        out.add(value.lower())
        for form in (puller.routable_scope_entry(value),
                     puller.routable_scope_entry(value, url_to_host=exclusion),
                     puller.bugcrowd_descriptive_host(value)):
            if form:
                out.add(form.lower())
        if value in review:
            out.add(review[value].lower())
    return out


def _review_map(base: Path) -> tuple[dict[str, str], dict[str, str]]:
    review = read_json(base / "scope-review.json")
    grants, exclusions = {}, {}
    if isinstance(review, dict):
        for target, entries in ((grants, review.get("grants")), (exclusions, review.get("exclusions"))):
            for entry in entries if isinstance(entries, list) else []:
                if isinstance(entry, dict) and entry.get("platform_name") and entry.get("entry"):
                    target[str(entry["platform_name"])] = str(entry["entry"])
    return grants, exclusions


def _merge(items: dict[str, dict], item: dict) -> None:
    existing = items.get(item["key"])
    if existing is None:
        items[item["key"]] = item
        return
    # The same asset listed both in and out of scope: exclusion wins, as in the checker.
    existing["in_scope"] = existing["in_scope"] and item["in_scope"]
    existing["enforced"] = existing["enforced"] or item["enforced"]
    for field in ("tier", "max_severity", "eligible_for_bounty", "platform_type"):
        if existing[field] is None:
            existing[field] = item[field]
    if not existing["description"]:
        existing["description"] = item["description"]
    existing["_values"] = existing["_values"] + [v for v in item["_values"] if v not in existing["_values"]]


def enforced_rules(path: Path) -> set[str]:
    """Rule-shaped lines the checker can enforce; prose lines are skipped by it."""
    rules = set()
    for rule in read_rule_lines(path):
        if match := NAMED_RULE.fullmatch(rule):
            rule = match.group(1)
        if rule and not any(char.isspace() for char in rule):
            rules.add(rule.lower())
    return rules


def build_items(base: Path) -> list[dict]:
    """Normalize the saved scope files under ``base`` into sorted typed items."""
    in_rules = enforced_rules(base / "in-scope.txt")
    out_rules = enforced_rules(base / "out-of-scope.txt")
    grants, exclusions = _review_map(base)
    raw: list[dict] = []

    assets = read_json(base / "assets.json")
    for record, group in iter_asset_records(assets):
        if item := normalize_record(record, group=group, default_in_scope=True):
            raw.append(item)
    if not raw:
        raw.extend(_reparse_saved_page(base))
    oos = read_json(base / "out-of-scope.json")
    for record, group in iter_asset_records(oos if isinstance(oos, list) else []):
        if item := normalize_record(record, group=group, default_in_scope=False, force_out=True):
            raw.append(item)

    items: dict[str, dict] = {}
    for item in raw:
        if item["in_scope"]:
            item["enforced"] = bool(_candidates(item, grants, exclusion=False) & in_rules)
        else:
            item["enforced"] = bool(_candidates(item, exclusions, exclusion=True) & out_rules)
        _merge(items, item)

    if not any(item["in_scope"] for item in items.values()):
        # No typed in-scope record survives (hand-made or legacy scope dirs):
        # inventory the enforced rule lines themselves so the program still
        # has a typed list of what it grants.
        for rules, in_scope in ((read_rule_lines(base / "in-scope.txt"), True),
                                (read_rule_lines(base / "out-of-scope.txt"), False)):
            for rule in rules:
                kind, identifier = infer_from_value(rule) or ("other", _norm_other(rule))
                _merge(items, {
                    "key": f"{kind}:{identifier}", "kind": kind, "identifier": identifier,
                    "name": rule, "in_scope": in_scope, "tier": None, "max_severity": None,
                    "eligible_for_bounty": None, "platform_type": None,
                    "enforced": not any(char.isspace() for char in rule) or bool(NAMED_RULE.fullmatch(rule)),
                    "description": "", "_values": [rule],
                })

    result = []
    for key in sorted(items):
        item = dict(items[key])
        item.pop("_values", None)
        result.append(item)
    return result


def _reparse_saved_page(base: Path) -> list[dict]:
    """Re-read a saved Intigriti page when assets.json holds no typed records."""
    page = base / "raw" / "intigriti-page.html"
    if not page.is_file():
        return []
    try:
        parsed = _puller().parse_intigriti_public_program(base.name, page.read_text(encoding="utf-8", errors="replace"))
    except Exception:  # noqa: BLE001 - a stale or partial page just means no typed records
        return []
    records = []
    for record, group in iter_asset_records(parsed.get("assets") or []):
        if item := normalize_record(record, group=group, default_in_scope=True):
            records.append(item)
    for record, group in iter_asset_records(parsed.get("out_of_scope") or []):
        if item := normalize_record(record, group=group, default_in_scope=False, force_out=True):
            records.append(item)
    return records


def items_hash(items: list[dict]) -> str:
    canonical = [{field: item.get(field) for field in HASH_FIELDS} for item in items]
    return hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# --------------------------------------------------------------------------
# Release-changed signal


class _HeadRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and req.get_method() == "HEAD":
            new.method = "HEAD"
        return new


def http_request(url: str, method: str = "GET") -> tuple[int, dict, bytes]:
    """One public HTTP request for a release signal. Tests replace this."""
    request = urllib.request.Request(url, method=method, headers={
        "User-Agent": "Mozilla/5.0 (compatible; ScopePuller/1.0)",
        "Accept-Language": "en-US,en;q=0.8",
    })
    opener = urllib.request.build_opener(_HeadRedirect)
    with opener.open(request, timeout=RELEASE_TIMEOUT) as response:
        body = b"" if method == "HEAD" else response.read(RELEASE_MAX_BODY)
        return response.status, {k.lower(): v for k, v in response.headers.items()}, body


def release_target(item: dict) -> tuple[str | None, str | None, str | None]:
    """Return (method, url, error) for an item's release check."""
    identifier = item["identifier"]
    is_url = bool(re.match(r"https?://\S+$", identifier, re.I))
    if item["kind"] == "ios_app":
        if identifier.isdigit():
            return "itunes_lookup", f"https://itunes.apple.com/lookup?id={identifier}", None
        if PACKAGE_ID.fullmatch(identifier):
            return "itunes_lookup", f"https://itunes.apple.com/lookup?bundleId={urllib.parse.quote(identifier)}", None
        return None, None, "no App Store id"
    if item["kind"] == "android_app":
        if is_url and urllib.parse.urlparse(identifier).path.lower().endswith((".apk", ".aab", ".xapk")):
            return "download_head", identifier, None
        if PACKAGE_ID.fullmatch(identifier):
            return "play_page", f"https://play.google.com/store/apps/details?id={identifier}&hl=en_US&gl=US", None
        return None, None, "no package id"
    if item["kind"] == "executable" and is_url:
        return "download_head", identifier, None
    return None, None, "no download URL"


def fetch_release_signal(method: str, url: str) -> tuple[str, str | None]:
    """Return (signal, version); raise on any failure."""
    if method == "download_head":
        _status, headers, _ = http_request(url, "HEAD")
        parts = [f"{name}={headers[name]}" for name in ("etag", "last-modified", "content-length") if headers.get(name)]
        if not parts:
            raise ValueError("no ETag, Last-Modified or Content-Length")
        return "; ".join(parts), None
    _status, _headers, body = http_request(url, "GET")
    text = body.decode("utf-8", errors="replace")
    if method == "itunes_lookup":
        data = json.loads(text)
        results = data.get("results") or []
        if not results:
            raise ValueError("app not found in iTunes lookup")
        version = results[0].get("version")
        released = results[0].get("currentVersionReleaseDate")
        if not version and not released:
            raise ValueError("iTunes lookup returned no version")
        return " ".join(str(part) for part in (version, released) if part), (str(version) if version else None)
    match = PLAY_UPDATED.search(text)
    if not match:
        raise ValueError("no 'Updated on' text on Play page")
    return f"Updated on {match.group(1).strip()}", None


def _short_error(exc: Exception) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code}"
    if isinstance(exc, urllib.error.URLError):
        reason = exc.reason
        return f"URLError: {type(reason).__name__ if isinstance(reason, Exception) else reason}"[:200]
    if isinstance(exc, TimeoutError):
        return "timeout"
    return f"{type(exc).__name__}: {exc}"[:200]


def check_release(item: dict, previous: dict | None, now: datetime) -> tuple[dict, dict | None]:
    """Check one item; return (release, release_changed_event_or_None). Never raises."""
    previous = previous if isinstance(previous, dict) else {}
    previous_signal = previous.get("signal")
    method, url, error = release_target(item)
    release = {
        "method": method,
        "signal": previous_signal,
        "version": previous.get("version"),
        "checked_at": iso(now),
        "changed_at": previous.get("changed_at"),
        "previous_signal": previous.get("previous_signal"),
        "error": error,
    }
    if method is None:
        release["signal"] = release["version"] = None
        return release, None
    try:
        signal, version = fetch_release_signal(method, url)
    except Exception as exc:  # noqa: BLE001 - a release check never fails the pull
        release["error"] = _short_error(exc)
        return release, None
    release["signal"], release["version"], release["error"] = signal, version, None
    if previous_signal and previous_signal != signal:
        release["changed_at"] = iso(now)
        release["previous_signal"] = previous_signal
        return release, {"key": item["key"], "name": item["name"], "previous": previous_signal, "signal": signal}
    return release, None


# --------------------------------------------------------------------------
# Inventory write


def _summary(item: dict) -> dict:
    return {"key": item["key"], "kind": item["kind"], "name": item["name"], "in_scope": item["in_scope"]}


def _source_mtime(base: Path) -> datetime | None:
    for name in ("assets.json", "in-scope.txt"):
        try:
            return datetime.fromtimestamp((base / name).stat().st_mtime, timezone.utc)
        except OSError:
            continue
    return None


def write_inventory(base: Path, *, source: str, program: str, release_check: bool = False,
                    now: datetime | None = None) -> dict:
    """Build and write the three inventory files from the saved scope under ``base``.

    ``source`` is ``pull`` (just saved by a real pull) or ``rebuild`` (offline).
    Release checks run only for ``pull`` with ``release_check``. Returns a
    short summary dict.
    """
    if source not in ("pull", "rebuild"):
        raise ValueError(f"unknown inventory source: {source}")
    now = now or utcnow()
    seen = now if source == "pull" else (_source_mtime(base) or now)
    previous_doc = read_json(base / ITEMS_FILE)
    previous_items = previous_doc.get("items") if isinstance(previous_doc, dict) else None
    previous = {
        item["key"]: item for item in previous_items or []
        if isinstance(item, dict) and isinstance(item.get("key"), str)
    } if isinstance(previous_items, list) else None

    items = build_items(base)
    release_changed = []
    for item in items:
        prior = (previous or {}).get(item["key"], {})
        item["first_seen"] = prior.get("first_seen") or iso(seen)
        item["last_seen"] = iso(seen) if source == "pull" else (prior.get("last_seen") or iso(seen))
        item["release"] = None
        if item["kind"] in RELEASE_KINDS and item["in_scope"]:
            if source == "pull" and release_check:
                item["release"], event = check_release(item, prior.get("release"), now)
                if event:
                    release_changed.append(event)
            else:
                item["release"] = prior.get("release") if isinstance(prior.get("release"), dict) else None

    rules = read_json(base / "rules-of-engagement.json")
    rules = rules if isinstance(rules, dict) else {}
    atomic_write_json(base / ITEMS_FILE, {
        "version": INVENTORY_VERSION,
        "program": program,
        "generated_at": iso(now),
        "source": source,
        "items": items,
    })

    history = None
    if previous is None:
        history = {"at": iso(now), "source": "baseline", "added": [_summary(i) for i in items],
                   "removed": [], "changed": [], "release_changed": []}
    else:
        current = {item["key"]: item for item in items}
        added = [_summary(current[k]) for k in sorted(current.keys() - previous.keys())]
        removed = [
            {"key": k, "kind": previous[k].get("kind"), "name": previous[k].get("name"),
             "in_scope": previous[k].get("in_scope")}
            for k in sorted(previous.keys() - current.keys())
        ]
        changed = [
            {"key": k, "field": field, "from": previous[k].get(field), "to": current[k].get(field)}
            for k in sorted(current.keys() & previous.keys())
            for field in CHANGE_FIELDS
            if previous[k].get(field) != current[k].get(field)
        ]
        if added or removed or changed or release_changed:
            history = {"at": iso(now), "source": source, "added": added, "removed": removed,
                       "changed": changed, "release_changed": release_changed}
    if history:
        append_jsonl(base / HISTORY_FILE, history)

    state = read_json(base / PULL_FILE)
    state = state if isinstance(state, dict) else {}
    state.update({
        "version": INVENTORY_VERSION,
        "program": program,
        "platform": rules.get("platform") or state.get("platform"),
        "source_url": rules.get("source_url") or state.get("source_url"),
        "items": len(items),
        "items_hash": items_hash(items),
    })
    if source == "pull":
        state.update({"pulled_at": iso(now), "last_attempt_at": iso(now), "last_attempt_status": "ok",
                      "last_error": None, "last_failed_at": None})
    else:
        for field in ("pulled_at", "last_attempt_at", "last_attempt_status", "last_error"):
            state.setdefault(field, None)
    atomic_write_json(base / PULL_FILE, state)
    return {"items": len(items), "history": history["source"] if history else None,
            "release_changed": len(release_changed)}


def record_attempt(base: Path, status: str, *, error: str | None = None, now: datetime | None = None,
                   program: str | None = None) -> None:
    """Record a failed or skipped pull attempt in an existing scope dir only."""
    if not base.is_dir():
        return
    now = now or utcnow()
    state = read_json(base / PULL_FILE)
    state = state if isinstance(state, dict) else {}
    state.setdefault("version", INVENTORY_VERSION)
    state.setdefault("program", program or base.name)
    for field in ("platform", "source_url", "pulled_at", "items", "items_hash"):
        state.setdefault(field, None)
    state["last_attempt_at"] = iso(now)
    state["last_attempt_status"] = status
    if status == "failed":
        state["last_error"] = (error or "unknown error")[:300]
        state["last_failed_at"] = iso(now)
    atomic_write_json(base / PULL_FILE, state)


def last_pulled(base: Path) -> datetime | None:
    """When scope was last pulled: scope-pull.json, else saved-file mtime."""
    state = read_json(base / PULL_FILE)
    if isinstance(state, dict) and (moment := parse_iso(state.get("pulled_at"))):
        return moment
    return _source_mtime(base)
