#!/usr/bin/env python3
"""Create a sanitized endpoint-analysis artifact folder from a raw HTTP request."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit


SECRET_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-canva-authz",
    "x-csrf-token",
    "x-xsrf-token",
    "x-api-key",
}
AUTH_CONTEXT_HEADERS = {
    "authorization",
    "x-canva-authz",
    "x-canva-active-user",
    "x-canva-user",
    "x-canva-brand",
    "x-csrf-token",
    "x-xsrf-token",
}
BROWSER_CONTEXT_HEADERS = {
    "origin",
    "referer",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
}
TRACKING_HEADERS = {
    "x-canva-analytics",
    "priority",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def split_head_body(raw: str) -> tuple[str, str]:
    raw = raw.replace("\r\n", "\n")
    if "\n\n" in raw:
        return raw.split("\n\n", 1)
    return raw, ""


def unfold_headers(lines: list[str]) -> list[str]:
    unfolded: list[str] = []
    for line in lines:
        if not line:
            continue
        if line[0] in " \t" and unfolded:
            unfolded[-1] += " " + line.strip()
        else:
            unfolded.append(line.rstrip("\n"))
    return unfolded


def parse_raw_request(raw: str) -> tuple[str, str, list[tuple[str, str]], str]:
    head, body = split_head_body(raw)
    lines = head.splitlines()
    if not lines:
        raise ValueError("empty request")

    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError(f"invalid request line: {lines[0]!r}")

    headers: list[tuple[str, str]] = []
    for line in unfold_headers(lines[1:]):
        if ":" not in line:
            raise ValueError(f"invalid header line: {line!r}")
        name, value = line.split(":", 1)
        headers.append((name.strip(), value.lstrip()))
    return parts[0].upper(), parts[1], headers, body


def header_value(headers: list[tuple[str, str]], name: str) -> str | None:
    lname = name.lower()
    return next((value for hname, value in headers if hname.lower() == lname), None)


def full_url(target: str, headers: list[tuple[str, str]], scheme: str) -> str:
    parsed = urlsplit(target)
    if parsed.scheme and parsed.netloc:
        return target
    host = header_value(headers, "host")
    if not host:
        raise ValueError("origin-form request target needs Host header")
    path = target if target.startswith("/") else f"/{target}"
    return f"{scheme}://{host}{path}"


def route_placeholder(previous: str, index: int) -> str:
    stem = previous.strip("_-") or "segment"
    if stem.endswith("ies"):
        stem = stem[:-3] + "y"
    elif stem.endswith("s") and len(stem) > 1:
        stem = stem[:-1]
    stem = re.sub(r"[^a-zA-Z0-9_]+", "_", stem).strip("_").lower() or f"id_{index}"
    return f"{{{stem}_id}}"


def looks_identifier(segment: str) -> bool:
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}", segment):
        return True
    if re.fullmatch(r"\d{4,}", segment):
        return True
    if len(segment) >= 9 and re.fullmatch(r"[A-Za-z0-9_-]+", segment):
        has_alpha = any(ch.isalpha() for ch in segment)
        has_digit_or_case_mix = any(ch.isdigit() for ch in segment) or (
            any(ch.islower() for ch in segment) and any(ch.isupper() for ch in segment)
        )
        return has_alpha and has_digit_or_case_mix
    return False


def route_template(path: str) -> tuple[str, dict[str, str]]:
    parts = [part for part in path.split("/") if part]
    templated: list[str] = []
    params: dict[str, str] = {}
    for index, part in enumerate(parts):
        if looks_identifier(part):
            prev = parts[index - 1] if index else "path"
            placeholder = route_placeholder(prev, index)
            name = placeholder.strip("{}")
            suffix = 2
            while name in params:
                name = f"{placeholder.strip('{}')}_{suffix}"
                placeholder = f"{{{name}}}"
                suffix += 1
            templated.append(placeholder)
            params[name] = part
        else:
            templated.append(part)
    return "/" + "/".join(templated), params


def slug_for(method: str, route: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9{}]+", "_", route.strip("/"))
    slug = slug.replace("{", "").replace("}", "").strip("_") or "root"
    return f"{method.lower()}_{slug[:80]}"


def value_fingerprint(value: str) -> dict[str, Any]:
    return {
        "redacted": True,
        "length": len(value),
        "sha256_12": hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12],
    }


def sanitize_value(name: str, value: str, location: str) -> Any:
    lname = name.lower()
    if location == "cookie" or lname in SECRET_HEADER_NAMES:
        return value_fingerprint(value)
    if location == "header" and lname in AUTH_CONTEXT_HEADERS:
        return value_fingerprint(value)
    if re.search(r"(token|secret|auth|session|password|csrf|xsrf|cookie|key)", lname):
        return value_fingerprint(value)
    if len(value) > 120:
        return {"sample": value[:32] + "...", "length": len(value)}
    return value


def cookie_names(cookie_header: str | None) -> list[str]:
    if not cookie_header:
        return []
    names = []
    for chunk in cookie_header.split(";"):
        if "=" in chunk:
            names.append(chunk.split("=", 1)[0].strip())
    return [name for name in names if name]


def header_role(name: str) -> str:
    lname = name.lower()
    if lname in SECRET_HEADER_NAMES or lname in AUTH_CONTEXT_HEADERS:
        return "auth-bound"
    if lname == "x-canva-request":
        return "operation-marker"
    if lname in BROWSER_CONTEXT_HEADERS:
        return "browser-context"
    if lname in TRACKING_HEADERS:
        return "analytics-noise"
    if lname in {"content-type", "accept"}:
        return "content"
    if lname in {"host"}:
        return "routing"
    return "unknown"


def scalar_type(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int) or isinstance(value, float):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    if value is None:
        return "null"
    if isinstance(value, str) and "@" in value and "." in value:
        return "email"
    return "string"


def sanitized_example(value: Any, location: str, path: str) -> Any:
    if isinstance(value, dict):
        return {"shape": {key: scalar_type(child) for key, child in value.items()}}
    if isinstance(value, list):
        return {
            "array_length": len(value),
            "item_type": scalar_type(value[0]) if value else "unknown",
        }
    if isinstance(value, str) and scalar_type(value) == "email":
        return "<OWNED_EMAIL>"
    name = path
    if location == "header" and path.startswith("header."):
        name = path.split(".", 1)[1]
    if location == "cookie" and path.startswith("cookie."):
        name = path.split(".", 1)[1]
    return sanitize_value(name, str(value), location)


def sanitize_json_for_replay(value: Any, lane: str, key: str = "") -> Any:
    key_l = key.lower()
    if isinstance(value, dict):
        return {
            child_key: sanitize_json_for_replay(child, lane, child_key)
            for child_key, child in value.items()
        }
    if isinstance(value, list):
        return [sanitize_json_for_replay(child, lane, key) for child in value]
    if isinstance(value, str):
        if "@" in value and "." in value:
            return "<OWNED_EMAIL>"
        if re.search(r"(token|secret|auth|session|password|csrf|xsrf|cookie|key)", key_l):
            placeholder = re.sub(r"[^A-Za-z0-9]+", "_", key).strip("_").upper() or "VALUE"
            return f"<FRESH_{placeholder}_{lane}>"
        if key_l in {"user", "userid", "user_id", "owner", "ownerid", "owner_id"}:
            return f"<USER_ID_{lane}>"
    return value


def body_paths(value: Any, prefix: str = "body") -> dict[str, Any]:
    found: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}"
            found[path] = child
            found.update(body_paths(child, path))
    elif isinstance(value, list):
        for index, child in enumerate(value[:3]):
            path = f"{prefix}[]"
            found[path] = child
            found.update(body_paths(child, path))
    return found


def load_body(body: str, content_type: str | None) -> tuple[str, Any]:
    if not body:
        return "none", None
    if content_type and "json" in content_type.lower():
        try:
            return "json", json.loads(body)
        except json.JSONDecodeError:
            return "json-invalid", None
    return "raw", None


def parameter_entry(
    location: str,
    path: str,
    value: Any,
    role: str,
    meaning: str = "unknown",
    confidence: str = "low",
) -> dict[str, Any]:
    example = sanitized_example(value, location, path) if value is not None else None
    return {
        "location": location,
        "type": scalar_type(value),
        "role": role,
        "required": "unknown",
        "meaning": meaning,
        "confidence": confidence,
        "observed_examples": [] if example is None else [example],
        "evidence": ["observed in baseline proxy request"],
        "fuzzing": {
            "guidance": "classify before mutating",
            "safe_mutations": [],
            "keep_stable_when_testing": [],
        },
    }


def build_parameters(
    route_params: dict[str, str],
    query_pairs: list[tuple[str, str]],
    headers: list[tuple[str, str]],
    cookie_names_list: list[str],
    body_format: str,
    body_obj: Any,
) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for name, value in route_params.items():
        entry = parameter_entry("path", f"path.{name}", value, "object-id")
        entry["fuzzing"]["safe_mutations"] = ["owned object-id swap", "mismatch with body/header owner"]
        entry["fuzzing"]["keep_stable_when_testing"] = ["parser/content mutation"]
        params[f"path.{name}"] = entry
    for name, value in query_pairs:
        params[f"query.{name}"] = parameter_entry("query", f"query.{name}", value, "unknown")
    for name, value in headers:
        role = header_role(name)
        entry = parameter_entry("header", f"header.{name}", value, role)
        if role == "auth-bound":
            entry["fuzzing"]["guidance"] = "keep stable unless testing auth/header binding with owned accounts"
            entry["fuzzing"]["keep_stable_when_testing"] = ["body field fuzzing", "parser mutation"]
        elif role == "analytics-noise":
            entry["fuzzing"]["guidance"] = "usually omit or ignore after one controlled check"
            entry["required"] = "unknown"
        params[f"header.{name}"] = entry
    for name in cookie_names_list:
        entry = parameter_entry("cookie", f"cookie.{name}", "<redacted>", "auth-bound")
        entry["type"] = "cookie"
        entry["observed_examples"] = [{"redacted": True}]
        entry["fuzzing"]["guidance"] = "do not fuzz cookie value; refresh from owned lane"
        params[f"cookie.{name}"] = entry
    if body_format == "json" and body_obj is not None:
        for path, value in body_paths(body_obj).items():
            role = "content"
            if path.lower().endswith("user") or path.lower().endswith("userid"):
                role = "object-id"
            entry = parameter_entry("body", path, value, role)
            if scalar_type(value) == "email":
                entry["meaning"] = "email-shaped value; verify UI semantics before replay"
                entry["confidence"] = "medium"
                entry["fuzzing"]["safe_mutations"] = ["owned email alias", "invalid email format", "omit", "null"]
            params[path] = entry
    return params


def body_schema_summary(body_format: str, body_obj: Any) -> Any:
    if body_format != "json" or body_obj is None:
        return {"format": body_format}

    def summarize(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: summarize(child) for key, child in value.items()}
        if isinstance(value, list):
            return [summarize(value[0])] if value else []
        return scalar_type(value)

    return summarize(body_obj)


def replay_template(
    method: str,
    url_template: str,
    headers: list[tuple[str, str]],
    body: str,
    body_format: str,
    body_obj: Any,
    pwnfox_color: str | None,
) -> str:
    lane = (pwnfox_color or "LANE").upper()
    replay_body = body
    if body_format == "json" and body_obj is not None:
        replay_body = json.dumps(sanitize_json_for_replay(body_obj, lane), separators=(",", ":"))
    lines = [
        "# Sanitized Replay Template",
        "",
        "Resolve fresh auth from an approved owned agent lane before running. Do not paste live cookies or tokens into this file.",
        "",
        "```bash",
        f"curl {json.dumps(url_template)} \\",
        f"  -X {method} \\",
    ]
    for name, value in headers:
        lname = name.lower()
        if lname == "cookie":
            continue
        placeholder = value
        if lname in SECRET_HEADER_NAMES or lname in AUTH_CONTEXT_HEADERS:
            placeholder = f"<FRESH_{re.sub(r'[^A-Za-z0-9]+', '_', name).strip('_').upper()}_{lane}>"
        elif len(value) > 120:
            placeholder = f"<{re.sub(r'[^A-Za-z0-9]+', '_', name).strip('_').upper()}_{lane}>"
        lines.append(f"  -H {json.dumps(f'{name}: {placeholder}')} \\")
    if header_value(headers, "cookie"):
        lines.append(f"  -b '<FRESH_COOKIE_JAR_{lane}>' \\")
    if replay_body:
        lines.append(f"  --data-binary {json.dumps(replay_body)}")
    else:
        lines[-1] = lines[-1].rstrip(" \\")
    lines.extend(["```", "", "## Fresh Auth Requirements", ""])
    lines.append(f"- Cookie jar: `<FRESH_COOKIE_JAR_{lane}>`")
    for name, _ in headers:
        if name.lower() in AUTH_CONTEXT_HEADERS:
            lines.append(f"- Header `{name}`: refresh from owned `{lane}` lane")
    return "\n".join(lines) + "\n"


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("program")
    parser.add_argument("request", help="Raw HTTP request file, or '-' for stdin.")
    parser.add_argument("--base", default="/home/ryushe/Shared/bounty_recon")
    parser.add_argument("--scheme", choices=["https", "http"], default="https")
    parser.add_argument("--proxy-lane", default="unknown")
    parser.add_argument("--pwnfox-color")
    parser.add_argument("--account-alias")
    parser.add_argument("--ui-flow")
    args = parser.parse_args(argv)

    raw = sys.stdin.read() if args.request == "-" else Path(args.request).read_text(encoding="utf-8")
    method, target, headers, body = parse_raw_request(raw)
    url = full_url(target, headers, args.scheme)
    parsed = urlsplit(url)
    template_path, route_params = route_template(parsed.path)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    body_format, body_obj = load_body(body, header_value(headers, "content-type"))
    cookies = cookie_names(header_value(headers, "cookie"))
    timestamp = now_iso()
    url_template = f"{parsed.scheme}://{parsed.netloc}{template_path}"
    if parsed.query:
        url_template += f"?{parsed.query}"
    endpoint_hash = hashlib.sha256(f"{method} {parsed.netloc} {template_path}".encode()).hexdigest()[:10]
    endpoint_id = f"{method} {parsed.netloc}{template_path}"
    out_dir = (
        Path(args.base)
        / args.program
        / "ghost"
        / "endpoints"
        / parsed.netloc
        / f"{slug_for(method, template_path)}_{endpoint_hash}"
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    parameters = build_parameters(route_params, query_pairs, headers, cookies, body_format, body_obj)
    header_roles = [
        {
            "name": name,
            "role": header_role(name),
            "value": sanitize_value(name, value, "header"),
        }
        for name, value in headers
        if name.lower() != "cookie"
    ]
    contract = {
        "schema_version": 1,
        "program": args.program,
        "endpoint_id": endpoint_id,
        "created_at": timestamp,
        "updated_at": timestamp,
        "identity": {
            "method": method,
            "scheme": parsed.scheme,
            "host": parsed.netloc,
            "path": parsed.path,
            "route_template": template_path,
            "full_url_template": url_template,
        },
        "source": {
            "proxy_lane": args.proxy_lane,
            "pwnfox_color": args.pwnfox_color,
            "account_alias": args.account_alias,
            "ui_flow": args.ui_flow,
            "referer": header_value(headers, "referer"),
            "observation_count": 1,
        },
        "request_shape": {
            "content_type": header_value(headers, "content-type"),
            "headers": header_roles,
            "cookie_names": cookies,
            "query_fields": [name for name, _ in query_pairs],
            "body_format": body_format,
            "body_schema": body_schema_summary(body_format, body_obj),
        },
        "auth_context": {
            "auth_required": "unknown",
            "account_bound_headers": [
                name for name, _ in headers if name.lower() in AUTH_CONTEXT_HEADERS
            ],
            "object_bound_fields": [
                key for key, entry in parameters.items() if entry.get("role") == "object-id"
            ],
        },
        "state_change": {
            "class": "write" if method not in {"GET", "HEAD", "OPTIONS"} else "read",
            "description": "unknown; infer from UI flow, request marker, and response behavior",
        },
        "replay": {
            "template_file": "replay.md",
            "fresh_auth_required": True,
            "one_time_token_warning": "unknown",
        },
        "fuzzing_handoff": {
            "candidate_skills": ["request-exploration", "intelligent-fuzzing"],
            "notes": "Keep auth-bound fields stable unless testing owned auth/object binding.",
        },
        "redaction": {
            "secret_values_saved": False,
            "cookie_values": "names-only",
            "secret_headers": "fingerprint-or-placeholder",
        },
    }
    observation = {
        "observed_at": timestamp,
        "source": contract["source"],
        "method": method,
        "url": url_template,
        "status": "unknown",
        "request_hash": hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest(),
        "header_names": [name for name, _ in headers],
        "cookie_names": cookies,
        "body_format": body_format,
        "body_field_paths": [
            key for key, entry in parameters.items() if entry.get("location") == "body"
        ],
    }
    notes = f"""# {method} {url_template}

## Summary

- State change: {contract["state_change"]["class"]}; exact semantics still need confirmation.
- Source UI/referrer: {header_value(headers, "referer") or "unknown"}
- PwnFox/account lane: {args.pwnfox_color or "unknown"} / {args.account_alias or "unknown"}

## Open Questions

- Which fields are truly required?
- Which object identifiers must match account-bound headers or cookies?
- Which obfuscated fields are discriminators, operation markers, or generated state?
- Does exact replay work, or does this require live interception because of one-time state?

## Next Handoffs

- Load `request-exploration` for omission/null/type-change tests.
- Load `intelligent-fuzzing` for hidden sibling fields.
- Load `access-control` or `idor` for owned cross-account object binding.
"""

    write_json(out_dir / "contract.json", contract)
    write_json(out_dir / "parameters.json", parameters)
    (out_dir / "replay.md").write_text(
        replay_template(method, url_template, headers, body, body_format, body_obj, args.pwnfox_color),
        encoding="utf-8",
    )
    with (out_dir / "observations.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(observation, sort_keys=True) + "\n")
    (out_dir / "notes.md").write_text(notes, encoding="utf-8")
    print(out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
