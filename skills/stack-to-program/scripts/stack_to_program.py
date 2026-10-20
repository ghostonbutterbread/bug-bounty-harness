#!/usr/bin/env python3
"""Join local technology evidence to a local public program directory snapshot.

This is a candidate generator, not proof of vulnerability, payment, scope, or
permission to test. It makes no network requests.
"""

import argparse
import hashlib
import json
import sys
from datetime import date
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


LABELS = {"source-derived", "disclosure", "artifact", "feature-inferred", "contradicted", "unknown"}


def normalized_name(value):
    return " ".join(value.casefold().split())


def normalized_domain(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("domain must be a nonempty string")
    domain = value.strip().lower().rstrip(".")
    if not domain or any(char in domain for char in "/:@?# ") or "." not in domain:
        raise ValueError(f"invalid domain: {value!r}")
    return domain


def normalized_url(value):
    if not isinstance(value, str):
        raise ValueError("URL must be a string")
    parts = urlsplit(value.strip())
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        raise ValueError(f"invalid HTTP(S) URL: {value!r}")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"invalid HTTP(S) URL: {value!r}") from exc
    host = parts.hostname.lower()
    authority = host + (f":{port}" if port is not None else "")
    return urlunsplit((parts.scheme.lower(), authority, parts.path.rstrip("/"), parts.query, ""))


def required_text(row, key, context):
    value = row.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{context}: {key} must be a nonempty string")
    return value.strip()


def load_evidence(path):
    evidence = set()
    with path.open(encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            if not line.strip():
                continue
            context = f"{path}:{line_no}"
            try:
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError("expected JSON object")
                item = {key: required_text(row, key, context) for key in
                        ("component", "product", "evidence_label", "source_url", "observed_date")}
                if item["evidence_label"] not in LABELS:
                    raise ValueError(f"evidence_label must be one of {sorted(LABELS)}")
                try:
                    date.fromisoformat(item["observed_date"])
                except ValueError as exc:
                    raise ValueError("observed_date must be an ISO calendar date") from exc
                normalized_url(item["source_url"])
                for key in ("product_domain", "program_url"):
                    if row.get(key) is not None:
                        item[key] = required_text(row, key, context)
                if "product_domain" in item:
                    item["product_domain"] = normalized_domain(item["product_domain"])
                if "program_url" in item:
                    item["program_url"] = normalized_url(item["program_url"])
                evidence.add(json.dumps(item, sort_keys=True))
            except (ValueError, json.JSONDecodeError) as exc:
                raise ValueError(f"{context}: {exc}") from exc
    return [json.loads(item) for item in sorted(evidence)]


def load_programs(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("programs"), list):
        raise ValueError(f"{path}: expected object with programs array")
    programs = {}
    for index, row in enumerate(data["programs"]):
        context = f"{path}:programs[{index}]"
        if not isinstance(row, dict):
            raise ValueError(f"{context}: expected object")
        name = required_text(row, "name", context)
        url = normalized_url(required_text(row, "url", context))
        domains = row.get("domains", [])
        if not isinstance(domains, list):
            raise ValueError(f"{context}: domains must be an array")
        domains = sorted({normalized_domain(domain) for domain in domains})
        bounty = row.get("bounty")
        if bounty is not None and not isinstance(bounty, bool):
            raise ValueError(f"{context}: bounty must be boolean")
        # Distinct directory records sharing a URL still produce one candidate.
        if url in programs:
            previous = programs[url]
            previous["names"].add(name)
            previous["domains"].update(domains)
            previous["bounty_flags"].add(bounty)
        else:
            programs[url] = {"names": {name}, "domains": set(domains), "bounty_flags": {bounty}}
    return programs


def join(evidence, programs):
    by_name = defaultdict(set)
    by_domain = defaultdict(set)
    for url, program in programs.items():
        for name in program["names"]:
            by_name[normalized_name(name)].add(url)
        for domain in program["domains"]:
            by_domain[domain].add(url)

    matched = defaultdict(list)
    unmatched = []
    for item in evidence:
        if "program_url" in item:
            method = "explicit_program_url"
            urls = {item["program_url"]} & programs.keys()
        elif "product_domain" in item:
            method = "exact_product_domain"
            urls = by_domain[item["product_domain"]]
        else:
            method = "exact_product_name"
            urls = by_name[normalized_name(item["product"])]
        if not urls:
            unmatched.append({"evidence": item, "reason": f"no_{method}_match"})
        for url in urls:
            matched[url].append({"match": method, "evidence": item})

    candidates = []
    review_only = []
    for url in sorted(matched):
        program = programs[url]
        entries = sorted(matched[url], key=lambda entry: (entry["match"], json.dumps(entry["evidence"], sort_keys=True)))
        flags = sorted(program["bounty_flags"], key=lambda flag: (flag is not None, str(flag)))
        labels = sorted({entry["evidence"]["evidence_label"] for entry in entries})
        positive = set(labels) & {"source-derived", "disclosure", "artifact"}
        hypothesis = "feature-inferred" in labels
        record = {
            "program_name": sorted(program["names"])[0],
            "program_url": url,
            "source": "ProjectDiscovery public-bugbounty-programs dist/data.json (local snapshot)",
            "bounty_directory_flags_unverified": flags,
            "evidence_labels": labels,
            "support_status": "public_evidence" if positive else "hypothesis_only" if hypothesis else "no_support",
            "matches": entries,
            "unknowns": ["current_program_rules", "current_paid_status", "authorized_scope", "vulnerability_status"],
        }
        if positive or hypothesis:
            candidates.append(record)
        else:
            review_only.append(record)
    return {"count": len(candidates), "candidates": candidates, "review_only": review_only,
            "unmatched": sorted(unmatched, key=lambda row: json.dumps(row, sort_keys=True)), "exhaustive": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True, help="Local evidence JSONL path")
    parser.add_argument("--programs", type=Path, required=True, help="Local ProjectDiscovery dist/data.json snapshot")
    parser.add_argument("--snapshot-date", required=True, help="ISO date when this directory snapshot was obtained")
    parser.add_argument("--output", type=Path, help="Output JSON path (default: stdout)")
    args = parser.parse_args(argv)
    try:
        try:
            date.fromisoformat(args.snapshot_date)
        except ValueError as exc:
            raise ValueError("snapshot-date must be an ISO calendar date") from exc
        digest = hashlib.sha256()
        with args.programs.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        result = join(load_evidence(args.evidence), load_programs(args.programs))
        result["directory_snapshot"] = {"source_url": "https://github.com/projectdiscovery/public-bugbounty-programs/blob/main/dist/data.json",
                                        "observed_date": args.snapshot_date, "sha256": digest.hexdigest()}
        text = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        if args.output:
            args.output.write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.exit(2, f"stack-to-program: {exc}\n")


if __name__ == "__main__":
    main()
