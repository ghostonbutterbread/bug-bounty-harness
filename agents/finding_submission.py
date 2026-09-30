#!/usr/bin/env python3
"""Prepare one reviewed per-FID submission draft; never submit externally.

The author supplies the concise submission text. This command checks structural
readiness, not the truth of the claim: the author must verify the evidence and
program rules before invoking it. It never rewrites an existing submission.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agents.storage_resolver import resolve_storage
from bounty_core.ledger import ledger_get
from bounty_core.reports import canonical_finding_report_dir

SUBMISSION_SECTIONS = ("Summary", "Technical details", "How to reproduce", "Impact", "Remediation")
EVIDENCE_SECTIONS = (
    "Claim and status", "Attacker model and prerequisites", "Evidence index",
    "Complete reproduction record", "Demonstrated impact and negative boundaries",
)
_PLACEHOLDER = re.compile(r"(?i)\b(?:TODO|TBD|FIXME|placeholder|unverified|unproven|hypothetical)\b|<[^>\n]+>|\[[^]\n]*(?:insert|describe|provide)[^]\n]*\]")
_HEADING = re.compile(r"^## ([^\n]+)\s*$", re.MULTILINE)
_FID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")


def _sections(text: str, expected: tuple[str, ...], *, label: str) -> dict[str, str]:
    matches = list(_HEADING.finditer(text))
    names = [match.group(1).strip() for match in matches]
    missing = [name for name in expected if names.count(name) != 1]
    if missing:
        raise ValueError(f"{label} requires exactly one nonempty section for each of: {', '.join(missing)}")
    parts = {
        name: text[match.end():matches[index + 1].start() if index + 1 < len(matches) else len(text)].strip()
        for index, (name, match) in enumerate(zip(names, matches))
    }
    for name in expected:
        body = re.sub(r"(?m)^#{3,6} .*$", "", parts[name]).strip()
        if not body or _PLACEHOLDER.search(body):
            raise ValueError(f"{label} section {name!r} is empty or contains a placeholder")
    return parts


def prepare_submission(
    program: str,
    fid: str,
    *,
    lane: str,
    from_file: str | Path,
    evidence_pointers: list[str],
    family: str | None = None,
    root_override: str | Path | None = None,
) -> Path:
    """Create reports/<FID>/SUBMISSION.md once, returning its path.

    Raises ValueError on unmet readiness requirements and FileExistsError if a
    submission already exists. No ledger or external submission state is changed.
    """
    if not _FID.fullmatch(fid):
        raise ValueError("FID must be a single path-safe identifier")
    layout = resolve_storage(program, lane=lane, family=family, root_override=root_override, create=False)
    finding = ledger_get(program, fid, lane=layout.lane, family=layout.family, root_override=root_override)
    if finding is None or finding.get("fid") != fid:
        raise ValueError(f"finding not found for exact FID {fid}")
    packet = canonical_finding_report_dir(layout, finding)
    if packet.name != fid:
        raise ValueError("canonical packet does not match requested FID")
    destination = packet / "SUBMISSION.md"
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"submission already exists; revise in place: {destination}")
    evidence_path = packet / "EVIDENCE.md"
    if not evidence_path.is_file():
        raise ValueError(f"missing EVIDENCE.md for {fid}")
    evidence = evidence_path.read_text(encoding="utf-8")
    if not re.search(rf"(?m)^#\s+{re.escape(fid)}(?:\s|\s*[—-])", evidence):
        raise ValueError("EVIDENCE.md heading must identify the exact FID")
    sections = _sections(evidence, EVIDENCE_SECTIONS, label="EVIDENCE.md")
    if not re.search(r"(?im)^\s*(?:[-*]\s*)?(?:status:\s*)?verified\b", sections["Claim and status"]):
        raise ValueError("EVIDENCE.md Claim and status must explicitly mark the claim verified")
    if not evidence_pointers or any(not pointer.strip() for pointer in evidence_pointers):
        raise ValueError("provide at least one --evidence-pointer from EVIDENCE.md's Evidence index")
    for pointer in evidence_pointers:
        if pointer not in sections["Evidence index"]:
            raise ValueError(f"evidence pointer not in EVIDENCE.md Evidence index: {pointer}")
    report_path = packet / "REPORT.md"
    if not report_path.is_file():
        raise ValueError(f"missing REPORT.md draft for {fid}")
    _sections(report_path.read_text(encoding="utf-8"), SUBMISSION_SECTIONS, label="REPORT.md")
    source = Path(from_file).expanduser()
    draft = source.read_text(encoding="utf-8")
    if not re.search(r"(?m)^#\s+\S", draft):
        raise ValueError("submission requires a specific nonempty title")
    matches = list(_HEADING.finditer(draft))
    if [m.group(1).strip() for m in matches] != list(SUBMISSION_SECTIONS):
        raise ValueError("submission headings must be the five required sections in order, without extras")
    _sections(draft, SUBMISSION_SECTIONS, label="submission")
    if source.resolve(strict=False) == destination.resolve(strict=False):
        raise ValueError("--from-file cannot be the canonical submission")
    # Exclusive creation prevents concurrent invocations from silently replacing a reviewer's edits.
    packet.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8") as handle:
        handle.write("<!-- Prepared draft only; not externally submitted. -->\n" + draft.rstrip() + "\n")
    return destination


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create a prepared, not-submitted per-FID draft from author-reviewed text.")
    parser.add_argument("program", help="Canonical program slug")
    parser.add_argument("fid", help="Exact ledger FID")
    parser.add_argument("--lane", required=True, help="Canonical storage lane (web, api, apk, exe, mac)")
    parser.add_argument("--family", help="Storage family override")
    parser.add_argument("--root", dest="root_override", help="Explicit local storage root (for testing/local use)")
    parser.add_argument("--from-file", required=True, help="Author-written concise Markdown submission; no automatic claim synthesis")
    parser.add_argument("--evidence-pointer", action="append", required=True, dest="evidence_pointers", help="Literal evidence-index pointer supporting the draft (repeatable)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        path = prepare_submission(
            args.program, args.fid, lane=args.lane, family=args.family,
            root_override=args.root_override, from_file=args.from_file,
            evidence_pointers=args.evidence_pointers,
        )
    except (ValueError, OSError) as exc:
        print(f"submission not prepared: {exc}", file=sys.stderr)
        return 1
    print(f"Prepared draft (not externally submitted): {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
