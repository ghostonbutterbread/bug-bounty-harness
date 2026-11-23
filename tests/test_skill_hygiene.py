"""Structural guards for the skill corpus.

These assert shape rather than wording, so a rewrite that preserves routing
does not need a test edit. They are the counterpart to the ~555 prose-fragment
assertions elsewhere in this suite: those pin specific sentences, many of which
encode safety boundaries and are deliberate. Nothing here replaces them.

The size guard is a ratchet: it records the current worst case and fails only
on regression, so the corpus can shrink but not grow.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
BUDGET = Path(__file__).with_name("skill_size_budget.json")

SKILL_FILES = sorted(p for p in SKILLS.glob("*/SKILL.md"))
NAMES = {p.parent.name for p in SKILL_FILES}


def frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---\n"):
        return {}
    block = text.split("---", 2)[1]
    out = {}
    for line in block.splitlines():
        if ":" in line and not line.startswith(" "):
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip().strip('"')
    return out


def test_every_skill_has_a_name_matching_its_directory():
    """A mismatch makes one of the two invocation paths dead."""
    bad = []
    for p in SKILL_FILES:
        name = frontmatter(p.read_text(encoding="utf-8")).get("name")
        if name != p.parent.name:
            bad.append(f"{p.parent.name}: frontmatter name={name!r}")
    assert not bad, "name/directory mismatch:\n  " + "\n  ".join(bad)


def test_every_skill_has_a_description():
    missing = [p.parent.name for p in SKILL_FILES
               if not frontmatter(p.read_text(encoding="utf-8")).get("description")]
    assert not missing, f"no description (never selected): {missing}"


def test_backticked_skill_references_resolve():
    """A load directive naming a skill that does not exist is a silent no-op.

    Cross-repo policy names and CLI subcommands are excluded by the allowlist;
    add to it only when the name is genuinely owned elsewhere.
    """
    external = {
        # AI Policies repository
        "general-security-testing-policy", "live-testing-policy", "program-testing-policy",
        "bug-bounty-approach", "browser-session-policy", "attempt-recording-policy",
        "injection-testing-policy", "waf-live-policy", "http-status-live-policy",
        "idor-live-policy", "race-live-policy", "payment-testing-policy",
        "account-testing-policy", "email-access-policy", "captcha-policy",
        "hypothesis-live-testing", "hypothesis-expansion-policy", "impact-fit-policy",
        "impact-escalation", "class-derivation-policy", "hunt-orchestration-policy",
        "assumption-testing", "technology-research", "business-logic-modeling",
        "information-disclosure-policy", "electron-live-testing-policy",
        "desktop-mobile-amplifier-policy", "poc-tooling-policy",
        "triager-first-poc-authoring", "recon-corpus-write-policy",
        "bounty-directory-structure-policy", "resource-safety-policy",
        "social-integration-policy", "public-forums", "safe-fetch",
        "proxy-routing-policy", "surface-expansion", "policy-authoring",
        # installed from other sources
        "bunny-report-and-triage", "hoster-ssh", "script-manager", "account-manager",
        "agent-network", "web-data-source-analysis", "mail", "bitwarden",
    }
    dangling: dict[str, set[str]] = {}
    for p in SKILL_FILES:
        text = p.read_text(encoding="utf-8")
        for m in re.finditer(r"load `(/?[a-z][a-z0-9-]{3,})`", text, re.I):
            ref = m.group(1).lstrip("/")
            if ref in NAMES or ref in external or ref == p.parent.name:
                continue
            dangling.setdefault(p.parent.name, set()).add(ref)
    assert not dangling, "load directives naming no known skill:\n  " + "\n  ".join(
        f"{k}: {sorted(v)}" for k, v in sorted(dangling.items()))


def test_reference_paths_resolve():
    """Resolve locally, then anywhere under skills/, per the owner-attributed
    convention ("load Hunter Loop's `references/x.md`")."""
    # owned by general-security-testing-policy in the AI Policies repository and
    # cited here by owner name, so they cannot resolve inside this tree
    cross_repo = {
        "references/testing-posture.md",
        "references/opening-and-knowledge.md",
        "references/obstacle-classification.md",
        "references/finding-capture-and-goal-mode.md",
        "references/conclusion-provenance.md",
        "references/boundaries.md",
        "references/rate-and-evidence.md",
        "references/permission-decision-log.md",
        "references/safety-incident-response.md",
        "references/operating-details.md",
        "references/authenticated-coverage.md",
        "references/status-cards.md",
    }
    bad = []
    for p in sorted(SKILLS.rglob("*.md")):
        text = p.read_text(encoding="utf-8", errors="replace")
        for ref in re.findall(r"`(references/[^`\s<]+\.md)`", text):
            if ref in cross_repo:
                continue
            if (p.parent / ref).is_file() or list(SKILLS.glob(f"*/{ref}")):
                continue
            bad.append(f"{p.relative_to(ROOT)}: {ref}")
        for ref in re.findall(r"`(skills/[^`\s<]+\.md)`", text):
            if (ROOT / ref).is_file() or "Supersedes" in text:
                continue
            bad.append(f"{p.relative_to(ROOT)}: {ref}")
    assert not bad, "unresolvable reference paths:\n  " + "\n  ".join(bad)


def test_skill_size_does_not_regress():
    """Ratchet: SKILL.md may shrink, not grow past its recorded worst case.

    Regenerate deliberately with:
        python -c "import json,pathlib;p=pathlib.Path('skills');\
print(json.dumps({q.parent.name:len(q.read_text().splitlines()) \
for q in sorted(p.glob('*/SKILL.md'))},indent=2))" > tests/skill_size_budget.json
    """
    if not BUDGET.is_file():
        pytest.skip("no recorded budget yet")
    budget = json.loads(BUDGET.read_text())
    grew = []
    for p in SKILL_FILES:
        name = p.parent.name
        now = len(p.read_text(encoding="utf-8").splitlines())
        cap = budget.get(name)
        if cap is not None and now > cap:
            grew.append(f"{name}: {now} lines, budget {cap}")
    assert not grew, (
        "SKILL.md grew past its budget; move depth into references/ or update "
        "tests/skill_size_budget.json deliberately:\n  " + "\n  ".join(grew))


def test_no_two_skills_share_a_near_identical_trigger():
    """Two skills whose descriptions are near-duplicates will mis-select."""
    def toks(s: str) -> set[str]:
        stop = {"use","when","the","a","an","and","or","for","to","of","in","on",
                "with","that","this","its","it","is","are","be","from","into","by"}
        return {w for w in re.findall(r"[a-z][a-z-]{2,}", s.lower())} - stop

    descs = {p.parent.name: frontmatter(p.read_text(encoding="utf-8")).get("description", "")
             for p in SKILL_FILES}
    names = sorted(descs)
    collisions = []
    for i, a in enumerate(names):
        ta = toks(descs[a])
        if len(ta) < 5:
            continue
        for b in names[i + 1:]:
            tb = toks(descs[b])
            if len(tb) < 5:
                continue
            j = len(ta & tb) / len(ta | tb)
            if j >= 0.60:
                collisions.append(f"{a} / {b}: jaccard {j:.2f}")
    assert not collisions, (
        "descriptions too similar to select between:\n  " + "\n  ".join(collisions))
