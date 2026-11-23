"""The conditional XSS idea tree stays reachable and evidence-bound."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REF = ROOT / "skills/xss/references/payload-engineering"
LEAVES = (
    "mechanism-ideation.md",
    "parser-stage-character-variants.md",
    "client-interpreters.md",
    "derived-consumers.md",
    "defense-edges.md",
)


def _norm(text: str) -> str:
    """Collapse whitespace and strip markdown emphasis so a reflow or a
    bolding change does not break a claim that is still true."""
    return " ".join(re.sub(r"[*`_]", "", text).split())


def text(relative: str) -> str:
    return _norm((ROOT / relative).read_text(encoding="utf-8"))


def raw(relative: str) -> str:
    """Line structure preserved, for checks that count rows or sections."""
    return (ROOT / relative).read_text(encoding="utf-8")


def test_conditional_root_to_leaf_route_is_resolvable() -> None:
    router = text("skills/xss/SKILL.md")
    payload = text("skills/xss/references/payload-engineering.md")
    tree = text("skills/xss/references/payload-engineering/idea-tree.md")
    assert "references/payload-engineering/idea-tree.md" in router
    assert "references/payload-engineering/idea-tree.md" in payload
    assert "Keep multiple hypotheses alive" in payload
    assert "not a second payload corpus or a required per-run checklist" in payload
    for leaf in LEAVES:
        assert leaf in tree
        assert (REF / leaf).is_file()
    for lane in ("reflected-xss", "stored-xss", "dom-xss", "blind-xss"):
        assert lane in router


def test_tree_invites_uncapped_ideation_but_preserves_per_claim_proof() -> None:
    router = text("skills/xss/SKILL.md")
    payload = text("skills/xss/references/payload-engineering.md")
    tree = text("skills/xss/references/payload-engineering/idea-tree.md")
    mechanism = text("skills/xss/references/payload-engineering/mechanism-ideation.md")
    client = text("skills/xss/references/payload-engineering/client-interpreters.md")
    derived = text("skills/xss/references/payload-engineering/derived-consumers.md")
    doc = text("docs/xss-idea-tree.md")
    assert "not a ceiling on ideas" in router
    assert "including ones outside the tree" in payload
    assert "unlisted/surprising mechanism?" in tree
    assert "not by leaf count" in tree
    assert "not a control prerequisite or idea quota" in mechanism
    assert "Explore sink-first with the missing source named" in derived
    assert "investigate a suspected reparse" in client
    assert "without a count limit" in derived
    assert "no number of ideas or leaves to exhaust" in doc
    assert "source / plausible sink / surprising transform or research clue" in doc
    assert "selected lane owns live testing and browser proof" in doc
    assert "not a validated bypass" in tree


def test_new_leaves_require_observed_consumers_and_falsifiers() -> None:
    client = text("skills/xss/references/payload-engineering/client-interpreters.md")
    derived = text("skills/xss/references/payload-engineering/derived-consumers.md")
    defense = text("skills/xss/references/payload-engineering/defense-edges.md")
    for content in (client, derived, defense):
        assert "control" in content.lower()
        assert "sink" in content.lower()
        assert "browser proof" in content.lower() or "browser execution" in content.lower()
    for boundary in ("Service Workers", "Import maps", "WebAssembly", "Console/DevTools", "Content-type/charset"):
        assert boundary in client
    for boundary in ("Prototype pollution", "postMessage", "GraphQL", "SSE / WebSocket", "AI/model"):
        assert boundary in derived
    for boundary in ("CSP nonces", "Trusted Types", "WAF / app filter", "Sanitizer"):
        assert boundary in defense
    assert "data: registration is not a valid shortcut" in client
    assert "A CSS selector seeing script[nonce] is not assumed" in defense
    assert "header-delivered CSP" in defense
    assert "already resolved" in client and "not yet resolved" in client
    assert "CSWSH is not XSS" in derived


def test_human_tree_accounts_for_pinned_technique_headings_without_claiming_bypasses() -> None:
    # the row count and the commit line depend on line structure, so read raw
    doc = raw("docs/xss-idea-tree.md")
    section = doc.split("## Pinned upstream heading audit", 1)[1].split("What remains deliberately unimported:", 1)[0]
    entries = [line for line in section.splitlines() if line.startswith("| ")][2:]
    assert len(entries) == 29
    assert len({row.split("|", 2)[1].strip() for row in entries}) == 29
    assert "Current" not in doc.split("**Implementation commits:**", 1)[1].splitlines()[0]
    # these are plain claims, so reflowing the document must not break them
    flat = text("docs/xss-idea-tree.md")
    assert "Out of XSS:" in flat
    assert "not the set of independently demonstrated bypasses" in flat
    assert "Mismatched Contexts (2025/2026 Trend)" in flat


def test_leaves_preserve_existing_research_and_evidence_ownership() -> None:
    tree = text("skills/xss/references/payload-engineering/idea-tree.md")
    assert "references/technology-research.md" in tree
    assert "attempt-recording-policy owns the exact" in tree
    assert "ResearchMap" in tree and "MapStore" in tree and "Attempts" in tree
    assert "not a validated bypass" in tree
    assert "use skillview(name='xss', filepath='references/payload-engineering/" in tree
