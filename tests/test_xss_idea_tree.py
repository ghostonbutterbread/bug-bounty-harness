"""The conditional XSS idea tree stays reachable and evidence-bound."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REF = ROOT / "skills/xss-payload-engineering/references"
LEAVES = (
    "mechanism-ideation.md",
    "parser-stage-character-variants.md",
    "client-interpreters.md",
    "derived-consumers.md",
    "defense-edges.md",
)


def text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_conditional_root_to_leaf_route_is_resolvable() -> None:
    router = text("skills/xss/SKILL.md")
    payload = text("skills/xss-payload-engineering/SKILL.md")
    tree = text("skills/xss-payload-engineering/references/idea-tree.md")
    assert "references/idea-tree.md" in router
    assert "references/idea-tree.md" in payload
    assert "Keep multiple\nhypotheses alive" in payload
    assert "not a second payload corpus or a required per-run checklist" in " ".join(payload.split())
    for leaf in LEAVES:
        assert leaf in tree
        assert (REF / leaf).is_file()
    for lane in ("reflected-xss", "stored-xss", "dom-xss", "blind-xss"):
        assert lane in router


def test_tree_invites_uncapped_ideation_but_preserves_per_claim_proof() -> None:
    router = text("skills/xss/SKILL.md")
    payload = text("skills/xss-payload-engineering/SKILL.md")
    tree = text("skills/xss-payload-engineering/references/idea-tree.md")
    mechanism = text("skills/xss-payload-engineering/references/mechanism-ideation.md")
    client = text("skills/xss-payload-engineering/references/client-interpreters.md")
    derived = text("skills/xss-payload-engineering/references/derived-consumers.md")
    doc = text("docs/xss-idea-tree.md")
    assert "not a ceiling on ideas" in router
    assert "including ones outside the tree" in payload
    assert "unlisted/surprising mechanism?" in tree
    assert "not by leaf count" in tree
    assert "not a control prerequisite or idea quota" in mechanism
    assert "Explore sink-first with the missing source named" in derived
    assert "investigate a suspected reparse" in client
    assert "without a count limit" in derived
    assert "no\nnumber of ideas or leaves to exhaust" in doc
    assert "source / plausible sink / surprising transform or research clue" in doc
    assert "selected lane owns\nlive testing and browser proof" in doc
    assert "not a validated bypass" in tree


def test_new_leaves_require_observed_consumers_and_falsifiers() -> None:
    client = text("skills/xss-payload-engineering/references/client-interpreters.md")
    derived = text("skills/xss-payload-engineering/references/derived-consumers.md")
    defense = text("skills/xss-payload-engineering/references/defense-edges.md")
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
    assert "`data:` registration is not a valid shortcut" in client
    assert "A CSS selector seeing `script[nonce]` is **not** assumed" in defense
    assert "header-delivered CSP" in defense
    assert "already resolved" in client and "not yet resolved" in client
    assert "CSWSH is not XSS" in derived


def test_human_tree_accounts_for_pinned_technique_headings_without_claiming_bypasses() -> None:
    doc = text("docs/xss-idea-tree.md")
    section = doc.split("## Pinned upstream heading audit", 1)[1].split("**What remains deliberately unimported:**", 1)[0]
    entries = [line for line in section.splitlines() if line.startswith("| ")][2:]
    assert len(entries) == 29
    assert len({row.split("|", 2)[1].strip() for row in entries}) == 29
    assert "**Out of XSS:**" in section
    assert "not the set of independently demonstrated bypasses" in doc
    assert "Mismatched Contexts (2025/2026 Trend)" in doc
    assert "Current" not in doc.split("- **Implementation commits:**", 1)[1].splitlines()[0]


def test_leaves_preserve_existing_research_and_evidence_ownership() -> None:
    tree = text("skills/xss-payload-engineering/references/idea-tree.md")
    assert "xss-technology-research" in tree
    assert "`attempt-recording-policy` owns the exact" in tree
    assert "ResearchMap" in tree and "MapStore" in tree and "Attempts" in tree
    assert "not a validated bypass" in tree
    assert "use `skill_view(name='xss-payload-engineering'" in tree
