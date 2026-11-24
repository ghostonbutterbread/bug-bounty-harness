"""XSS entry guidance remains clear, progressive, and evidence-led.

Every claim below is matched against whitespace- and emphasis-normalised text,
so reflowing a paragraph or changing bolding does not break a test while the
claim itself stays pinned. The previous version matched raw substrings, which
pinned line-wrap positions ("No inventory is a\nprerequisite") and markdown
emphasis mid-word ("not** all accepted request") and made the router
unrewrappable.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
XSS = ROOT / "skills/xss/SKILL.md"
SOURCE = ROOT / "skills/xss/references/source-acquisition.md"
BLIND = ROOT / "skills/blind-xss/SKILL.md"
SCRIPT_MAP = ROOT / "skills/xss/scripts/README.md"
LENS = ROOT / "skills/surface-expansion/SKILL.md"


def norm(text: str) -> str:
    """Collapse whitespace and strip markdown emphasis and code fences."""
    return " ".join(re.sub(r"[*`_]", "", text).split())


def read(path: Path) -> str:
    return norm(path.read_text(encoding="utf-8"))


def raw(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def claims(text: str, *fragments: str) -> None:
    missing = [f for f in fragments if norm(f) not in text]
    assert not missing, f"missing claims: {missing}"


def absent(text: str, *fragments: str) -> None:
    present = [f for f in fragments if norm(f) in text]
    assert not present, f"should no longer appear: {present}"


def test_xss_router_has_one_cold_start_and_no_observation_quota() -> None:
    text = read(XSS)
    claims(text,
           "references/opening-and-knowledge.md",
           "current input and render context",
           "Do not delay investigation of an existing source-to-sink path")
    absent(text, "notes/summary.md", "before deep payload work")
    # any numeric observation quota, not just the literal "3-5 fresh"
    assert not re.search(r"\b\d+\s*[-–]\s*\d+\s+fresh\b", text), "observation quota reintroduced"


def test_xss_route_preserves_pressure_without_automatic_pivot_on_one_inert_probe() -> None:
    text = read(XSS)
    claims(text,
           "plausible executable consumer", "context-appropriate discovery pass",
           "pending", "missing artifact",
           "account-testing-policy", "injection-testing-policy",
           "references/source-acquisition.md")
    assert SOURCE.is_file()
    absent(text, "docs/xss-blocker-deepening")


def test_xss_record_and_proof_contract_has_one_owner() -> None:
    text = read(XSS)
    claims(text,
           "attempt-recording-policy", "references/payload-engineering.md",
           "browser or equivalent execution evidence", "bare collector hit",
           "planted executable payload", "tested context")
    # these sections moved to their owners; they must not come back here
    assert "## Evidence Standard" not in raw(XSS)
    absent(text, "Typical XSS pressure ladder")


def test_xss_pairs_named_inputs_and_sinks_without_rigid_census_gate() -> None:
    router, reference, script_map = read(XSS), read(SOURCE), read(SCRIPT_MAP)
    claims(router, "source_sites", "sink_sites", "parameter-mining",
           "Do not delay investigation of an existing source-to-sink path")
    claims(reference, "recon_bus.py query", "params.txt", "name-only",
           "untested", "truncated", "not a taint trace")
    claims(script_map, "xss_source_sites.py")


def test_xss_routes_optional_new_surface_lens_without_a_startup_gate() -> None:
    router, reference, lens = read(XSS), read(SOURCE), read(LENS)
    # the entry section owns lane selection; slice on the heading, not on offsets
    entry_raw = raw(XSS).split("## Entry and lane selection", 1)[1].split("## Next-question overlays", 1)[0]
    entry = norm(entry_raw)
    claims(entry, "load surface-expansion", "not a preflight")
    claims(router, "No inventory is a prerequisite to begin XSS",
           "if JS evidence is the chosen lens",
           "When a JS corpus is the chosen XSS discovery lens",
           "If new JS is needed, load `js` -> `js-pull`".replace("->", "→"))
    absent(router, "XSS breadth discovery checkpoint", "use js for the paired JS inventory")
    claims(reference, "When new JS is needed, feed scoped observed JS URLs",
           "Coverage brief", "missing chunks")
    absent(reference, "API/endpoint breadth checkpoint")
    for route in ("Another consumer", "Another input", "Another endpoint from JavaScript",
                  "Another JavaScript", "Another app area or scoped host"):
        claims(lens, route)
    claims(lens, "jsluice for offline local-file URL",
           "-jc crawl for offline extraction",
           "not a startup sequence")


def test_xss_routes_live_js_loading_and_stack_specific_source_sink_review() -> None:
    router, reference, script_map = read(XSS), read(SOURCE), read(SCRIPT_MAP)
    assert (ROOT / "agents/xss_source_sites.py").is_file()
    assert (ROOT / "agents/xss_sink_sites.py").is_file()
    for route in ("browser-session-policy", "chromium-test", "js-pull"):
        claims(router, route)
        claims(reference, route)
    js = read(ROOT / "skills/js/SKILL.md")
    lens = read(ROOT / "skills/js/references/analysis-lens.md")
    for text in (router, reference):
        claims(text, "skills/js/references/analysis-lens.md", "js → js-pull")
    claims(js, "references/analysis-lens.md", "JS in an existing investigation")
    claims(lens, "caller to callee",
           "forward from the value and backward from its final consumer",
           "parsing, coercion, escaping")
    claims(reference, "framework raw-HTML/template/trust APIs", "API request builders",
           "inventory --page fetches HTML script URLs and bounded",
           "--input <scoped-js-url-list>", "browser-loaded chunk.php",
           "--provenance-input <observed-scripts.jsonl>", "fetched or cached response",
           "not all accepted request", "inventoried script", "browser-loaded script",
           "agents/xss_source_sites.py", "agents/xss_sink_sites.py",
           "unloaded", "server-rendered templates")
    claims(router, "source_sites are named reads",
           "not separate live scanners", "not a taint trace")
    for cue in ("Network", "Sources", "lazy-loaded", "forms", "hidden inputs"):
        claims(router, cue)
    # the script map keeps a per-script ownership block
    claims(script_map, "agents/xss_source_sites.py", "agents/xss_sink_sites.py",
           "scan_source_sites", "scan_sink_sites")
    for section_name in ("agents/xss_source_sites.py", "agents/xss_sink_sites.py"):
        section = norm(raw(SCRIPT_MAP).split(f"## `{section_name}`", 1)[1].split("\n## `", 1)[0])
        claims(section, "Owner/scope:", "Last verified:")


def test_blind_lane_uses_the_same_confirmed_evidence_threshold() -> None:
    router, blind = read(XSS), read(BLIND)
    for text in (router, blind):
        claims(text, "planted executable payload", "bare collector hit", "Confirmed")
    absent(blind, "jumps straight to Confirmed", "last-resort execution",
           "proves script execution")
    claims(blind, "can support Confirmed if",
           "full GET is retained and correlated",
           "A bare collector hit remains Pending-OOB",
           "Do not automatically resubmit to a staff queue")
    # the image variant carries a correlating probe and must not exfiltrate cookies
    image_line = next(line for line in raw(BLIND).splitlines() if "<img src onerror=" in line)
    assert "WEBHOOK_URL?probe=" in image_line
    assert "location.href" in image_line
    assert "document.cookie" not in image_line
