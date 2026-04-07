"""Test suite for DORMANT sub-tier split logic and key harness modules.

Actual decision logic in _normalize_claude_review (agents/zero_day_team.py ~L1027):
    if has_vague:
        tier = "DORMANT_HYPOTHETICAL"          # vague ALWAYS wins
    elif has_explicit_chain_req:
        tier = "DORMANT_ACTIVE"
    elif has_concrete:
        tier = "DORMANT_ACTIVE"
    else:
        tier = "DORMANT_HYPOTHETICAL"

Run: python3 agents/test_dormant_split.py
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from agents.zero_day_team import (  # noqa: E402
    _normalize_claude_review,
    _normalize_finding,
    is_placeholder_finding,
)
from agents.findings_ledger import FindingsLedger, LEDGER_FILENAME  # noqa: E402
from agents.chain_matrix import build_chain_graph, get_chainable_findings  # noqa: E402


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _finding(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "agent": "dom-xss", "category": "class", "class_name": "dom-xss",
        "type": "DOM-XSS", "file": "src/renderer.js", "line": 42,
        "description": "Unescaped user input assigned to innerHTML",
        "severity": "HIGH", "context": "", "source": "location.hash",
        "trust_boundary": "renderer", "flow_path": "location.hash -> innerHTML",
        "sink": "element.innerHTML = userInput", "exploitability": "", "fid": "",
    }
    base.update(kw)
    return base


def _dormant_review(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "tier": "DORMANT", "blocked_reason": "", "chain_requirements": None,
        "impact": "Potential renderer compromise", "severity_label": "HIGH",
        "vulnerability_name": "DOM XSS via innerHTML", "cvss_vector": "",
        "cvss_score": "", "remediation": "Sanitize user input.", "review_notes": "Blocked.",
        "poc": None,
    }
    base.update(kw)
    return base


# A blocked_reason that:
#   - is non-empty  (prevents fallback "Exploitability not confirmed — see review_notes."
#                    which contains the vague marker "not confirmed")
#   - has NO vague markers
#   - has NO concrete_prereq_markers
_NEUTRAL_BR = "Blocked by prerequisite chain."


def _split(blocked_reason: str = "", chain_requirements: str | None = None) -> str:
    """Call _normalize_claude_review with DORMANT tier; return resolved tier."""
    result = _normalize_claude_review(
        _finding(), None, "",
        _dormant_review(blocked_reason=blocked_reason, chain_requirements=chain_requirements),
    )
    return result["tier"]


def _make_ledger(tmp: Path) -> FindingsLedger:
    with patch.object(FindingsLedger, "_ensure_storage"):
        ledger = FindingsLedger("test_prog", base_dir=str(tmp))
    ledger.ledger_dir = tmp / "ledger"
    ledger.ledger_dir.mkdir(parents=True, exist_ok=True)
    ledger.path = ledger.ledger_dir / LEDGER_FILENAME
    ledger.lock_path = Path(f"{ledger.path}.lock")
    ledger.backup_path = Path(f"{ledger.path}.bak")
    ledger._entries_by_fid = {}
    ledger._fingerprint_to_fid = {}
    return ledger


def _gf(fid: str, class_name: str, tier: str = "CONFIRMED", **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "fid": fid, "review_tier": tier, "class_name": class_name,
        "type": class_name, "file": f"{class_name}.js",
        "description": f"{class_name} finding",
        "sink": f"sink_{class_name}", "source": f"src_{class_name}",
        "trust_boundary": "", "flow_path": "", "context": "", "exploitability": "",
        "impact": "", "blocked_reason": "", "chain_requirements": "", "review_notes": "",
    }
    base.update(kw)
    return base


# ===========================================================================
# 1. concrete_prereq_markers -> DORMANT_ACTIVE (only when no vague markers present)
# ===========================================================================

class TestConcretePrereqMarkers(unittest.TestCase):
    """Each concrete_prereq_marker produces DORMANT_ACTIVE — provided no vague markers are
    also present.  Note: 'attacker control' is tested with a phrase that does NOT contain
    any vague marker (e.g. 'assumed' would trigger has_vague and flip the result)."""

    def _assert_active(self, br: str) -> None:
        self.assertEqual(_split(blocked_reason=br), "DORMANT_ACTIVE", br)

    def test_needs_prior(self):
        self._assert_active("needs prior XSS to load malicious payload")

    def test_requires_prior(self):
        self._assert_active("requires prior authentication bypass to reach this path")

    def test_prior_xss(self):
        self._assert_active("exploit relies on prior xss in the login form")

    def test_javascript_execution_first(self):
        self._assert_active("javascript execution first is required to control the callback")

    def test_separate_exploit(self):
        self._assert_active("needs a separate exploit to reach the deserialization endpoint")

    def test_xss_first(self):
        self._assert_active("xss first to plant the payload in the DOM")

    def test_arbitrary_js(self):
        self._assert_active("attacker needs arbitrary js execution via a renderer compromise")

    def test_file_write_first(self):
        self._assert_active("file write first is required to place the malicious config")

    def test_renderer_compromise(self):
        self._assert_active("renderer compromise required to pivot into Node.js context")

    def test_code_execution_first(self):
        self._assert_active("code execution first needed to leverage this gadget")

    def test_depends_on(self):
        self._assert_active("depends on a DOM-XSS to execute the prototype pollution gadget")

    def test_authenticated_access(self):
        self._assert_active("authenticated access to the admin panel is required")

    def test_admin_role(self):
        self._assert_active("admin role needed to trigger this endpoint")

    def test_user_interaction(self):
        self._assert_active("user interaction required to click the malicious link")

    def test_network_position(self):
        self._assert_active("attacker must be in a privileged network position")

    def test_local_foothold(self):
        self._assert_active("local foothold is required before this can be triggered")

    def test_feature_enablement(self):
        self._assert_active("feature enablement — nodeIntegration must be on")

    def test_attacker_control(self):
        # NOTE: "attacker control ... is assumed" would fail because "assumed" is a vague marker.
        # The test string below avoids vague markers entirely.
        self._assert_active("attacker control of the target configuration is a prerequisite")

    def test_marker_in_chain_requirements_when_blocked_reason_is_neutral(self):
        """Concrete marker in chain_requirements works when blocked_reason has no vague markers."""
        self.assertEqual(
            _split(blocked_reason=_NEUTRAL_BR,
                   chain_requirements="needs prior XSS in the upload flow"),
            "DORMANT_ACTIVE",
        )

    def test_marker_case_insensitive(self):
        self.assertEqual(_split(blocked_reason="NEEDS PRIOR authentication token"), "DORMANT_ACTIVE")

    def test_vague_dominates_concrete_coexistence(self):
        """When BOTH concrete AND vague markers are present, has_vague wins -> DORMANT_HYPOTHETICAL.
        This is the actual behaviour as of the current codebase (has_vague checked first)."""
        self.assertEqual(
            _split(blocked_reason="unclear context, but needs prior XSS in the payment flow"),
            "DORMANT_HYPOTHETICAL",
        )

    def test_vague_in_blocked_reason_dominates_concrete_in_chain_req(self):
        """Vague in blocked_reason overrides concrete in chain_requirements."""
        self.assertEqual(
            _split(blocked_reason="unclear exploitability",
                   chain_requirements="depends on prior DOM-XSS execution"),
            "DORMANT_HYPOTHETICAL",
        )


# ===========================================================================
# 2. vague_markers -> DORMANT_HYPOTHETICAL
# ===========================================================================

class TestVagueMarkers(unittest.TestCase):
    """Each vague_marker produces DORMANT_HYPOTHETICAL (has_vague always wins)."""

    def _assert_hyp(self, br: str) -> None:
        self.assertEqual(_split(blocked_reason=br), "DORMANT_HYPOTHETICAL", br)

    def test_inconclusive(self):
        self._assert_hyp("review was inconclusive due to missing context")

    def test_needs_more_research(self):
        self._assert_hyp("needs more research before confirming exploitability")

    def test_placeholder(self):
        self._assert_hyp("placeholder — not yet analyzed")

    def test_not_confirmed(self):
        self._assert_hyp("not confirmed — analysis incomplete")

    def test_unclear(self):
        self._assert_hyp("unclear whether this sink is reachable from user input")

    def test_insufficient(self):
        self._assert_hyp("insufficient context to determine exploitability")

    def test_could_not_verify(self):
        self._assert_hyp("could not verify the data flow from source to sink")

    def test_requires_further(self):
        self._assert_hyp("requires further investigation of the IPC channel")

    def test_short_vulnerability_label(self):
        self._assert_hyp("short vulnerability label — no exploit path defined")

    def test_review_inconclusive(self):
        self._assert_hyp("review inconclusive for this finding")

    def test_possible(self):
        self._assert_hyp("possible exploit path but not substantiated")

    def test_potential(self):
        self._assert_hyp("potential XSS in the rendering pipeline")

    def test_may(self):
        self._assert_hyp("this may be exploitable under specific circumstances")

    def test_might(self):
        self._assert_hyp("might be reachable if the feature flag is enabled")

    def test_appears(self):
        self._assert_hyp("appears to reach a dangerous sink but not confirmed")

    def test_seems(self):
        self._assert_hyp("seems exploitable but analysis is incomplete")

    def test_theoretical(self):
        self._assert_hyp("theoretical exploit chain only — no working PoC")

    def test_assumed(self):
        self._assert_hyp("assumed reachable but trace was not completed")

    def test_likely(self):
        self._assert_hyp("likely exploitable under authenticated sessions")

    def test_empty_blocked_reason_triggers_fallback_vague_marker(self):
        """Empty blocked_reason triggers fallback 'Exploitability not confirmed...' which
        contains the vague marker 'not confirmed' -> always DORMANT_HYPOTHETICAL."""
        self.assertEqual(_split(blocked_reason="", chain_requirements=None), "DORMANT_HYPOTHETICAL")

    def test_empty_chain_req_string(self):
        self.assertEqual(_split(blocked_reason="unclear", chain_requirements=""), "DORMANT_HYPOTHETICAL")

    def test_vague_in_empty_br_fallback_overrides_concrete_chain_req(self):
        """Empty blocked_reason -> fallback has 'not confirmed' (vague) which overrides
        any concrete marker in chain_requirements."""
        self.assertEqual(
            _split(blocked_reason="", chain_requirements="needs prior XSS in the upload flow"),
            "DORMANT_HYPOTHETICAL",
        )


# ===========================================================================
# 3. Requirement-verb heuristic (has_explicit_chain_req path)
# ===========================================================================

class TestRequirementVerbHeuristic(unittest.TestCase):
    """Req-verb in chain_requirements + no hedge + no block word + no vague in blob -> DORMANT_ACTIVE.
    Uses _NEUTRAL_BR to keep has_vague=False."""

    def test_needs_verb(self):
        self.assertEqual(_split(_NEUTRAL_BR, "needs XSS execution in the upload pipeline"),
                         "DORMANT_ACTIVE")

    def test_requires_verb(self):
        self.assertEqual(_split(_NEUTRAL_BR, "requires node integration to be enabled"),
                         "DORMANT_ACTIVE")

    def test_must_verb(self):
        self.assertEqual(_split(_NEUTRAL_BR, "attacker must control the configuration file"),
                         "DORMANT_ACTIVE")

    def test_prerequisite_word(self):
        self.assertEqual(_split(_NEUTRAL_BR, "prerequisite: DOM XSS in the main window"),
                         "DORMANT_ACTIVE")

    def test_depend_verb(self):
        self.assertEqual(_split(_NEUTRAL_BR, "this exploit depends on a file write primitive"),
                         "DORMANT_ACTIVE")

    def test_necessary_word(self):
        self.assertEqual(_split(_NEUTRAL_BR, "an IPC bridge invocation is necessary"),
                         "DORMANT_ACTIVE")

    def test_after_verb(self):
        self.assertEqual(
            _split(_NEUTRAL_BR, "after obtaining renderer JS execution, this becomes reachable"),
            "DORMANT_ACTIVE",
        )

    def test_once_verb(self):
        self.assertEqual(
            _split(_NEUTRAL_BR, "once the prototype is poisoned, exec sink is reachable"),
            "DORMANT_ACTIVE",
        )

    # -- hedge words negate has_explicit_chain_req --

    def test_perhaps_hedge_gives_hypothetical(self):
        # No vague in _NEUTRAL_BR, no concrete in chain_req, "perhaps" negates req_verb
        # -> has_explicit_chain_req=False, has_concrete=False -> else -> DORMANT_HYPOTHETICAL
        self.assertEqual(_split(_NEUTRAL_BR, "perhaps requires elevated access"),
                         "DORMANT_HYPOTHETICAL")

    def test_could_hedge_gives_hypothetical(self):
        self.assertEqual(_split(_NEUTRAL_BR, "could require elevated access"),
                         "DORMANT_HYPOTHETICAL")

    # -- block words negate has_explicit_chain_req --

    def test_block_word_none(self):
        self.assertEqual(_split(_NEUTRAL_BR, "none"), "DORMANT_HYPOTHETICAL")

    def test_block_word_none_provided(self):
        self.assertEqual(_split(_NEUTRAL_BR, "none provided"), "DORMANT_HYPOTHETICAL")

    def test_block_word_ellipsis(self):
        self.assertEqual(_split(_NEUTRAL_BR, "..."), "DORMANT_HYPOTHETICAL")

    def test_block_word_see_blocked_reason(self):
        self.assertEqual(_split(_NEUTRAL_BR, "see blocked reason"), "DORMANT_HYPOTHETICAL")

    def test_block_word_see_review_notes(self):
        self.assertEqual(_split(_NEUTRAL_BR, "see review notes"), "DORMANT_HYPOTHETICAL")


# ===========================================================================
# 4. chain_requirements seeding from blocked_reason
# ===========================================================================

class TestChainRequirementsSeeding(unittest.TestCase):

    def test_concrete_in_blocked_reason_seeds_active(self):
        self.assertEqual(
            _split(blocked_reason="needs prior XSS to execute payload", chain_requirements=None),
            "DORMANT_ACTIVE",
        )

    def test_vague_in_blocked_reason_seeds_hypothetical(self):
        self.assertEqual(
            _split(blocked_reason="inconclusive — more research needed", chain_requirements=None),
            "DORMANT_HYPOTHETICAL",
        )

    def test_vague_in_blob_overrides_concrete_in_chain_req(self):
        """Vague blocked_reason + concrete chain_requirements: has_vague wins -> DORMANT_HYPOTHETICAL."""
        self.assertEqual(
            _split(blocked_reason="unclear", chain_requirements="depends on prior DOM-XSS"),
            "DORMANT_HYPOTHETICAL",
        )

    def test_neutral_blocked_reason_with_concrete_chain_req_gives_active(self):
        """No vague in blob + concrete marker in chain_req -> DORMANT_ACTIVE."""
        self.assertEqual(
            _split(blocked_reason=_NEUTRAL_BR, chain_requirements="depends on prior DOM-XSS"),
            "DORMANT_ACTIVE",
        )


# ===========================================================================
# 5. _normalize_claude_review field contract and tier validation
# ===========================================================================

class TestNormalizeClaudeReviewContract(unittest.TestCase):

    def test_invalid_tier_raises(self):
        with self.assertRaises(ValueError):
            _normalize_claude_review(_finding(), None, "", {"tier": "BOGUS"})

    def test_empty_tier_raises(self):
        with self.assertRaises(ValueError):
            _normalize_claude_review(_finding(), None, "", {"tier": ""})

    def test_confirmed_without_poc_raises(self):
        with self.assertRaises(ValueError):
            _normalize_claude_review(_finding(), None, "", {"tier": "CONFIRMED", "poc": None})

    def test_confirmed_with_placeholder_poc_raises(self):
        with self.assertRaises(ValueError):
            _normalize_claude_review(_finding(), None, "",
                                     {"tier": "CONFIRMED", "poc": "placeholder poc string"})

    def test_confirmed_with_real_poc_passes(self):
        poc = "document.getElementById('x').innerHTML = '<img src=x onerror=alert(1)>';"
        result = _normalize_claude_review(
            _finding(), None, "",
            {"tier": "CONFIRMED", "poc": poc, "impact": "XSS", "severity_label": "HIGH",
             "vulnerability_name": "DOM XSS", "remediation": "Sanitize.", "review_notes": "OK"},
        )
        self.assertEqual(result["tier"], "CONFIRMED")
        self.assertEqual(result["poc"], poc)

    def test_dormant_tiers_have_no_poc(self):
        result = _normalize_claude_review(
            _finding(), None, "", _dormant_review(blocked_reason="needs prior XSS")
        )
        self.assertIsNone(result["poc"])

    def test_result_has_required_keys(self):
        result = _normalize_claude_review(
            _finding(), None, "", _dormant_review(blocked_reason="depends on prior XSS")
        )
        for key in ("tier", "review_tier", "poc", "impact", "severity_label",
                    "blocked_reason", "chain_requirements", "remediation",
                    "review_notes", "review_reason", "severity"):
            self.assertIn(key, result, f"Missing: {key!r}")

    def test_tier_and_review_tier_match(self):
        result = _normalize_claude_review(
            _finding(), None, "", _dormant_review(blocked_reason="depends on prior XSS")
        )
        self.assertEqual(result["tier"], result["review_tier"])

    def test_review_tier_input_alias(self):
        result = _normalize_claude_review(
            _finding(), None, "", {"review_tier": "DORMANT", "blocked_reason": "needs prior XSS"}
        )
        self.assertEqual(result["tier"], "DORMANT_ACTIVE")

    def test_dormant_active_passthrough(self):
        result = _normalize_claude_review(
            _finding(), None, "", {"tier": "DORMANT_ACTIVE", "blocked_reason": "n/a"}
        )
        self.assertEqual(result["tier"], "DORMANT_ACTIVE")

    def test_dormant_hypothetical_passthrough(self):
        result = _normalize_claude_review(_finding(), None, "", {"tier": "DORMANT_HYPOTHETICAL"})
        self.assertEqual(result["tier"], "DORMANT_HYPOTHETICAL")

    def test_severity_fallback_from_finding(self):
        result = _normalize_claude_review(
            _finding(severity="CRITICAL"), None, "",
            _dormant_review(blocked_reason="inconclusive", severity_label=None),
        )
        self.assertEqual(result["severity_label"], "CRITICAL")

    def test_source_path_stored(self):
        src = Path("/tmp/fake.js")
        result = _normalize_claude_review(
            _finding(), src, "", _dormant_review(blocked_reason="depends on prior XSS")
        )
        self.assertEqual(result["resolved_file"], str(src))

    def test_none_source_path_gives_empty_resolved_file(self):
        result = _normalize_claude_review(
            _finding(), None, "", _dormant_review(blocked_reason="depends on prior XSS")
        )
        self.assertEqual(result["resolved_file"], "")

    def test_original_finding_fields_preserved(self):
        result = _normalize_claude_review(
            _finding(fid="D07", type="DOM-XSS-CUSTOM"), None, "",
            _dormant_review(blocked_reason="needs prior XSS"),
        )
        self.assertEqual(result["fid"], "D07")
        self.assertEqual(result["type"], "DOM-XSS-CUSTOM")


# ===========================================================================
# 6. is_placeholder_finding
# ===========================================================================

class TestIsPlaceholderFinding(unittest.TestCase):

    def test_short_vulnerability_label_title(self):
        self.assertTrue(is_placeholder_finding(
            {"title": "short vulnerability label", "file_ref": "/src/app.js:42", "description": "real"}
        ))

    def test_short_novel_pattern_label_title(self):
        self.assertTrue(is_placeholder_finding(
            {"title": "short novel pattern label", "file_ref": "/src/app.js:1", "description": "real"}
        ))

    def test_placeholder_title(self):
        self.assertTrue(is_placeholder_finding(
            {"title": "placeholder", "file_ref": "/src/app.js:1", "description": "desc"}
        ))

    def test_empty_file_ref_is_placeholder(self):
        self.assertTrue(is_placeholder_finding(
            {"title": "Real Vuln", "file_ref": "", "description": "real finding"}
        ))

    def test_path_123_file_ref(self):
        self.assertTrue(is_placeholder_finding(
            {"title": "Real Vuln", "file_ref": "path:123", "description": "real finding"}
        ))

    def test_none_provided_description(self):
        self.assertTrue(is_placeholder_finding(
            {"title": "Real Vuln", "file_ref": "/src/x.js:5", "description": "none provided."}
        ))

    def test_real_finding_passes(self):
        self.assertFalse(is_placeholder_finding(
            {"title": "DOM XSS via innerHTML", "file_ref": "/src/renderer.js:42",
             "description": "Unescaped user input flows to innerHTML sink"}
        ))

    def test_rce_finding_passes(self):
        self.assertFalse(is_placeholder_finding(
            {"title": "BrokerBridge RCE", "file_ref": "/main.js:142",
             "description": "unvalidated broker topic reaches exec() sink"}
        ))


# ===========================================================================
# 7. _normalize_finding — structure validation
# ===========================================================================

class TestNormalizeFinding(unittest.TestCase):

    def _call(self, raw: Any, agent: str = "dom-xss") -> Any:
        return _normalize_finding(raw, agent)

    def test_non_dict_returns_none(self):
        for bad in ("string", 42, None, []):
            self.assertIsNone(self._call(bad))

    def test_missing_type_returns_none(self):
        self.assertIsNone(self._call({"file": "foo.js", "description": "test"}))

    def test_missing_file_returns_none(self):
        self.assertIsNone(self._call({"type": "XSS", "description": "test"}))

    def test_missing_description_returns_none(self):
        self.assertIsNone(self._call({"type": "XSS", "file": "foo.js"}))

    def test_novel_without_source_returns_none(self):
        self.assertIsNone(self._call(
            _finding(category="novel", class_name="novel", source="", sink="innerHTML")
        ))

    def test_novel_without_sink_returns_none(self):
        self.assertIsNone(self._call(
            _finding(category="novel", class_name="novel", source="location.hash", sink="")
        ))

    def test_novel_with_source_and_sink_passes(self):
        result = self._call(
            _finding(category="novel", class_name="novel",
                     source="location.search", sink="element.outerHTML")
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["category"], "novel")

    def test_valid_class_finding(self):
        result = self._call(_finding())
        self.assertIsNotNone(result)
        self.assertEqual(result["type"], "DOM-XSS")
        self.assertEqual(result["severity"], "HIGH")

    def test_severity_uppercased(self):
        self.assertEqual(self._call(_finding(severity="high"))["severity"], "HIGH")

    def test_unknown_category_falls_back_to_class(self):
        result = self._call(_finding(category="unexpected", class_name="dom-xss"))
        self.assertIsNotNone(result)
        self.assertEqual(result["category"], "class")

    def test_unknown_class_name_falls_back_to_default_agent(self):
        result = self._call(_finding(class_name="not-a-known-class"), "dom-xss")
        self.assertEqual(result["class_name"], "dom-xss")

    def test_line_coerced_to_int(self):
        self.assertEqual(self._call(_finding(line="99"))["line"], 99)

    def test_non_numeric_line_becomes_zero(self):
        self.assertEqual(self._call(_finding(line="bad-line"))["line"], 0)

    def test_class_name_novel_triggers_novel_category(self):
        result = self._call(_finding(category="", class_name="novel", source="x", sink="y"))
        self.assertIsNotNone(result)
        self.assertEqual(result["category"], "novel")


# ===========================================================================
# 8. FindingsLedger — normalize_sink
# ===========================================================================

class TestNormalizeSink(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ledger = _make_ledger(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def _ns(self, s: str) -> str:
        return self.ledger.normalize_sink(s)

    def test_empty_string(self):
        self.assertEqual(self._ns(""), "")

    def test_whitespace_only(self):
        self.assertEqual(self._ns("   \t\n"), "")

    def test_call_normalizes_string_args(self):
        # String args in calls: string replacement runs first (-> <str>), then the call
        # normalizer replaces all arg slots with <arg> based on count.
        r1 = self._ns('res.send("hello")')
        r2 = self._ns('res.send("goodbye world")')
        self.assertEqual(r1, r2)
        self.assertNotIn('"hello"', r1)
        self.assertIn("<arg>", r1)

    def test_call_normalizes_number_args(self):
        r1 = self._ns("buf.slice(0, 10)")
        r2 = self._ns("buf.slice(5, 20)")
        self.assertEqual(r1, r2)
        self.assertIn("<arg>", r1)

    def test_assignment_gives_lhs_eq_expr(self):
        self.assertIn("= <expr>", self._ns("element.innerHTML = userInput"))

    def test_assignment_retains_stable_root(self):
        result = self._ns("document.body.innerHTML = data")
        self.assertIn("= <expr>", result)
        self.assertIn("document", result)

    def test_call_with_stable_root_retains_it(self):
        self.assertIn("child_process", self._ns("child_process.exec(cmd)"))

    def test_whitespace_collapsed(self):
        self.assertEqual(self._ns("eval ( x )"), self._ns("eval(x)"))

    def test_output_is_lowercase(self):
        result = self._ns("Element.innerHTML = Data")
        self.assertEqual(result, result.lower())


# ===========================================================================
# 9. FindingsLedger — fingerprint_for
# ===========================================================================

class TestFingerprintFor(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ledger = _make_ledger(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def test_returns_64_char_hex(self):
        self.assertRegex(
            self.ledger.fingerprint_for({"vuln_class": "dom-xss", "file": "f.js", "sink": "x"}),
            r"^[0-9a-f]{64}$",
        )

    def test_deterministic(self):
        f = {"vuln_class": "dom-xss", "file": "f.js", "sink": "x"}
        self.assertEqual(self.ledger.fingerprint_for(f), self.ledger.fingerprint_for(f))

    def test_different_class_different_fp(self):
        f1 = {"vuln_class": "dom-xss", "file": "f.js", "sink": "x"}
        f2 = {**f1, "vuln_class": "ssrf"}
        self.assertNotEqual(self.ledger.fingerprint_for(f1), self.ledger.fingerprint_for(f2))

    def test_different_file_different_fp(self):
        f1 = {"vuln_class": "dom-xss", "file": "a.js", "sink": "x"}
        f2 = {**f1, "file": "b.js"}
        self.assertNotEqual(self.ledger.fingerprint_for(f1), self.ledger.fingerprint_for(f2))

    def test_string_literal_difference_same_fp(self):
        f1 = {"vuln_class": "dom-xss", "file": "f.js", "sink": 'res.send("hello")'}
        f2 = {"vuln_class": "dom-xss", "file": "f.js", "sink": 'res.send("world")'}
        self.assertEqual(self.ledger.fingerprint_for(f1), self.ledger.fingerprint_for(f2))

    def test_class_name_falls_back_to_vuln_class(self):
        f1 = {"class_name": "dom-xss", "file": "f.js", "sink": "x"}
        f2 = {"vuln_class": "dom-xss", "file": "f.js", "sink": "x"}
        self.assertEqual(self.ledger.fingerprint_for(f1), self.ledger.fingerprint_for(f2))


# ===========================================================================
# 10. FindingsLedger — check / dedupe / FID assignment
# ===========================================================================

class TestLedgerCheck(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ledger = _make_ledger(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def _f(self, **kw: Any) -> dict[str, Any]:
        base = {"vuln_class": "dom-xss", "file": "src/r.js", "line": 10,
                "sink": "element.innerHTML = x", "type": "XSS",
                "description": "test", "severity": "HIGH"}
        base.update(kw)
        return base

    def test_first_check_not_duplicate(self):
        is_dup, fid, _ = self.ledger.check(self._f())
        self.assertFalse(is_dup)
        self.assertTrue(fid.startswith("D"))

    def test_second_check_is_duplicate(self):
        self.ledger.check(self._f())
        is_dup, _, _ = self.ledger.check(self._f())
        self.assertTrue(is_dup)

    def test_duplicate_returns_same_fid(self):
        _, fid1, _ = self.ledger.check(self._f())
        _, fid2, _ = self.ledger.check(self._f())
        self.assertEqual(fid1, fid2)

    def test_different_sink_creates_new_entry(self):
        _, fid1, _ = self.ledger.check(self._f(sink="a.innerHTML = x"))
        is_dup, fid2, _ = self.ledger.check(self._f(sink="b.outerHTML = y"))
        self.assertFalse(is_dup)
        self.assertNotEqual(fid1, fid2)

    def test_novel_gets_n_prefix(self):
        _, fid, _ = self.ledger.check(self._f(category="novel", class_name="novel",
                                               source="x", sink="y"))
        self.assertTrue(fid.startswith("N"))

    def test_fid_counter_increments(self):
        _, fid1, _ = self.ledger.check(self._f(sink="sink.a = x"))
        _, fid2, _ = self.ledger.check(self._f(sink="sink.b = y"))
        self.assertGreater(int(fid2[1:]), int(fid1[1:]))

    def test_merged_has_fid(self):
        _, fid, merged = self.ledger.check(self._f())
        self.assertEqual(merged["fid"], fid)

    def test_string_literal_normalization_dedupes(self):
        f1 = self._f(sink='res.send("hello world")')
        f2 = self._f(sink='res.send("goodbye world")')
        _, fid1, _ = self.ledger.check(f1)
        is_dup, fid2, _ = self.ledger.check(f2)
        self.assertTrue(is_dup)
        self.assertEqual(fid1, fid2)

    def test_different_vuln_class_not_deduped(self):
        _, fid1, _ = self.ledger.check(self._f(vuln_class="dom-xss"))
        is_dup, _, _ = self.ledger.check(self._f(vuln_class="ssrf"))
        self.assertFalse(is_dup)


# ===========================================================================
# 11. FindingsLedger — get_by_status / summary / export
# ===========================================================================

class TestLedgerStatusAndSummary(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ledger = _make_ledger(Path(self._tmp.name))
        self._add("src/a.js", "sink_a = x", "confirmed")
        self._add("src/b.js", "sink_b = y", "pending-review")
        self._add("src/c.js", "sink_c = z", "pending-review")

    def _add(self, file: str, sink: str, status: str) -> str:
        _, fid, _ = self.ledger.check({
            "vuln_class": "dom-xss", "file": file, "sink": sink,
            "type": "XSS", "description": "xss", "severity": "HIGH", "status": status,
        })
        return fid

    def tearDown(self):
        self._tmp.cleanup()

    def test_get_confirmed_count(self):
        self.assertEqual(len(self.ledger.get_by_status("confirmed")), 1)

    def test_get_pending_count(self):
        self.assertEqual(len(self.ledger.get_by_status("pending-review")), 2)

    def test_get_nonexistent_is_empty(self):
        self.assertEqual(self.ledger.get_by_status("does-not-exist"), [])

    def test_summary_has_program_name(self):
        self.assertIn("test_prog", self.ledger.summary())

    def test_summary_has_total_count(self):
        self.assertIn("3", self.ledger.summary())

    def test_summary_shows_status_distribution(self):
        s = self.ledger.summary()
        self.assertIn("confirmed=1", s)
        self.assertIn("pending-review=2", s)

    def test_export_markdown_creates_file(self):
        out = Path(self._tmp.name) / "report.md"
        content = self.ledger.export_markdown(out).read_text()
        self.assertIn("# Findings Ledger", content)
        self.assertIn("test_prog", content)


# ===========================================================================
# 12. FindingsLedger — update
# ===========================================================================

class TestLedgerUpdate(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ledger = _make_ledger(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()

    def _add(self, **kw: Any) -> str:
        base = {"vuln_class": "dom-xss", "file": "src/x.js", "sink": "x.innerHTML = y",
                "type": "XSS", "description": "test", "severity": "HIGH"}
        base.update(kw)
        _, fid, _ = self.ledger.check(base)
        return fid

    def test_update_without_fid_raises(self):
        with self.assertRaises(ValueError):
            self.ledger.update({"vuln_class": "dom-xss"})

    def test_update_unknown_fid_raises(self):
        with self.assertRaises(KeyError):
            self.ledger.update({"fid": "D99", "vuln_class": "dom-xss"})

    def test_update_status(self):
        fid = self._add()
        self.assertEqual(self.ledger.update({"fid": fid, "status": "confirmed"})["status"],
                         "confirmed")

    def test_update_persists_to_get_by_status(self):
        fid = self._add(file="src/y.js", sink="y.src = z")
        self.ledger.update({"fid": fid, "status": "confirmed"})
        self.assertIn(fid, [r["fid"] for r in self.ledger.get_by_status("confirmed")])


# ===========================================================================
# 13. chain_matrix — build_chain_graph
# ===========================================================================

class TestBuildChainGraph(unittest.TestCase):

    def test_empty_gives_empty_graph(self):
        g = build_chain_graph([])
        self.assertEqual(g["nodes"], [])
        self.assertEqual(g["edges"], [])
        self.assertEqual(g["chainable_node_ids"], [])

    def test_single_confirmed_included(self):
        self.assertEqual(len(build_chain_graph([_gf("D01", "dom-xss")])["nodes"]), 1)

    def test_dormant_active_excluded(self):
        self.assertEqual(
            len(build_chain_graph([_gf("D01", "dom-xss", tier="DORMANT_ACTIVE")])["nodes"]), 0
        )

    def test_dormant_tier_included(self):
        self.assertEqual(
            len(build_chain_graph([_gf("D01", "dom-xss", tier="DORMANT")])["nodes"]), 1
        )

    def test_chain_edge_dom_xss_to_exec(self):
        g = build_chain_graph([_gf("D01", "dom-xss"), _gf("D02", "exec-sink-reachability")])
        self.assertGreater(len(g["edges"]), 0)
        edge = g["edges"][0]
        self.assertEqual(edge["from"], "D01")
        self.assertEqual(edge["to"], "D02")
        self.assertIn("renderer_js_execution", edge["via"])

    def test_exec_chainable_with_incoming_edge(self):
        g = build_chain_graph([_gf("D01", "dom-xss"), _gf("D02", "exec-sink-reachability")])
        self.assertIn("D02", g["chainable_node_ids"])

    def test_stepping_stone_alone_not_chainable(self):
        g = build_chain_graph([_gf("D01", "dom-xss")])
        self.assertEqual(g["chainable_node_ids"], [])

    def test_single_endpoint_alone_is_chainable(self):
        """_chainable_node_ids special-cases single-node graphs: endpoint -> chainable."""
        g = build_chain_graph([_gf("D01", "exec-sink-reachability")])
        self.assertIn("D01", g["chainable_node_ids"])

    def test_node_grants_correct(self):
        g = build_chain_graph([_gf("D01", "dom-xss")])
        self.assertIn("renderer_js_execution", g["nodes"][0]["grants"])

    def test_node_requires_correct(self):
        g = build_chain_graph([_gf("D01", "exec-sink-reachability")])
        self.assertIn("renderer_js_execution", g["nodes"][0]["requires"])

    def test_no_self_edges(self):
        g = build_chain_graph([_gf("D01", "dom-xss")])
        for edge in g["edges"]:
            self.assertNotEqual(edge["from"], edge["to"])

    def test_fid_as_node_id(self):
        g = build_chain_graph([_gf("N01", "ssrf")])
        self.assertEqual(g["nodes"][0]["id"], "N01")


# ===========================================================================
# 14. chain_matrix — get_chainable_findings
# ===========================================================================

class TestGetChainableFindings(unittest.TestCase):

    def test_exec_returned_when_chained_from_xss(self):
        findings = [_gf("D01", "dom-xss"), _gf("D02", "exec-sink-reachability")]
        self.assertIn("D02", [f["fid"] for f in get_chainable_findings(findings)])

    def test_stepping_stone_alone_not_returned(self):
        self.assertEqual(get_chainable_findings([_gf("D01", "dom-xss")]), [])

    def test_unknown_class_always_returned(self):
        self.assertIn("D01", [f["fid"] for f in get_chainable_findings([_gf("D01", "custom-zero-day")])])

    def test_triple_chain_exec_is_chainable(self):
        findings = [_gf("D01", "dom-xss"), _gf("D02", "node-integration"),
                    _gf("D03", "exec-sink-reachability")]
        self.assertIn("D03", [f["fid"] for f in get_chainable_findings(findings)])


# ===========================================================================
# 15. chain_matrix — grant inference from text fields
# ===========================================================================

class TestGrantInference(unittest.TestCase):

    def _grants(self, text: str, field: str = "description") -> list[str]:
        g = build_chain_graph([_gf("D01", "unknown-class", **{field: text})])
        return g["nodes"][0]["grants"]

    def test_rce_text(self):
        self.assertIn("os_command_execution", self._grants("RCE via exec() call"))

    def test_file_write_text(self):
        self.assertIn("privileged_file_write", self._grants("write file to disk via fs"))

    def test_file_read_text(self):
        self.assertIn("privileged_file_read", self._grants("read arbitrary file from disk"))

    def test_proto_pollution_text(self):
        self.assertIn("prototype_control", self._grants("__proto__ manipulation gadget"))

    def test_ssrf_text(self):
        self.assertIn("internal_http_request", self._grants("SSRF to internal metadata endpoint"))

    def test_inference_from_sink_field(self):
        self.assertIn("os_command_execution", self._grants("child_process.exec(cmd)", "sink"))

    def test_inference_from_review_notes(self):
        self.assertIn("os_command_execution",
                      self._grants("remote code execution confirmed via IPC", "review_notes"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
