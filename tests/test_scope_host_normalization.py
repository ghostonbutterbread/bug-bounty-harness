#!/usr/bin/env python3
"""Regressions for scope host extraction and wildcard-kind promotion.

Both defects surfaced promoting a real recon-ry run:

* ``_extract_host`` let ``urlparse`` raise on httpx's ``<url> [<ip>]`` output,
  aborting the whole promotion with a misleading argparse error.
* A trailing DNS root label (``fab.com.``) matched neither the allow list nor
  the exclusion list, so in-scope URLs were quarantined.
* ``scope_violations`` demanded a literal ``*.`` prefix for ``wild`` values,
  but ``wild.txt`` holds wildcard bases with ``*.`` stripped.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for candidate in (PROJECT_ROOT, PROJECT_ROOT / "agents"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from agents.scope_validator import _extract_host, strip_tool_annotation


class ToolAnnotationTests(unittest.TestCase):
    """Only the annotated shape is unwrapped; other whitespace stays refusable."""

    def test_annotation_shapes_are_unwrapped(self):
        self.assertEqual(
            strip_tool_annotation("https://host.example.com [1.2.3.4]"),
            "https://host.example.com",
        )
        self.assertEqual(
            strip_tool_annotation("https://host.example.com [1.2.3.4] [200] [nginx]"),
            "https://host.example.com",
        )

    def test_a_second_target_is_never_stripped_away(self):
        """A line with two targets must not be vouched for by its first token."""
        for value in (
            "https://api.example.com https://evil.com",
            "api.example.com evil.com",
            "https://api.example.com\thttps://evil.com",
            "https://api.example.com https://evil.com",
        ):
            with self.subTest(value=value):
                self.assertEqual(strip_tool_annotation(value), value.strip())
                # and the residue must not resolve to a bare in-scope host
                self.assertNotEqual(_extract_host(value), "api.example.com")

    def test_persisted_value_matches_the_checked_value(self):
        """bus.normalize_line must store exactly what the scope gate inspects."""
        import agents.recon.bus as bus

        for value in (
            "https://host.example.com [1.2.3.4]",
            "https://api.example.com https://evil.com",
            "https://plain.example.com/x",
        ):
            with self.subTest(value=value):
                self.assertEqual(bus.normalize_line(value), strip_tool_annotation(value))


class ExtractHostTests(unittest.TestCase):
    def test_trailing_root_label_is_dropped(self):
        self.assertEqual(_extract_host("https://fab.com./browse/?ref=subnav"), "fab.com")
        self.assertEqual(_extract_host("fab.com."), "fab.com")

    def test_annotated_tool_output_keeps_the_target(self):
        """httpx emits '<url> [<resolved ip>]'; the bracket is not an IPv6 host."""
        self.assertEqual(
            _extract_host("https://api.kidswebservices.com [18.160.172.16]"),
            "api.kidswebservices.com",
        )
        self.assertEqual(
            _extract_host("https://audicagame.com [2606:4700::6812:202]"),
            "audicagame.com",
        )

    def test_real_ipv6_literals_still_parse(self):
        self.assertEqual(_extract_host("https://[2606:4700::1]/x"), "2606:4700::1")

    def test_unparseable_authority_returns_no_host_instead_of_raising(self):
        for value in ("https://[malformed", "http://[::", "https://[]["):
            with self.subTest(value=value):
                self.assertEqual(_extract_host(value), "")

    def test_ordinary_shapes_are_unchanged(self):
        self.assertEqual(_extract_host("https://api.example.com/path?q=1"), "api.example.com")
        self.assertEqual(_extract_host("api.example.com"), "api.example.com")
        self.assertEqual(_extract_host("192.168.1.1:8080"), "192.168.1.1")
        self.assertEqual(_extract_host(""), "")


class UrlPatternPathCheckTests(unittest.TestCase):
    """The url_pattern path check has its own urlparse; it must not raise."""

    def _validator(self):
        import tempfile

        from agents.scope_validator import ScopeValidator

        # Empty scopes_base so only the entry added below is in play.
        with tempfile.TemporaryDirectory() as empty:
            v = ScopeValidator(program="demo", strict=True, scopes_base=Path(empty))
        v.add_domain("https://svc.example.net/api/magpie")
        return v

    def test_annotated_url_pattern_host_does_not_raise(self):
        v = self._validator()
        self.assertFalse(v.is_in_scope("https://svc.example.net [1.2.3.4]"))

    def test_malformed_authority_does_not_raise(self):
        v = self._validator()
        self.assertFalse(v.is_in_scope("https://[malformed"))

    def test_declared_path_still_matches(self):
        v = self._validator()
        self.assertTrue(v.is_in_scope("https://svc.example.net/api/magpie"))


class WildKindPromotionTests(unittest.TestCase):
    """`wild.txt` stores bases with '*.' stripped; both spellings must work."""

    def _violations(self, values):
        import agents.recon.bus as bus

        class _Validator:
            def is_empty(self):
                return False

            def is_wildcard_scope(self, base):
                return base in {"epicgames.com", "fortnite.com"}

            def is_in_scope(self, value):  # pragma: no cover - not used for wild
                raise AssertionError("wild kind must not call is_in_scope")

        original = bus.ScopeValidator
        bus.ScopeValidator = lambda *a, **k: _Validator()
        try:
            return bus.scope_violations("demo", "wild", values)
        finally:
            bus.ScopeValidator = original

    def test_stripped_base_is_accepted(self):
        self.assertEqual(self._violations(["epicgames.com", "fortnite.com"]), [])

    def test_prefixed_spelling_still_accepted(self):
        self.assertEqual(self._violations(["*.epicgames.com"]), [])

    def test_base_outside_scope_is_still_refused(self):
        self.assertEqual(self._violations(["evil.com"]), ["evil.com"])
        self.assertEqual(self._violations(["*.evil.com"]), ["*.evil.com"])


if __name__ == "__main__":
    unittest.main()
