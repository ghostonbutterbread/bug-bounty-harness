"""Cross-class mapped-surface coverage contract (no live target required)."""
from __future__ import annotations

import json
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from agents.surface_coverage import SurfaceCoverageStore
from agents import me_ledger


class SurfaceCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = SurfaceCoverageStore("sample", family="web_bounty", lane="web", root_override=Path(self.tmp.name))

    def discover(self, *, class_name="xss", fingerprint="bundle-v1", input_key="state") -> str:
        return self.store.discover(
            kind="wcs_action", host="shop.example", surface_key="AddressFieldsDisplayView",
            input_key=input_key, consumer="account-address-render", class_name=class_name,
            source_ref="recon/wcs/actions.jsonl", run_id="mapper-1", fingerprint=fingerprint,
        )

    def test_discovery_creates_untested_class_without_static_file_index(self) -> None:
        surface_id = self.discover()
        result = self.store.brief(class_name="xss")
        self.assertEqual(result["counts"], {"untested": 1})
        self.assertEqual(result["items"][0]["surface_id"], surface_id)
        self.assertEqual(result["items"][0]["source_ref"], "recon/wcs/actions.jsonl")
        self.assertTrue(self.store.path.name == "surface_coverage.sqlite")

    def test_rediscovery_is_idempotent_and_does_not_erase_assessment(self) -> None:
        surface_id = self.discover()
        self.store.assess(surface_id, class_name="xss", status="in_progress", pressure="warm",
                          evidence_refs=["A-123"], reason="input reaches a renderer",
                          agent="pi", run_id="xss-run-1")
        self.assertEqual(self.discover(), surface_id)
        item = self.store.brief(class_name="xss")["items"][0]
        self.assertEqual(item["status"], "in_progress")
        self.assertEqual(item["pressure"], "warm")
        self.assertEqual(item["evidence_refs"], ["A-123"])
        self.assertEqual(item["agent"], "pi")
        self.assertEqual(item["assessment_run_id"], "xss-run-1")

    def test_classes_and_sibling_inputs_do_not_inherit_exhaustion(self) -> None:
        first = self.discover()
        self.discover(input_key="orgName")
        self.discover(class_name="idor")
        self.store.assess(first, class_name="xss", status="exhausted", evidence_refs=["A-123"],
                          reason="attribute encoding verified", boundary="state attribute in account view",
                          axes=["quote", "entity", "browser render"])
        self.assertEqual(self.store.brief(class_name="xss")["counts"], {"untested": 1, "exhausted": 1})
        self.assertEqual(self.store.brief(class_name="idor")["counts"], {"untested": 1})

    def test_blocked_requires_wake_condition_and_exhaustion_requires_boundary(self) -> None:
        surface_id = self.discover()
        with self.assertRaisesRegex(ValueError, "reopen"):
            self.store.assess(surface_id, class_name="xss", status="blocked", evidence_refs=["A-123"], reason="fixture missing")
        with self.assertRaisesRegex(ValueError, "boundary"):
            self.store.assess(surface_id, class_name="xss", status="exhausted", evidence_refs=["A-123"], reason="tested")
        self.assertEqual(self.store.brief(class_name="xss")["counts"], {"untested": 1})

    def test_new_fingerprint_reopens_old_assessment_without_erasing_evidence(self) -> None:
        surface_id = self.discover()
        self.store.assess(surface_id, class_name="xss", status="exhausted", evidence_refs=["A-123"],
                          reason="tested", boundary="one render path", axes=["quote"])
        self.discover(fingerprint="bundle-v2")
        item = self.store.brief(class_name="xss")["items"][0]
        self.assertEqual(item["status"], "stale")
        self.assertEqual(item["prior_status"], "exhausted")
        self.assertEqual(item["evidence_refs"], ["A-123"])
        self.assertEqual(item["fingerprint"], "bundle-v2")

    def test_reassessment_preserves_prior_evidence_in_history(self) -> None:
        surface_id = self.discover()
        self.store.assess(surface_id, class_name="xss", status="blocked", evidence_refs=["A-1"],
                          reason="fixture missing", reopen_when="fixture available")
        self.store.assess(surface_id, class_name="xss", status="in_progress", evidence_refs=["A-2"],
                          reason="fixture now available", pressure="warm")
        self.assertEqual(self.store.brief(class_name="xss")["items"][0]["evidence_refs"], ["A-2"])
        history = self.store.history(surface_id, class_name="xss")
        self.assertEqual([event["status"] for event in history], ["blocked", "in_progress"])
        self.assertEqual(history[0]["evidence_refs"], ["A-1"])

    def test_brief_limits_items_but_counts_all_and_keeps_blocked_open(self) -> None:
        first = self.discover()
        self.discover(input_key="orgName")
        self.store.assess(first, class_name="xss", status="blocked", evidence_refs=["A-123"],
                          reason="needs owned fixture", reopen_when="fixture available")
        result = self.store.brief(class_name="xss", limit=1)
        self.assertEqual(result["counts"], {"blocked": 1, "untested": 1})
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(result["items"][0]["status"], "blocked")

    def test_unclassified_inventory_is_visible_without_assuming_every_class_applies(self) -> None:
        self.discover()
        self.store.discover(kind="workflow", host="shop.example", surface_key="checkout-return",
                            source_ref="recon/workflows.jsonl", run_id="mapper-1")
        result = self.store.brief(class_name="xss")
        self.assertEqual(result["counts"], {"untested": 1})
        self.assertEqual(result["unclassified_surfaces"], 1)
        self.assertEqual(result["mapped_kinds"], {"wcs_action": 1, "workflow": 1})

    def test_refuses_payload_or_secret_bearing_evidence_reference(self) -> None:
        surface_id = self.discover()
        with self.assertRaises(ValueError):
            self.store.assess(surface_id, class_name="xss", status="in_progress",
                              evidence_refs=["https://shop.example/?token=secret"], reason="test")
        self.assertEqual(self.store.brief(class_name="xss")["counts"], {"untested": 1})

    def test_cli_import_brief_and_assess_work_without_shared_brain(self) -> None:
        inventory = Path(self.tmp.name) / "inventory.jsonl"
        inventory.write_text(json.dumps({
            "kind": "graphql_argument", "host": "api.example", "surface_key": "Checkout.placeOrder",
            "input_key": "comment", "consumer": "order-preview", "class_names": ["xss", "access-control"],
            "source_ref": "recon/api/operations.jsonl", "run_id": "map-1", "fingerprint": "schema-v1",
        }) + "\n", encoding="utf-8")

        def invoke(*args: str) -> dict:
            parsed = me_ledger.build_parser().parse_args(list(args))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(parsed.func(parsed), 0)
            return json.loads(out.getvalue())

        common = ("--program", "sample", "--family", "web_bounty", "--lane", "web", "--root", self.tmp.name)
        imported = invoke("surface-discover", *common, "--input-jsonl", str(inventory))
        self.assertEqual(imported["discovered"], 1)
        self.assertEqual(invoke("surface-brief", *common, "--class-name", "xss")["counts"], {"untested": 1})
        self.assertEqual(invoke("surface-brief", *common, "--class-name", "access-control")["counts"], {"untested": 1})
        surface_id = imported["surface_ids"][0]
        invoke("surface-assess", *common, "--surface-id", surface_id, "--class-name", "xss",
               "--status", "blocked", "--reason", "need owned order", "--reopen-when", "fixture available",
               "--evidence-ref", "A-123")
        self.assertEqual(invoke("surface-brief", *common, "--class-name", "xss")["counts"], {"blocked": 1})
        self.assertEqual(invoke("surface-history", *common, "--surface-id", surface_id,
                                "--class-name", "xss")["events"][0]["evidence_refs"], ["A-123"])
        self.assertEqual(invoke("surface-brief", *common, "--class-name", "access-control")["counts"], {"untested": 1})


if __name__ == "__main__":
    unittest.main()
