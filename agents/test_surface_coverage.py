"""Cross-class mapped-surface coverage contract (no live target required)."""
from __future__ import annotations

import json
import contextlib
import io
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
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

    def assess(self, surface_id: str, **kwargs):
        kwargs.setdefault("expected_fingerprint", "bundle-v1")
        return self.store.assess(surface_id, **kwargs)

    def test_old_sqlite_rows_and_history_read_as_narrow_review_without_rewrite(self) -> None:
        surface_id = self.discover()
        self.assess(surface_id, class_name="xss", status="exhausted", evidence_refs=["A-123"],
                    reason="specific renderer reviewed", boundary="state attribute", axes=["quote"],
                    pressure="exhausted")
        with sqlite3.connect(self.store.path) as db:
            db.execute("UPDATE assessments SET status='exhausted' WHERE surface_id=?", (surface_id,))
            db.execute("UPDATE assessment_history SET status='exhausted' WHERE surface_id=?", (surface_id,))
        before = self.store.path.read_bytes()
        brief = self.store.brief(class_name="xss")
        self.assertEqual(brief["counts"], {"bounded_review": 1})
        self.assertEqual(brief["items"][0]["status"], "bounded_review")
        self.assertEqual(brief["items"][0]["pressure"], "exhausted")
        self.assertEqual(self.store.history(surface_id, class_name="xss")[0]["status"], "bounded_review")
        self.assertEqual(self.store.history(surface_id, class_name="xss")[0]["pressure"], "exhausted")
        self.assertEqual(self.store.path.read_bytes(), before)
        with sqlite3.connect(self.store.path) as db:
            self.assertEqual(db.execute("SELECT status FROM assessments").fetchone()[0], "exhausted")
            self.assertEqual(db.execute("SELECT status FROM assessment_history").fetchone()[0], "exhausted")
        self.discover(fingerprint="bundle-v2")
        stale = self.store.brief(class_name="xss")["items"][0]
        self.assertEqual((stale["status"], stale["prior_status"]), ("stale", "bounded_review"))
        self.assertEqual(self.store.history(surface_id, class_name="xss")[0]["status"], "bounded_review")

    def test_new_discovery_and_review_write_canonical_statuses(self) -> None:
        surface_id = self.discover()
        self.assertEqual(self.store.brief()["counts"], {"no_assessment": 1})
        with sqlite3.connect(self.store.path) as db:
            self.assertEqual(db.execute("SELECT status FROM assessments").fetchone()[0], "no_assessment")
        result = self.assess(surface_id, class_name="xss", status="bounded_review",
                             evidence_refs=["A-123"], reason="specific renderer reviewed",
                             boundary="state attribute", axes=["quote"])
        self.assertEqual(result["status"], "bounded_review")
        self.assertEqual(self.store.brief()["counts"], {"bounded_review": 1})
        self.assertEqual(self.store.history(surface_id, class_name="xss")[0]["status"], "bounded_review")
        with sqlite3.connect(self.store.path) as db:
            self.assertEqual(db.execute("SELECT status FROM assessments").fetchone()[0], "bounded_review")

    def test_old_default_status_stays_readable_and_new_class_uses_new_status(self) -> None:
        surface_id = self.discover()
        with sqlite3.connect(self.store.path) as db:
            db.execute("UPDATE assessments SET status='untested' WHERE surface_id=?", (surface_id,))
        self.assertEqual(self.store.brief()["counts"], {"no_assessment": 1})
        self.store.discover(kind="route", host="shop.example", surface_key="GET /next",
                            class_name="idor", source_ref="map/next.jsonl", run_id="mapper-1")
        self.assertEqual(self.store.brief()["counts"], {"no_assessment": 2})
        with sqlite3.connect(self.store.path) as db:
            self.assertEqual({row[0] for row in db.execute("SELECT status FROM assessments")},
                             {"untested", "no_assessment"})

    def test_bounded_review_requires_exact_boundary_axes_and_evidence(self) -> None:
        surface_id = self.discover()
        for options in ({"boundary": "", "axes": ["quote"], "evidence_refs": ["A-123"]},
                        {"boundary": "state attribute", "axes": [], "evidence_refs": ["A-123"]},
                        {"boundary": "state attribute", "axes": ["quote"], "evidence_refs": []}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.assess(surface_id, class_name="xss", status="bounded_review",
                            reason="reviewed", **options)
        self.assertEqual(self.store.brief()["counts"], {"no_assessment": 1})

    def test_discovery_creates_untested_class_without_static_file_index(self) -> None:
        surface_id = self.discover()
        result = self.store.brief(class_name="xss")
        self.assertEqual(result["counts"], {"no_assessment": 1})
        self.assertEqual(result["items"][0]["surface_id"], surface_id)
        self.assertEqual(result["items"][0]["source_ref"], "recon/wcs/actions.jsonl")
        self.assertTrue(self.store.path.name == "surface_coverage.sqlite")

    def test_rediscovery_is_idempotent_and_does_not_erase_assessment(self) -> None:
        surface_id = self.discover()
        self.assess(surface_id, class_name="xss", status="in_progress", pressure="warm",
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
        self.assess(first, class_name="xss", status="exhausted", evidence_refs=["A-123"],
                          reason="attribute encoding verified", boundary="state attribute in account view",
                          axes=["quote", "entity", "browser render"])
        self.assertEqual(self.store.brief(class_name="xss")["counts"], {"no_assessment": 1, "bounded_review": 1})
        self.assertEqual(self.store.brief(class_name="idor")["counts"], {"no_assessment": 1})

    def test_blocked_requires_wake_condition_and_exhaustion_requires_boundary(self) -> None:
        surface_id = self.discover()
        with self.assertRaisesRegex(ValueError, "reopen"):
            self.assess(surface_id, class_name="xss", status="blocked", evidence_refs=["A-123"], reason="fixture missing")
        with self.assertRaisesRegex(ValueError, "boundary"):
            self.assess(surface_id, class_name="xss", status="exhausted", evidence_refs=["A-123"], reason="tested")
        self.assertEqual(self.store.brief(class_name="xss")["counts"], {"no_assessment": 1})

    def test_new_fingerprint_reopens_old_assessment_without_erasing_evidence(self) -> None:
        surface_id = self.discover()
        self.assess(surface_id, class_name="xss", status="exhausted", evidence_refs=["A-123"],
                          reason="tested", boundary="one render path", axes=["quote"])
        self.discover(fingerprint="bundle-v2")
        item = self.store.brief(class_name="xss")["items"][0]
        self.assertEqual(item["status"], "stale")
        self.assertEqual(item["prior_status"], "bounded_review")
        self.assertEqual(item["evidence_refs"], ["A-123"])
        self.assertEqual(item["fingerprint"], "bundle-v2")

    def test_new_unversioned_mapper_run_reopens_exhaustion_but_reimport_does_not(self) -> None:
        row = {"kind": "route", "host": "shop.example", "surface_key": "GET /search",
               "input_key": "query:q", "class_names": ["xss", "idor"],
               "source_ref": "recon/xss/mapper-1/sources.jsonl:s1", "run_id": "mapper-1"}
        surface_id = self.store.discover_many([row])[0]
        self.assess(surface_id, class_name="xss", status="exhausted", expected_fingerprint="",
                    evidence_refs=["A-123"], reason="reviewed", boundary="one renderer", axes=["quote"])
        self.store.discover_many([row])
        self.assertEqual(self.store.brief(class_name="xss")["counts"], {"bounded_review": 1})
        self.store.discover_many([{**row, "run_id": "mapper-2",
                                   "source_ref": "recon/xss/mapper-2/sources.jsonl:s2"}])
        item = self.store.brief(class_name="xss")["items"][0]
        self.assertEqual(item["status"], "stale")
        self.assertEqual(item["prior_status"], "bounded_review")
        self.assertEqual(item["evidence_refs"], ["A-123"])
        self.assertEqual(self.store.brief(class_name="idor")["counts"], {"no_assessment": 1})
        self.assertEqual({source["run_id"] for source in item["sources"]}, {"mapper-1", "mapper-2"})
        self.assertEqual([event["status"] for event in self.store.history(surface_id, class_name="xss")],
                         ["bounded_review"])

    def test_preexisting_unversioned_assessment_reopens_when_next_mapper_run_imports(self) -> None:
        surface_id = self.store.discover(kind="route", host="shop.example", surface_key="GET /search",
                                         source_ref="map/old.jsonl", run_id="mapper-1", class_name="xss")
        self.assess(surface_id, class_name="xss", status="exhausted", expected_fingerprint="",
                    evidence_refs=["A-123"], reason="reviewed", boundary="one renderer", axes=["quote"])
        # Simulate a database written before unversioned assessments tracked mapper runs.
        with self.store._connect() as db:
            db.execute("UPDATE assessments SET assessed_fingerprint='' WHERE surface_id=?", (surface_id,))
        self.store.discover(kind="route", host="shop.example", surface_key="GET /search",
                            source_ref="map/new.jsonl", run_id="mapper-2", class_name="xss")
        self.assertEqual(self.store.brief(class_name="xss")["counts"], {"stale": 1})

    def test_old_unversioned_mapper_run_cannot_restore_exhaustion(self) -> None:
        row = {"kind": "route", "host": "shop.example", "surface_key": "GET /search",
               "source_ref": "map/old.jsonl", "run_id": "mapper-1", "class_name": "xss"}
        surface_id = self.store.discover(**row)
        self.assess(surface_id, class_name="xss", status="exhausted", expected_fingerprint="",
                    evidence_refs=["A-123"], reason="reviewed", boundary="one renderer", axes=["quote"])
        self.store.discover(**{**row, "source_ref": "map/new.jsonl", "run_id": "mapper-2"})
        with self.assertRaisesRegex(ValueError, "older mapper run"):
            self.store.discover(**row)
        self.assertEqual(self.store.brief(class_name="xss")["counts"], {"stale": 1})

    def test_older_known_fingerprint_cannot_restore_exhausted_state(self) -> None:
        surface_id = self.discover()
        self.assess(surface_id, class_name="xss", status="exhausted", evidence_refs=["A-123"],
                          reason="tested", boundary="one render path", axes=["quote"])
        self.discover(fingerprint="bundle-v2")
        with self.assertRaisesRegex(ValueError, "older fingerprint"):
            self.discover(fingerprint="bundle-v1")
        self.assertEqual(self.store.brief(class_name="xss")["items"][0]["status"], "stale")

    def test_assess_rejects_review_of_obsolete_fingerprint(self) -> None:
        surface_id = self.discover()
        self.discover(fingerprint="bundle-v2")
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            self.assess(surface_id, class_name="xss", status="exhausted",
                              expected_fingerprint="bundle-v1", evidence_refs=["A-123"],
                              reason="reviewed old bundle", boundary="account render", axes=["quote"])
        self.assertEqual(self.store.brief(class_name="xss")["counts"], {"no_assessment": 1})

    def test_reassessment_preserves_prior_evidence_in_history(self) -> None:
        surface_id = self.discover()
        self.assess(surface_id, class_name="xss", status="blocked", evidence_refs=["A-1"],
                          reason="fixture missing", reopen_when="fixture available")
        self.assess(surface_id, class_name="xss", status="in_progress", evidence_refs=["A-2"],
                          reason="fixture now available", pressure="warm")
        self.assertEqual(self.store.brief(class_name="xss")["items"][0]["evidence_refs"], ["A-2"])
        history = self.store.history(surface_id, class_name="xss")
        self.assertEqual([event["status"] for event in history], ["blocked", "in_progress"])
        self.assertEqual(history[0]["evidence_refs"], ["A-1"])

    def test_brief_limits_items_but_counts_all_and_keeps_blocked_open(self) -> None:
        first = self.discover()
        self.discover(input_key="orgName")
        self.assess(first, class_name="xss", status="blocked", evidence_refs=["A-123"],
                          reason="needs owned fixture", reopen_when="fixture available")
        result = self.store.brief(class_name="xss", limit=1)
        self.assertEqual(result["counts"], {"blocked": 1, "no_assessment": 1})
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(result["items"][0]["status"], "blocked")

    def test_brief_can_page_through_every_counted_row(self) -> None:
        for number in range(201):
            self.discover(input_key=f"field-{number:03d}")
        first = self.store.brief(class_name="xss", limit=200)
        second = self.store.brief(class_name="xss", limit=200, offset=first["next_offset"])
        self.assertEqual(first["total"], 201)
        self.assertEqual(len(first["items"]), 200)
        self.assertEqual(len(second["items"]), 1)
        self.assertIsNone(second["next_offset"])
        self.assertEqual(len({item["surface_id"] for item in first["items"] + second["items"]}), 201)

    def test_unclassified_inventory_is_visible_without_assuming_every_class_applies(self) -> None:
        self.discover()
        self.store.discover(kind="workflow", host="shop.example", surface_key="checkout-return",
                            source_ref="recon/workflows.jsonl", run_id="mapper-1")
        result = self.store.brief(class_name="xss")
        self.assertEqual(result["counts"], {"no_assessment": 1})
        self.assertEqual(result["unclassified_surfaces"], 1)
        self.assertEqual(result["mapped_kinds"], {"wcs_action": 1, "workflow": 1})

    def test_refuses_payload_or_secret_bearing_evidence_reference(self) -> None:
        surface_id = self.discover()
        with self.assertRaises(ValueError):
            self.assess(surface_id, class_name="xss", status="in_progress",
                              evidence_refs=["https://shop.example/?token=secret"], reason="test")
        self.assertEqual(self.store.brief(class_name="xss")["counts"], {"no_assessment": 1})

    def test_refuses_bearer_material_in_reference_or_reason(self) -> None:
        surface_id = self.discover()
        for field in ("reference", "reason"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.assess(surface_id, class_name="xss", status="in_progress",
                                  evidence_refs=["Bearer sensitive-value"] if field == "reference" else ["A-123"],
                                  reason="Bearer sensitive-value" if field == "reason" else "review in progress")
        self.assertEqual(self.store.brief(class_name="xss")["counts"], {"no_assessment": 1})

    def test_refuses_named_secret_values_in_assessment_text(self) -> None:
        surface_id = self.discover()
        for secret_text in ("token=sensitive-value", "password: sensitive-value", "api_key=sensitive-value",
                            "Bearer\tsensitive-value", "access_token=sensitive-value",
                            "refresh_token=sensitive-value", "client_secret=sensitive-value"):
            with self.subTest(secret_text=secret_text), self.assertRaises(ValueError):
                self.assess(surface_id, class_name="xss", status="in_progress",
                                  evidence_refs=["A-123"], reason=secret_text)
        self.assertEqual(self.store.brief(class_name="xss")["counts"], {"no_assessment": 1})

    def test_bulk_import_rejects_invalid_second_row_without_partial_discovery(self) -> None:
        # A later validation error must not make the earlier mapped row visible.
        inventory = Path(self.tmp.name) / "invalid-inventory.jsonl"
        valid = {"kind": "route", "host": "shop.example", "surface_key": "/account",
                 "source_ref": "map/routes.jsonl", "run_id": "map-1", "class_names": ["xss"]}
        inventory.write_text(json.dumps(valid) + "\n" + json.dumps({**valid, "surface_key": "/checkout",
                                                                  "class_names": "xss"}) + "\n", encoding="utf-8")
        common = ("--program", "sample", "--family", "web_bounty", "--lane", "web", "--root", self.tmp.name)
        args = me_ledger.build_parser().parse_args(["surface-discover", *common, "--input-jsonl", str(inventory)])
        with self.assertRaisesRegex(ValueError, "line 2"):
            args.func(args)
        self.assertEqual(self.store.brief()["mapped_kinds"], {})

    def test_parallel_writers_preserve_all_distinct_questions_and_decisions(self) -> None:
        """Independent agents can register and assess one lane without lost writes."""
        def worker(number: int) -> str:
            store = SurfaceCoverageStore("sample", family="web_bounty", lane="web",
                                         root_override=Path(self.tmp.name))
            surface_id = store.discover(kind="route", host="shop.example", surface_key="GET /search",
                                        input_key=f"query:field-{number}", class_name="xss",
                                        source_ref=f"recon/xss/source-{number}.jsonl", run_id=f"map-{number}")
            store.assess(surface_id, class_name="xss", status="in_progress",
                         expected_fingerprint="", evidence_refs=[f"attempt:probe-{number}:A-{number}"],
                         reason=f"consumer {number} remains open", run_id=f"probe-{number}")
            return surface_id

        with ThreadPoolExecutor(max_workers=6) as pool:
            surface_ids = list(pool.map(worker, range(6)))
        self.assertEqual(len(set(surface_ids)), 6)
        brief = self.store.brief(class_name="xss")
        self.assertEqual(brief["counts"], {"in_progress": 6})
        self.assertEqual({item["surface_id"] for item in brief["items"]}, set(surface_ids))
        self.assertTrue(all(len(self.store.history(surface_id, class_name="xss")) == 1
                            for surface_id in surface_ids))

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
        self.assertEqual(invoke("surface-brief", *common, "--class-name", "xss")["counts"], {"no_assessment": 1})
        self.assertEqual(invoke("surface-brief", *common, "--class-name", "access-control")["counts"], {"no_assessment": 1})
        self.assertEqual(invoke("surface-brief", *common, "--limit", "1")["next_offset"], 1)
        self.assertEqual(len(invoke("surface-brief", *common, "--limit", "1", "--offset", "1")["items"]), 1)
        surface_id = imported["surface_ids"][0]
        invoke("surface-assess", *common, "--surface-id", surface_id, "--class-name", "xss",
               "--expected-fingerprint", "schema-v1",
               "--status", "blocked", "--reason", "need owned order", "--reopen-when", "fixture available",
               "--evidence-ref", "A-123")
        self.assertEqual(invoke("surface-brief", *common, "--class-name", "xss")["counts"], {"blocked": 1})
        self.assertEqual(invoke("surface-history", *common, "--surface-id", surface_id,
                                "--class-name", "xss")["events"][0]["evidence_refs"], ["A-123"])
        self.assertEqual(invoke("surface-brief", *common, "--class-name", "access-control")["counts"], {"no_assessment": 1})


if __name__ == "__main__":
    unittest.main()
