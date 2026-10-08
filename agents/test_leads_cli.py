from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents import leads
from agents.leads import build_lead_body


def test_build_lead_body_has_class_neutral_lifecycle_fields() -> None:
    body = build_lead_body(
        observed_basis="owned input reaches the worker",
        candidate_chain="input -> worker -> internal fetch question",
        exact_unknown="whether redirect targets are fetched",
        next_discriminator="owned redirect fixture",
        blocker="fixture",
        wake_condition="fixture is available",
        evidence_refs=["mapstore:worker"],
    )

    assert "Observed basis: owned input reaches the worker" in body
    assert "Candidate chain: input -> worker -> internal fetch question" in body
    assert "Blocker: fixture" in body
    assert "Evidence: mapstore:worker" in body


def test_search_keeps_listing_after_a_legacy_lead_without_path(monkeypatch, capsys) -> None:
    entries = [
        {"status": "candidate", "surface": "web", "title": "legacy lead", "tags": ["lead"]},
        {"status": "active", "surface": "api", "title": "new lead", "path": "api/new/index.md"},
    ]

    class FakeStore:
        def __init__(self, *args, **kwargs):
            pass

        def init(self):
            pass

        def query(self, **kwargs):
            assert kwargs["tags"] == ["lead"]
            return entries

    monkeypatch.setattr(leads, "MapStore", FakeStore)
    assert leads.main(["search", "--program", "testprog"]) == 0
    assert capsys.readouterr().out.splitlines() == [
        "candidate\tweb\tlegacy lead\t",
        "active\tapi\tnew lead\tapi/new/index.md",
    ]
