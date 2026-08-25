from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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
