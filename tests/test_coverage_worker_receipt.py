"""A worker's assessment receipt resolves even after a later assessment."""
from __future__ import annotations

import argparse
import json

from agents.coverage import cmd_surface_verify
from agents.surface_coverage import SurfaceCoverageStore


def test_assessment_event_id_and_exact_verify(tmp_path, capsys):
    store = SurfaceCoverageStore("sample", family="web_bounty", lane="web", root_override=tmp_path)
    surface_id = store.discover(kind="route", host="app.example", surface_key="GET /preview",
                                input_key="comment", consumer="preview", source_ref="recon/preview.jsonl",
                                run_id="mapper-1", class_name="xss")
    first_stream = store.path.parent.parent / "attempts" / "_runs" / "worker-1" / "attempts.jsonl"
    second_stream = store.path.parent.parent / "attempts" / "_runs" / "worker-2" / "attempts.jsonl"
    for stream, attempt_id in ((first_stream, "A-1"), (second_stream, "A-2")):
        stream.parent.mkdir(parents=True)
        stream.write_text(json.dumps({"attempt_id": attempt_id}) + "\n", encoding="utf-8")
    first = store.assess(surface_id, class_name="xss", status="in_progress", expected_fingerprint="",
                         reason="Preview consumer remains open", evidence_refs=["attempt:worker-1:A-1"],
                         run_id="worker-1")
    second = store.assess(surface_id, class_name="xss", status="in_progress", expected_fingerprint="",
                          reason="Another worker reviewed the same question", evidence_refs=["attempt:worker-2:A-2"],
                          run_id="worker-2")
    assert first["event_id"] != second["event_id"]
    own = store.history(surface_id, class_name="xss", event_id=first["event_id"])
    assert len(own) == 1
    assert own[0]["evidence_refs"] == ["attempt:worker-1:A-1"]

    args = argparse.Namespace(program="sample", family="web_bounty", lane="web", root_override=str(tmp_path),
                              surface_id=surface_id, class_name="xss", event_id=first["event_id"])
    cmd_surface_verify(args)
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["event_id"] == first["event_id"]
    assert receipt["references"] == [{"ref": "attempt:worker-1:A-1", "status": "resolved"}]
    # A source can disappear after a valid write; exact historical verification remains useful.
    second_stream.unlink()
    args.event_id = second["event_id"]
    cmd_surface_verify(args)
    later = json.loads(capsys.readouterr().out)
    assert later["references"] == [{"ref": "attempt:worker-2:A-2", "status": "missing"}]