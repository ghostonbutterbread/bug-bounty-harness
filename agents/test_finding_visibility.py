from agents.finding_visibility import is_closed_finding, normalize_submission, visible_for_default_work


def test_submission_states_are_small_and_normalized() -> None:
    assert normalize_submission(None) == {"state": "not_submitted"}
    assert normalize_submission({"state": "duplicate", "report": "H1-12"}) == {
        "state": "duplicate",
        "report": "H1-12",
    }


def test_default_work_excludes_confirmed_and_submission_closed_findings() -> None:
    findings = [
        {"fid": "D01", "status": "active"},
        {"fid": "D02", "status": "confirmed"},
        {"fid": "D03", "submission": {"state": "submitted"}},
        {"fid": "D04", "submission": {"state": "duplicate"}},
    ]

    assert [item["fid"] for item in visible_for_default_work(findings)] == ["D01"]
    assert [item["fid"] for item in visible_for_default_work(findings, include_closed=True)] == ["D01", "D02", "D03", "D04"]
    assert is_closed_finding(findings[1]) is True
    assert is_closed_finding(findings[2]) is True
