"""Fixture-first compatibility coverage for the Ledger v2 migration."""

from __future__ import annotations

import json
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from agents.ledger_v2 import ledger_add, ledger_get, ledger_list, ledger_path


PROGRAM = "notion"
FAMILY = "binaries"
LANE = "apk"


def _write_ledger(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _read_ledger(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@contextmanager
def _isolated_ledger_path(tmp_path: Path):
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    with patch.dict(os.environ, {"HOME": str(home)}, clear=False):
        yield ledger_path(PROGRAM, family=FAMILY, lane=LANE)


def _current_v2_payload(*, program: str = PROGRAM) -> dict:
    return {
        "version": 2,
        "program": program,
        "updated_at": "2026-04-28T00:00:00Z",
        "findings": [
            {
                "fid": "D01",
                "type": "Fixture IPC issue",
                "class_name": "ipc-trust-boundary",
                "file": "src/preload.js",
                "line": 44,
                "severity": "HIGH",
                "first_seen": "2026-04-27T10:00:00Z",
                "first_snapshot": "snap-a",
                "last_seen": "2026-04-27T11:00:00Z",
                "last_snapshot": "snap-b",
                "sightings": [
                    {
                        "snapshot_id": "snap-a",
                        "version_label": "v1.0.0",
                        "run_id": "run-a",
                        "seen_at": "2026-04-27T10:00:00Z",
                        "status": "active",
                        "review_tier": "PENDING_REVIEW",
                        "agent": "fixture-builder",
                    },
                    {
                        "snapshot_id": "snap-b",
                        "version_label": "v1.1.0",
                        "run_id": "run-b",
                        "seen_at": "2026-04-27T11:00:00Z",
                        "status": "active",
                        "review_tier": "CONFIRMED",
                        "agent": "fixture-builder",
                    },
                ],
                "current": {
                    "review_tier": "CONFIRMED",
                    "status": "active",
                    "version_label": "v1.1.0",
                },
            }
        ],
    }


def test_unknown_fields_inside_sightings_round_trip_on_read_and_update(tmp_path: Path) -> None:
    with _isolated_ledger_path(tmp_path) as path:
        payload = _current_v2_payload()
        payload["findings"][0]["sightings"][0]["source_artifact"] = {
            "kind": "caido-flow",
            "path": "artifacts/flow-1.json",
        }
        payload["findings"][0]["sightings"][0]["review_notes"] = ["kept for reviewer context"]
        _write_ledger(path, payload)

        read_back = ledger_get(PROGRAM, "D01", family=FAMILY, lane=LANE)
        assert read_back is not None
        assert read_back["sightings"][0]["source_artifact"]["path"] == "artifacts/flow-1.json"
        assert read_back["sightings"][0]["review_notes"] == ["kept for reviewer context"]

        ledger_add(
            PROGRAM,
            {
                "type": "Fixture IPC issue",
                "class_name": "ipc-trust-boundary",
                "file": "src/preload.js",
                "line": 44,
                "severity": "CRITICAL",
            },
            "snap-c",
            "v1.2.0",
            "run-c",
            "fixture-updater",
            family=FAMILY,
            lane=LANE,
        )

        written = _read_ledger(path)
        sightings = written["findings"][0]["sightings"]
        assert sightings[0]["source_artifact"]["path"] == "artifacts/flow-1.json"
        assert sightings[0]["review_notes"] == ["kept for reviewer context"]
        assert [item["snapshot_id"] for item in sightings] == ["snap-a", "snap-b", "snap-c"]


def test_sighting_count_is_preserved_and_never_overrides_sightings_history(tmp_path: Path) -> None:
    with _isolated_ledger_path(tmp_path) as path:
        payload = _current_v2_payload()
        payload["findings"][0]["sighting_count"] = 99
        _write_ledger(path, payload)

        listed = ledger_list(PROGRAM, family=FAMILY, lane=LANE)
        assert listed[0]["sighting_count"] == 99
        assert len(listed[0]["sightings"]) == 2

        ledger_add(
            PROGRAM,
            {
                "type": "Fixture IPC issue",
                "class_name": "ipc-trust-boundary",
                "file": "src/preload.js",
                "line": 44,
                "severity": "HIGH",
            },
            "snap-c",
            "v1.2.0",
            "run-c",
            "fixture-updater",
            family=FAMILY,
            lane=LANE,
        )

        written = _read_ledger(path)
        finding = written["findings"][0]
        assert finding["sighting_count"] == 99
        assert [item["snapshot_id"] for item in finding["sightings"]] == ["snap-a", "snap-b", "snap-c"]
        assert len(finding["sightings"]) == 3


def test_baseteam_style_payload_round_trips_coverage_sighting_count_and_team_type(tmp_path: Path) -> None:
    with _isolated_ledger_path(tmp_path) as path:
        payload = _current_v2_payload()
        payload["coverage"] = {
            "src/preload.js": {
                "ipc-trust-boundary": {
                    "line": 44,
                    "team_type": "base-team",
                }
            }
        }
        payload["findings"][0]["sighting_count"] = 2
        payload["findings"][0]["team_type"] = "base-team"
        _write_ledger(path, payload)

        ledger_add(
            PROGRAM,
            {
                "type": "Fixture IPC issue",
                "class_name": "ipc-trust-boundary",
                "file": "src/preload.js",
                "line": 44,
                "severity": "HIGH",
                "team_type": "base-team",
            },
            "snap-c",
            "v1.2.0",
            "run-c",
            "base-team-adapter",
            family=FAMILY,
            lane=LANE,
        )

        written = _read_ledger(path)
        assert written["coverage"] == payload["coverage"]
        finding = written["findings"][0]
        assert finding["team_type"] == "base-team"
        assert finding["sighting_count"] == 2
        assert [item["snapshot_id"] for item in finding["sightings"]] == ["snap-a", "snap-b", "snap-c"]


def test_baseteam_distinct_findings_same_file_and_class_are_represented_safely(tmp_path: Path) -> None:
    with _isolated_ledger_path(tmp_path):
        first_is_new, first_fid = ledger_add(
            PROGRAM,
            {
                "type": "Renderer IPC trust boundary",
                "class_name": "ipc-trust-boundary",
                "file": "src/preload.js",
                "line": 44,
                "severity": "HIGH",
            },
            "snap-a",
            "v1.0.0",
            "run-a",
            "base-team-adapter",
            family=FAMILY,
            lane=LANE,
        )
        second_is_new, second_fid = ledger_add(
            PROGRAM,
            {
                "type": "Different IPC sink",
                "class_name": "ipc-trust-boundary",
                "file": "src/preload.js",
                "line": 88,
                "severity": "HIGH",
            },
            "snap-a",
            "v1.0.0",
            "run-a",
            "base-team-adapter",
            family=FAMILY,
            lane=LANE,
        )

        findings = ledger_list(PROGRAM, family=FAMILY, lane=LANE)
        assert first_is_new is True
        assert second_is_new is True
        assert first_fid != second_fid
        assert {(item["line"], item["type"]) for item in findings} == {
            (44, "Renderer IPC trust boundary"),
            (88, "Different IPC sink"),
        }


def test_current_v2_fixture_read_does_not_mutate_ledger_json(tmp_path: Path) -> None:
    with _isolated_ledger_path(tmp_path) as path:
        _write_ledger(path, _current_v2_payload())
        before = path.read_bytes()

        findings = ledger_list(PROGRAM, family=FAMILY, lane=LANE)
        fetched = ledger_get(PROGRAM, "D01", family=FAMILY, lane=LANE)

        assert len(findings) == 1
        assert fetched is not None
        assert fetched["fid"] == "D01"
        assert path.read_bytes() == before
