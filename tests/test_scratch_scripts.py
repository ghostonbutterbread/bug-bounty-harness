"""Offline contract for program-lane scratch script management."""
import json
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "scratch_scripts.py"


def call(profile, *args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--profile", str(profile), *args],
        capture_output=True, text=True,
    )


def profile(tmp_path):
    lane = tmp_path / "Shared" / "web_bounty" / "example" / "web"
    context = lane / "context"
    context.mkdir(parents=True)
    path = context / "target_profile.json"
    path.write_text(json.dumps({"program": "example", "family": "web_bounty", "lane": "web", "canonical_root": str(lane)}))
    return path, lane


def test_create_indexes_shared_run_scratch_without_overwriting(tmp_path):
    selected, lane = profile(tmp_path)
    created = call(selected, "create", "--run-id", "run-1", "--name", "parse-js", "--description", "Extract named JS fields")
    assert created.returncode == 0, created.stderr
    script = lane / "working" / "_runs" / "run-1" / "_scratch" / "scripts" / "parse-js.py"
    assert script.is_file()
    assert "Extract named JS fields" in (lane / "scripts" / "SCRATCH.md").read_text()
    assert "parse-js.py" in (script.parent / "README.md").read_text()
    assert call(selected, "create", "--run-id", "run-1", "--name", "parse-js", "--description", "Different").returncode != 0
    assert "Extract named JS fields" in (lane / "scripts" / "SCRATCH.md").read_text()
    listed = call(selected, "list")
    assert listed.returncode == 0 and "parse-js" in listed.stdout


def test_recorded_use_count_only_after_helper_run(tmp_path):
    selected, lane = profile(tmp_path)
    assert call(selected, "create", "--run-id", "run-1", "--name", "hello", "--description", "A fixture").returncode == 0
    script = lane / "working" / "_runs" / "run-1" / "_scratch" / "scripts" / "hello.py"
    script.write_text("print('hello from fixture')\n")
    used = call(selected, "run", "--run-id", "run-1", "--name", "hello")
    assert used.returncode == 0 and "hello from fixture" in used.stdout
    assert "1 uses" in call(selected, "list").stdout
    assert call(selected, "run", "--run-id", "run-1", "--name", "hello").returncode == 0
    assert "2 uses" in call(selected, "list").stdout
    events = list((lane / "scripts" / "_scratch_uses").glob("*/*.json"))
    assert len(events) == 2
    assert all(json.loads(event.read_text())["returncode"] == 0 for event in events)


def test_promotion_requires_review_and_does_not_auto_publish_bbh(tmp_path):
    selected, lane = profile(tmp_path)
    assert call(selected, "create", "--run-id", "run-1", "--name", "helper", "--description", "A fixture").returncode == 0
    denied = call(selected, "promote", "--run-id", "run-1", "--name", "helper", "--to", "program")
    assert denied.returncode != 0
    assert not (lane / "scripts" / "helper.py").exists()
    proposed = call(selected, "promote", "--run-id", "run-1", "--name", "helper", "--to", "bbh")
    assert proposed.returncode == 0
    assert "proposal" in proposed.stdout.lower()
    assert not (lane / "scripts" / "helper.py").exists()
    promoted = call(selected, "promote", "--run-id", "run-1", "--name", "helper", "--to", "program", "--review-ref", "review-1", "--verification", "offline smoke passed")
    assert promoted.returncode == 0, promoted.stderr
    assert (lane / "scripts" / "helper.py").exists()
    assert "review-1" in (lane / "scripts" / "README.md").read_text()
    assert "promoted" in (lane / "scripts" / "SCRATCH.md").read_text()


def test_description_update_rebuilds_both_indexes(tmp_path):
    selected, lane = profile(tmp_path)
    assert call(selected, "create", "--run-id", "run-1", "--name", "helper", "--description", "First purpose").returncode == 0
    result = call(selected, "describe", "--run-id", "run-1", "--name", "helper", "--description", "Revised purpose")
    assert result.returncode == 0, result.stderr
    assert "Revised purpose" in (lane / "scripts" / "SCRATCH.md").read_text()
    assert "Revised purpose" in (lane / "working" / "_runs" / "run-1" / "_scratch" / "scripts" / "README.md").read_text()


def test_rejects_path_escape_and_missing_script_without_counting(tmp_path):
    selected, lane = profile(tmp_path)
    assert call(selected, "create", "--run-id", "../outside", "--name", "helper", "--description", "No").returncode != 0
    assert call(selected, "create", "--run-id", "run-1", "--name", "helper", "--description", "Fixture").returncode == 0
    script = lane / "working" / "_runs" / "run-1" / "_scratch" / "scripts" / "helper.py"
    script.unlink()
    script.symlink_to(tmp_path / "outside.py")
    assert call(selected, "run", "--run-id", "run-1", "--name", "helper").returncode != 0
    assert not list((lane / "scripts" / "_scratch_uses").glob("*/*.json"))


def test_rejects_symlinked_parent_and_dangling_promotion_target(tmp_path):
    selected, lane = profile(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (lane / "working").symlink_to(outside, target_is_directory=True)
    assert call(selected, "create", "--run-id", "run-1", "--name", "helper", "--description", "Fixture").returncode != 0
    assert not list(outside.rglob("helper.py"))
    (lane / "working").unlink()
    assert call(selected, "create", "--run-id", "run-1", "--name", "helper", "--description", "Fixture").returncode == 0
    (lane / "scripts" / "helper.py").symlink_to(outside / "victim.py")
    attempted = call(selected, "promote", "--run-id", "run-1", "--name", "helper", "--to", "program", "--review-ref", "review-1", "--verification", "offline smoke")
    assert attempted.returncode != 0
    assert not (outside / "victim.py").exists()


def test_promotion_preserves_existing_program_index_and_records_contract(tmp_path):
    selected, lane = profile(tmp_path)
    index = lane / "scripts" / "README.md"
    index.parent.mkdir(parents=True)
    index.write_text("# Curated program tools\n\nExisting helper remains.\n")
    assert call(selected, "create", "--run-id", "run-1", "--name", "helper", "--description", "Fixture").returncode == 0
    result = call(selected, "promote", "--run-id", "run-1", "--name", "helper", "--to", "program", "--review-ref", "review-1", "--verification", "offline smoke")
    assert result.returncode == 0, result.stderr
    text = index.read_text()
    assert "Existing helper remains." in text
    assert all(field in text for field in ("**Purpose:**", "**Inputs:**", "**Outputs:**", "**Mutates:**", "**Verification:**", "**Owner/scope:**", "**Last verified:**", "**Coverage:**"))


def test_failed_index_preflight_does_not_leave_partial_create(tmp_path):
    selected, lane = profile(tmp_path)
    index = lane / "scripts" / "SCRATCH.md"
    index.parent.mkdir(parents=True)
    index.write_text("Operator content\n")
    failed = call(selected, "create", "--run-id", "one", "--name", "helper", "--description", "Fixture")
    assert failed.returncode != 0
    assert not (lane / "working" / "_runs" / "one" / "_scratch" / "scripts" / "helper.py").exists()
    assert not list((lane / "scripts" / "_scratch_records").rglob("*.json"))
    index.unlink()
    assert call(selected, "create", "--run-id", "one", "--name", "helper", "--description", "Fixture").returncode == 0


def test_failed_program_index_preflight_does_not_leave_partial_promotion(tmp_path):
    selected, lane = profile(tmp_path)
    assert call(selected, "create", "--run-id", "one", "--name", "helper", "--description", "Fixture").returncode == 0
    index = lane / "scripts" / "README.md"
    index.mkdir()
    args = ("promote", "--run-id", "one", "--name", "helper", "--to", "program", "--review-ref", "review-1", "--verification", "offline smoke")
    assert call(selected, *args).returncode != 0
    assert not (lane / "scripts" / "helper.py").exists()
    index.rmdir()
    assert call(selected, *args).returncode == 0


def test_record_keys_do_not_collide_for_distinct_run_name_pairs(tmp_path):
    selected, lane = profile(tmp_path)
    for run_id, name in (("a--b", "c"), ("a", "b--c")):
        result = call(selected, "create", "--run-id", run_id, "--name", name, "--description", "Fixture")
        assert result.returncode == 0, result.stderr
    assert len(list((lane / "scripts" / "_scratch_records").glob("*.json"))) == 2
