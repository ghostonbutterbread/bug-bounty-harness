import json
import tempfile
import unittest
from pathlib import Path

from agents import bounty_notes


class BountyNotesTests(unittest.TestCase):
    def test_init_creates_note_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = bounty_notes.main(["init", "demo", "--family", "web_bounty", "--lane", "web", "--root", tmp])
            self.assertEqual(rc, 0)
            root = Path(tmp) / "web_bounty" / "demo" / "web"
            self.assertTrue((root / "notes" / "index.md").exists())
            self.assertTrue((root / "notes" / "hypotheses").is_dir())
            self.assertTrue((root / "working" / "scratch").is_dir())
            self.assertTrue((root / "context" / "target_profile.json").exists())

    def test_hypothesis_note_uses_bucket_and_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = bounty_notes.main(
                [
                    "note",
                    "demo",
                    "--family",
                    "web_bounty",
                    "--lane",
                    "web",
                    "--root",
                    tmp,
                    "--bucket",
                    "hypotheses",
                    "--title",
                    "Avatar metadata render",
                    "--status",
                    "testing",
                    "--run-id",
                    "run-1",
                    "--body",
                    "Check whether metadata reaches admin review.",
                    "--refs",
                    "notes/timeline/2026-06-15.md",
                    "--url",
                    "canva.com/api/designs?b=2&a=1",
                    "--tag",
                    "avatar",
                    "--report",
                    "FID-123",
                ]
            )
            self.assertEqual(rc, 0)
            note = Path(tmp) / "web_bounty" / "demo" / "web" / "notes" / "hypotheses" / "avatar-metadata-render.md"
            text = note.read_text(encoding="utf-8")
            self.assertIn("Status: testing", text)
            self.assertIn("https://canva.com/api/designs?a=1&b=2", text)
            self.assertIn("#avatar", text)
            self.assertIn("Check whether metadata reaches admin review.", text)
            index = note.parents[1] / "index.md"
            self.assertIn("hypotheses/avatar-metadata-render.md", index.read_text(encoding="utf-8"))
            machine_index = json.loads((note.parents[1] / "_index" / "notes.json").read_text(encoding="utf-8"))
            self.assertEqual(machine_index["notes"][0]["urls"], ["https://canva.com/api/designs?a=1&b=2"])
            self.assertIn("FID-123", machine_index["notes"][0]["reports"])
            self.assertIn("avatar", machine_index["notes"][0]["tags"])

    def test_search_and_link_use_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = ["demo", "--family", "web_bounty", "--lane", "web", "--root", tmp]
            bounty_notes.main(
                [
                    "note",
                    *base,
                    "--bucket",
                    "hypotheses",
                    "--title",
                    "Endpoint ownership",
                    "--status",
                    "untested",
                    "--run-id",
                    "run-1",
                    "--body",
                    "Check object ownership.",
                    "--url",
                    "https://canva.com/api/team/1",
                ]
            )
            bounty_notes.main(
                [
                    "note",
                    *base,
                    "--bucket",
                    "handoffs",
                    "--title",
                    "run-1",
                    "--slug",
                    "run-1",
                    "--run-id",
                    "run-1",
                    "--body",
                    "Continue endpoint ownership.",
                    "--link",
                    "hypotheses/endpoint-ownership.md",
                ]
            )
            rc = bounty_notes.main(
                [
                    "link",
                    *base,
                    "--source",
                    "hypotheses/endpoint-ownership.md",
                    "--target",
                    "handoffs/run-1.md",
                    "--relationship",
                    "handoff",
                ]
            )
            self.assertEqual(rc, 0)
            note = Path(tmp) / "web_bounty" / "demo" / "web" / "notes" / "hypotheses" / "endpoint-ownership.md"
            self.assertIn("[[handoffs/run-1]]", note.read_text(encoding="utf-8"))
            by_url = note.parents[1] / "_index" / "by-url.md"
            self.assertIn("[[hypotheses/endpoint-ownership|Endpoint ownership]]", by_url.read_text(encoding="utf-8"))

    def test_artifact_copies_to_scratch_and_writes_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "probe.json"
            src.write_text('{"ok": true}\n', encoding="utf-8")
            rc = bounty_notes.main(
                [
                    "artifact",
                    "demo",
                    "--family",
                    "web_bounty",
                    "--lane",
                    "web",
                    "--root",
                    tmp,
                    "--source",
                    str(src),
                    "--run-id",
                    "run-1",
                    "--note",
                    "baseline response shape",
                ]
            )
            self.assertEqual(rc, 0)
            run_root = Path(tmp) / "web_bounty" / "demo" / "web" / "working" / "scratch" / "run-1"
            self.assertTrue((run_root / "artifacts" / "probe.json").exists())
            manifest = json.loads((run_root / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["artifact_note"], "baseline response shape")


if __name__ == "__main__":
    unittest.main()
