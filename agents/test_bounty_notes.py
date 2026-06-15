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
                ]
            )
            self.assertEqual(rc, 0)
            note = Path(tmp) / "web_bounty" / "demo" / "web" / "notes" / "hypotheses" / "avatar-metadata-render.md"
            text = note.read_text(encoding="utf-8")
            self.assertIn("Status: testing", text)
            self.assertIn("Check whether metadata reaches admin review.", text)
            index = note.parents[1] / "index.md"
            self.assertIn("hypotheses/avatar-metadata-render.md", index.read_text(encoding="utf-8"))

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
