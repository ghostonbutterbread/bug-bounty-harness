"""Guard the canonical storage skill's safe bulk-artifact routing."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1] / "skills" / "bounty-storage"


class BountyStorageSkillContractTest(unittest.TestCase):
    def test_javascript_layout_matches_analyzer_library(self):
        layout = (ROOT / "references" / "storage-layout.md").read_text(encoding="utf-8")
        self.assertIn("_library/downloads/<sha256>.js", layout)
        self.assertIn("_library/ledger.json", layout)
        self.assertNotIn("downloads/by-host/` is the human browse path", layout)

    def test_active_browser_profiles_are_not_shared_or_generic_bulk_artifacts(self):
        entry = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        layout = (ROOT / "references" / "storage-layout.md").read_text(encoding="utf-8")
        playbook = (ROOT.parents[1] / "prompts" / "chromium-test-playbook.md").read_text(encoding="utf-8")
        bulk = entry.split("- `/mnt/bounty`:", 1)[1].split("\n- ", 1)[0]
        self.assertNotIn("browser profiles", bulk)
        self.assertIn("restricted node-local", entry)
        self.assertNotIn("files in `~/Shared` or `/mnt/bounty`", entry)
        self.assertIn("exact location and retention reason", " ".join(entry.split()))
        self.assertNotIn("    browser-profiles/", layout)
        self.assertNotIn('$HARNESS_SHARED_BASE/<program>/ghost/chromium-test/profiles/', playbook)
        self.assertIn("lease-recorded", playbook)
        huge_ingest = (ROOT.parents[1] / "skills" / "huge-ingest" / "SKILL.md").read_text(encoding="utf-8")
        self.assertNotIn("- browser profiles and CDP traces", huge_ingest)
        self.assertIn("restricted node-local", huge_ingest)

    def test_binary_artifacts_and_symlink_reference_are_packaged(self):
        entry = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        layout = (ROOT / "references" / "storage-layout.md").read_text(encoding="utf-8")
        self.assertIn("desktop-app installers", entry)
        self.assertIn("embedded secrets", entry)
        self.assertIn("`references/storage-layout.md`", entry)
        self.assertIn("## Existing Bulk-Artifact Symlinks", layout)
        self.assertIn("Do not replace\nthe symlink with a bulk copy", layout)
        self.assertIn("verify the\nconfigured sync transport's actual link handling", layout)
        self.assertIn("Preserve the original\nuntil the owner approves", layout)
        self.assertNotIn("clear it when Shared bloats", layout)


if __name__ == "__main__":
    unittest.main()
