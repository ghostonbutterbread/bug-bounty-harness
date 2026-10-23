"""Guard the canonical storage skill's safe bulk-artifact routing."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1] / "skills" / "bounty-storage"


class BountyStorageSkillContractTest(unittest.TestCase):
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
