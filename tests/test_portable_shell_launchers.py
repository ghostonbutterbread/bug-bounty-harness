from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PortableShellLauncherTests(unittest.TestCase):
    def test_run_zdt_anchors_to_its_own_checkout(self) -> None:
        path = ROOT / "run_zdt.sh"
        text = path.read_text(encoding="utf-8")
        self.assertIn("BASH_SOURCE", text)
        self.assertNotIn("~/projects/bug_bounty_harness", text)
        subprocess.run(["bash", "-n", str(path)], check=True)

    def test_legacy_skill_sync_uses_its_own_checkout_without_pulling_stable(self) -> None:
        path = ROOT / "sync_ghost.sh"
        text = path.read_text(encoding="utf-8")
        self.assertIn("BASH_SOURCE", text)
        self.assertNotIn("${HOME}/projects/bug_bounty_harness", text)
        self.assertNotIn("git pull --ff-only origin master", text)
        subprocess.run(["bash", "-n", str(path)], check=True)


if __name__ == "__main__":
    unittest.main()
