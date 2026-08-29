from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("worktree_lifecycle", ROOT / "scripts" / "worktree_lifecycle.py")
assert SPEC and SPEC.loader
lifecycle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lifecycle)


class WorktreeLifecycleTests(unittest.TestCase):
    def test_frontmatter_reads_v1_dossier(self) -> None:
        meta = lifecycle.frontmatter("---\nlifecycle: bbh-worktree/v1\nbranch: feat/demo\n---\nbody\n")
        self.assertEqual(meta["lifecycle"], "bbh-worktree/v1")
        self.assertEqual(meta["branch"], "feat/demo")

    def test_classify_requires_dossier_for_clean_feature(self) -> None:
        with patch.object(lifecycle, "run", return_value=""), patch.object(lifecycle, "dossier", return_value=None):
            state, _ = lifecycle.classify({"branch": "feat/demo", "path": "/tmp/demo"}, "beta", 7)
        self.assertEqual(state, "missing-dossier")

    def test_classify_reports_dirty_without_retirement(self) -> None:
        meta = {"branch": "feat/demo", "target": "beta"}
        with patch.object(lifecycle, "run", return_value="M tracked.py"), patch.object(lifecycle, "dossier", return_value=("docs/integrations/demo.md", meta)):
            state, detail = lifecycle.classify({"branch": "feat/demo", "path": "/tmp/demo"}, "beta", 7)
        self.assertEqual(state, "dirty")
        self.assertIn("never auto-remove", detail)

    def test_classify_recognizes_contained_branch(self) -> None:
        meta = {"branch": "feat/demo", "target": "beta"}
        with patch.object(lifecycle, "run", return_value=""), patch.object(lifecycle, "dossier", return_value=("docs/integrations/demo.md", meta)), patch.object(lifecycle, "is_ancestor", return_value=True):
            state, _ = lifecycle.classify({"branch": "feat/demo", "path": "/tmp/demo"}, "beta", 7)
        self.assertEqual(state, "merged-cleanup")

    def test_classify_recognizes_patch_equivalence(self) -> None:
        meta = {"branch": "feat/demo", "target": "beta"}
        with patch.object(lifecycle, "run", return_value=""), patch.object(lifecycle, "dossier", return_value=("docs/integrations/demo.md", meta)), patch.object(lifecycle, "is_ancestor", return_value=False), patch.object(lifecycle, "has_unique", return_value=False):
            state, _ = lifecycle.classify({"branch": "feat/demo", "path": "/tmp/demo"}, "beta", 7)
        self.assertEqual(state, "patch-equivalent-cleanup")


if __name__ == "__main__":
    unittest.main()
