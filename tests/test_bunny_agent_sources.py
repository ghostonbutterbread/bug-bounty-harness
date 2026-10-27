"""One physical source per reusable Bunny worker definition."""

from pathlib import Path
import io
import subprocess
import tarfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
ROLES = ("hunter", "recon", "verifier", "reporter")


class BunnyAgentSourcesTest(unittest.TestCase):
    def test_canonical_roles_are_regular_files_under_root_agents(self):
        for role in ROLES:
            name = f"bunny-{role}"
            source = ROOT / "agents" / f"{name}.md"
            with self.subTest(role=role):
                self.assertTrue(source.is_file())
                self.assertFalse(source.is_symlink())
                body = source.read_text(encoding="utf-8")
                self.assertTrue(body.startswith(f"---\nname: {name}\n"))
                self.assertIn("description: ", body)
                self.assertIn("load `bunny-collaborative`", body)
                self.assertIn("Do not allocate other workers", body)

    def test_skill_packaging_reads_the_same_canonical_files(self):
        for role in ROLES:
            name = f"bunny-{role}.md"
            source = ROOT / "agents" / name
            packaged = ROOT / "skills" / "bunny" / "agents" / name
            with self.subTest(role=role):
                self.assertTrue(packaged.is_symlink())
                self.assertEqual(packaged.resolve(strict=True), source.resolve(strict=True))
                self.assertEqual(packaged.read_bytes(), source.read_bytes())

    def test_git_archive_preserves_complete_package(self):
        # The index includes the migration before its first commit.
        tree = subprocess.run(
            ["git", "write-tree"], cwd=ROOT, text=True,
            capture_output=True, check=True,
        ).stdout.strip()
        archive = subprocess.run(
            ["git", "archive", tree, "agents", "skills/bunny/agents"],
            cwd=ROOT, capture_output=True, check=True,
        ).stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as package:
            for role in ROLES:
                name = f"bunny-{role}.md"
                canonical = package.getmember(f"agents/{name}")
                exported = package.getmember(f"skills/bunny/agents/{name}")
                with self.subTest(role=role):
                    self.assertTrue(canonical.isfile())
                    self.assertTrue(exported.issym())
                    self.assertEqual(exported.linkname, f"../../../agents/{name}")
                    stream = package.extractfile(canonical)
                    self.assertIsNotNone(stream)
                    assert stream is not None
                    self.assertEqual(
                        stream.read(), (ROOT / "agents" / name).read_bytes(),
                    )


if __name__ == "__main__":
    unittest.main()
