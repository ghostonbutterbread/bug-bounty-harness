from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REVIEWED_CORE_SHA = "8cc64e68bc93919573c5e3cb2662283889d7858c"


class RuntimeDependencyTests(unittest.TestCase):
    def test_single_manifest_preserves_runtime_and_test_dependencies(self) -> None:
        manifest = ROOT / "requirements.txt"
        self.assertTrue(manifest.is_file(), "checkout must provide requirements.txt")
        requirements = [
            line.strip() for line in manifest.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertCountEqual(requirements, [
            "bounty-core @ git+https://github.com/ghostonbutterbread/bounty-core.git@"
            + REVIEWED_CORE_SHA,
            "httpx>=0.28,<1",
            "pytest>=9,<10",
            "requests>=2.34,<3",
            "PyYAML>=6,<7",
            "beautifulsoup4>=4.15,<5",
            "websocket-client>=1.9,<2",
            "aiohttp>=3.12,<4",
        ])
        self.assertEqual(sorted(p.name for p in ROOT.glob("requirements*.txt")),
                         ["requirements.txt"])

    def test_setup_installs_canonical_manifest_from_another_directory(self) -> None:
        # Exercise the actual setup entry point without network/package side effects.
        with tempfile.TemporaryDirectory(prefix="bbh setup ") as directory:
            root = Path(directory)
            checkout = root / "checkout with spaces"
            checkout.mkdir()
            shutil.copy2(ROOT / "setup.sh", checkout / "setup.sh")
            (checkout / "requirements.txt").write_text("# fixture\n", encoding="utf-8")
            bin_dir = root / "bin"
            bin_dir.mkdir()
            log = root / "uv-args"
            uv = bin_dir / "uv"
            uv.write_text('#!/bin/bash\nprintf "%s\\n" "$@" >> "$UV_LOG"\n', encoding="utf-8")
            uv.chmod(0o755)
            python = checkout / ".venv/bin/python"
            python.parent.mkdir(parents=True)
            python.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
            python.chmod(0o755)
            env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", UV_LOG=str(log))
            result = subprocess.run(
                ["bash", str(checkout / "setup.sh"), "--install-python-deps"],
                cwd=root, env=env, text=True, capture_output=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(log.read_text(encoding="utf-8").splitlines(), [
                "venv", "--allow-existing", "--python", "3.11", str(checkout / ".venv"),
                "pip", "install", "--python", str(python),
                "--upgrade-package", "bounty-core", "--refresh-package", "bounty-core",
                "-r", str(checkout / "requirements.txt"),
            ])


if __name__ == "__main__":
    unittest.main()
