"""Discovery contracts for the canonical Bunny roles (no model calls)."""
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_pi_package_exports_the_existing_role_definitions():
    manifest = ROOT / "skills/bunny/package.json"
    assert manifest.is_file(), "Bunny roles need a Pi package export, not worker aliases"
    package = json.loads(manifest.read_text())
    roots = package["pi"]["subagents"]["agents"]
    assert roots == ["./agents"]
    roles = {}
    for directory in roots:
        for path in (manifest.parent / directory).glob("*.md"):
            _, header, body = path.read_text().split("---", 2)
            metadata = yaml.safe_load(header)
            roles[metadata["name"]] = (metadata, body)
    assert set(roles) == {"bunny-hunter", "bunny-recon", "bunny-verifier", "bunny-reporter"}
    for metadata, body in roles.values():
        assert metadata.get("advertise") is True
        assert "bunny-collaborative" in body
        assert "Do not allocate other workers" in body
