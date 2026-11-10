from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/nebula-browser-lane/SKILL.md"
REGISTRY = ROOT / "SKILL_REGISTRY.md"


def test_nebula_lane_replaces_portafort_facts() -> None:
    text = SKILL.read_text(encoding="utf-8")
    assert "name: nebula-browser-lane" in text
    assert "portafort" not in text.lower()
    assert "192.168.0.146" not in text
    assert "google-chrome-stable" in text
    assert "100.124.250.25" in text
    assert "nebula_ed25519" in text
    assert "SHA256:F0GSROTz2q14wRX9TxfuRyRGEQTmRg+uIERSMrgAJnM" in text
    assert "/tmp/nebula-lane.lock" in text
    assert 'echo "nebula lane locked; defer"' in text
    assert "$HOME/AI/nebula-lane/chrome-profile" in text
    assert "WAYLAND_DISPLAY=wayland-0" in text
    assert "DISPLAY=:0" in text
    assert "mullvad_exit_ip: true" in text
    assert "Firefox is off-limits" in text
    assert "Do not copy the private key" in text
    assert "BEGIN OPENSSH PRIVATE KEY" not in text
    assert "skills/nebula-browser-lane/SKILL.md" in REGISTRY.read_text(encoding="utf-8")


def test_description_is_quoted_and_index_sized() -> None:
    lines = SKILL.read_text(encoding="utf-8").splitlines()
    description = next(line for line in lines if line.startswith("description:"))
    assert description.startswith('description: "')
    assert description.endswith('"')
    body = description.removeprefix('description: "').removesuffix('"')
    assert body == "Captcha/login or CF/DataDome after GPU: Nebula Chrome"
    assert len(body) <= 60
