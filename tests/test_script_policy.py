from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "SCRIPT_POLICY.md"
ROOT_INDEX = ROOT / "scripts" / "README.md"


def script_dirs() -> list[Path]:
    return sorted(
        path
        for path in (ROOT / "skills").glob("*/scripts")
        if any(
            child.is_file()
            and child.suffix in {".py", ".sh", ".js", ".ts"}
            and not child.name.startswith("test_")
            for child in path.iterdir()
        )
    )


def test_repository_script_policy_defines_owner_based_placement() -> None:
    text = " ".join(POLICY.read_text(encoding="utf-8").lower().split())

    assert "repository-local script policy" in text
    assert "scripts/" in text
    assert "skills/<skill>/scripts/" in text
    assert "skills/<program-skill>/scripts/" in text
    assert "multiple cohesive scripts" in text
    assert "one giant script" in text
    assert "reuse" in text


def test_script_maintenance_lane_cannot_edit_policy() -> None:
    text = " ".join(POLICY.read_text(encoding="utf-8").lower().split())

    assert "script_policy.md" in text
    assert "skill.md" in text
    assert "must not edit" in text


def test_every_skill_script_home_has_an_index() -> None:
    missing = [path.relative_to(ROOT).as_posix() for path in script_dirs() if not (path / "README.md").is_file()]
    assert not missing, f"script homes missing README.md: {missing}"


def test_root_index_links_every_skill_script_index() -> None:
    root_text = ROOT_INDEX.read_text(encoding="utf-8")
    missing = [
        (path / "README.md").relative_to(ROOT).as_posix()
        for path in script_dirs()
        if f"../{(path / 'README.md').relative_to(ROOT).as_posix()}" not in root_text
    ]
    assert not missing, f"root script index missing child indexes: {missing}"


def test_each_skill_index_names_its_scripts() -> None:
    missing: list[str] = []
    for path in script_dirs():
        text = (path / "README.md").read_text(encoding="utf-8")
        for script in path.iterdir():
            if (
                script.is_file()
                and script.suffix in {".py", ".sh", ".js", ".ts"}
                and not script.name.startswith("test_")
                and script.name not in text
            ):
                missing.append(script.relative_to(ROOT).as_posix())
    assert not missing, f"scripts missing from local index: {missing}"
