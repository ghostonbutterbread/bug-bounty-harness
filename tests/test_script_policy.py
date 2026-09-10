import os
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "SCRIPT_POLICY.md"
ROOT_INDEX = ROOT / "scripts" / "README.md"
BOUNTY_TOOLS_SCRIPTS = ROOT / "skills" / "bounty-tools" / "scripts"
BOUNTY_TOOLS_INDEX = BOUNTY_TOOLS_SCRIPTS / "README.md"
SCRIPT_SUFFIXES = {".py", ".sh", ".js", ".ts"}
REQUIRED_RECORD_FIELDS = (
    "**Purpose:**",
    "**Inputs:**",
    "**Outputs:**",
    "**Mutates:**",
    "**Verification:**",
    "**Owner/scope:**",
    "**Last verified:**",
)


def script_files(path: Path, *, include_tests: bool = False) -> list[Path]:
    return sorted(
        child
        for child in path.iterdir()
        if child.is_file()
        and (child.suffix in SCRIPT_SUFFIXES or os.access(child, os.X_OK))
        and (include_tests or not child.name.startswith("test_"))
        and child.name != "README.md"
    )


def script_dirs() -> list[Path]:
    return sorted(
        path
        for path in (ROOT / "skills").glob("*/scripts")
        if any(
            child.is_file()
            and child.suffix in SCRIPT_SUFFIXES
            and not child.name.startswith("test_")
            for child in path.iterdir()
        )
    )


def bounty_tool_category_dirs() -> list[Path]:
    if not BOUNTY_TOOLS_SCRIPTS.is_dir():
        return []
    return sorted(
        path
        for path in BOUNTY_TOOLS_SCRIPTS.iterdir()
        if path.is_dir()
    )


def test_repository_script_policy_defines_owner_based_placement() -> None:
    text = " ".join(POLICY.read_text(encoding="utf-8").lower().split())

    assert "repository-local script policy" in text
    assert "scripts/" in text
    assert "skills/<skill>/scripts/" in text
    assert "skills/<program-skill>/scripts/" in text
    assert "skills/bounty-tools/scripts/<category>/" in text
    assert "abstract reusable bug bounty tool" in text
    assert "vulnerability-class helper" in text
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


def test_bounty_tools_uses_category_indexes() -> None:
    assert BOUNTY_TOOLS_INDEX.is_file()
    root_text = ROOT_INDEX.read_text(encoding="utf-8")
    assert "../skills/bounty-tools/scripts/README.md" in root_text
    assert not script_files(BOUNTY_TOOLS_SCRIPTS, include_tests=True), (
        "Bounty Tools scripts must live in a category"
    )

    parent_text = BOUNTY_TOOLS_INDEX.read_text(encoding="utf-8")
    expected_links: set[str] = set()
    for category in bounty_tool_category_dirs():
        assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", category.name)
        assert category.name not in {"general", "misc", "other"}
        index = category / "README.md"
        assert index.is_file(), f"Bounty Tools category missing README.md: {category}"
        direct_scripts = script_files(category, include_tests=True)
        assert direct_scripts, f"empty Bounty Tools category: {category}"
        nested_scripts = [
            path
            for path in category.rglob("*")
            if path.parent != category
            and path.is_file()
            and (path.suffix in SCRIPT_SUFFIXES or os.access(path, os.X_OK))
            and path.name != "README.md"
        ]
        assert not nested_scripts, (
            f"nested Bounty Tools scripts bypass category inventory: {nested_scripts}"
        )
        expected_links.add(f"{category.name}/README.md")
        assert_index_covers_scripts(category, index, include_tests=True)

    catalog_links = {
        target.removeprefix("./")
        for target in re.findall(r"\[[^]]+\]\(([^)\s]+)\)", parent_text)
        if target.endswith("/README.md")
    }
    assert catalog_links == expected_links, (
        f"Bounty Tools category catalog drift: expected {sorted(expected_links)}, "
        f"found {sorted(catalog_links)}"
    )


def record(text: str, script_name: str) -> str | None:
    match = re.search(
        rf"(?ms)^## `{re.escape(script_name)}`\s*$\n(.*?)(?=^## |\Z)",
        text,
    )
    return match.group(1) if match else None


def assert_index_covers_scripts(
    path: Path, index: Path, *, include_tests: bool = False
) -> None:
    text = index.read_text(encoding="utf-8")
    failures: list[str] = []
    actual = {
        script.name for script in script_files(path, include_tests=include_tests)
    }
    for script_name in sorted(actual):
        section = record(text, script_name)
        if section is None:
            failures.append(f"{index.relative_to(ROOT)} missing record for {script_name}")
            continue
        missing_fields = [field for field in REQUIRED_RECORD_FIELDS if field not in section]
        if missing_fields:
            failures.append(
                f"{index.relative_to(ROOT)} record {script_name} missing {missing_fields}"
            )

    indexed = set(re.findall(r"(?m)^## `([^`]+)`\s*$", text))
    stale = sorted(indexed - actual)
    if stale:
        failures.append(f"{index.relative_to(ROOT)} has stale records {stale}")
    assert not failures, "\n".join(failures)


def test_root_index_has_complete_nonstale_records() -> None:
    assert_index_covers_scripts(ROOT / "scripts", ROOT_INDEX)


def test_each_skill_index_has_complete_nonstale_records() -> None:
    for path in script_dirs():
        assert_index_covers_scripts(path, path / "README.md")


def test_index_verification_commands_are_lane_safe_and_resolve() -> None:
    indexes = [
        ROOT_INDEX,
        *(path / "README.md" for path in script_dirs()),
        *(path / "README.md" for path in bounty_tool_category_dirs()),
    ]
    failures: list[str] = []
    for index in indexes:
        text = index.read_text(encoding="utf-8")
        verification_blocks = re.findall(
            r"(?ms)^- \*\*Verification:\*\*(.*?)(?=^- \*\*[A-Z]|^## |\Z)",
            text,
        )
        for block in verification_blocks:
            normalized = " ".join(block.split())
            if re.search(r"`bbh\s", normalized):
                failures.append(f"{index.relative_to(ROOT)} uses installed bbh for verification")
            if "python3 -m pytest" in normalized:
                failures.append(f"{index.relative_to(ROOT)} bypasses checkout-local test runner")
            for relative in re.findall(
                r"(?:agents|tests|skills|scripts)/[A-Za-z0-9_./-]+\.(?:py|sh|js)",
                normalized,
            ):
                if not (ROOT / relative).is_file():
                    failures.append(f"{index.relative_to(ROOT)} missing verification path {relative}")
    assert not failures, "\n".join(failures)
