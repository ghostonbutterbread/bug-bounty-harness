from pathlib import Path

import pytest

from agents.program_docs import main, search


def args(root: Path, *extra: str) -> list[str]:
    return [*extra, "--program", "poster", "--family", "web_bounty", "--lane", "web", "--root", str(root)]


def test_init_creates_docs_readme(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(args(tmp_path, "init")) == 0
    root = tmp_path / "web_bounty" / "poster" / "web" / "docs"
    assert root.exists()
    assert (root / "README.md").exists()
    assert "Do not read this directory broadly" in (root / "README.md").read_text(encoding="utf-8")
    assert str(root) in capsys.readouterr().out


def test_write_creates_structured_cross_linked_doc(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    body = tmp_path / "body.md"
    body.write_text("The export flow creates an asynchronous job scoped to a workspace.\n", encoding="utf-8")

    assert main(args(
        tmp_path,
        "write",
        "--topic", "integrations/poster-sdk-export-flow",
        "--title", "Poster SDK export integration",
        "--body-file", str(body),
        "--source", "https://docs.poster.example/sdk",
        "--mapstore-ref", "recon/maps/_app/poster-sdk/index.md",
        "--recognition", "@imtbl/passport, relayerUrl/v1/transactions",
        "--question", "Does the server bind the submission to the evaluated transaction, account, and session?",
    )) == 0

    path = tmp_path / "web_bounty" / "poster" / "web" / "docs" / "integrations" / "poster-sdk-export-flow.md"
    content = path.read_text(encoding="utf-8")
    assert "topic: integrations/poster-sdk-export-flow" in content
    assert "https://docs.poster.example/sdk" in content
    assert "recon/maps/_app/poster-sdk/index.md" in content
    assert "@imtbl/passport" in content
    assert "Does the server bind the submission" in content
    assert "## Recognition signals" in content
    assert "MapStore pointer: docs/integrations/poster-sdk-export-flow.md" in capsys.readouterr().out


def test_write_rejects_accidental_overwrite(tmp_path: Path) -> None:
    command = args(
        tmp_path, "write", "--topic", "sdk/poster", "--title", "Poster", "--body", "Observed model."
    )
    assert main(command) == 0
    with pytest.raises(FileExistsError):
        main(command)


def test_search_uses_concrete_terms_and_skips_readme(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(args(
        tmp_path,
        "write",
        "--topic", "integrations/poster-sdk",
        "--title", "Poster SDK",
        "--body", "The SDK submits export jobs with workspace authorization.",
        "--status", "partially-verified",
    )) == 0
    root = tmp_path / "web_bounty" / "poster" / "web" / "docs"
    rows = search(root, "sdk workspace")
    assert len(rows) == 1
    assert rows[0]["topic"] == "integrations/poster-sdk"

    assert main(args(tmp_path, "search", "--query", "sdk workspace")) == 0
    output = capsys.readouterr().out
    assert "integrations/poster-sdk | partially-verified | Poster SDK" in output


def test_topic_rejects_traversal(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        main(args(tmp_path, "write", "--topic", "../escape", "--title", "No", "--body", "No."))
