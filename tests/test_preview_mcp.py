import json
import stat
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import preview_mcp  # noqa: E402


def test_load_key_file_reads_simple_key_value_file(tmp_path):
    key_file = tmp_path / "preview.env"
    key_file.write_text("# local only\nexport PREVIEW_API_KEY='rk_test'\n", encoding="utf-8")
    key_file.chmod(0o600)

    assert preview_mcp.load_key_file(key_file) == "rk_test"


def test_load_key_file_rejects_insecure_permissions(tmp_path):
    key_file = tmp_path / "preview.env"
    key_file.write_text("PREVIEW_API_KEY=rk_test\n", encoding="utf-8")
    key_file.chmod(0o644)

    try:
        preview_mcp.load_key_file(key_file)
    except ValueError as exc:
        assert "permissions" in str(exc)
    else:
        raise AssertionError("insecure key file was accepted")


def test_search_uses_json_body_and_key_header():
    response = MagicMock()
    response.read.return_value = b'{"count": 0, "results": []}'
    response.__enter__.return_value = response
    with patch.object(preview_mcp, "urlopen", return_value=response) as urlopen_mock:
        result = preview_mcp.search(
            endpoint="https://example.test/search",
            api_key="rk_test",
            query="DOM clobbering",
            k=5,
            min_score=0.1,
            candidates=40,
            full_content=False,
            timeout=5,
        )

    request = urlopen_mock.call_args.args[0]
    assert result == {"count": 0, "results": []}
    assert request.full_url == "https://example.test/search"
    assert request.get_header("X-api-key") == "rk_test"
    assert json.loads(request.data) == {
        "query": "DOM clobbering", "k": 5, "min_score": 0.1, "candidates": 40,
    }
