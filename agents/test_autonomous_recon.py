from __future__ import annotations

from agents.autonomous_recon import ReconResult, _extract_forms


def test_extract_forms_scopes_inputs_per_form() -> None:
    result = ReconResult(
        program="demo",
        target="https://example.com",
        target_host="example.com",
    )

    _extract_forms(
        """
        <html>
          <form action="/login">
            <input name="username" />
            <input name="password" />
          </form>
          <form action="/search">
            <input name="q" />
          </form>
        </html>
        """,
        "https://example.com/account",
        result,
    )

    assert result.forms == [
        {
            "action": "https://example.com/login",
            "inputs": ["username", "password"],
        },
        {
            "action": "https://example.com/search",
            "inputs": ["q"],
        },
    ]
