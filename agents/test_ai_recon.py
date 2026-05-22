from __future__ import annotations

from unittest.mock import Mock, patch

from agents.ai_recon import AIReconAgent


def test_ai_recon_scope_fallback_accepts_exact_and_subdomain_hosts_only(tmp_path) -> None:
    agent = AIReconAgent("demo", ["example.com"], results_dir=str(tmp_path))
    agent.scope = None

    assert agent.is_in_scope("https://example.com/admin") is True
    assert agent.is_in_scope("https://api.example.com/admin") is True
    assert agent.is_in_scope("https://example.com.evil.test/admin") is False
    assert agent.is_in_scope("https://evil-example.com/admin") is False


def test_ai_recon_execute_dorks_filters_tavily_lookalike_domains(tmp_path) -> None:
    agent = AIReconAgent("demo", ["example.com"], results_dir=str(tmp_path))
    agent.scope = None

    response = Mock()
    response.status_code = 200
    response.text = "{}"
    response.json.return_value = {
        "results": [
            {"url": "https://api.example.com/admin", "content": "valid"},
            {"url": "https://example.com.evil.test/admin", "content": "lookalike"},
            {"url": "https://evil-example.com/admin", "content": "lookalike"},
        ]
    }

    with patch("agents.ai_recon.TAVILY_API_KEY", "test-key"), patch("agents.ai_recon.httpx.post", return_value=response):
        findings = agent._execute_dorks(["site:example.com inurl:admin"], max_dorks=1)

    assert [finding.url for finding in findings] == ["https://api.example.com/admin"]
    assert findings[0].target_domain == "example.com"


def test_ai_recon_perplexity_fallback_rejects_lookalike_domains(tmp_path) -> None:
    agent = AIReconAgent("demo", ["example.com"], results_dir=str(tmp_path))
    agent.scope = None

    response = Mock()
    response.status_code = 200
    response.text = "ok"
    response.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": "\n".join(
                        [
                            "URL: https://api.example.com/admin",
                            "URL: https://example.com.evil.test/admin",
                            "URL: https://evil-example.com/admin",
                        ]
                    )
                }
            }
        ]
    }

    with patch("agents.ai_recon.PERPLEXITY_API_KEY", "test-key"), patch("agents.ai_recon.httpx.post", return_value=response):
        findings = agent._execute_dorks_via_perplexity(["site:example.com inurl:admin"])

    assert [finding.url for finding in findings] == ["https://api.example.com/admin"]
    assert findings[0].target_domain == "example.com"
