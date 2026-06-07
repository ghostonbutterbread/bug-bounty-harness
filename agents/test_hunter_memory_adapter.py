import json
from pathlib import Path

from agents.hunter_memory_adapter import build_hunter_memory_ref, harvest_hunter_memory_from_log


def test_hunter_memory_adapter_harvests_attempts_and_claims(tmp_path: Path) -> None:
    ref = build_hunter_memory_ref(
        program="adapter-smoke",
        agent_key="xss",
        vulnerability="xss",
        surface="file-upload",
        goal="learn upload behavior",
        target="/tmp/target",
        root=tmp_path,
    )
    assert ref.enabled
    assert ref.agent_path is not None

    log_path = tmp_path / "agent.log"
    log_path.write_text(
        """
```hunter-memory-attempts
{"goal":"learn upload behavior","action":"sent benign upload","result":"inconclusive","observation":"accepted png","interpretation":"content-type allowed","learning":"png path works","next_action":"try filename reflection","evidence_refs":["evidence/upload.txt"]}
{"goal":"learn upload behavior","action":"sent Cookie: sessionid=abc123","result":"blocked","observation":"Authorization: Bearer verysecretvalue","interpretation":"token should redact","learning":"password=secret","next_action":"stop","evidence_refs":[]}
```
```hunter-memory-claims
{"claim":"Upload accepts png baseline","status":"confirmed","confidence":"medium"}
```
""",
        encoding="utf-8",
    )

    result = harvest_hunter_memory_from_log(log_path, ref)
    assert result["attempts"] == 2
    assert result["claims"] == 1
    assert result["errors"] == []

    attempts_path = ref.agent_path / "attempts.jsonl"
    rows = [json.loads(line) for line in attempts_path.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 2
    assert rows[0]["learning"] == "png path works"
    assert "abc123" not in json.dumps(rows[1])
    assert "verysecretvalue" not in json.dumps(rows[1])
    assert "secret" not in rows[1]["learning"]

    claims_path = ref.run_path / "claims.jsonl"
    claims = [json.loads(line) for line in claims_path.read_text(encoding="utf-8").splitlines()]
    assert claims[0]["claim"] == "Upload accepts png baseline"


def test_hunter_memory_adapter_ignores_missing_disabled_ref(tmp_path: Path) -> None:
    log_path = tmp_path / "agent.log"
    log_path.write_text("{}", encoding="utf-8")

    result = harvest_hunter_memory_from_log(log_path, None)

    assert result == {"enabled": False, "attempts": 0, "claims": 0, "errors": []}

