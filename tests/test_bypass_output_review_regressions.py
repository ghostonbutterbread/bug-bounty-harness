"""Synthetic regressions for honest bypass output and safe reports."""
import asyncio
from contextlib import asynccontextmanager

import httpx
import pytest

from agents.bypass_types.cors import CORSBypass


@pytest.mark.parametrize('acac,credentialed', [('true', True), ('TRUE', False), ('True', False), ('false', False), (None, False)])
def test_cors_credentials_require_exact_browser_literal(acac, credentialed):
    class Limiter:
        @asynccontextmanager
        async def http(self):
            yield
        def adapt_to_response(self, response):
            pass
    class Client:
        async def get(self, url, headers):
            headers_out = {'Access-Control-Allow-Origin': headers['Origin']}
            if acac is not None:
                headers_out['Access-Control-Allow-Credentials'] = acac
            return httpx.Response(200, headers=headers_out)
    async def probe(category):
        return await CORSBypass()._probe('https://app.example.test/', category,
            'https://attacker.example.test', Client(), asyncio.Semaphore(1), Limiter())
    result = asyncio.run(probe('evil_absolute'))
    assert result.success and not result.incomplete
    assert f'credentials: {str(credentialed).lower()}' in result.evidence
    assert ('with credentials=true' if credentialed else 'without credentials') in result.note
    conditional = asyncio.run(probe('evil_subdomain'))
    assert not conditional.success and conditional.incomplete
    assert f'credentials: {str(credentialed).lower()}' in conditional.evidence


def test_cli_distinguishes_candidates_weak_signals_and_incomplete(monkeypatch, tmp_path, capsys):
    from agents import bypass_harness as h
    from agents.bypass_types import BypassResult
    from agents.bypass_types.race import RaceBypass, RACE_COUNT
    marker = 'synthetic-private-body'
    cors = BypassResult(True, 'cors', 'origin_header', 'evil_absolute', 'origin',
                        'https://app.example.test', 200, marker,
                        'validate browser access and sensitive data')
    response = {'status': 200, 'hash': 'a', 'text': marker}
    burst = [response] * (RACE_COUNT - 1) + [{'status': 200, 'hash': 'b', 'text': marker}]
    race = RaceBypass()._analyse('https://app.example.test', response, burst, 'GET')
    incomplete = BypassResult(False, '403', 'baseline', 'unknown', '',
                              'https://app.example.test', 200, '', 'baseline unknown', True)
    candidate = BypassResult(True, 'ssti', 'test', 'test', '',
                             'https://app.example.test', 200, marker, 'matched marker')
    class FakeOrchestrator:
        def __init__(self, **kwargs):
            self.deferred = {}; self.request_counts = h.RequestCounts(); self.execution_errors = 0
        async def run_bypass(self, *args, **kwargs):
            for result in [cors, *race, incomplete, candidate]:
                yield result
    monkeypatch.setattr(h, 'BypassOrchestrator', FakeOrchestrator)
    hits, misses = asyncio.run(h.run_and_report('https://app.example.test', 'cors', output_dir=str(tmp_path), quiet=True))
    output = capsys.readouterr().out
    assert 'SUCCESSFUL BYPASSES' not in output and '[HIT]' not in output
    assert 'WEAK OBSERVATION' in output and 'INCOMPLETE' in output
    assert 'CANDIDATE' in output and 'validate browser access' in output
    assert 'validate state changes and dynamic content' in output
    assert 'not validated' in output.lower() and marker not in output
    assert len(hits) == 5 and len(misses) == 1  # historical API, not proof


def test_reports_retain_typed_complete_nonhit_race_counts_without_raw_data(tmp_path):
    import json
    from agents import bypass_harness as h
    from agents.bypass_types.race import RaceBypass
    marker = 'synthetic-secret-body-marker'
    statuses = [200, 201, 202, 203, 204, 400, 401, 403, 404, 405, 409, 418, 429, 500, 503]
    baseline = {'status': 200, 'hash': 'same', 'text': marker}
    burst = [{'status': status, 'hash': 'same', 'text': marker} for status in statuses]
    result = RaceBypass()._analyse('https://app.example.test', baseline, burst, 'GET')[0]
    assert not result.success and not result.incomplete
    h._write_report(tmp_path / 'race.txt', [result], 'https://app.example.test', 'race')
    h._write_json(tmp_path / 'race.json', [result], 'https://app.example.test', 'race')
    text = (tmp_path / 'race.txt').read_text()
    data = json.loads((tmp_path / 'race.json').read_text())
    assert all(f'HTTP {status}: 1' in text for status in statuses)
    assert data['schema_version'] == 2 and data['hits'] == [] and data['incomplete_results'] == []
    evidence = data['results'][0]['derived_evidence']
    assert evidence['type'] == 'race' and evidence['baseline_status'] == 200
    assert evidence['status_counts'] == {str(status): 1 for status in statuses}
    assert evidence['errors'] == 0 and evidence['body_variants'] == 1
    assert marker not in text + json.dumps(data)


def test_text_report_matches_cli_for_each_result_and_race_variant(tmp_path):
    from agents import bypass_harness as h
    from agents.bypass_types import BypassResult
    from agents.bypass_types.race import RaceBypass, RACE_COUNT

    secret = 'synthetic-private-body-marker'
    baseline = {'status': 200, 'hash': 'a', 'text': secret}
    varied = {'status': 200, 'hash': 'b', 'text': secret}
    race = RaceBypass()
    complete = race._analyse('https://app.example.test/', baseline, [baseline] * (RACE_COUNT - 1) + [varied], 'GET')
    partial = race._analyse('https://app.example.test/', baseline, [baseline, varied, None], 'GET')
    other = [
        BypassResult(True, 'cors', 'origin', 'reflection', '', 'https://app.example.test/', 200, secret, 'validate browser access'),
        BypassResult(True, 'ssti', 'marker', 'candidate', '', 'https://app.example.test/', 200, secret),
        BypassResult(False, 'ssti', 'marker', 'miss', '', 'https://app.example.test/', 200, secret),
        BypassResult(True, 'ssti', 'marker', 'no_response', '', 'https://app.example.test/', 0, secret),
    ]
    results = complete + partial + other
    h._write_report(tmp_path / 'report.txt', results, 'https://app.example.test/?q=synthetic-secret', 'sweep')
    text = (tmp_path / 'report.txt').read_text()
    assert len(complete) == len(partial) == 3  # aggregate plus two variants
    assert all(h._display_result(result) in text for result in results)
    assert all(h._display_result(result).startswith('[WEAK OBSERVATION]') for result in complete)
    assert all(h._display_result(result).startswith('[INCOMPLETE]') for result in partial)
    assert [h._display_result(result).split(']', 1)[0] + ']' for result in other] == [
        '[WEAK OBSERVATION]', '[CANDIDATE]', '[MISS]', '[INCOMPLETE]']
    assert text.count('validate state changes and dynamic content') == 6
    assert 'not validated bypasses' in text
    assert '[HIT]' not in text and secret not in text and 'synthetic-secret' not in text
    # The legacy Python representation remains unchanged and is not proof.
    assert partial[0].success and '[HIT]' in partial[0].to_line()


def test_race_derived_projection_rejects_untrusted_fields():
    from agents.bypass_redaction import RaceEvidence
    from agents.bypass_types import BypassResult
    marker = 'synthetic-secret-body-marker'
    result = BypassResult(False, 'race', 'test', 'test', '', 'https://app.example.test',
                          200, RaceEvidence(200, {200: marker}, 0, 1))
    assert result.derived_evidence is None
    assert result.evidence == '[response evidence withheld]'
    assert marker not in repr(result)
