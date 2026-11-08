"""Offline regression for indexing captures made by a shell-wrapped mitmdump."""
import argparse
import importlib.util
from pathlib import Path
import sqlite3

import pytest


def test_bash_wrapper_indexes_real_flow_without_executing_wrapper(tmp_path):
    if not Path('/usr/bin/mitmdump').is_file():
        pytest.skip('system mitmdump reader unavailable')
    from mitmproxy import connection, http
    from mitmproxy.io import FlowWriter
    script = Path(__file__).resolve().parents[1] / 'skills/chromium-test/scripts/mitm_lane.py'
    spec = importlib.util.spec_from_file_location('wrapper_lane', script)
    lane = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lane)
    wrapper = tmp_path / 'mitmdump'
    marker = tmp_path / 'executed'
    wrapper.write_text(f'#!/bin/bash\ntouch {marker}\nexit 99\n')
    wrapper.chmod(0o700)
    flow = http.HTTPFlow(connection.Client(peername=('127.0.0.1', 1234),
                                          sockname=('127.0.0.1', 8080), timestamp_start=1),
                         connection.Server(address=('example.test', 80)))
    flow.request = http.Request.make('GET', 'http://example.test/wrapper-fixture')
    flow.response = http.Response.make(200, b'synthetic')
    capture = tmp_path / 'capture.mitm'
    with capture.open('wb') as output:
        FlowWriter(output).add(flow)
    db = tmp_path / 'private' / 'index.sqlite'
    db.parent.mkdir(mode=0o700)
    args = argparse.Namespace(root=str(tmp_path / 'lanes'), lane='wrapper-lane',
                              mitmdump=str(wrapper), db=str(db), flow_file=str(capture),
                              store_full_requests=True)
    result = lane.index_store(args)
    assert result.get('status') == 'indexed', result
    assert not marker.exists()
    with sqlite3.connect(db) as con:
        assert con.execute('select count(*) from requests').fetchone()[0] == 1
