"""Offline regression tests for the subdomain HTTP probe."""
import asyncio
import contextlib
import gzip
import inspect
import io
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from agents import subdomain_agent as agent


class ProbeRedirectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        for name in ("connect", "connect_ex"):
            p = patch.object(socket.socket, name, side_effect=AssertionError("network blocked"))
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS blocked"))
        p.start()
        self.addCleanup(p.stop)
        p = patch.object(agent, "RECON_BASE", Path(self.temp.name))
        p.start()
        self.addCleanup(p.stop)

    def probe(self, handler, domains=("start.invalid",)):
        requests = []
        async def record(request):
            requests.append(request)
            result = handler(request)
            return await result if inspect.isawaitable(result) else result
        original = httpx.AsyncClient
        def factory(**kwargs):
            return original(transport=httpx.MockTransport(record), **kwargs)
        with patch.object(httpx, "AsyncClient", side_effect=factory):
            results = asyncio.run(agent.probe_all(list(domains)))
        return results, requests

    def test_redirect_is_observed_without_following_or_persisting_secret(self):
        marker = "FAKE_SENSITIVE_8c2f"
        def handler(request):
            if request.url.host == "start.invalid":
                return httpx.Response(302, headers={"Location": "https://destination.invalid/?token=" + marker}, text="<title>" + marker + "</title>")
            return httpx.Response(200, text="<title>" + marker + "</title>")
        results, requests = self.probe(handler)
        out = agent.write_outputs("test", "start.invalid", {"start.invalid"}, ["start.invalid"], results, [])
        data = json.loads((out / "scan_results.json").read_text())
        self.assertEqual(len(requests), 1)
        self.assertNotIn("subdomain_probe_response", requests[0].extensions)
        self.assertEqual(data[0]["status"], 302)
        self.assertEqual(data[0]["title"], "")
        self.assertEqual(data[0]["content_length"], 0)
        self.assertTrue(data[0]["redirect_url"])
        self.assertNotIn(marker, json.dumps(data))
    def test_redirect_variants_never_follow_or_decode(self):
        marker = "FAKE_PRIVATE_MARKER"
        locations = [
            "https://user:" + marker + "@else.invalid/path?token=" + marker + "#" + marker,
            "https://else.invalid:invalid/" + marker,
            "/local/" + marker + "?query=" + marker,
            None,
        ]
        for location in locations:
            with self.subTest(location=location):
                headers = {"Content-Encoding": "gzip"}
                if location is not None:
                    headers["Location"] = location
                results, requests = self.probe(lambda req: httpx.Response(302, headers=headers, stream=httpx.ByteStream(b"not-gzip")))
                self.assertEqual(len(requests), 1)
                result = results[0]
                self.assertEqual(result.status, 302)
                self.assertEqual(result.title, "")
                self.assertEqual(result.content_length, 0)
                self.assertEqual(result.redirect_url, "[redacted]" if location else "")
                self.assertNotIn(marker, json.dumps(result.__dict__))

    def test_redirect_stream_is_closed_without_reading_for_all_3xx(self):
        class Stream(httpx.AsyncByteStream):
            def __init__(self):
                self.read = False
                self.closed = False
            async def __aiter__(self):
                self.read = True
                yield b"<title>SECRET</title>"
            async def aclose(self):
                self.closed = True
        for status in (300, 301, 302, 303, 304, 307, 308, 399):
            with self.subTest(status=status):
                stream = Stream()
                results, requests = self.probe(lambda req: httpx.Response(status, headers={"Location": "/SECRET"}, stream=stream))
                self.assertEqual(len(requests), 1)
                self.assertEqual((results[0].status, results[0].title, results[0].content_length), (status, "", 0))
                self.assertFalse(stream.read)
                self.assertTrue(stream.closed)

    def test_capture_hook_leaves_unrelated_requests_unmodified(self):
        async def exercise():
            async with httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(200, text="ok")), event_hooks={"response": [agent._capture_probe_response]}) as client:
                response = await client.get("https://other.invalid")
                self.assertEqual(response.text, "ok")
                self.assertNotIn("subdomain_probe_response", response.request.extensions)
                self.assertEqual(client.event_hooks["response"], [agent._capture_probe_response])
        asyncio.run(exercise())

    def test_successful_title_and_gzip_are_preserved(self):
        body = b"<html><title>Normal page</title></html>"
        results, requests = self.probe(lambda req: httpx.Response(200, headers={"Content-Encoding": "gzip"}, content=gzip.compress(body)))
        self.assertEqual(len(requests), 1)
        self.assertEqual((results[0].status, results[0].title, results[0].content_length), (200, "Normal page", len(body)))
        self.assertEqual(results[0].redirect_url, "")

    def test_only_no_response_causes_http_fallback_and_errors_are_silent(self):
        marker = "FAKE_EXCEPTION_SECRET"
        def handler(req):
            if req.url.scheme == "https":
                raise httpx.ConnectError("failed https://user:" + marker + "@host/?token=" + marker, request=req)
            return httpx.Response(200, text="<title>Fallback</title>")
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            results, requests = self.probe(handler)
        self.assertEqual([r.url.scheme for r in requests], ["https", "http"])
        self.assertEqual((results[0].status, results[0].title), (200, "Fallback"))
        self.assertNotIn(marker, output.getvalue())
        self.assertNotIn(marker, json.dumps(results[0].__dict__))

    def test_no_response_on_either_scheme_yields_zero(self):
        def handler(req):
            raise httpx.ConnectError("sensitive https://example.invalid/?secret=SECRET", request=req)
        results, requests = self.probe(handler)
        self.assertEqual([r.url.scheme for r in requests], ["https", "http"])
        self.assertEqual(results[0].status, 0)

    def test_non_redirect_corrupt_body_retains_received_status(self):
        results, requests = self.probe(lambda req: httpx.Response(200, headers={"Content-Encoding": "gzip"}, stream=httpx.ByteStream(b"invalid")))
        self.assertEqual(len(requests), 1)
        self.assertEqual((results[0].status, results[0].title, results[0].content_length), (200, "", 0))

    def test_concurrent_responses_do_not_share_state(self):
        async def handler(req):
            await asyncio.sleep(0)
            if req.url.host.startswith("redirect"):
                return httpx.Response(302, headers={"Location": "https://bad.invalid:bad/SECRET"})
            return httpx.Response(200, text="<title>" + req.url.host + "</title>")
        domains = tuple(f"{'redirect' if i % 2 else 'ok'}{i}.invalid" for i in range(30))
        results, requests = self.probe(handler, domains)
        self.assertEqual(len(requests), len(domains))
        self.assertEqual(len(results), len(domains))
        for result in results:
            if result.subdomain.startswith("redirect"):
                self.assertEqual((result.status, result.title, result.redirect_url), (302, "", "[redacted]"))
            else:
                self.assertEqual((result.status, result.title), (200, result.subdomain))

    def test_response_hooks_close_stream_and_do_not_trigger_retry(self):
        requests, streams = [], []
        class Stream(httpx.AsyncByteStream):
            closed = False
            async def __aiter__(self):
                yield b"body"
            async def aclose(self):
                self.closed = True
        async def fail_after_capture(response):
            raise RuntimeError("FAKE_SECRET_IN_HOOK")
        original = httpx.AsyncClient
        def handler(request):
            requests.append(request)
            stream = Stream()
            streams.append(stream)
            return httpx.Response(302, headers={"Location": "https://other.invalid/?token=SECRET"}, stream=stream)
        def factory(**kwargs):
            kwargs["follow_redirects"] = True
            kwargs["event_hooks"]["response"].append(fail_after_capture)
            return original(transport=httpx.MockTransport(handler), **kwargs)
        with patch.object(httpx, "AsyncClient", side_effect=factory):
            results = asyncio.run(agent.probe_all(["start.invalid"]))
        self.assertEqual(len(requests), 1)
        self.assertEqual((results[0].status, results[0].redirect_url), (302, "[redacted]"))
        self.assertTrue(streams[0].closed)

    def test_cancelled_after_headers_closes_response_and_propagates(self):
        streams = []
        class Stream(httpx.AsyncByteStream):
            closed = False
            async def __aiter__(self):
                yield b"body"
            async def aclose(self):
                self.closed = True
        async def cancel(response):
            raise asyncio.CancelledError()
        original = httpx.AsyncClient
        def handler(request):
            stream = Stream()
            streams.append(stream)
            return httpx.Response(302, headers={"Location": "/test"}, stream=stream)
        def factory(**kwargs):
            kwargs["event_hooks"]["response"].append(cancel)
            return original(transport=httpx.MockTransport(handler), **kwargs)
        with patch.object(httpx, "AsyncClient", side_effect=factory), self.assertRaises(asyncio.CancelledError):
            asyncio.run(agent.probe_all(["start.invalid"]))
        self.assertEqual(len(streams), 1)
        self.assertTrue(streams[0].closed)

    def test_run_recon_store_receives_only_redacted_artifacts(self):
        marker = "FAKE_STORE_SECRET"
        real_client = httpx.AsyncClient
        def factory(**kwargs):
            return real_client(transport=httpx.MockTransport(lambda req: httpx.Response(302, headers={"Location": "https://user:" + marker + "@other.invalid/?token=" + marker}, text="<title>" + marker + "</title>")), **kwargs)
        captured = {}
        def store(**kwargs):
            captured.update({p.name: p.read_text() for p in kwargs["source_paths"]})
            return "synthetic-manifest"
        class Collector:
            def __init__(self, *args): pass
            def from_crtsh(self): return {"start.invalid"}
            def from_js_files(self): return set()
            def from_local_urls(self): return set()
            def from_mutations(self, subs): return set()
        with patch.object(httpx, "AsyncClient", side_effect=factory), patch.object(agent, "SubdomainCollector", Collector), patch.object(agent, "_which", return_value=None), patch.object(agent, "record_recon_artifacts", side_effect=store):
            agent.run("start.invalid", "test", ["crtsh"], None, 2, False, False, True)
        self.assertEqual(set(captured), {"raw_subs.txt", "all_subs.txt", "alive_subs.txt", "dead_subs.txt", "takeover_candidates.txt", "scan_results.json", "summary.json"})
        self.assertNotIn(marker, json.dumps(captured))
        record = json.loads(captured["scan_results.json"])[0]
        self.assertEqual((record["status"], record["redirect_url"], record["title"]), (302, "[redacted]", ""))


if __name__ == "__main__":
    unittest.main()
