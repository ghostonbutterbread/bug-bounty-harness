from __future__ import annotations

from pathlib import Path
from unittest.mock import patch
import hashlib
import json
import os
import sqlite3
from argparse import Namespace

import pytest

from agents import js_analyzer as J


@pytest.mark.parametrize("shared_map_body", [False, True])
def test_identical_bundles_at_distinct_urls_preserve_source_map_packets(tmp_path: Path, shared_map_body: bool):
    urls = ["https://app.example.com/one/app.js", "https://app.example.com/two/app.js"]
    source = tmp_path / "urls.txt"
    source.write_text("\n".join(urls) + "\n")
    maps = {url + ".map": json.dumps({"version": 3, "sources": ["src/app.ts"],
             "sourcesContent": [f"export const origin = '{urls[0] if shared_map_body else url}';"]}).encode() for url in urls}

    def fetch_map(url: str, *, timeout: int, max_bytes: int):
        return maps[url], 200, "application/json", False

    with patch.object(J, "http_get", return_value=(b"//# sourceMappingURL=app.js.map\n", 200, "application/javascript")), patch.object(J, "http_get_limited", side_effect=fetch_map):
        assert J.main(["inventory", "demo", "--input", str(source), "--target-host", "example.com", "--output-root", str(tmp_path / "out"), "--library-root", str(tmp_path / "lib"), "--integration-index-root", str(tmp_path / "integrations")]) == 0
    rows = J.read_jsonl(tmp_path / "out" / "source_map_modules.jsonl")
    metadata = J.read_jsonl(tmp_path / "out" / "metadata.jsonl")
    packets = J.read_jsonl(tmp_path / "out" / "packets.jsonl")
    assert len(rows) == 2
    assert len({row["packet_paths"][0] for row in rows}) == 2
    for row in rows:
        packet = Path(row["packet_paths"][0]).read_text()
        assert f"- Bundle URL: {row['bundle_url']}\n" in packet
        assert f"export const origin = '{urls[0] if shared_map_body else row['bundle_url']}';" in packet
        own = next(item for item in metadata if item["url"] == row["bundle_url"])
        assert row["packet_paths"][0] in own["packet_paths"]
        assert row["packet_paths"][0] in own["artifact_links"]["packets"]
        assert all(other["bundle_url"] == own["url"] or other["packet_paths"][0] not in own["packet_paths"] for other in rows)
        assert any(item["url"] == own["url"] and item["packet_path"] == row["packet_paths"][0] for item in packets)


def test_identical_bundles_keep_bundle_packets_and_metadata_url_specific(tmp_path: Path):
    urls = ["https://app.example.com/one/app.js", "https://app.example.com/two/app.js"]
    source = tmp_path / "urls.txt"
    source.write_text("\n".join(urls) + "\n")
    with patch.object(J, "http_get", return_value=(b"const same = true;", 200, "application/javascript")):
        assert J.main(["inventory", "demo", "--input", str(source), "--target-host", "example.com", "--output-root", str(tmp_path / "out"), "--library-root", str(tmp_path / "lib"), "--integration-index-root", str(tmp_path / "integrations")]) == 0
    metadata = J.read_jsonl(tmp_path / "out" / "metadata.jsonl")
    packets = J.read_jsonl(tmp_path / "out" / "packets.jsonl")
    assert [row["url"] for row in metadata] == urls
    assert metadata[0]["sha256"] == metadata[1]["sha256"]
    assert len({packet["packet_path"] for packet in packets}) == len(packets)
    for row in metadata:
        own = [packet["packet_path"] for packet in packets if packet["url"] == row["url"]]
        assert row["packet_paths"] == own
        assert f"- URL: {row['url']}\n" in Path(own[0]).read_text()


def test_identical_bundles_keep_metadata_provenance_url_specific(tmp_path: Path):
    urls = ["https://app.example.com/one/app.js", "https://app.example.com/two/app.js"]
    source = tmp_path / "urls.txt"
    source.write_text("\n".join(urls) + "\n")
    hints = tmp_path / "hints.jsonl"
    hints.write_text("\n".join(json.dumps({"js_url": url, "page_url": f"https://app.example.com/page-{i}", "proxy_request_id": f"req-{i}"}) for i, url in enumerate(urls)) + "\n")
    with patch.object(J, "http_get", return_value=(b"const same = true;", 200, "application/javascript")):
        assert J.main(["inventory", "demo", "--input", str(source), "--target-host", "example.com", "--output-root", str(tmp_path / "out"), "--library-root", str(tmp_path / "lib"), "--integration-index-root", str(tmp_path / "integrations"), "--provenance-input", str(hints)]) == 0
    metadata = J.read_jsonl(tmp_path / "out" / "metadata.jsonl")
    assert len(J.read_jsonl(tmp_path / "out" / "js_provenance.jsonl")) == 2
    for i, row in enumerate(metadata):
        assert row["provenance"]["row_count"] == 1
        assert row["provenance"]["page_urls"] == [f"https://app.example.com/page-{i}"]
        assert row["provenance"]["proxy_request_ids"] == [f"req-{i}"]


def test_cached_source_map_obeys_lowered_byte_cap_without_refetch(tmp_path: Path):
    source = tmp_path / "urls.txt"
    source.write_text("https://app.example.com/app.js\n")
    body = json.dumps({"version": 3, "sources": ["src/app.ts"], "sourcesContent": ["export const long = '" + "x" * 100 + "';"]}).encode()
    common = ["inventory", "demo", "--input", str(source), "--target-host", "example.com", "--library-root", str(tmp_path / "lib"), "--integration-index-root", str(tmp_path / "integrations")]
    map_reads = []
    real_open = Path.open

    class TrackedMapFile:
        def __init__(self, file):
            self.file = file

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.file.__exit__(*args)

        def read(self, size=-1):
            map_reads.append(size)
            return self.file.read(size)

    def track_map_open(path, *args, **kwargs):
        file = real_open(path, *args, **kwargs)
        return TrackedMapFile(file) if path.suffix == ".map" else file

    with patch.object(J, "http_get", return_value=(b"//# sourceMappingURL=app.js.map\n", 200, "application/javascript")), patch.object(J, "http_get_limited", return_value=(body, 200, "application/json", False)) as fetch:
        assert J.main(common + ["--output-root", str(tmp_path / "first"), "--run-id", "first"]) == 0
        with patch.object(Path, "open", track_map_open), patch.object(J, "is_source_map_body", wraps=J.is_source_map_body) as validate_map:
            assert J.main(common + ["--output-root", str(tmp_path / "second"), "--run-id", "second", "--source-map-max-bytes", "10"]) == 0
        validate_map.assert_not_called()
    assert map_reads == [11]
    assert fetch.call_count == 1
    metadata = J.read_jsonl(tmp_path / "second" / "metadata.jsonl")[0]
    manifest = json.loads((tmp_path / "second" / "manifest.json").read_text())
    assert metadata["source_map_status"] == "too_large"
    assert metadata["source_map_sha256"] == ""
    assert metadata["source_map_artifact_path"] == ""
    assert metadata["source_map_module_count"] == 0
    assert J.read_jsonl(tmp_path / "second" / "source_map_modules.jsonl") == []
    assert manifest["source_maps_reused"] == 0
    assert manifest["source_maps_too_large"] == 1


def test_default_inventory_paths_use_mounted_bounty_program_js_root():
    root, library, integrations, summary = J.resolve_inventory_paths(Namespace(program="demo", config=None, output_root=None, library_root=None, integration_index_root=None), "run-1")

    assert root == Path("/mnt/bounty/demo/web/recon/js/run-1")
    assert library == Path("/mnt/bounty/demo/web/recon/js/_library")
    assert integrations == Path("/mnt/bounty/demo/web/intel/integrations")
    assert summary["program_root"] == "/mnt/bounty/demo"


def test_write_text_atomic_publishes_complete_packet_without_temp_file(tmp_path: Path):
    packet_path = tmp_path / "packets" / "packet.md"

    J.write_text_atomic(packet_path, "complete packet\n")

    assert packet_path.read_text(encoding="utf-8") == "complete packet\n"
    assert os.stat(packet_path).st_mode & 0o777 == 0o644
    assert list(packet_path.parent.glob(".*.tmp")) == []


def test_write_text_atomic_removes_temp_file_when_write_fails(tmp_path: Path):
    packet_path = tmp_path / "packets" / "packet.md"

    with pytest.raises(TypeError):
        J.write_text_atomic(packet_path, object())  # type: ignore[arg-type]

    assert not packet_path.exists()
    assert list(packet_path.parent.glob(".*.tmp")) == []


def test_write_text_atomic_respects_restrictive_umask(tmp_path: Path):
    packet_path = tmp_path / "packets" / "packet.md"
    previous_umask = os.umask(0o077)
    try:
        J.write_text_atomic(packet_path, "sensitive packet\n")
    finally:
        os.umask(previous_umask)

    assert os.stat(packet_path).st_mode & 0o777 == 0o600


def test_extract_signals_finds_endpoints_params_and_sinks():
    text = """
    const url = "/api/v1/login?return_to=/home";
    fetch(url, {body: JSON.stringify({user_id: localStorage.uid})});
    document.querySelector('#out').innerHTML = location.hash;
    //# sourceMappingURL=app.js.map
    """
    signals = J.extract_signals(text, "https://app.example.com/static/app.js")

    assert "https://app.example.com/api/v1/login?return_to=/home" in signals["endpoints"]
    assert "return_to" in signals["params"]
    assert signals["source_map"] == "https://app.example.com/static/app.js.map"
    assert "storage" in signals["sources"]
    assert "location" in signals["sources"]
    assert "request" in signals["sinks"]
    assert "dom_write" in signals["sinks"]
    assert "auth" in signals["flow_hints"]
    assert "user_id" in signals["interesting_keys"]


@pytest.mark.parametrize(
    ("snippet", "bucket"),
    [
        ("node.innerHTML = value", "dom_write"),
        ("node['outerHTML'] += value", "dom_write"),
        ("node.insertAdjacentHTML('beforeend', value)", "dom_write"),
        ("document.writeln(value)", "dom_write"),
        ("node.setHTMLUnsafe(value)", "html_parse"),
        ("Document.parseHTMLUnsafe(value)", "html_parse"),
        ("range.createContextualFragment(value)", "html_parse"),
        ("new DOMParser().parseFromString(value, 'text/html')", "html_parse"),
        ("iframe.srcdoc = value", "iframe_srcdoc"),
        ("iframe.setAttribute('srcdoc', value)", "iframe_srcdoc"),
        ("iframe.attributes.srcdoc.nodeValue = value", "iframe_srcdoc"),
        ("iframe.attributes['srcdoc'].textContent = value", "iframe_srcdoc"),
        ("document['write'](value)", "dom_write"),
        ("el['insertAdjacentHTML']('beforeend', value)", "dom_write"),
        ("el.setAttribute('onerror', value)", "event_handler"),
        ("el.setAttributeNS(null, 'onload', value)", "event_handler"),
        ("el.onclick = value", "event_handler"),
        ("el.oncustom = value", "event_handler_candidate"),
        ("$(el).html(value)", "jquery_html"),
        ("jQuery.parseHTML(value)", "jquery_parse"),
        ("$.parseHTML(value)", "jquery_parse"),
        ("jQuery(location.hash)", "jquery_selector_candidate"),
        ("const html = location.hash.slice(1); $(html)", "jquery_selector_candidate"),
        ("const $out = $('#out'); $out.html(input)", "jquery_alias_candidate"),
        ("$(el).attr('href', value)", "jquery_attribute"),
        ("$(el).prop('action', value)", "jquery_attribute"),
        ("$(el).find('.x').attr('href', value)", "jquery_attribute"),
        ("$(el).wrap(value)", "jquery_html"),
        ("$(el).appendTo(target)", "jquery_html"),
        ("jQuery(el).prependTo(target)", "jquery_html"),
        ("$(el).prop('innerHTML', value)", "jquery_html_property"),
        ("jQuery(el).prop('outerHTML', value)", "jquery_html_property"),
        ("$(el).find('.target').append(value)", "jquery_html"),
        ("angular.element(el).html(value)", "jquery_html"),
        ("$(el).animate(value)", "jquery_legacy_candidate"),
        ("jQuery.globalEval(value)", "eval"),
        ("<div dangerouslySetInnerHTML={{__html: value}} />", "framework_raw_html"),
        ("<div v-html=\"value\" />", "framework_raw_html"),
        ("<div x-html=\"value\" />", "framework_raw_html"),
        ("<div set:html={value} />", "framework_raw_html"),
        ("<div innerHTML={value} />", "framework_raw_html"),
        ("<div [innerHTML]=\"value\" />", "framework_raw_html"),
        ("{@html value}", "framework_raw_html"),
        ("unsafeHTML(value)", "framework_raw_html"),
        ("unsafeSVG(value)", "framework_raw_html"),
        ("renderer.setProperty(host, 'innerHTML', value)", "framework_raw_html"),
        ("Vue.createApp({template: userTemplate}).mount('#app')", "framework_template_candidate"),
        ("Vue.compile(userTemplate)", "framework_template_candidate"),
        ('Vue.createApp({template: "<div>" + userTemplate + "</div>"}).mount("#app")', "framework_template_candidate"),
        ("Vue.compile(`<div>${userTemplate}</div>`)", "framework_template_candidate"),
        ("Vue.createApp({template: `<div>` + userTemplate + `</div>`})", "framework_template_candidate"),
        ("Vue.compile(/* dynamic */ userTemplate)", "framework_template_candidate"),
        ("$sce.trustAsJs(value)", "framework_trust_bypass"),
        ("createNodesFromMarkup(value, callback)", "html_parse"),
        ("sanitizer.bypassSecurityTrustResourceUrl(value)", "framework_trust_bypass"),
        ("$sce.trustAsHtml(value)", "framework_trust_bypass"),
        ("new Handlebars.SafeString(value)", "framework_trust_bypass"),
        ("trustedTypes.createPolicy('default', callbacks)", "trusted_types_policy_candidate"),
        ("policy.createHTML(value)", "trusted_types_policy_candidate"),
        ("document.createElement('script')", "script_create"),
        ("script.src = value", "script_content"),
        ("script['textContent'] = value", "script_content"),
        ("script.innerHTML = value", "script_content"),
        ("jQuery.getScript(url)", "script_import"),
        ("$.getScript(url)", "script_import"),
        ("$.ajax({url: userUrl, dataType: 'script'})", "script_import_candidate"),
        ("const n = document.createElement('script'); n.textContent = code; document.head.appendChild(n)", "script_alias_candidate"),
        ("const $s = document.createElement('script'); $s.textContent = code;", "script_alias_candidate"),
        ("const s = document.createElement('script'); s.appendChild(document.createTextNode(input)); document.head.appendChild(s)", "script_alias_candidate"),
        ("importScripts(value)", "script_import"),
        ("import(moduleName)", "script_import"),
        ("a.href = value", "url_attribute"),
        ("el.setAttribute('xlink:href', value)", "url_attribute"),
        ("location.replace(value)", "navigation"),
        ("location.href = value", "navigation"),
        ("document.location = value", "navigation"),
        ("window['location']['href'] = value", "navigation"),
        ("location['href'] = value", "navigation"),
        ("window.open(value)", "navigation"),
        ("open(value)", "unqualified_open_candidate"),
        ("object.data = value", "url_attribute"),
        ("new Function(value)", "eval"),
        ("window.eval(value)", "eval"),
        ("globalThis.eval(value)", "eval"),
        ("self.eval(value)", "eval"),
        ("setTimeout(value, 1)", "string_timer_candidate"),
        ("setInterval('render()', 1)", "string_timer_candidate"),
    ],
)
def test_xss_sink_inventory_recognizes_distinct_families(snippet: str, bucket: str):
    assert bucket in J.extract_signals(snippet, "https://app.example/static/app.js")["sinks"]


@pytest.mark.parametrize(
    ("snippet", "absent_bucket"),
    [
        ("node.textContent = value", "dom_write"),
        ("node.setHTML(value)", "html_parse"),
        ("document.parseHTML(value)", "html_parse"),
        ("storage.write(value)", "dom_write"),
        ("document.createElement('div')", "script_create"),
        ("element.addEventListener('click', callback)", "event_handler"),
        ("logger.write(value)", "dom_write"),
        ("logger['write'](value)", "dom_write"),
        ("img.attributes.alt.nodeValue = value", "iframe_srcdoc"),
        ("iframe.attributes.srcdoc.nodeValue === expected", "iframe_srcdoc"),
        ("el['insertAdjacentText']('beforeend', value)", "dom_write"),
        ("renderer.setProperty(host, 'textContent', value)", "framework_raw_html"),
        ("Vue.createApp({template: '<p>Fixed</p>'})", "framework_template_candidate"),
        ("Vue.compile('<p>Fixed</p>')", "framework_template_candidate"),
        ("Vue.compile(/* static */ '<p>Fixed</p>')", "framework_template_candidate"),
        ("Vue.createApp({template: /* static */ '<p>Fixed</p>'})", "framework_template_candidate"),
        ("Vue.compile()", "framework_template_candidate"),
        ("Vue.createApp({template: null})", "framework_template_candidate"),
        ("$sce.getTrustedJs(value)", "framework_trust_bypass"),
        ("createNodesFromMarkup('<b>Fixed</b>', callback)", "html_parse"),
        ("$.ajax({url: userUrl, dataType: 'json'})", "script_import_candidate"),
        ("const n = document.createElement('div'); n.textContent = code; document.body.appendChild(n)", "script_alias_candidate"),
        ("element.insertAdjacentText('beforeend', value)", "dom_write"),
        ("element.append(value)", "jquery_html"),
        ("element.before(value)", "jquery_html"),
        ("element.wrap(value)", "jquery_html"),
        ("$(el).html()", "jquery_html"),
        ("$(el).html( )", "jquery_html"),
        ("const html = location.hash.slice(1); $('#results')", "jquery_selector_candidate"),
        ("const $out = $('#out'); $out.text(input)", "jquery_alias_candidate"),
        ("const $out = $('#out'); $out.html()", "jquery_alias_candidate"),
        ("const out = 3; out.html(input)", "jquery_alias_candidate"),
        ("angular.element(el).html()", "jquery_html"),
        ("$(el).attr('href')", "jquery_attribute"),
        ("$(el).prop('action')", "jquery_attribute"),
        ("node.attr('href', value)", "jquery_attribute"),
        ("$(el).prop('innerHTML')", "jquery_html_property"),
        ("node.prop('innerHTML', value)", "jquery_html_property"),
        ('$(el).attr("innerHTML", value)', "jquery_html_property"),
        ("nativeNode.appendTo(target)", "jquery_html"),
        ("logger.getScript(url)", "script_import"),
        ("script['textContent'] === expected", "script_content"),
        ("setTimeout(() => render(), 1)", "string_timer_candidate"),
        ("setInterval(function tick() {}, 1)", "string_timer_candidate"),
        ("element.innerHTML == value", "dom_write"),
        ("obj.eval(value)", "eval"),
        ("obj.one = fn", "event_handler"),
        ("obj.once = callback", "event_handler"),
        ("obj.only = true", "event_handler"),
        ("el.onclick === fn", "event_handler"),
        ("el.oncustom === fn", "event_handler_candidate"),
        ("iframe.srcdoc === expected", "iframe_srcdoc"),
        ("iframe['srcdoc'] === expected", "iframe_srcdoc"),
        ("script.textContent === text", "script_content"),
        ("element.href === nextUrl", "url_attribute"),
        ("object.data === nextUrl", "url_attribute"),
        ("location.href === nextUrl", "navigation"),
        ("window['location']['href'] === nextUrl", "navigation"),
        ("location['href'] === nextUrl", "navigation"),
        ("element.innerHTML.length", "dom_write"),
    ],
)
def test_xss_sink_inventory_does_not_conflate_safe_or_unrelated_apis(snippet: str, absent_bucket: str):
    assert absent_bucket not in J.extract_signals(snippet, "https://app.example/static/app.js")["sinks"]


def test_xss_sink_inventory_safe_unrelated_methods_emit_no_sink_buckets():
    text = """
    node.append(value);
    node.prepend(value);
    node.before(value);
    $(el).html();
    const html = location.hash.slice(1); $('#results');
    const $out = $('#out'); $out.text(input);
    const other = 3; other.html(input);
    angular.element(el).html();
    $(el).attr('href');
    $(el).prop('action');
    node.attr('href', value);
    $(el).prop('innerHTML');
    node.prop('innerHTML', value);
    $(el).attr('innerHTML', value);
    nativeNode.appendTo(target);
    logger.getScript(url);
    logger['write'](value);
    img.attributes.alt.nodeValue = value;
    if (iframe.attributes.srcdoc.nodeValue === expected) {}
    renderer.setProperty(host, 'textContent', value);
    Vue.createApp({template: '<p>Fixed</p>'});
    Vue.compile('<p>Fixed</p>');
    createNodesFromMarkup('<b>Fixed</b>', callback);
    $.ajax({url: userUrl, dataType: 'json'});
    if (script['textContent'] === expected) {}
    items.index(value);
    Set.add(value);
    graph.data = rows;
    obj.one = fn;
    obj.once = callback;
    obj.only = true;
    obj.eval(value);
    if (el.onclick === fn) {}
    if (el.oncustom === fn) {}
    if (iframe.srcdoc === expected) {}
    if (iframe['srcdoc'] === expected) {}
    if (script.textContent === text) {}
    if (element.href === nextUrl) {}
    if (object.data === nextUrl) {}
    if (location.href === nextUrl) {}
    xhr.open('GET', url);
    setTimeout(() => render(), 1);
    """
    assert J.extract_signals(text, "https://app.example/static/app.js")["sinks"] == []


def test_extract_signals_accepts_legacy_source_map_directive():
    signals = J.extract_signals("//@ sourceMappingURL=legacy.js.map", "https://app.example.com/static/app.js")

    assert signals["source_map"] == "https://app.example.com/static/legacy.js.map"


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("const value = 1;\n/*# sourceMappingURL=block.js.map */", "block.js.map"),
        ("//# sourceMappingURL=first.js.map\n//# sourceMappingURL=last.js.map", "last.js.map"),
        ("//# sourceMappingURL=first.js.map\n/*# sourceMappingURL=last.js.map */", "last.js.map"),
        ("if (ready) /[//]/.test(value); //# sourceMappingURL=regex.js.map", "regex.js.map"),
        ("if (ready) /[//# sourceMappingURL=decoy.js.map]/.test(value); //# sourceMappingURL=real.js.map", "real.js.map"),
        ("if (ready) work(); else /[//]/.test(value); //# sourceMappingURL=real.js.map", "real.js.map"),
        ("if (ready) work(); else /[//# sourceMappingURL=fake.js.map]/.test(value); //# sourceMappingURL=real.js.map", "real.js.map"),
    ],
)
def test_extract_signals_uses_last_applicable_source_map_directive(body: str, expected: str):
    signals = J.extract_signals(body, "https://app.example.com/static/app.js")
    assert signals["source_map"] == f"https://app.example.com/static/{expected}"


@pytest.mark.parametrize("decoy", [
    "const text = '//# sourceMappingURL=fake.js.map';",
    "const text = `/*# sourceMappingURL=fake.js.map */`;",
    "if (ready) /[//# sourceMappingURL=fake.js.map]/.test(value);",
    "if (ready) work(); else /[//# sourceMappingURL=fake.js.map]/.test(value);",
    "if (ready) /[//]/.test(value); const text = '/*# sourceMappingURL=fake.js.map */';",
])
def test_extract_signals_ignores_source_map_directive_decoys(decoy: str):
    assert J.extract_signals(decoy, "https://app.example.com/app.js")["source_map"] == ""


def test_extract_signals_does_not_select_quoted_later_directive():
    body = "//# sourceMappingURL=real.js.map\nconst text = '//# sourceMappingURL=fake.js.map';"
    assert J.extract_signals(body, "https://app.example.com/app.js")["source_map"] == "https://app.example.com/real.js.map"


def test_extract_signals_splits_in_scope_and_external_endpoints():
    text = """
    const internal = "https://static.canva.com/app.js";
    const route = "/api/apps/install?appId=abc";
    const external = "https://slack.com/apps/A06GQJFDUP9";
    """
    signals = J.extract_signals(text, "https://www.canva.com/apps", ["canva.com"])

    assert "https://static.canva.com/app.js" in signals["in_scope_endpoints"]
    assert "https://www.canva.com/api/apps/install?appId=abc" in signals["in_scope_endpoints"]
    assert "https://slack.com/apps/A06GQJFDUP9" in signals["external_endpoints"]


def test_extract_signals_uses_target_host_url_as_scope_hint():
    text = """
    const cdn = "https://assets.canva-apps.com/app.js";
    const api = "https://api.canva.com/v1/designs";
    const third = "https://slack.com/apps/A06GQJFDUP9";
    """
    signals = J.extract_signals(
        text,
        "https://www.canva.com/apps",
        ["canva.com"],
    )

    assert "https://assets.canva-apps.com/app.js" in signals["external_endpoints"]
    assert "https://api.canva.com/v1/designs" in signals["in_scope_endpoints"]
    assert "https://slack.com/apps/A06GQJFDUP9" in signals["external_endpoints"]


def test_external_url_classification_and_policy():
    assert J.classify_external_url("https://slack.com/apps/A06GQJFDUP9") == "integration_reference"
    assert J.classify_external_url("https://docs.example.com/help/canva") == "public_reference"
    assert J.classify_external_url("https://cdn.example.com/file?token=abc") == "possible_sensitive_reference"
    assert J.external_action_policy("integration_reference") == "context-only-find-scoped-integration-flow"
    assert "open_public_page_read_only" in J.allowed_context_actions("integration_reference")
    assert "do_not_open_without_approval" in J.allowed_context_actions("possible_sensitive_reference")


def test_extract_signals_prioritizes_flow_and_route_hints():
    text = """
    mutation UpdateInvoice($invoiceId: ID!) { updateInvoice(id: $invoiceId) { id } }
    const route = { path: "/api/billing/invoices/:invoice_id/refund" };
    const payload = { tenant_id: tenantId, redirect_uri: nextUrl, featureFlag: "new_checkout" };
    imagePreview({ remoteUrl: image_url, importPath: file_path });
    """
    signals = J.extract_signals(text, "https://app.example.com/static/billing.js")

    assert "UpdateInvoice" in signals["graphql_operations"]
    assert "/api/billing/invoices/:invoice_id/refund" in signals["route_hints"]
    assert "invoice_id" in signals["interesting_keys"]
    assert "tenant_id" in signals["interesting_keys"]
    assert "redirect_uri" in signals["interesting_keys"]
    assert "payment" in signals["flow_hints"]
    assert "access_control" in signals["flow_hints"]
    assert "server_fetch" in signals["flow_hints"]


def test_extract_signals_finds_hidden_bootstrap_state_hints():
    text = """
    const csrf = document.querySelector('input[type="hidden"][name="csrf_token"]');
    const orgId = document.body.dataset.orgId;
    const boot = JSON.parse(document.getElementById('__NEXT_DATA__').textContent);
    window.__INITIAL_STATE__ = { featureFlag: 'new_editor' };
    """
    signals = J.extract_signals(text, "https://app.example.com/static/app.js")

    hints = set(signals["hidden_state_hints"])
    assert "querySelector(" in hints
    assert "dataset" in hints
    assert "document.getElementById" in hints
    assert "__NEXT_DATA__" in hints
    assert "__INITIAL_STATE__" in hints


def test_extract_signals_ignores_malformed_urlish_strings():
    signals = J.extract_signals(
        'const noisy = "https://[not-an-ipv6]/bad"; const ok = "/api/v1/me?user_id=1";',
        "https://app.example.com/static/app.js",
    )

    assert "https://app.example.com/api/v1/me?user_id=1" in signals["endpoints"]
    assert "user_id" in signals["params"]


def test_limited_source_map_fetch_uses_no_redirect_handler():
    class Response:
        headers = {"content-type": "application/json"}
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, _size: int):
            return b"{}"

    class Opener:
        def open(self, _request, timeout: int):
            assert timeout == 7
            return Response()

    with patch.object(J.urllib.request, "build_opener", return_value=Opener()) as build_opener:
        assert J.http_get_limited("https://app.example.com/app.js.map", timeout=7, max_bytes=100) == (b"{}", 200, "application/json", False)

    assert isinstance(build_opener.call_args.args[0], J.NoRedirectHandler)


def test_inventory_writes_metadata_and_packets(tmp_path: Path):
    input_file = tmp_path / "jsfiles.txt"
    input_file.write_text("https://app.example.com/static/app.js\n", encoding="utf-8")
    provenance_file = tmp_path / "provenance-input.jsonl"
    provenance_file.write_text(json.dumps({
        "js_url": "https://app.example.com/static/app.js",
        "source": "unit-proxy",
        "page_url": "https://app.example.com/login",
        "page_context": "login/auth",
        "proxy_request_id": "req-1",
        "initiator": "script",
        "referrer": "https://app.example.com/login",
        "status": 200,
        "content_type": "application/javascript",
        "related_requests": ["req-2"],
    }) + "\n", encoding="utf-8")
    output_root = tmp_path / "out"
    library_root = tmp_path / "library"

    def fake_get(url: str, timeout: int = 20):
        return (
            b"const endpoint='/api/auth/login?next=/dashboard'; const external='https://slack.com/apps/A06GQJFDUP9'; fetch(endpoint);",
            200,
            "application/javascript",
        )

    with patch.object(J, "http_get", side_effect=fake_get):
        rc = J.main([
            "inventory",
            "demo",
            "--input",
            str(input_file),
            "--target-host",
            "example.com",
            "--output-root",
            str(output_root),
            "--library-root",
            str(library_root),
            "--run-id",
            "unit",
            "--integration-index-root",
            str(tmp_path / "integrations"),
            "--provenance-input",
            str(provenance_file),
            "--chunk-size",
            "30",
            "--chunk-overlap",
            "5",
        ])

    assert rc == 0
    assert (output_root / "manifest.json").exists()
    metadata_text = (output_root / "metadata.jsonl").read_text(encoding="utf-8")
    metadata_rows = [json.loads(line) for line in metadata_text.splitlines()]
    assert metadata_rows[0]["url"] == "https://app.example.com/static/app.js"
    assert "https://app.example.com/api/auth/login?next=/dashboard" in metadata_text
    assert metadata_rows[0]["metadata_schema_version"] == 2
    assert metadata_rows[0]["signal_coverage"] == {
        "method": "deterministic_seed_patterns",
        "exhaustive": False,
        "interpretation": "starting_points_for_agent_review",
    }
    assert metadata_rows[0]["provenance"]["page_urls"] == ["https://app.example.com/login"]
    assert metadata_rows[0]["provenance"]["proxy_request_ids"] == ["req-1"]
    assert metadata_rows[0]["artifact_links"]["packets"]
    assert (library_root / "metadata.jsonl").exists()
    external_rows = (output_root / "external_integrations.jsonl").read_text(encoding="utf-8")
    assert "https://slack.com/apps/A06GQJFDUP9" in external_rows
    assert "open_public_page_read_only" in external_rows
    provenance_rows = (output_root / "js_provenance.jsonl").read_text(encoding="utf-8")
    assert "unit-proxy" in provenance_rows
    assert "https://app.example.com/login" in provenance_rows
    assert "req-1" in provenance_rows
    assert "application/javascript" in provenance_rows
    assert (library_root / "provenance.jsonl").exists()
    assert (library_root / "js_info.sqlite").exists()
    with sqlite3.connect(library_root / "js_info.sqlite") as db:
        count = db.execute(
            "SELECT count(*) FROM js_provenance WHERE js_url = ? AND page_context = ?",
            ("https://app.example.com/static/app.js", "login/auth"),
        ).fetchone()[0]
        file_count = db.execute(
            "SELECT count(*) FROM js_files WHERE latest_run_id = ? AND target_host = ?",
            ("unit", "example.com"),
        ).fetchone()[0]
        alias_count = db.execute(
            "SELECT count(*) FROM js_url_aliases WHERE js_url = ?",
            ("https://app.example.com/static/app.js",),
        ).fetchone()[0]
        artifact_count = db.execute(
            "SELECT count(*) FROM js_artifacts WHERE artifact_type = 'packet'",
        ).fetchone()[0]
        observation_count = db.execute("SELECT count(*) FROM js_observations").fetchone()[0]
    assert count == 1
    assert file_count == 1
    assert alias_count == 1
    assert artifact_count > 0
    assert observation_count == 0
    host_index = json.loads((tmp_path / "integrations" / "external_hosts.json").read_text(encoding="utf-8"))
    assert any(host["host"] == "slack.com" for host in host_index["hosts"])
    packets = list((output_root / "packets").glob("*.md"))
    assert packets
    packet = packets[0].read_text(encoding="utf-8")
    assert "JS Deep Review Packet" in packet
    assert "Deterministic seed coverage: non-exhaustive starting points for agent review" in packet
    assert "Zero hits do not mean the bundle or technology was fully searched" in packet
    assert "Nearby In-Scope Extracted Endpoints" in packet
    assert "Trace:" in packet
    assert "Hidden/bootstrap state hints" in packet


def test_inventory_page_includes_inline_executable_script_in_packets(tmp_path: Path):
    page = "https://app.example.com/account"
    html = b'''<html><script src="/static/app.js"></script>
    <script type="application/json">{"url":"/api/ignored"}</script>
    <script>const endpoint = "/api/account?owner_id=7";
    document.querySelector('#target').innerHTML = location.hash;</script></html>'''
    requested = []

    def fake_get(url: str, timeout: int = 20):
        requested.append(url)
        if url == page:
            return html, 200, "text/html"
        if url == "https://app.example.com/static/app.js":
            return b"console.log('external')", 200, "application/javascript"
        raise AssertionError(f"unexpected fetch: {url}")

    with patch.object(J, "http_get", side_effect=fake_get):
        assert J.main([
            "inventory", "demo", "--page", page, "--target-host", "example.com",
            "--output-root", str(tmp_path / "out"), "--library-root", str(tmp_path / "library"),
            "--integration-index-root", str(tmp_path / "integrations"),
        ]) == 0

    rows = [json.loads(line) for line in (tmp_path / "out" / "metadata.jsonl").read_text().splitlines()]
    inline = [row for row in rows if "inline-script" in row["url"]]
    assert len(inline) == 1
    assert inline[0]["in_scope_endpoints"] == ["https://app.example.com/api/account?owner_id=7"]
    assert inline[0]["sink_sites"]
    assert inline[0]["artifact_links"]["packets"]
    page_row = json.loads((tmp_path / "out" / "page_context.jsonl").read_text().splitlines()[0])
    assert page_row["inline_script_count"] == 1
    assert page_row["inline_scripts_truncated"] == 0
    provenance = [json.loads(line) for line in (tmp_path / "out" / "js_provenance.jsonl").read_text().splitlines()]
    assert any(row["js_url"] == inline[0]["url"] and row["page_url"] == page for row in provenance)
    assert requested == [page, "https://app.example.com/static/app.js"]


def test_inline_parser_caps_bodies_and_counts_omissions():
    parser = J.ScriptSrcParser()
    parser.feed('<script>' + 'x' * (2 * 1024 * 1024 + 1) + '</script>')
    parser.feed('<script type="application/ld+json">{"@context":"https://example.com"}</script>')
    parser.feed('<script type="module">fetch("/api/safe")</script>')
    assert len(parser.inline_scripts) == 2
    assert len(parser.inline_scripts[0][1]) == 2 * 1024 * 1024
    assert parser.inline_truncated == 1
    assert parser.inline_scripts[1][1] == 'fetch("/api/safe")'


def test_inventory_keeps_extensionless_page_script_src(tmp_path: Path):
    page = "https://app.example.com/account"
    seen = []

    def fake_get(url: str, timeout: int = 20):
        seen.append(url)
        if url == page:
            return b'<script src="/assets/runtime"></script>', 200, "text/html"
        if url == "https://app.example.com/assets/runtime":
            return b'fetch("/api/account")', 200, "application/javascript"
        raise AssertionError(f"unexpected fetch: {url}")

    with patch.object(J, "http_get", side_effect=fake_get):
        assert J.main([
            "inventory", "demo", "--page", page, "--target-host", "example.com",
            "--output-root", str(tmp_path / "out"), "--library-root", str(tmp_path / "library"),
            "--integration-index-root", str(tmp_path / "integrations"),
        ]) == 0
    assert seen == [page, "https://app.example.com/assets/runtime"]


def test_inventory_rejects_out_of_scope_page_before_fetch(tmp_path: Path):
    with patch.object(J, "http_get") as get:
        with pytest.raises(SystemExit, match="outside --target-host scope"):
            J.main([
                "inventory", "demo", "--page", "https://other.example.net/account",
                "--target-host", "example.com", "--output-root", str(tmp_path / "out"),
                "--library-root", str(tmp_path / "library"),
            ])
    get.assert_not_called()


def test_http_get_does_not_follow_redirects():
    from email.message import Message
    from urllib.error import HTTPError

    headers = Message()
    headers["Location"] = "https://other.example.net/account"
    with patch.object(J.urllib.request, "build_opener") as build_opener:
        build_opener.return_value.open.side_effect = HTTPError(
            "https://app.example.com/account", 302, "Found", headers, None
        )
        body, status, _ = J.http_get("https://app.example.com/account")
    assert body == b""
    assert status == 302
    assert isinstance(build_opener.call_args.args[0], J.NoRedirectHandler)


def test_inventory_ignores_redirect_page_body(tmp_path: Path):
    with patch.object(J, "http_get", return_value=(b'<script>fetch("/api/private")</script>', 302, "text/html")):
        assert J.main([
            "inventory", "demo", "--page", "https://app.example.com/account",
            "--target-host", "example.com", "--output-root", str(tmp_path / "out"),
            "--library-root", str(tmp_path / "library"),
        ]) == 0
    assert (tmp_path / "out" / "metadata.jsonl").read_text() == ""


def test_limit_bounds_inline_script_inventory(tmp_path: Path):
    html = b'<script>fetch("/api/one")</script><script>fetch("/api/two")</script>'
    with patch.object(J, "http_get", return_value=(html, 200, "text/html")):
        assert J.main([
            "inventory", "demo", "--page", "https://app.example.com/account",
            "--target-host", "example.com", "--limit", "1",
            "--output-root", str(tmp_path / "out"), "--library-root", str(tmp_path / "library"),
            "--integration-index-root", str(tmp_path / "integrations"),
        ]) == 0
    rows = (tmp_path / "out" / "metadata.jsonl").read_text().splitlines()
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert len(rows) == 1
    assert manifest["js_urls_seen"] == 1


def test_inventory_accepts_extensionless_explicit_js_input(tmp_path: Path):
    source = tmp_path / "jsfiles.txt"
    source.write_text("https://app.example.com/assets/runtime\n")
    seen = []

    def fake_get(url: str, timeout: int = 20):
        seen.append(url)
        return b'fetch("/api/account")', 200, "application/javascript"

    with patch.object(J, "http_get", side_effect=fake_get):
        assert J.main([
            "inventory", "demo", "--input", str(source), "--target-host", "example.com",
            "--output-root", str(tmp_path / "out"), "--library-root", str(tmp_path / "library"),
            "--integration-index-root", str(tmp_path / "integrations"),
        ]) == 0
    assert seen == ["https://app.example.com/assets/runtime"]


def test_inline_provenance_hint_retains_synthetic_script_identity(tmp_path: Path):
    hint_path = tmp_path / "provenance.jsonl"
    identity = "https://app.example.com/account#inline-script-1"
    hint_path.write_text(json.dumps({"js_url": identity, "proxy_request_id": "req-1"}) + "\n")
    assert J.load_provenance_hints(hint_path)[identity][0]["proxy_request_id"] == "req-1"


def test_inventory_reuses_ledger_download_and_chunk_set(tmp_path: Path):
    input_file = tmp_path / "jsfiles.txt"
    input_file.write_text("https://app.example.com/static/app.js\n", encoding="utf-8")
    library_root = tmp_path / "library"
    calls = {"count": 0}

    def fake_get(url: str, timeout: int = 20):
        calls["count"] += 1
        return (
            b"const endpoint='/api/auth/login?next=/dashboard'; fetch(endpoint);",
            200,
            "application/javascript",
        )

    args = [
        "inventory",
        "demo",
        "--input",
        str(input_file),
        "--target-host",
        "example.com",
        "--library-root",
        str(library_root),
        "--chunk-size",
        "30",
        "--chunk-overlap",
        "5",
    ]
    with patch.object(J, "http_get", side_effect=fake_get):
        assert J.main(args + ["--output-root", str(tmp_path / "run1"), "--run-id", "unit1"]) == 0
        assert J.main(args + ["--output-root", str(tmp_path / "run2"), "--run-id", "unit2"]) == 0

    assert calls["count"] == 1
    ledger = J.load_ledger(library_root / "ledger.json")
    sha = J.ledger_lookup_url(ledger, "https://app.example.com/static/app.js")
    assert sha
    assert (library_root / "downloads" / f"{sha}.js").exists()
    metadata = (tmp_path / "run2" / "metadata.jsonl").read_text(encoding="utf-8")
    assert '"reused_download": true' in metadata
    assert '"reused_chunks": true' in metadata


def test_inventory_unpacks_in_scope_source_map_into_module_packets(tmp_path: Path):
    input_file = tmp_path / "jsfiles.txt"
    input_file.write_text("https://app.example.com/static/app.js\n", encoding="utf-8")
    source_map = {
        "version": 3,
        "sources": ["src/auth.ts", "src/no-content.ts"],
        "sourcesContent": ["export const login = () => fetch('/api/login');", None],
    }

    def fake_get(url: str, timeout: int = 20):
        return (b"//# sourceMappingURL=app.js.map\n", 200, "application/javascript")

    def fake_limited(url: str, *, timeout: int, max_bytes: int):
        assert url == "https://app.example.com/static/app.js.map"
        return json.dumps(source_map).encode(), 200, "application/json", False

    with patch.object(J, "http_get", side_effect=fake_get), patch.object(J, "http_get_limited", side_effect=fake_limited):
        assert J.main([
            "inventory", "demo", "--input", str(input_file), "--target-host", "example.com",
            "--output-root", str(tmp_path / "out"), "--library-root", str(tmp_path / "library"),
            "--run-id", "source-map-unit", "--chunk-size", "30", "--chunk-overlap", "5",
        ]) == 0

    metadata = [json.loads(line) for line in (tmp_path / "out" / "metadata.jsonl").read_text().splitlines()]
    assert metadata[0]["source_map_status"] == "downloaded"
    assert metadata[0]["source_map_module_count"] == 2
    assert metadata[0]["source_map_modules_with_content"] == 1
    assert metadata[0]["source_map_packet_count"] > 0
    module_rows = [json.loads(line) for line in (tmp_path / "out" / "source_map_modules.jsonl").read_text().splitlines()]
    assert [row["source_label"] for row in module_rows] == ["src/auth.ts", "src/no-content.ts"]
    assert module_rows[0]["packet_paths"]
    assert not module_rows[1]["packet_paths"]
    packet = Path(module_rows[0]["packet_paths"][0]).read_text(encoding="utf-8")
    assert "Source-Map Module Review Packet" in packet
    assert "src/auth.ts" in packet
    with sqlite3.connect(tmp_path / "library" / "js_info.sqlite") as db:
        source_map_artifacts = db.execute("SELECT count(*) FROM js_artifacts WHERE artifact_type = 'source_map'").fetchone()[0]
    assert source_map_artifacts == 1


def test_identical_bundle_bodies_with_distinct_maps_keep_distinct_packets(tmp_path: Path):
    urls = ["https://app.example.com/one/app.js", "https://app.example.com/two/app.js"]
    input_file = tmp_path / "jsfiles.txt"
    input_file.write_text("\n".join(urls) + "\n", encoding="utf-8")
    bundle = b"//# sourceMappingURL=app.js.map\n"
    map_bodies = {
        "https://app.example.com/one/app.js.map": json.dumps({
            "version": 3, "sources": ["src/one.ts"], "sourcesContent": ["export const one = 1;"]
        }).encode(),
        "https://app.example.com/two/app.js.map": json.dumps({
            "version": 3, "sources": ["src/two.ts"], "sourcesContent": ["export const two = 2;"]
        }).encode(),
    }

    def fake_limited(url: str, *, timeout: int, max_bytes: int):
        return map_bodies[url], 200, "application/json", False

    with patch.object(J, "http_get", return_value=(bundle, 200, "application/javascript")), patch.object(
        J, "http_get_limited", side_effect=fake_limited
    ):
        assert J.main([
            "inventory", "demo", "--input", str(input_file), "--target-host", "example.com",
            "--output-root", str(tmp_path / "out"), "--library-root", str(tmp_path / "library"),
            "--run-id", "same-bundle-distinct-maps",
        ]) == 0

    modules = [json.loads(line) for line in (tmp_path / "out" / "source_map_modules.jsonl").read_text().splitlines()]
    assert len(modules) == 2
    assert {row["bundle_url"]: row["source_label"] for row in modules} == {
        urls[0]: "src/one.ts", urls[1]: "src/two.ts"
    }
    packet_paths = [Path(row["packet_paths"][0]) for row in modules]
    assert packet_paths[0] != packet_paths[1], "distinct maps must not claim the same packet path"
    for row, packet_path in zip(modules, packet_paths):
        packet = packet_path.read_text(encoding="utf-8")
        assert row["bundle_url"] in packet
        assert row["source_label"] in packet


def test_inventory_does_not_store_or_count_source_map_error_body(tmp_path: Path):
    input_file = tmp_path / "jsfiles.txt"
    input_file.write_text("https://app.example.com/static/app.js\n", encoding="utf-8")
    body = b"<Error><Code>AccessDenied</Code></Error>"
    common = ["inventory", "demo", "--input", str(input_file), "--target-host", "example.com",
              "--library-root", str(tmp_path / "library")]
    with patch.object(J, "http_get", return_value=(b"//# sourceMappingURL=app.js.map\n", 200, "application/javascript")), patch.object(
        J, "http_get_limited", return_value=(body, 403, "application/xml", False)
    ):
        assert J.main(common + ["--output-root", str(tmp_path / "run1"), "--run-id", "map-error-1"]) == 0
        assert J.main(common + ["--output-root", str(tmp_path / "run2"), "--run-id", "map-error-2"]) == 0
    for name in ("run1", "run2"):
        metadata = [json.loads(line) for line in (tmp_path / name / "metadata.jsonl").read_text().splitlines()]
        manifest = json.loads((tmp_path / name / "manifest.json").read_text())
        assert metadata[0]["source_map_status"] == "fetch_failed"
        assert manifest["source_maps_downloaded"] == 0
        assert manifest["source_maps_reused"] == 0
    assert list((tmp_path / "library" / "sourcemaps").glob("*.map")) == []
    assert json.loads((tmp_path / "library" / "ledger.json").read_text()).get("source_maps", {}) == {}


def test_inventory_rejects_successful_non_map_body(tmp_path: Path):
    input_file = tmp_path / "jsfiles.txt"
    input_file.write_text("https://app.example.com/static/app.js\n", encoding="utf-8")
    with patch.object(J, "http_get", return_value=(b"//# sourceMappingURL=app.js.map\n", 200, "application/javascript")), patch.object(
        J, "http_get_limited", return_value=(b"{\"message\":\"AccessDenied\"}", 200, "application/json", False)
    ):
        assert J.main(["inventory", "demo", "--input", str(input_file), "--target-host", "example.com",
                       "--output-root", str(tmp_path / "out"), "--library-root", str(tmp_path / "library"),
                       "--run-id", "invalid-map"]) == 0
    metadata = [json.loads(line) for line in (tmp_path / "out" / "metadata.jsonl").read_text().splitlines()]
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert metadata[0]["source_map_status"] == "invalid"
    assert manifest["source_maps_downloaded"] == 0
    assert list((tmp_path / "library" / "sourcemaps").glob("*.map")) == []



def test_inventory_accepts_empty_source_map_and_reuses_it(tmp_path: Path):
    input_file = tmp_path / "jsfiles.txt"
    input_file.write_text("https://app.example.com/static/app.js\n", encoding="utf-8")
    map_body = json.dumps({"version": 3, "sources": []}).encode()
    common = ["inventory", "demo", "--input", str(input_file), "--target-host", "example.com",
              "--library-root", str(tmp_path / "library")]
    with patch.object(J, "http_get", return_value=(b"//# sourceMappingURL=app.js.map\n", 200, "application/javascript")), patch.object(
        J, "http_get_limited", return_value=(map_body, 200, "application/json", False)
    ) as limited:
        assert J.main(common + ["--output-root", str(tmp_path / "run1"), "--run-id", "empty-map-1"]) == 0
        assert J.main(common + ["--output-root", str(tmp_path / "run2"), "--run-id", "empty-map-2"]) == 0
    assert limited.call_count == 1
    for name, expected_status, downloaded, reused in (("run1", "downloaded", 1, 0), ("run2", "cached", 0, 1)):
        metadata = [json.loads(line) for line in (tmp_path / name / "metadata.jsonl").read_text().splitlines()]
        manifest = json.loads((tmp_path / name / "manifest.json").read_text())
        assert metadata[0]["source_map_status"] == expected_status
        assert metadata[0]["source_map_module_count"] == 0
        assert manifest["source_maps_downloaded"] == downloaded
        assert manifest["source_maps_reused"] == reused


def test_inventory_records_too_large_source_map_without_reading_it(tmp_path: Path):
    input_file = tmp_path / "jsfiles.txt"
    input_file.write_text("https://app.example.com/static/app.js\n", encoding="utf-8")

    with patch.object(J, "http_get", return_value=(b"//# sourceMappingURL=app.js.map\n", 200, "application/javascript")), patch.object(
        J, "http_get_limited", return_value=(b"", 200, "application/json", True)
    ):
        assert J.main([
            "inventory", "demo", "--input", str(input_file), "--target-host", "example.com",
            "--output-root", str(tmp_path / "out"), "--library-root", str(tmp_path / "library"),
            "--run-id", "source-map-limit-unit",
        ]) == 0

    metadata = [json.loads(line) for line in (tmp_path / "out" / "metadata.jsonl").read_text().splitlines()]
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert metadata[0]["source_map_status"] == "too_large"
    assert manifest["source_maps_too_large"] == 1


def test_inventory_records_source_map_packet_budget_truncation(tmp_path: Path):
    input_file = tmp_path / "jsfiles.txt"
    input_file.write_text("https://app.example.com/static/app.js\n", encoding="utf-8")
    source_map = {"version": 3, "sources": ["src/large.ts"], "sourcesContent": ["x" * 100]}
    with patch.object(J, "http_get", return_value=(b"//# sourceMappingURL=app.js.map\n", 200, "application/javascript")), patch.object(J, "http_get_limited", return_value=(json.dumps(source_map).encode(), 200, "application/json", False)):
        assert J.main(["inventory", "demo", "--input", str(input_file), "--target-host", "example.com", "--output-root", str(tmp_path / "out"), "--library-root", str(tmp_path / "library"), "--source-map-max-expanded-bytes", "10"]) == 0

    modules = [json.loads(line) for line in (tmp_path / "out" / "source_map_modules.jsonl").read_text().splitlines()]
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert modules[0]["packet_status"] == "truncated_by_budget"
    assert manifest["source_map_packet_budgets"][0]["truncated_modules"] == 1


def test_inventory_reuses_cached_source_map(tmp_path: Path):
    input_file = tmp_path / "jsfiles.txt"
    input_file.write_text("https://app.example.com/static/app.js\n", encoding="utf-8")
    source_map_calls = {"count": 0}

    def fake_limited(url: str, *, timeout: int, max_bytes: int):
        source_map_calls["count"] += 1
        return json.dumps({"version": 3, "sources": ["src/app.ts"], "sourcesContent": ["export const app = 1;"]}).encode(), 200, "application/json", False

    common = ["inventory", "demo", "--input", str(input_file), "--target-host", "example.com", "--library-root", str(tmp_path / "library")]
    with patch.object(J, "http_get", return_value=(b"//# sourceMappingURL=app.js.map\n", 200, "application/javascript")), patch.object(J, "http_get_limited", side_effect=fake_limited):
        assert J.main(common + ["--output-root", str(tmp_path / "run1"), "--run-id", "source-map-cache-1"]) == 0
        assert J.main(common + ["--output-root", str(tmp_path / "run2"), "--run-id", "source-map-cache-2"]) == 0

    assert source_map_calls["count"] == 1
    metadata = [json.loads(line) for line in (tmp_path / "run2" / "metadata.jsonl").read_text().splitlines()]
    manifest = json.loads((tmp_path / "run2" / "manifest.json").read_text())
    assert metadata[0]["source_map_status"] == "cached"
    assert manifest["source_maps_reused"] == 1


def test_inventory_rejects_cached_source_map_after_byte_cap_is_lowered(tmp_path: Path):
    input_file = tmp_path / "jsfiles.txt"
    input_file.write_text("https://app.example.com/static/app.js\n", encoding="utf-8")
    map_body = json.dumps({
        "version": 3, "sources": ["src/app.ts"], "sourcesContent": ["export const app = 1;"]
    }).encode()
    common = ["inventory", "demo", "--input", str(input_file), "--target-host", "example.com",
              "--library-root", str(tmp_path / "library")]
    with patch.object(J, "http_get", return_value=(b"//# sourceMappingURL=app.js.map\n", 200, "application/javascript")), patch.object(
        J, "http_get_limited", return_value=(map_body, 200, "application/json", False)
    ) as limited:
        assert J.main(common + ["--output-root", str(tmp_path / "first"), "--run-id", "seed-map"]) == 0
        assert J.main(common + ["--output-root", str(tmp_path / "second"), "--run-id", "lower-cap",
                                "--source-map-max-bytes", "10"]) == 0
    assert limited.call_count == 1, "cached over-limit map must not be fetched again"
    metadata = [json.loads(line) for line in (tmp_path / "second" / "metadata.jsonl").read_text().splitlines()]
    manifest = json.loads((tmp_path / "second" / "manifest.json").read_text())
    assert metadata[0]["source_map_status"] == "too_large"
    assert metadata[0]["source_map_packet_count"] == 0
    assert manifest["source_maps_too_large"] == 1
    assert manifest["source_maps_reused"] == 0
    assert not (tmp_path / "second" / "source_map_packets").exists()


def test_inventory_refetches_legacy_cached_error_body(tmp_path: Path):
    input_file = tmp_path / "jsfiles.txt"
    input_file.write_text("https://app.example.com/static/app.js\n", encoding="utf-8")
    map_url = "https://app.example.com/static/app.js.map"
    valid_map = json.dumps({"version": 3, "sources": ["src/app.ts"]}).encode()
    common = ["inventory", "demo", "--input", str(input_file), "--target-host", "example.com",
              "--library-root", str(tmp_path / "library")]
    with patch.object(J, "http_get", return_value=(b"//# sourceMappingURL=app.js.map\n", 200, "application/javascript")), patch.object(
        J, "http_get_limited", return_value=(valid_map, 200, "application/json", False)
    ) as limited:
        assert J.main(common + ["--output-root", str(tmp_path / "run1"), "--run-id", "cache-seed"]) == 0
        error_body = b"<Error>AccessDenied</Error>"
        error_sha = hashlib.sha256(error_body).hexdigest()
        (tmp_path / "library" / "sourcemaps" / f"{error_sha}.map").write_bytes(error_body)
        ledger_path = tmp_path / "library" / "ledger.json"
        ledger = json.loads(ledger_path.read_text())
        ledger["source_maps"][map_url]["sha256"] = error_sha
        ledger["source_maps"][map_url]["status"] = 403
        ledger_path.write_text(json.dumps(ledger))
        assert J.main(common + ["--output-root", str(tmp_path / "run2"), "--run-id", "cache-refetch"]) == 0
    assert limited.call_count == 2
    metadata = [json.loads(line) for line in (tmp_path / "run2" / "metadata.jsonl").read_text().splitlines()]
    manifest = json.loads((tmp_path / "run2" / "manifest.json").read_text())
    assert metadata[0]["source_map_status"] == "downloaded"
    assert metadata[0]["source_map_module_count"] == 1
    assert manifest["source_maps_reused"] == 0
    assert manifest["source_maps_downloaded"] == 1


def test_inventory_can_skip_cached_url_processing(tmp_path: Path):
    input_file = tmp_path / "jsfiles.txt"
    input_file.write_text("https://app.example.com/static/app.js\n", encoding="utf-8")
    library_root = tmp_path / "library"
    calls = {"count": 0}

    def fake_get(url: str, timeout: int = 20):
        calls["count"] += 1
        return (
            b"const endpoint='/api/auth/login?next=/dashboard'; fetch(endpoint);",
            200,
            "application/javascript",
        )

    args = [
        "inventory",
        "demo",
        "--input",
        str(input_file),
        "--target-host",
        "example.com",
        "--library-root",
        str(library_root),
        "--chunk-size",
        "30",
        "--chunk-overlap",
        "5",
    ]
    with patch.object(J, "http_get", side_effect=fake_get):
        assert J.main(args + ["--output-root", str(tmp_path / "run1"), "--run-id", "unit1"]) == 0
        assert J.main(args + [
            "--output-root",
            str(tmp_path / "run2"),
            "--run-id",
            "unit2",
            "--skip-cached-processing",
        ]) == 0

    assert calls["count"] == 1
    manifest = json.loads((tmp_path / "run2" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["js_urls_seen"] == 1
    assert manifest["cached_urls_skipped"] == 1
    assert manifest["js_downloaded"] == 0
    assert manifest["packets"] == 0
    assert (tmp_path / "run2" / "metadata.jsonl").read_text(encoding="utf-8") == ""
    assert not list((tmp_path / "run2" / "packets").glob("*.md"))


def test_inventory_uses_configured_program_roots(tmp_path: Path):
    input_file = tmp_path / "jsfiles.txt"
    input_file.write_text("https://static.example.com/static/app.js\n", encoding="utf-8")
    config_path = tmp_path / "js_analyzer.json"
    configured_program_root = tmp_path / "bounty" / "canva"
    config_path.write_text(json.dumps({
        "programs": {
            "canva": {
                "program_root": str(configured_program_root)
            }
        }
    }) + "\n", encoding="utf-8")

    def fake_get(url: str, timeout: int = 20):
        return (b"fetch('/api/config?design_id=1')", 200, "application/javascript")

    with patch.object(J, "http_get", side_effect=fake_get):
        assert J.main([
            "inventory",
            "canva",
            "--input",
            str(input_file),
            "--target-host",
            "example.com",
            "--config",
            str(config_path),
            "--run-id",
            "configured-unit",
        ]) == 0

    js_root = configured_program_root / "web" / "recon" / "js"
    run_root = js_root / "configured-unit"
    library_root = js_root / "_library"
    manifest = json.loads((run_root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["root"] == str(run_root)
    assert manifest["config"]["program_root"] == str(configured_program_root)
    assert manifest["outputs"]["library"] == str(library_root)
    assert (library_root / "ledger.json").exists()


def test_inventory_target_host_accepts_url_and_keeps_external_artifacts(tmp_path: Path):
    input_file = tmp_path / "jsfiles.txt"
    input_file.write_text("https://static.example.com/static/app.js\n", encoding="utf-8")
    output_root = tmp_path / "out"
    library_root = tmp_path / "library"
    calls = {"count": 0}

    def fake_get(url: str, timeout: int = 20):
        calls["count"] += 1
        return (b"fetch('https://api.example.com/v1/me')", 200, "application/javascript")

    with patch.object(J, "http_get", side_effect=fake_get):
        rc = J.main([
            "inventory",
            "demo",
            "--input",
            str(input_file),
            "--target-host",
            "https://example.com/dashboard",
            "--output-root",
            str(output_root),
            "--library-root",
            str(library_root),
            "--run-id",
            "scope-unit",
        ])

    assert rc == 0
    assert calls["count"] == 1
    metadata = [json.loads(line) for line in (output_root / "metadata.jsonl").read_text(encoding="utf-8").splitlines()]
    assert metadata[0]["url"] == "https://static.example.com/static/app.js"
    assert metadata[0]["target_host"] == "example.com"
    assert "https://api.example.com/v1/me" in metadata[0]["in_scope_endpoints"]


def test_observe_appends_observations_jsonl_and_sqlite_rows(tmp_path: Path):
    library_root = tmp_path / "library"
    observations_input = tmp_path / "observations.jsonl"
    observations_input.write_text(json.dumps({
        "sha256": "abc123",
        "js_url": "https://static.example.com/app.js",
        "packet_path": "/tmp/packet.md",
        "lens": "access-control",
        "run_id": "worker-run",
        "agent_id": "agent-1",
        "title": "Potential owner id request field",
        "summary": "Worker saw owner_id flow into a request body but did not prove controllability.",
        "confidence": "medium",
        "evidence": ["owner_id", "fetch('/api/projects')"],
        "next_action": "Compare owned-account request contract.",
    }) + "\n", encoding="utf-8")

    rc = J.main([
        "observe",
        "demo",
        "--input",
        str(observations_input),
        "--library-root",
        str(library_root),
    ])

    assert rc == 0
    assert (library_root / "observations.jsonl").exists()
    with sqlite3.connect(library_root / "js_info.sqlite") as db:
        row = db.execute(
            "SELECT lens, run_id, title, evidence_json FROM js_observations WHERE sha256 = ?",
            ("abc123",),
        ).fetchone()
    assert row[0] == "access-control"
    assert row[1] == "worker-run"
    assert row[2] == "Potential owner id request field"
    assert "owner_id" in row[3]


def test_iter_jsonl_streams_without_reading_whole_file(tmp_path: Path):
    """The library metadata file can reach gigabytes; a whole-file read gets OOM-killed."""
    path = tmp_path / "rows.jsonl"
    path.write_text(
        json.dumps({"sha256": "a"}) + "\n"
        + "\n"
        + "{not json}\n"
        + json.dumps({"sha256": "b"}) + "\n",
        encoding="utf-8",
    )

    def explode(*args, **kwargs):
        raise AssertionError("iter_jsonl must not load the whole file into memory")

    with patch.object(Path, "read_text", explode):
        rows = list(J.iter_jsonl(path))

    assert [row["sha256"] for row in rows] == ["a", "b"]
    assert list(J.iter_jsonl(tmp_path / "missing.jsonl")) == []


def test_write_metadata_db_accepts_single_pass_iterator(tmp_path: Path):
    """metadata_rows is a generator over the library file, so it may only be traversed once."""
    db_path = tmp_path / "js_info.sqlite"
    rows = [{
        "sha256": "abc123",
        "url": "https://app.example.com/static/app.js",
        "artifact_path": str(tmp_path / "abc123.js"),
        "byte_count": 12,
        "content_type": "application/javascript",
        "generated_at": "2026-01-01T00:00:00Z",
        "run_id": "unit",
        "target_host": "example.com",
        "chunk_count": 1,
        "status": 200,
        "chunk_paths": [str(tmp_path / "chunk-001.js")],
    }]

    J.write_metadata_db(db_path, iter(rows), [])

    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT count(*) FROM js_files").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM js_url_aliases").fetchone()[0] == 1
        assert db.execute(
            "SELECT count(*) FROM js_artifacts WHERE artifact_type = 'chunk'"
        ).fetchone()[0] == 1


def test_inventory_collects_mjs_and_cjs_modules(tmp_path: Path):
    """ES/CommonJS modules are real app code; a bare '.js' suffix test drops them silently."""
    input_file = tmp_path / "jsfiles.txt"
    input_file.write_text(
        "https://app.example.com/navigation.mjs\n"
        "https://app.example.com/legacy.cjs\n"
        "https://app.example.com/styles.css\n",
        encoding="utf-8",
    )
    output_root = tmp_path / "out"
    library_root = tmp_path / "library"

    def fake_get(url: str, timeout: int = 20):
        return (b"export const ping = () => fetch('/api/ping');", 200, "text/javascript")

    with patch.object(J, "http_get", side_effect=fake_get):
        rc = J.main([
            "inventory", "demo",
            "--input", str(input_file),
            "--target-host", "example.com",
            "--output-root", str(output_root),
            "--library-root", str(library_root),
            "--run-id", "unit-mjs",
            "--integration-index-root", str(tmp_path / "integrations"),
        ])

    assert rc == 0
    urls = {json.loads(line)["url"] for line in
            (output_root / "metadata.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()}
    assert "https://app.example.com/navigation.mjs" in urls
    assert "https://app.example.com/legacy.cjs" in urls
    assert "https://app.example.com/styles.css" not in urls

def test_param_name_boundary_rejects_delimiter_qualified_duplicate():
    """PARAM_NAME_RE anchors at a token boundary: the bare key is kept, the
    `:`-delimited `this.`-qualified duplicate is not."""
    snippet = 'switch(k){case"validation":this.validation=o[k];break;}'
    keys = J.extract_signals(snippet, "https://app.example/app.js")["interesting_keys"]
    assert "validation" in keys
    assert "this.validation" not in keys


def test_param_name_does_not_backtrack_on_inline_base64_source_map():
    """Regression: the greedy prefix class also matches base64, so an unanchored
    start backtracked quadratically inside an inline data: source map. Pre-fix this
    took ~13s at 8KB and ~85min at the 157KB runs seen in real bundles."""
    import time

    blob = "QUFBQmlk" * (8000 // 8)
    snippet = "var a=1;\n//# sourceMappingURL=data:application/json;charset=utf-8;base64," + blob + "\n"
    start = time.monotonic()
    J.extract_signals(snippet, "https://app.example/app.js")
    assert time.monotonic() - start < 5.0
