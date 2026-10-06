"""Individual static XSS site seeds; none is source-to-sink or browser proof."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from agents import js_analyzer as J
from agents.xss_sink_sites import SITE_RULES, scan_sink_sites


@pytest.mark.parametrize(
    ("snippet", "site"),
    [
        ("document.write(value)", "document.write"),
        ("document['writeln'](value)", "document.writeln"),
        ("el.innerHTML = value", "Element.innerHTML"),
        ("el['outerHTML'] += value", "Element.outerHTML"),
        ("el.insertAdjacentHTML('beforeend', value)", "Element.insertAdjacentHTML"),
        ("frame.srcdoc = html", "HTMLIFrameElement.srcdoc"),
        ("document.querySelector('iframe').attributes.srcdoc.nodeValue = html", "HTMLIFrameElement.attributes.srcdoc.nodeValue"),
        ("document.querySelector('iframe').attributes.srcdoc.textContent = html", "HTMLIFrameElement.attributes.srcdoc.textContent"),
        ("iframe.setAttribute('srcdoc', html)", "HTMLIFrameElement.setAttribute(srcdoc)"),
        ("el.onclick = code", "Element.onclick"),
        ("el['onerror'] = code", "Element.onerror"),
        ("el.setAttribute('onload', code)", "Element.setAttribute(onload)"),
        ("script.textContent = code", "HTMLScriptElement.textContent"),
        ("script['src'] = url", "HTMLScriptElement.src"),
        ("const s = document.createElement('script'); s.appendChild(document.createTextNode(code));", "HTMLScriptElement.appendChild(textNode)"),
        ("const s = document.createElement('script'); s.append(document.createTextNode(code));", "HTMLScriptElement.append(textNode)"),
        ("const s = document.createElement('script'); s.textContent = code;", "HTMLScriptElement.alias.textContent"),
        ("const s = document.createElement('script'); s.src = url;", "HTMLScriptElement.alias.src"),
        ("eval(value)", "eval"),
        ("window.eval(value)", "window.eval"),
        ("new Function(value)", "Function"),
        ("jQuery.globalEval(value)", "jQuery.globalEval"),
        ("eval.call(null, value)", "eval.call"),
        ("Reflect.construct(Function, [value])", "Reflect.construct(Function)"),
        ("setTimeout('run()', 5)", "setTimeout(string)"),
        ("setInterval(code, 5)", "setInterval(candidate)"),
        ("importScripts(url)", "importScripts"),
        ("import(moduleUrl)", "import(dynamic)"),
        ("new Worker(workerUrl)", "Worker(url)"),
        ("$.getScript(url)", "jQuery.getScript"),
        ("$.ajax({url, dataType: 'script'})", "jQuery.ajax(script)"),
        ("location.assign(url)", "Location.assign"),
        ("location.replace(url)", "Location.replace"),
        ("window.open(url)", "window.open"),
        ("navigation.navigate(url)", "Navigation.navigate"),
        ("location.href = url", "Location.href"),
        ("Object.assign(location, {href: url})", "Object.assign(location,href)"),
        ("anchor.href = url", "HTMLAnchorElement.href"),
        ("iframe['src'] = url", "HTMLIFrameElement.src"),
        ("form.action = url", "HTMLFormElement.action"),
        ("button.formAction = url", "HTMLButtonElement.formAction"),
        ("embed.src = url", "HTMLEmbedElement.src"),
        ("a.setAttribute('href', url)", "Element.setAttribute(href)"),
        ("object.data = url", "HTMLObjectElement.data"),
        ("new DOMParser().parseFromString(html, 'text/html')", "DOMParser.parseFromString(text/html)"),
        ("Document.parseHTMLUnsafe(html)", "Document.parseHTMLUnsafe"),
        ("el.setHTMLUnsafe(html)", "Element.setHTMLUnsafe"),
        ("range.createContextualFragment(html)", "Range.createContextualFragment"),
        ("el.insertAdjacentHTML('beforeend', html)", "Element.insertAdjacentHTML"),
        ("document.execCommand('insertHTML', false, html)", "Document.execCommand(insertHTML)"),
        ("$.parseHTML(html)", "jQuery.parseHTML"),
        ("$(el).find('.result').html(user)", "jQuery.html"),
        ("$(el).find('.result').eq(0).append(user)", "jQuery.append"),
        ("$(el).html(html)", "jQuery.html"),
        ("$(el).append(html)", "jQuery.append"),
        ("$(el).before(html)", "jQuery.before"),
        ("$(el).wrapInner(html)", "jQuery.wrapInner"),
        ("$(el).insertAfter(html)", "jQuery.insertAfter"),
        ("$(el).prop('innerHTML', html)", "jQuery.prop(innerHTML)"),
        ("$(html)", "jQuery.constructor(candidate)"),
        ("$(location.hash)", "jQuery.constructor(candidate)"),
        ("$compile(template)(scope)", "AngularJS.$compile"),
        ("WinJS.Utilities.setInnerHTMLUnsafe(el, html)", "WinJS.Utilities.setInnerHTMLUnsafe"),
        ("unsafeHTML(value)", "Lit.unsafeHTML"),
        ("unsafeSVG(value)", "Lit.unsafeSVG"),
        ("html`${unsafeStatic(value)}`", "Lit.unsafeStatic(template)"),
        ("<div dangerouslySetInnerHTML={{__html: value}} />", "React.dangerouslySetInnerHTML"),
        ("<div v-html=\"value\" />", "Vue.v-html"),
        ("Vue.compile(template)", "Vue.compile"),
        ("<div x-html=\"value\" />", "Alpine.x-html"),
        ("{@html value}", "Svelte.@html"),
        ("<div set:html={value} />", "Astro.set:html"),
        ("renderer.setProperty(node, 'innerHTML', value)", "Angular.Renderer2.setProperty(innerHTML)"),
        ("$sce.trustAsHtml(value)", "AngularJS.$sce.trustAsHtml"),
        ("Object.assign(el, {innerHTML: value})", "Object.assign(innerHTML,candidate)"),
    ],
)
def test_individual_site_signatures(snippet: str, site: str):
    hits = scan_sink_sites(snippet)["hits"]
    assert site in {hit["signature"] for hit in hits}, (site, hits)
    assert all(hit["start"] >= 0 and hit["end"] > hit["start"] for hit in hits)
    assert site in {hit["signature"] for hit in J.extract_signals(snippet, "https://app.example/app.js")["sink_sites"]}


@pytest.mark.parametrize(
    ("snippet", "absent"),
    [
        ("document.write === callback", "document.write"),
        ("el.innerHTML === html", "Element.innerHTML"),
        ("el.onclick === handler", "Element.onclick"),
        ("el['onerror'] === code", "Element.onerror"),
        ("img.attributes.alt.nodeValue = value", "HTMLIFrameElement.attributes.srcdoc.nodeValue"),
        ("el.attributes.srcdoc.nodeValue = value", "HTMLIFrameElement.attributes.srcdoc.nodeValue"),
        ("script.textContent === code", "HTMLScriptElement.textContent"),
        ("div.textContent = code", "HTMLScriptElement.textContent"),
        ("document.createElement('div').appendChild(document.createTextNode(code))", "HTMLScriptElement.appendChild(textNode)"),
        ("obj.eval(value)", "eval"),
        ("obj.Function(value)", "Function"),
        ("setTimeout(callback, 5)", "setTimeout(string)"),
        ("new Worker('/fixed.js')", "Worker(url)"),
        ("$.ajax({url, dataType: 'json'})", "jQuery.ajax(script)"),
        ("location.href === url", "Location.href"),
        ("Object.assign(obj, {href: url})", "Object.assign(location,href)"),
        ("router.execCommand('insertHTML', false, html)", "Document.execCommand(insertHTML)"),
        ("link.href === url", "HTMLAnchorElement.href"),
        ("stylesheet.href = url", "HTMLAnchorElement.href"),
        ("frame.src === url", "HTMLIFrameElement.src"),
        ("new DOMParser().parseFromString(xml, 'text/xml')", "DOMParser.parseFromString(text/html)"),
        ("node.find('.result').html(user)", "jQuery.html"),
        ("$(el).find('.result').html()", "jQuery.html"),
        ("$(el).html()", "jQuery.html"),
        ("$(el).attr('innerHTML', html)", "jQuery.prop(innerHTML)"),
        ("node.append(html)", "jQuery.append"),
        ("other.wrapInner(html)", "jQuery.wrapInner"),
        ("$(el)", "jQuery.constructor(candidate)"),
        ("$(node)", "jQuery.constructor(candidate)"),
        ("$('#known-id')", "jQuery.constructor(candidate)"),
        ("Vue.compile('<p>fixed</p>')", "Vue.compile"),
        ("unsafeStatic(value)", "Lit.unsafeStatic(template)"),
        ("Object.assign(obj, {innerHTML: value})", "Object.assign(innerHTML,candidate)"),
        ("WinJS.Utilities.setInnerHTMLUnsafe === helper", "WinJS.Utilities.setInnerHTMLUnsafe"),
        ("$sce.getTrustedHtml(value)", "AngularJS.$sce.trustAsHtml"),
    ],
)
def test_individual_site_false_positives(snippet: str, absent: str):
    assert absent not in {hit["signature"] for hit in scan_sink_sites(snippet)["hits"]}


def test_jquery_constructor_candidates_do_not_lose_html_to_dom_wrappers():
    scan = scan_sink_sites("$(el);" * 9 + "$(html);")
    assert [site["signature"] for site in scan["hits"]] == ["jQuery.constructor(candidate)"]
    assert scan["truncated"] is False


def test_script_alias_stops_at_rebinding():
    shadowed = 'const s = document.createElement("script"); { const s = document.createElement("div"); s.textContent = user; }'
    reassigned = 'const s = document.createElement("script"); s = document.createElement("div"); s.appendChild(document.createTextNode(user));'
    parameter = 'const s = document.createElement("script"); function render(s) { s.textContent = user; }'
    arrow = 'const s = document.createElement("script"); const render = (s) => { s.textContent = user; };'
    expression_arrow = 'const s = document.createElement("script"); const render = s => s.textContent = user;'
    first_param = 'const s = document.createElement("script"); const render = (s, x) => { s.textContent = user; };'
    middle_param = 'const s = document.createElement("script"); const render = (x, s, y) => { s.textContent = user; };'
    first_param_expression = 'const s = document.createElement("script"); const render = (s, x) => s.textContent = user;'
    middle_param_expression = 'const s = document.createElement("script"); const render = (x, s, y) => s.textContent = user;'
    object_method = 'const s = document.createElement("script"); const o = { f(s) { s.textContent = user; } };'
    class_method = 'const s = document.createElement("script"); class C { f(x, s) { s.textContent = user; } }'
    inner_reassignment = 'const s = document.createElement("script"); { s = document.createElement("div"); } s.textContent = user;'
    uninitialized = 'const s = document.createElement("script"); { let s; s.textContent = user; }'
    for snippet in (shadowed, reassigned, parameter, arrow, expression_arrow, first_param, middle_param,
                    first_param_expression, middle_param_expression, object_method, class_method,
                    inner_reassignment, uninitialized):
        assert not any(site["family"] == "script_alias_candidate" for site in scan_sink_sites(snippet)["hits"])


def test_script_alias_resumes_after_inner_shadowing():
    snippets = (
        'const s = document.createElement("script"); { const s = document.createElement("div"); s.textContent = ignored; } s.textContent = user;',
        'const s = document.createElement("script"); const render = s => s.textContent = ignored; s.textContent = user;',
        'const s = document.createElement("script"); const render = (s, x) => { s.textContent = ignored; }; s.textContent = user;',
        'const s = document.createElement("script"); const render = (x, s, y) => s.textContent = ignored; s.textContent = user;',
        'const s = document.createElement("script"); const o = { f(s) { s.textContent = ignored; } }; s.textContent = user;',
        'const s = document.createElement("script"); class C { f(s) { s.textContent = ignored; } } s.textContent = user;',
        'const s = document.createElement("script"); function render() { s.textContent = user; }',
        'const s = document.createElement("script"); const o = { f() { s.textContent = user; } };',
        'const s = document.createElement("script"); { if(s) { s.textContent = user; } }',
    )
    for snippet in snippets:
        sites = [site for site in scan_sink_sites(snippet)["hits"] if site["family"] == "script_alias_candidate"]
        assert len(sites) == 1
        assert sites[0]["start"] == snippet.rfind("s.textContent")


def test_site_output_is_bounded_and_deterministic():
    text = "document.write(value);" * 1000 + "el.innerHTML = value;"
    first = scan_sink_sites(text, max_hits=6, per_rule=3)
    assert first == scan_sink_sites(text, max_hits=6, per_rule=3)
    assert first["truncated"] is True
    assert len(first["hits"]) <= 6
    assert [h["start"] for h in first["hits"]] == sorted(h["start"] for h in first["hits"])
    assert len({rule.signature for rule in SITE_RULES}) == len(SITE_RULES)
    assert all(h["tier"] in {"html", "code", "url", "candidate"} for h in first["hits"])


def test_site_offsets_reference_original_text():
    snippet = "before\ndocument.write(value)\nafter"
    hits = scan_sink_sites(snippet)["hits"]
    hit = next(h for h in hits if h["signature"] == "document.write")
    assert snippet[hit["start"]:hit["end"]].startswith("document.write")
    assert hit["start"] == len("before\n")


def test_source_map_packet_rows_carry_individual_sites(tmp_path: Path):
    record = J.JsRecord(url="https://app.example/app.js", status=200, content_type="text/javascript", byte_count=10, sha256="a" * 64, artifact_path=str(tmp_path / "app.js"))
    modules = [{"source_index": 0, "source": "src/widget.js", "source_root": "", "source_label": "src/widget.js", "has_content": True, "content": "document.write(value);"}]
    rows, _packets, _budget = J.write_source_map_modules(root=tmp_path, source_maps_dir=tmp_path / "maps", record=record, source_map_sha256="b" * 64, modules=modules, chunk_size=500, chunk_overlap=0, module_limit=10, max_packets=10, max_expanded_bytes=10000)
    assert rows[0]["sink_sites"][0]["signature"] == "document.write"
    assert rows[0]["sink_sites"][0]["start"] == 0
    assert rows[0]["sink_sites_truncated"] is False
    packet = Path(rows[0]["packet_paths"][0]).read_text()
    assert "document.write [html] at char 0" in packet
    assert json.loads(json.dumps(rows))[0]["module_path"].endswith(".js")


def test_offline_inventory_persists_site_offsets_and_packet_route(tmp_path: Path):
    url = "https://app.example.com/static/app.js"
    js_list = tmp_path / "jsfiles.txt"
    js_list.write_text(url + "\n", encoding="utf-8")
    body = b"const x = location.hash; document.write(x); window.open(x);"
    with patch.object(J, "http_get", return_value=(body, 200, "application/javascript")):
        assert J.main([
            "inventory", "demo", "--input", str(js_list), "--target-host", "example.com",
            "--output-root", str(tmp_path / "out"), "--library-root", str(tmp_path / "library"),
            "--run-id", "site-unit", "--chunk-size", "200", "--chunk-overlap", "0",
        ]) == 0
    metadata = [json.loads(line) for line in (tmp_path / "out" / "metadata.jsonl").read_text().splitlines()]
    row = metadata[0]
    sites = row["sink_sites"]
    assert {site["signature"] for site in sites} >= {"document.write", "window.open"}
    assert row["sink_sites_truncated"] is False
    assert row["signal_counts"]["sink_sites"] == len(sites)
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert manifest["sink_site_hits"] == len(sites)
    assert manifest["sink_site_capped_artifacts"] == 0
    original = body.decode()
    assert all(original[site["start"]:site["end"]] for site in sites)
    packet = next((tmp_path / "out" / "packets").glob("*.md")).read_text()
    assert "Individual XSS Sink Review Sites" in packet
    assert "document.write [html]" in packet
    assert "window.open [url]" in packet
