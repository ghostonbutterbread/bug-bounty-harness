"""Individual static XSS source-site seeds; none is attacker control or browser proof."""
from __future__ import annotations

import pytest

from agents.xss_source_sites import SOURCE_RULES, scan_source_sites


@pytest.mark.parametrize(
    ("snippet", "signature", "name"),
    [
        ("const q = searchParams.get('searchTerm')", "URLSearchParams-receiver.get(NAME)", "searchTerm"),
        ("const q = query.get('campaignId')", "URLSearchParams-receiver.get(NAME)", "campaignId"),
        ("const q = searchParams.get('q')", "URLSearchParams-receiver.get(NAME)", "q"),
        ("const q = urlSearchParams.get('campaignId')", "URLSearchParams-receiver.get(NAME)", "campaignId"),
        ("var v = queryParams.getAll('facet')", "URLSearchParams-receiver.get(NAME)", "facet"),
        ("if (sp.has('urlRoot')) {}", "URLSearchParams-receiver.get(NAME)", "urlRoot"),
        ("new URLSearchParams(window.location.search).get('email')",
         "new URLSearchParams(...).get(NAME)", "email"),
        ("const s = window.location.search; const t = s.match(/x/) && params.get('textKey')",
         "URLSearchParams-receiver.get(NAME)", "textKey"),
        ("id = getQueryString('orderId')", "legacy-getQueryString(NAME)", "orderId"),
        ("cat = getQueryParam('categoryId')", "legacy-getQueryString(NAME)", "categoryId"),
        ("store = getParameter('storeId')", "legacy-getQueryString(NAME)", "storeId"),
        ("router.query.giftMessage", "router-query.NAME", "giftMessage"),
        ("route . query . giftMessage", "router-query.NAME", "giftMessage"),
        ("route.query['giftMessage']", "router-query.NAME", "giftMessage"),
        ("req.query.coupon", "router-query.NAME", "coupon"),
        ("useSearchParams().get('previewTitle')", "useSearchParams().get(NAME)", "previewTitle"),
        ("if (window.location.hash) {}", "location.hash-read", "location.hash-read"),
        ("if (window.location . hash) {}", "location.hash-read", "location.hash-read"),
        ("searchParams                    .get('longGap')", "URLSearchParams-receiver.get(NAME)", "longGap"),
    ],
)
def test_url_and_fragment_sources(snippet, signature, name):
    result = scan_source_sites(snippet)
    hits = [h for h in result["hits"] if h["signature"] == signature]
    assert hits, f"missing {signature} in: {snippet}"
    assert any(h["name"] == name for h in hits)


@pytest.mark.parametrize(
    ("snippet", "signature", "name"),
    [
        ("Cookies.get('selectedStore')", "Cookies.get(NAME)", "selectedStore"),
        ("const t = jsCookie.get('uPref')", "Cookies.get(NAME)", "uPref"),
        ("v = getCookie('mboxEdgeCluster')", "getCookie(NAME)", "mboxEdgeCluster"),
        ("sessionStorage.getItem('orderDetailsParams')", "sessionStorage.getItem(KEY)", "orderDetailsParams"),
        ("window.localStorage.getItem('recentSearches')", "localStorage.getItem(KEY)", "recentSearches"),
    ],
)
def test_cookie_and_storage_sources(snippet, signature, name):
    result = scan_source_sites(snippet)
    hits = [h for h in result["hits"] if h["signature"] == signature]
    assert hits, f"missing {signature} in: {snippet}"
    assert hits[0]["name"] == name
    assert hits[0]["tier"] in ("cookie", "storage")


@pytest.mark.parametrize(
    ("snippet", "signature", "name"),
    [
        ("const id = node.dataset.catIdentifier", "dataset.NAME-read", "catIdentifier"),
        ("v = el.getAttribute('data-cat-identifier')", "getAttribute(data-NAME)", "cat-identifier"),
        ("const s = params.storeId", "route-params.NAME", "storeId"),
        ("map.forEach(params.get('label'))", "URLSearchParams-receiver.get(NAME)", "label"),
        ("formData.get('productCaption')", "FormData.get(NAME)", "productCaption"),
        ("new FormData(form).getAll('lineItems')", "FormData.get(NAME)", "lineItems"),
        ("window.addEventListener('message', handler)", "message-listener", "message-listener"),
        ("if (window.name) {}", "window.name-read", "window.name-read"),
    ],
)
def test_dom_route_form_sources(snippet, signature, name):
    result = scan_source_sites(snippet)
    hits = [h for h in result["hits"] if h["signature"] == signature]
    assert hits, f"missing {signature} in: {snippet}"
    assert hits[0]["name"] == name


def test_route_params_not_method_names():
    result = scan_source_sites("params.get('x'); params.has('y'); params.set('z', 1)")
    assert not [h for h in result["hits"] if h["signature"] == "route-params.NAME"]


def test_noise_not_flagged():
    text = (
        "response.headers.get('Content-Type');"
        "map.get('items');"
        "config.get('apiKey');"
        "headers.get('Location');"
        "this.state = {}"
    )
    result = scan_source_sites(text)
    families = {h["family"] for h in result["hits"]}
    assert "url_param" not in families


def test_assignment_not_read():
    # el.dataset.state = 'x' is a WRITE, not a source read
    result = scan_source_sites("el.dataset.state = value")
    assert not [h for h in result["hits"] if h["signature"] == "dataset.NAME-read"]


@pytest.mark.parametrize("text", [
    "const url = window.location.search; headers.get('Authorization')",
    "window.location.search && headers.get('Authorization')",
    "new URLSearchParams(location.search); unrelated.get('notQuery')",
    "location.hash = 'fixed'",
    "window.location.hash += '#fixed'",
    "location.hash &&= value",
    "location.hash ||= value",
    "location.hash ??= value",
    "URLSearchParams.append('note', value)",
    "fd.append('gift-card-number', num)",
])
def test_unrelated_getter_and_writes_are_not_ingress_sites(text):
    assert not scan_source_sites(text)["hits"]


def test_offsets_and_bounds():
    text = "const q = searchParams.get('searchTerm'); // pad " + "x" * 2000
    result = scan_source_sites(text)
    assert result["hits"]
    hit = result["hits"][0]
    assert text[hit["start"]:hit["end"]].startswith("searchParams.get")
    assert hit["name"] == "searchTerm"
    import pytest
    with pytest.raises(ValueError):
        scan_source_sites(text, max_hits=0)


def test_truncation_flag():
    text = " ".join(["searchParams.get('pp')"] * 60)
    result = scan_source_sites(text, per_rule=3)
    assert result["truncated"] is True
    assert len(result["hits"]) <= 3


def test_default_budget_retains_later_named_fields():
    text = ";".join(f"searchParams.get('input{i:02d}')" for i in range(20))
    result = scan_source_sites(text)
    assert {f"input{i:02d}" for i in range(20)} <= {site["name"] for site in result["hits"]}
    assert not result["truncated"]


def test_incidental_short_receiver_tokens_do_not_hide_later_named_input():
    text = ("sp " * 10_001) + "sp.get('lateParam')"
    result = scan_source_sites(text)
    assert "lateParam" in {site["name"] for site in result["hits"]}
    assert not result["truncated"]


def test_rule_table_shape():
    assert SOURCE_RULES, "rule table must not be empty"
    for item in SOURCE_RULES:
        assert item.tier in ("url", "cookie", "storage", "dom-data", "form", "route", "postmessage")
        assert isinstance(item.needles, tuple)
