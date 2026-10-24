"""Offline signal tests: reflected text is not proof of execution."""

import httpx

from agents.context_detector import ContextType
from agents.xss_hunter import XSSHunter


def test_escaped_html_payload_is_not_executable_candidate() -> None:
    hunter = XSSHunter("https://example.test/search?q=baseline")
    payload = "<img src=x onerror=alert(1)>"
    baseline = httpx.Response(200, text="<p>baseline</p>", request=httpx.Request("GET", hunter.target_url))
    response = httpx.Response(200, text="<p>&lt;img src=x onerror=alert(1)&gt;</p>", request=httpx.Request("GET", hunter.target_url))
    hunter._make_request = lambda params: response
    try:
        result = hunter._submit_payload_for_param("q", payload, baseline)
        assert result.reflected
        assert result.context == ContextType.HTML_BODY
        assert not result.likely_executable
        assert not hunter._is_finding(result)
    finally:
        hunter.close()


def test_absent_payload_cannot_be_executable_candidate() -> None:
    hunter = XSSHunter("https://example.test/search?q=baseline")
    payload = "<img src=x onerror=alert(1)>"
    baseline = httpx.Response(200, text="<p>baseline</p>", request=httpx.Request("GET", hunter.target_url))
    response = httpx.Response(200, text="<p>nothing</p>", request=httpx.Request("GET", hunter.target_url))
    hunter._make_request = lambda params: response
    try:
        result = hunter._submit_payload_for_param("q", payload, baseline)
        assert not result.reflected
        assert not result.likely_executable
    finally:
        hunter.close()


def test_escaped_tag_in_attribute_is_not_executable_candidate() -> None:
    hunter = XSSHunter("https://example.test/search?q=baseline")
    payload = "<img src=x onerror=alert(1)>"
    baseline = httpx.Response(200, text="<input value='baseline'>", request=httpx.Request("GET", hunter.target_url))
    response = httpx.Response(200, text="<input value='&lt;img src=x onerror=alert(1)&gt;'>", request=httpx.Request("GET", hunter.target_url))
    hunter._make_request = lambda params: response
    try:
        result = hunter._submit_payload_for_param("q", payload, baseline)
        assert result.context == ContextType.HTML_ATTRIBUTE
        assert not result.likely_executable
    finally:
        hunter.close()


def test_raw_tag_inside_html_comment_is_not_a_finding() -> None:
    hunter = XSSHunter("https://example.test/search?q=baseline")
    payload = "<img src=x onerror=alert(1)>"
    baseline = httpx.Response(200, text="<!-- baseline -->", request=httpx.Request("GET", hunter.target_url))
    response = httpx.Response(200, text=f"<!-- {payload} -->", request=httpx.Request("GET", hunter.target_url))
    hunter._make_request = lambda params: response
    try:
        result = hunter._submit_payload_for_param("q", payload, baseline)
        assert result.context == ContextType.HTML_COMMENT
        assert result.reflected
        assert not result.likely_executable
        assert not hunter._is_finding(result)
    finally:
        hunter.close()


def test_comment_opener_in_script_string_is_not_html_comment() -> None:
    hunter = XSSHunter("https://example.test/search?q=baseline")
    payload = "alert(1)"
    baseline = httpx.Response(200, text='<script>const v = "baseline";</script>', request=httpx.Request("GET", hunter.target_url))
    response = httpx.Response(200, text=f'<script>const v = "<!-- {payload} -->";</script>', request=httpx.Request("GET", hunter.target_url))
    hunter._make_request = lambda params: response
    try:
        result = hunter._submit_payload_for_param("q", payload, baseline)
        assert result.context == ContextType.JS_STRING
    finally:
        hunter.close()


def test_script_tag_inside_html_comment_remains_comment() -> None:
    hunter = XSSHunter("https://example.test/search?q=baseline")
    baseline = httpx.Response(200, text="<!-- baseline -->", request=httpx.Request("GET", hunter.target_url))
    response = httpx.Response(200, text="<!-- <script>alert(1)</script> -->", request=httpx.Request("GET", hunter.target_url))
    hunter._make_request = lambda params: response
    try:
        result = hunter._submit_payload_for_param("q", "alert(1)", baseline)
        assert result.context == ContextType.HTML_COMMENT
        assert not result.likely_executable
    finally:
        hunter.close()


def test_js_string_code_token_remains_data_not_finding() -> None:
    hunter = XSSHunter("https://example.test/search?q=baseline")
    payload = "alert(1)"
    baseline = httpx.Response(200, text='<script>const v = "baseline";</script>', request=httpx.Request("GET", hunter.target_url))
    response = httpx.Response(200, text=f'<script>const v = "{payload}";</script>', request=httpx.Request("GET", hunter.target_url))
    hunter._make_request = lambda params: response
    try:
        result = hunter._submit_payload_for_param("q", payload, baseline)
        assert result.context == ContextType.JS_STRING
        assert result.reflected
        assert not result.likely_executable
        assert not hunter._is_finding(result)
    finally:
        hunter.close()


def test_js_string_matching_quote_breakout_remains_candidate_not_browser_proof() -> None:
    hunter = XSSHunter("https://example.test/search?q=baseline")
    payload = '";alert(1)//'
    baseline = httpx.Response(200, text='<script>const v = "baseline";</script>', request=httpx.Request("GET", hunter.target_url))
    response = httpx.Response(200, text=f'<script>const v = "{payload}";</script>', request=httpx.Request("GET", hunter.target_url))
    hunter._make_request = lambda params: response
    try:
        result = hunter._submit_payload_for_param("q", payload, baseline)
        assert result.context == ContextType.JS_STRING
        assert result.likely_executable
        assert hunter._is_finding(result)
        assert hunter._build_finding(result).type == "reflected"
    finally:
        hunter.close()


def test_escaped_quote_in_js_string_does_not_break_out() -> None:
    hunter = XSSHunter("https://example.test/search?q=baseline")
    payload = '\\";alert(1)//'
    baseline = httpx.Response(200, text='<script>const v = "baseline";</script>', request=httpx.Request("GET", hunter.target_url))
    response = httpx.Response(200, text=f'<script>const v = "{payload}";</script>', request=httpx.Request("GET", hunter.target_url))
    hunter._make_request = lambda params: response
    try:
        result = hunter._submit_payload_for_param("q", payload, baseline)
        assert result.reflected
        assert not result.likely_executable
    finally:
        hunter.close()


def test_js_template_escaped_interpolation_remains_data() -> None:
    hunter = XSSHunter("https://example.test/search?q=baseline")
    payload = r'\${alert(1)}'
    baseline = httpx.Response(200, text='<script>const v = `baseline`;</script>', request=httpx.Request("GET", hunter.target_url))
    response = httpx.Response(200, text=f'<script>const v = `{payload}`;</script>', request=httpx.Request("GET", hunter.target_url))
    hunter._make_request = lambda params: response
    try:
        result = hunter._submit_payload_for_param("q", payload, baseline)
        assert result.context == ContextType.JS_TEMPLATE
        assert not result.likely_executable
    finally:
        hunter.close()


def test_js_template_interpolation_is_distinct_candidate() -> None:
    hunter = XSSHunter("https://example.test/search?q=baseline")
    payload = '${alert(1)}'
    baseline = httpx.Response(200, text='<script>const v = `baseline`;</script>', request=httpx.Request("GET", hunter.target_url))
    response = httpx.Response(200, text=f'<script>const v = `{payload}`;</script>', request=httpx.Request("GET", hunter.target_url))
    hunter._make_request = lambda params: response
    try:
        result = hunter._submit_payload_for_param("q", payload, baseline)
        assert result.context == ContextType.JS_TEMPLATE
        assert result.likely_executable
        assert hunter._is_finding(result)
    finally:
        hunter.close()


def test_template_syntax_inside_ordinary_js_string_remains_data() -> None:
    hunter = XSSHunter("https://example.test/search?q=baseline")
    payload = '${alert(1)}'
    baseline = httpx.Response(200, text='<script>const v = "baseline";</script>', request=httpx.Request("GET", hunter.target_url))
    response = httpx.Response(200, text=f'<script>const v = "{payload}";</script>', request=httpx.Request("GET", hunter.target_url))
    hunter._make_request = lambda params: response
    try:
        result = hunter._submit_payload_for_param("q", payload, baseline)
        assert result.context == ContextType.JS_STRING
        assert not result.likely_executable
    finally:
        hunter.close()


def test_script_tag_breakout_is_separate_candidate() -> None:
    hunter = XSSHunter("https://example.test/search?q=baseline")
    payload = '</ScRiPt><svg onload=alert(1)>'
    baseline = httpx.Response(200, text='<script>const v = "baseline";</script>', request=httpx.Request("GET", hunter.target_url))
    response = httpx.Response(200, text=f'<script>const v = "{payload}";</script>', request=httpx.Request("GET", hunter.target_url))
    hunter._make_request = lambda params: response
    try:
        result = hunter._submit_payload_for_param("q", payload, baseline)
        assert result.reflected
        assert result.likely_executable
        assert hunter._is_finding(result)
    finally:
        hunter.close()


def test_other_quote_inside_js_string_does_not_break_out() -> None:
    hunter = XSSHunter("https://example.test/search?q=baseline")
    payload = "';alert(1)//"
    baseline = httpx.Response(200, text='<script>const v = "baseline";</script>', request=httpx.Request("GET", hunter.target_url))
    response = httpx.Response(200, text=f'<script>const v = "{payload}";</script>', request=httpx.Request("GET", hunter.target_url))
    hunter._make_request = lambda params: response
    try:
        result = hunter._submit_payload_for_param("q", payload, baseline)
        assert result.reflected
        assert not result.likely_executable
    finally:
        hunter.close()
