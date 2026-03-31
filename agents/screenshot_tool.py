#!/usr/bin/env python3
"""
Screenshot tool with WAF bypass.
Uses BrowserBlockFix stealth browser (Akamai/Cloudflare/Imperva bypass).

Usage:
    # Single URL
    python3 screenshot_tool.py --single "https://target.com/"

    # Batch from file
    python3 screenshot_tool.py urls.txt -o ~/Shared/bounty_recon/program/screenshots/

    # Skip WAF bypass (faster for accessible sites)
    python3 screenshot_tool.py urls.txt --no-bypass
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, "/home/ryushe/projects/bug_bounty_harness/agents")

try:
    from browser_block_fix import BrowserBlockFix
    _HAS_BBF = True
except ImportError:
    _HAS_BBF = False
    print("[!] browser_block_fix not found — WAF bypass disabled")


# ---------------------------------------------------------------------------
# ScreenshotTool
# ---------------------------------------------------------------------------

class ScreenshotTool:
    """Take screenshots with optional WAF bypass via BrowserBlockFix stealth browser."""

    def __init__(self, output_dir: str = "screenshots"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)

    # -----------------------------------------------------------------------
    # Core: stealth browser context
    # -----------------------------------------------------------------------

    def _make_bbf(self, url: str) -> "BrowserBlockFix":
        """Return a BBF instance with stealth browser spawned."""
        bbf = BrowserBlockFix(url)
        bbf.spawn_browser()
        return bbf

    def _safe_name(self, url: str, name: str | None) -> str:
        """Derive a filesystem-safe filename from URL."""
        if name:
            return name
        parsed = urlparse(url)
        path_slug = parsed.path.strip("/").replace("/", "_") or "root"
        return f"{parsed.netloc.replace('.', '_')}_{path_slug}"

    # -----------------------------------------------------------------------
    # screenshot_url — basic capture with WAF detection
    # -----------------------------------------------------------------------

    def screenshot_url(self, url: str, name: str | None = None,
                       bypass: bool = True) -> str:
        """Take a full-page screenshot, using WAF bypass when blocked.

        Args:
            url:    Target URL.
            name:   Output filename stem (no extension).
            bypass: Enable stealth browser (always used; curl probes WAF first
                    and prints the WAF name for awareness).

        Returns:
            Absolute path to saved PNG.
        """
        out_path = self.output_dir / f"{self._safe_name(url, name)}.png"

        if bypass and _HAS_BBF:
            with BrowserBlockFix(url) as bbf:
                # Probe with curl to surface WAF info before going headless
                probe = bbf.curl_get(url)
                blocked, waf_name = bbf.is_blocked(probe)
                if blocked:
                    print(f"    [WAF] {waf_name} detected — using stealth browser")
                else:
                    print(f"    [curl] {probe.get('status', '?')} — no WAF, stealth browser anyway")

                bbf.spawn_browser()
                page = bbf._page
                _goto_wait(page, url, wait_until="networkidle", timeout=30_000)
                page.wait_for_timeout(2_000)
                page.screenshot(path=str(out_path), full_page=True)
        else:
            # Plain Playwright, no stealth patches
            try:
                from playwright.sync_api import sync_playwright
            except ImportError:
                print("[!] Playwright not installed: pip install playwright && playwright install chromium")
                sys.exit(1)

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                _goto_wait(page, url, wait_until="domcontentloaded", timeout=15_000)
                page.wait_for_timeout(1_500)
                page.screenshot(path=str(out_path), full_page=True)
                browser.close()

        return str(out_path)

    # -----------------------------------------------------------------------
    # screenshot_spa — wait for a JS selector before capture
    # -----------------------------------------------------------------------

    def screenshot_spa(self, url: str, name: str | None = None,
                       wait_for: str | None = None,
                       bypass: bool = True) -> str:
        """Screenshot a SPA, optionally waiting for a CSS selector to appear.

        Args:
            url:      Target URL.
            name:     Output filename stem.
            wait_for: CSS selector to wait for (e.g. '#app', '.content-loaded').
                      None = wait for networkidle only.
            bypass:   Use stealth browser.

        Returns:
            Absolute path to saved PNG.
        """
        out_path = self.output_dir / f"{self._safe_name(url, name)}_spa.png"

        def _capture(page) -> None:
            _goto_wait(page, url, wait_until="networkidle", timeout=45_000)
            if wait_for:
                try:
                    page.wait_for_selector(wait_for, timeout=15_000)
                    print(f"    [SPA] selector '{wait_for}' appeared")
                except Exception:
                    print(f"    [SPA] selector '{wait_for}' timed out — capturing anyway")
            page.wait_for_timeout(2_000)
            page.screenshot(path=str(out_path), full_page=True)

        if bypass and _HAS_BBF:
            with BrowserBlockFix(url) as bbf:
                bbf.spawn_browser()
                _capture(bbf._page)
        else:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                _capture(browser.new_page())
                browser.close()

        return str(out_path)

    # -----------------------------------------------------------------------
    # screenshot_scrolled — scroll-then-capture for infinite scroll pages
    # -----------------------------------------------------------------------

    def screenshot_scrolled(self, url: str, name: str | None = None,
                            scrolls: int = 3, pause: float = 1.5,
                            bypass: bool = True) -> str:
        """Scroll down N times (triggering lazy-load/infinite scroll) then capture.

        Args:
            url:    Target URL.
            name:   Output filename stem.
            scrolls: Number of scroll-to-bottom cycles.
            pause:  Seconds to wait between scrolls for content to load.
            bypass: Use stealth browser.

        Returns:
            Absolute path to saved PNG.
        """
        out_path = self.output_dir / f"{self._safe_name(url, name)}_scrolled.png"

        def _capture(page) -> None:
            _goto_wait(page, url, wait_until="domcontentloaded", timeout=30_000)
            page.wait_for_timeout(2_000)
            for i in range(scrolls):
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                page.wait_for_timeout(int(pause * 1_000))
                print(f"    [scroll] {i + 1}/{scrolls}")
            # Scroll back to top so header is visible
            page.evaluate("window.scrollTo(0, 0)")
            page.wait_for_timeout(500)
            page.screenshot(path=str(out_path), full_page=True)

        if bypass and _HAS_BBF:
            with BrowserBlockFix(url) as bbf:
                bbf.spawn_browser()
                _capture(bbf._page)
        else:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                _capture(browser.new_page())
                browser.close()

        return str(out_path)

    # -----------------------------------------------------------------------
    # screenshot_with_auth — fill login form then capture target page
    # -----------------------------------------------------------------------

    def screenshot_with_auth(self, url: str, credentials: dict,
                             login_url: str | None = None,
                             name: str | None = None,
                             bypass: bool = True) -> str:
        """Log in then screenshot an authenticated page.

        Args:
            url:         Page to capture after login.
            credentials: Dict with keys mapping to form field names/ids.
                         e.g. {"username": "admin", "password": "secret"}
            login_url:   Login page URL (defaults to url if same page).
            name:        Output filename stem.
            bypass:      Use stealth browser.

        Returns:
            Absolute path to saved PNG.
        """
        out_path = self.output_dir / f"{self._safe_name(url, name)}_auth.png"
        login_target = login_url or url

        def _capture(bbf_or_page, is_bbf: bool) -> None:
            if is_bbf:
                # Use BBF's browser_post for human-like form fill
                bbf_or_page.browser_post(login_target, data=credentials)
                page = bbf_or_page._page
            else:
                page = bbf_or_page
                page.goto(login_target, wait_until="domcontentloaded", timeout=30_000)
                for field, value in credentials.items():
                    selector = f"[name={field}], [id={field}]"
                    try:
                        page.fill(selector, str(value))
                    except Exception:
                        pass
                try:
                    page.click("[type=submit]", timeout=3_000)
                except Exception:
                    page.keyboard.press("Enter")
                page.wait_for_load_state("networkidle", timeout=15_000)

            # Navigate to target if different from login page
            if login_url and login_url != url:
                _goto_wait(page, url, wait_until="networkidle", timeout=30_000)

            page.wait_for_timeout(2_000)
            page.screenshot(path=str(out_path), full_page=True)

        if bypass and _HAS_BBF:
            with BrowserBlockFix(login_target) as bbf:
                bbf.spawn_browser()
                _capture(bbf, is_bbf=True)
        else:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                _capture(browser.new_page(), is_bbf=False)
                browser.close()

        return str(out_path)


# ---------------------------------------------------------------------------
# Batch processing
# ---------------------------------------------------------------------------

def screenshot_file(input_file: str, output_dir: str = "screenshots",
                    bypass: bool = True, delay: float = 1.5,
                    categorize: bool = False) -> list[dict]:
    """Screenshot every URL in a file (one per line, # = comment)."""
    import urllib.request
    import urllib.error

    tool = ScreenshotTool(output_dir)
    base_output = Path(output_dir)

    # Category folders
    categories = {
        "200": base_output / "200_success",
        "301": base_output / "301_redirect",
        "302": base_output / "302_redirect",
        "401": base_output / "401_unauthorized",
        "403": base_output / "403_forbidden",
        "404": base_output / "404_not_found",
        "500": base_output / "500_error",
        "error": base_output / "error",
        "screenshot": base_output / "screenshots",  # all screenshots together
    }

    if categorize:
        for cat_dir in categories.values():
            cat_dir.mkdir(parents=True, exist_ok=True)
        print("[*] Categorization enabled — organizing by status code")

    with open(input_file) as f:
        urls = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]

    if not urls:
        print("[!] No URLs found in file")
        return []

    print(f"[*] {len(urls)} URLs → {output_dir}")

    results: list[dict] = []
    stats = {cat: 0 for cat in categories}
    stats["total"] = len(urls)

    # --- Persistent browser for batch speed ---
    browser = None
    browser_ctx = None
    playwright_ctx = None
    browser_restart_counter = 0
    BROWSER_RESTART_EVERY = 100  # Restart browser every 100 URLs

    def _launch_browser():
        """Launch or relaunch browser."""
        nonlocal browser, browser_ctx, playwright_ctx, browser_restart_counter
        if browser:
            try:
                browser.close()
            except Exception:
                pass
        if playwright_ctx:
            try:
                playwright_ctx.stop()
            except Exception:
                pass
        try:
            from playwright.sync_api import sync_playwright
            playwright_ctx = sync_playwright().start()
            browser = playwright_ctx.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage",
                      "--disable-blink-features=AutomationControlled"]
            )
            browser_ctx = browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
            browser_restart_counter = 0
            return True
        except Exception as e:
            print(f"[!] Browser launch failed: {e}")
            browser = None
            return False

    if not _launch_browser():
        print("[!] Could not start browser, exiting")
        return []

    print("[*] Persistent browser launched — auto-restarts every 100 URLs")

    try:
        for i, url in enumerate(urls):
            if not url.startswith(("http://", "https://")):
                url = "https://" + url

            print(f"[{i + 1}/{len(urls)}] {url} ...", end=" ", flush=True)

            # Probe first to get status code (fast timeout)
            status_code = "error"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    status_code = str(resp.status)
            except urllib.error.HTTPError as e:
                status_code = str(e.code)
            except Exception:
                pass

            print(f"[{status_code}] ", end="", flush=True)

            screenshot_ok = False
            if status_code == "error":
                # Skip browser for DNS/connection errors
                print("[DNS fail] skip")
                stats["error"] += 1
                results.append({"url": url, "status_code": status_code, "status": "dns_fail"})
            else:
                try:
                    out_path = tool.output_dir / f"{tool._safe_name(url, None)}.png"

                    if browser and browser_ctx:
                        # Check browser is functional before using
                        try:
                            # Try to create a page to verify browser is alive
                            test_page = browser_ctx.new_page()
                            test_page.close()
                        except Exception as e:
                            print(f"[browser dead, restarting] ", end="")
                            _launch_browser()

                        # Use persistent browser — fast mode for batch
                        try:
                            page = browser_ctx.new_page()
                        except Exception as e:
                            print(f"[ctx err: {type(e).__name__}] ", end="")
                            _launch_browser()
                            continue  # Skip this URL, will retry next iteration

                        try:
                            _goto_wait(page, url, wait_until="domcontentloaded", timeout=10_000)
                            page.wait_for_timeout(300)  # Minimal wait
                            page.screenshot(path=str(out_path), full_page=True)
                            screenshot_ok = True
                            browser_restart_counter += 1
                            # Restart browser every N URLs to prevent memory issues
                            if browser_restart_counter >= BROWSER_RESTART_EVERY:
                                print("[browser restart] ", end="")
                                _launch_browser()
                        except Exception as e:
                            print(f"[nav err: {type(e).__name__}]", end=" ")
                            # Browser might be dead, try to restart
                            if "Connection" in str(e) or "closed" in str(e).lower() or "Target" in str(e):
                                print("[browser dead, restarting] ", end="")
                                _launch_browser()
                        finally:
                            try:
                                page.close()
                            except Exception:
                                pass
                    else:
                        # Fallback to old method
                        try:
                            path = tool.screenshot_url(url, bypass=bypass)
                            screenshot_ok = True
                        except Exception as e:
                            print(f"[scr err: {type(e).__name__}]", end=" ")
                except Exception as exc:
                    print(f"FAIL: {exc}")

                if screenshot_ok:
                    if categorize:
                        # Determine category folder
                        if status_code in ("200", "301", "302"):
                            cat_folder = categories["200"] if status_code == "200" else (
                                categories["301"] if status_code == "301" else categories["302"]
                            )
                        elif status_code in ("401", "403", "404", "500"):
                            cat_folder = categories[status_code]
                        else:
                            cat_folder = categories["error"]

                        # Generate safe filename
                        safe_name = tool._safe_name(url, None)
                        dest_path = cat_folder / f"{safe_name}.png"

                        # Copy to category folder
                        shutil.copy2(out_path, dest_path)
                        print(f"→ {dest_path}")
                        results.append({
                            "url": url,
                            "status_code": status_code,
                            "screenshot": str(dest_path),
                            "category": cat_folder.name
                        })
                    else:
                        print(f"OK")
                        results.append({"url": url, "status_code": status_code, "path": str(out_path)})

                    stats[status_code] = stats.get(status_code, 0) + 1
                else:
                    print(f"skip")
                    stats["error"] += 1
                    results.append({"url": url, "status_code": status_code, "status": "skipped"})

            if i < len(urls) - 1:
                time.sleep(delay)
    finally:
        # Cleanup persistent browser
        if browser:
            browser.close()
            print("[*] Browser closed")
        if playwright_ctx:
            playwright_ctx.stop()
            print("[*] Playwright stopped")

    # Generate Eyewitness-style HTML report
    if categorize:
        _generate_eyewitness_report(base_output, results, stats)

    report_path = base_output / "screenshots_report.json"
    report_path.write_text(json.dumps({"results": results, "stats": stats}, indent=2))
    print(f"\n[+] Report: {report_path}")
    print(f"[*] Stats: {dict(stats)}")
    return results



# ---------------------------------------------------------------------------
# Eyewitness-style HTML report
# ---------------------------------------------------------------------------

def _generate_eyewitness_report(output_dir: Path, results: list[dict], stats: dict) -> None:
    """Generate Eyewitness-style HTML report with thumbnails organized by category."""

    def _thumb(url: str, screenshot_path: str, category: str) -> str:
        """Generate thumbnail HTML."""
        if screenshot_path and Path(screenshot_path).exists():
            rel_path = Path(screenshot_path).relative_to(output_dir)
            thumb_url = str(rel_path).replace("\\", "/")
            return f'''
    <div class="thumb">
      <a href="{thumb_url}" target="_blank">
        <img src="{thumb_url}" alt="{url}" loading="lazy">
        <div class="label">{category}</div>
      </a>
      <div class="url"><a href="{url}" target="_blank">{url}</a></div>
    </div>'''
        else:
            return f'''
    <div class="thumb">
      <div class="label error">NO SCREENSHOT</div>
      <div class="url"><a href="{url}" target="_blank">{url}</a></div>
    </div>'''

    # Group by category
    by_cat: dict[str, list] = {}
    for r in results:
        cat = r.get("category", "error")
        if cat not in by_cat:
            by_cat[cat] = []
        by_cat[cat].append(r)

    # Build category sections
    cat_sections = ""
    for cat_name in sorted(by_cat.keys(), key=lambda x: (
        0 if x == "200_success" else
        1 if x == "403_forbidden" else
        2 if x == "401_unauthorized" else
        3 if x == "404_not_found" else
        4 if x in ("301_redirect", "302_redirect") else
        5 if x == "500_error" else 9
    )):
        items = by_cat[cat_name]
        thumbs_html = "".join(_thumb(i["url"], i.get("screenshot", ""), i.get("status_code", "?")) for i in items)
        cat_sections += f'''
    <div class="category">
      <h2>{cat_name} ({len(items)})</h2>
      <div class="thumbs">{thumbs_html}</div>
    </div>'''

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Eyewitness Report — {output_dir.name}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #1a1a1a; color: #eee; padding: 20px; }}
    h1 {{ margin-bottom: 10px; }}
    .stats {{ margin-bottom: 20px; display: flex; gap: 15px; flex-wrap: wrap; }}
    .stat {{ background: #2a2a2a; padding: 8px 16px; border-radius: 6px; }}
    .stat span {{ color: #4af; font-weight: bold; }}
    .category {{ margin-bottom: 40px; }}
    .category h2 {{ color: #4af; margin-bottom: 15px; padding-bottom: 8px; border-bottom: 1px solid #333; }}
    .thumbs {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 15px; }}
    .thumb {{ background: #222; border-radius: 8px; overflow: hidden; border: 1px solid #333; }}
    .thumb img {{ width: 100%; height: 140px; object-fit: cover; display: block; }}
    .thumb .label {{ background: #333; padding: 4px 8px; font-size: 12px; font-weight: bold; color: #4af; }}
    .thumb .label.error {{ color: #f44; }}
    .thumb .url {{ padding: 8px; font-size: 11px; word-break: break-all; }}
    .thumb .url a {{ color: #aaa; text-decoration: none; }}
    .thumb .url a:hover {{ color: #4af; }}
    .nav {{ position: sticky; top: 0; background: #1a1a1a; padding: 10px 0; margin-bottom: 20px; border-bottom: 1px solid #333; }}
    .nav a {{ color: #4af; margin-right: 15px; text-decoration: none; }}
    .nav a:hover {{ text-decoration: underline; }}
  </style>
</head>
<body>
  <h1>Eyewitness Report</h1>
  <div class="stats">
    <div class="stat">Total: <span>{stats["total"]}</span></div>
    <div class="stat">200: <span>{stats.get("200", 0)}</span></div>
    <div class="stat">403: <span>{stats.get("403", 0)}</span></div>
    <div class="stat">401: <span>{stats.get("401", 0)}</span></div>
    <div class="stat">404: <span>{stats.get("404", 0)}</span></div>
    <div class="stat">500: <span>{stats.get("500", 0)}</span></div>
    <div class="stat">Redirects: <span>{stats.get("301", 0) + stats.get("302", 0)}</span></div>
    <div class="stat">Errors: <span>{stats.get("error", 0)}</span></div>
  </div>
  <div class="nav">
    <a href="#200_success">200 ({by_cat.get("200_success", [[]]).__len__()})</a>
    <a href="#403_forbidden">403 ({by_cat.get("403_forbidden", [[]]).__len__()})</a>
    <a href="#401_unauthorized">401 ({by_cat.get("401_unauthorized", [[]]).__len__()})</a>
    <a href="#404_not_found">404 ({by_cat.get("404_not_found", [[]]).__len__()})</a>
    <a href="#500_error">500 ({by_cat.get("500_error", [[]]).__len__()})</a>
    <a href="#error">Error ({by_cat.get("error", [[]]).__len__()})</a>
  </div>
  {cat_sections}
</body>
</html>'''

    report_path = output_dir / "eyewitness_report.html"
    report_path.write_text(html)
    print(f"[*] Eyewitness HTML report: {report_path}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _goto_wait(page, url: str, wait_until: str = "networkidle",
               timeout: int = 30_000) -> None:
    """Navigate, falling back to domcontentloaded if networkidle times out."""
    try:
        page.goto(url, wait_until=wait_until, timeout=timeout)
    except Exception:
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=timeout)
        except Exception as exc:
            print(f"    [nav] warning: {exc}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Screenshot tool with WAF bypass (BrowserBlockFix stealth browser)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single URL with WAF bypass
  python3 screenshot_tool.py --single "https://media.superdrug.com/"

  # Batch from file
  python3 screenshot_tool.py urls.txt -o ~/Shared/bounty_recon/program/screenshots/

  # SPA with selector wait
  python3 screenshot_tool.py --single "https://app.example.com/" --spa --wait-for "#app"

  # Scroll capture
  python3 screenshot_tool.py --single "https://example.com/blog" --scrolled --scrolls 5

  # Authenticated capture
  python3 screenshot_tool.py --single "https://example.com/dashboard" \\
      --auth '{"username": "admin", "password": "secret"}' \\
      --login-url "https://example.com/login"

  # Fast mode (no stealth bypass)
  python3 screenshot_tool.py urls.txt --no-bypass

  # Eyewitness-style categorization by status code
  python3 screenshot_tool.py urls.txt --categorize --rate-limit 5 \\
      -o ~/Shared/bounty_recon/target/screenshots/
""",
    )

    parser.add_argument("input", nargs="?", help="File of URLs (one per line)")
    parser.add_argument("-o", "--output", default="screenshots",
                        help="Output directory (default: screenshots/)")
    parser.add_argument("--no-bypass", action="store_true",
                        help="Disable WAF bypass stealth browser")
    parser.add_argument("--delay", type=float, default=1.5,
                        help="Seconds between batch requests (default: 1.5)")
    parser.add_argument("--rate-limit", type=float, metavar="N",
                        help="Rate limit: N requests per second (overrides --delay)")
    parser.add_argument("--categorize", action="store_true",
                        help="Organize screenshots into folders by HTTP status code (like Eyewitness)")

    # Single URL mode
    single = parser.add_argument_group("Single URL mode")
    single.add_argument("--single", metavar="URL",
                        help="Screenshot one URL instead of a file")
    single.add_argument("--name", help="Output filename stem")

    # Capture modes (single URL only)
    mode = parser.add_argument_group("Capture mode (--single only)")
    mode.add_argument("--spa", action="store_true",
                      help="SPA mode: wait for networkidle + optional selector")
    mode.add_argument("--wait-for", metavar="SELECTOR",
                      help="CSS selector to wait for in --spa mode")
    mode.add_argument("--scrolled", action="store_true",
                      help="Scroll before capture (infinite scroll / lazy load)")
    mode.add_argument("--scrolls", type=int, default=3,
                      help="Number of scroll cycles (default: 3)")
    mode.add_argument("--auth", metavar="JSON",
                      help='Credentials JSON e.g. \'{"username":"x","password":"y"}\'')
    mode.add_argument("--login-url", metavar="URL",
                      help="Login page URL (if different from --single target)")

    args = parser.parse_args()

    bypass = not args.no_bypass

    if args.single:
        tool = ScreenshotTool(args.output)
        url = args.single
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        if args.auth:
            creds = json.loads(args.auth)
            path = tool.screenshot_with_auth(
                url, creds, login_url=args.login_url,
                name=args.name, bypass=bypass,
            )
        elif args.spa:
            path = tool.screenshot_spa(
                url, name=args.name,
                wait_for=args.wait_for, bypass=bypass,
            )
        elif args.scrolled:
            path = tool.screenshot_scrolled(
                url, name=args.name,
                scrolls=args.scrolls, bypass=bypass,
            )
        else:
            path = tool.screenshot_url(url, name=args.name, bypass=bypass)

        print(f"[+] Saved: {path}")

    elif args.input:
        # Convert rate-limit to delay if provided
        delay = args.delay
        if args.rate_limit:
            delay = 1.0 / args.rate_limit
            print(f"[*] Rate limit: {args.rate_limit} req/sec (delay={delay:.3f}s)")

        screenshot_file(args.input, args.output,
                        bypass=bypass, delay=delay,
                        categorize=args.categorize)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
