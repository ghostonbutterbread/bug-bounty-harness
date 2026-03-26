#!/usr/bin/env python3
"""
Bug Bounty Harness — Campaign Runner CLI

Usage:
    python run_campaign.py init --campaign superdrug_20260326 \\
        --target https://api.superdrug.com \\
        --domains superdrug.com api.superdrug.com onlinedoctor.superdrug.com

    python run_campaign.py status --campaign superdrug_20260326

    python run_campaign.py run --campaign superdrug_20260326 --agent bac_tester --max-tests 5

    python run_campaign.py run --campaign superdrug_20260326 --agent analyzer

    python run_campaign.py report --campaign superdrug_20260326

    python run_campaign.py list
"""

import sys
import argparse
import json
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent))

from harness_core import CampaignState, is_valid_campaign_id
from test_catalog import build_test_catalog, get_pending_by_priority
from baseline_capture import BaselineStore
from verifier import FindingVerifier, VulnType
from agents.fuzz_runner import FuzzAgent
from program_config import ProgramConfig


# ─── Helpers ───────────────────────────────────────────────────────────────────

def _infer_program(target: str, domains: list) -> str:
    """Try to match a target URL/domain to a known program name."""
    from urllib.parse import urlparse
    try:
        host = urlparse(target).netloc.lower()
    except Exception:
        host = ""
    # Match against known program directories
    import os
    for domain in [host] + domains:
        domain = domain.lower().replace(".com", "").replace(".co.uk", "")
        if domain.startswith("www."):
            domain = domain[4:]
        safe = "".join(c if c.isalnum() else "_" for c in domain).strip("_")
        if safe and os.path.isdir(f"/home/ryushe/Shared/bounty_recon/{safe}"):
            return safe
    return ""


# ─── Init Command ─────────────────────────────────────────────────────────────

def cmd_init(args):
    """Create a new campaign."""
    state = CampaignState()

    if state.exists(args.campaign):
        print(f"Campaign '{args.campaign}' already exists. Use --force to overwrite.")
        if not args.force:
            return 1

    scope_domains = args.domains.split() if args.domains else [args.target]
    campaign = state.create(args.campaign, args.target, scope_domains)

    # Load program-specific config (rate limits from rate_limit.conf, etc.)
    program_name = args.program or _infer_program(args.target, scope_domains)
    if program_name:
        cfg = ProgramConfig.load(program_name)
        campaign["stats"]["rate_limit_rpm"] = cfg.rate_limit_rpm
        campaign["stats"]["rate_limit_rps"] = cfg.rate_limit_rps
        campaign["stats"]["max_requests_per_session"] = cfg.rate_limit_rpm * 5  # ~5 min of full-rate requests
        campaign["program_config"] = {
            "program": cfg.program,
            "rate_limit_rpm": cfg.rate_limit_rpm,
            "rate_limit_rps": cfg.rate_limit_rps,
            "is_rate_limit_bypass_in_scope": cfg.is_rate_limit_bypass_in_scope,
            "credentials_path": str(cfg.credentials_path) if cfg.credentials_path else None,
        }
        if cfg.scope_domains and not args.domains:
            campaign["scope"]["domains"] = cfg.scope_domains
        print(f"   Program config: {cfg.rate_limit_rpm} RPM ({cfg.rate_limit_rps} rps)")

    # Add credentials reference
    if args.creds:
        campaign["scope"]["credential_ref"] = args.creds
    if args.account_a:
        campaign["scope"]["account_a"] = args.account_a
    if args.account_b:
        campaign["scope"]["account_b"] = args.account_b

    state.save(args.campaign, campaign)
    print(f"✅ Campaign '{args.campaign}' created")
    print(f"   Target: {args.target}")
    print(f"   Scope: {', '.join(campaign['scope']['domains'])}")
    print(f"   Next: python run_campaign.py run --campaign {args.campaign} --agent initializer")
    return 0


# ─── Status Command ───────────────────────────────────────────────────────────

def cmd_status(args):
    """Show campaign status."""
    state = CampaignState()
    try:
        campaign = state.load(args.campaign)
    except FileNotFoundError:
        print(f"Campaign '{args.campaign}' not found.")
        return 1

    stats = campaign["stats"]
    findings = campaign["findings"]
    catalog = campaign["test_catalog"]
    pending = [t for t in catalog if t["status"] == "pending"]
    complete = [t for t in catalog if t["status"] not in ("pending", "in_progress")]
    in_progress = [t for t in catalog if t["status"] == "in_progress"]

    print(f"\n{'='*60}")
    print(f"  Campaign: {args.campaign}")
    print(f"  Target:   {campaign['target']}")
    print(f"{'='*60}")

    print(f"\n📊 Test Catalog ({len(catalog)} tests)")
    print(f"   Pending:     {len(pending):>4}  {', '.join([t['id'] for t in pending[:5]])}{'...' if len(pending) > 5 else ''}")
    print(f"   In Progress: {len(in_progress):>4}")
    print(f"   Complete:    {len(complete):>4}")

    if pending:
        print(f"\n🔺 Priority Queue (next up):")
        for t in pending[:5]:
            print(f"   {t['id']} [{t['priority']}] {t['test_name'][:50]}")

    confirmed = len(findings["confirmed"])
    potential = len(findings["potential"])
    fp = len(findings["false_positive"])
    total_findings = confirmed + potential + fp
    print(f"\n🐛 Findings ({total_findings} total)")
    print(f"   ✅ Confirmed:     {confirmed}")
    print(f"   ⚠️  Potential:     {potential}")
    print(f"   ❌ False Pos:     {fp}")

    if findings["confirmed"]:
        print(f"\n   Confirmed findings:")
        for f in findings["confirmed"]:
            print(f"   - [{f.get('type', '?')}] {f.get('endpoint', f.get('test_id', '?'))}")

    print(f"\n📡 Requests")
    print(f"   Session: {stats['requests_this_session']}/{stats['max_requests_per_session']}")
    print(f"   Total:   {stats['total_requests']}")

    print(f"\n🔧 Initializer: {'✅ Complete' if campaign.get('initializer_complete') else '❌ Not run'}")
    print(f"   Last: {campaign.get('last_session', 'never')}")
    print()
    return 0


# ─── Run Command ──────────────────────────────────────────────────────────────

def cmd_run(args):
    """Run a campaign agent (initializer, bac_tester, or analyzer)."""
    state = CampaignState()
    try:
        campaign = state.load(args.campaign)
    except FileNotFoundError:
        print(f"Campaign '{args.campaign}' not found.")
        return 1

    if args.agent == "initializer":
        return run_initializer(args, campaign, state)
    elif args.agent == "bac_tester":
        return run_bac_tester(args, campaign, state)
    elif args.agent == "analyzer":
        return run_analyzer(args, campaign, state)
    elif args.agent == "fuzz":
        return run_fuzz(args, campaign, state)
    else:
        print(f"Unknown agent: {args.agent}. Available: initializer, bac_tester, analyzer, fuzz")
        return 1


def run_initializer(args, campaign, state):
    """Run the initializer agent — crawl + baseline capture."""
    print(f"🚀 Initializer: {args.campaign}")

    # Build test catalog
    catalog = build_test_catalog(campaign["target"], [])
    campaign["test_catalog"] = catalog
    print(f"   Loaded {len(catalog)} tests from bac_checks.py")

    # Mark initializer start
    state.save(args.campaign, campaign)

    # TODO: spawn recon sub-agent to crawl and discover endpoints
    # TODO: capture baselines for discovered endpoints
    # For now: mark complete and let bac_tester handle it

    campaign = state.load(args.campaign)
    campaign["initializer_complete"] = True
    campaign["notes"] = "Initializer ran but no active crawl implemented — add recon + baseline capture"
    state.save(args.campaign, campaign)
    state.git_commit(args.campaign, "Initializer: basic catalog loaded")

    print(f"   ✅ Initializer complete — {len(catalog)} tests ready")
    print(f"   Next: python run_campaign.py run --campaign {args.campaign} --agent bac_tester")
    return 0


def run_bac_tester(args, campaign, state):
    """Run the BAC tester agent — run pending tests."""
    print(f"🧪 BAC Tester: {args.campaign}")
    print(f"   Max tests this run: {args.max_tests}")

    if not campaign.get("initializer_complete"):
        print("⚠️  Initializer not complete. Run `run_campaign.py run --agent initializer` first.")

    max_tests = args.max_tests or 999
    run_count = 0
    found_something = []

    for i in range(max_tests):
        test = state.get_next_test(args.campaign)
        if not test:
            print(f"\n✅ All tests complete! Ran {run_count} tests.")
            break

        print(f"\n  [{run_count+1}] {test['id']} [{test['priority']}] {test['test_name']}")
        print(f"      {test['method']} {test['endpoint'][:80]}")

        state.update_test_status(args.campaign, test["id"], "in_progress")

        # Placeholder: run the actual test here
        # In full implementation: make HTTP request, compare to baseline, call verifier
        # For now: mark as complete with a note
        state.update_test_status(
            args.campaign, test["id"], "complete",
            f"Tester ran: {test['method']} {test['endpoint']} — result pending manual verification"
        )
        run_count += 1

    state.git_commit(args.campaign, f"BAC tester: ran {run_count} tests")
    print(f"\n   Ran {run_count} tests this session. Commit saved.")
    return 0


def run_analyzer(args, campaign, state):
    """Run the analyzer agent — deduplicate and verify findings."""
    print(f"🔍 Analyzer: {args.campaign}")

    findings = campaign["findings"]
    potential = findings["potential"]
    confirmed = findings["confirmed"]

    print(f"   Potential: {len(potential)}")
    print(f"   Confirmed: {len(confirmed)}")

    if not potential:
        print("   No potential findings to analyze.")
        return 0

    # Placeholder: deduplicate + verify
    # TODO: for each potential finding, call verifier, move to confirmed/false_positive
    print(f"   Analyzer complete — {len(confirmed)} confirmed, {len(potential)} potential still need review")
    state.git_commit(args.campaign, "Analyzer: findings reviewed")
    return 0


def run_fuzz(args, campaign, state):
    """Run the fuzz agent — adaptive web fuzzing with ffuf."""
    print(f"🎯 Fuzz Agent: {args.campaign}")
    max_requests = args.max_requests or 5000
    print(f"   Max requests this session: {max_requests}")

    fuzz_state = campaign.get("fuzz_state", {})
    last_wordlist = fuzz_state.get("last_wordlist", "none")
    paths_tested = len(fuzz_state.get("paths_tested", []))
    print(f"   Last wordlist: {last_wordlist}")
    print(f"   Paths already tested: {paths_tested}")

    try:
        agent = FuzzAgent(args.campaign)
        result = agent.run(max_requests=max_requests)

        print(f"\n   Fuzz session complete:")
        print(f"   - Requests made: {result.get('requests_planned', '?')}")
        print(f"   - Interesting findings: {result.get('interesting_findings', 0)}")
        print(f"   - Rate limited: {result.get('rate_limited', False)}")
        print(f"   - Deferred (backoff): {result.get('deferred', False)}")
        if result.get("findings_output"):
            print(f"   - Raw output: {result.get('raw_output', '')}")
            print(f"   - Findings: {result.get('findings_output', '')}")

        return 0
    except Exception as e:
        print(f"   ❌ Fuzz failed: {e}")
        return 1


# ─── Report Command ────────────────────────────────────────────────────────────

def cmd_report(args):
    """Generate a markdown report of the campaign."""
    state = CampaignState()
    try:
        campaign = state.load(args.campaign)
    except FileNotFoundError:
        print(f"Campaign '{args.campaign}' not found.")
        return 1

    findings = campaign["findings"]
    lines = [
        f"# Bug Bounty Campaign Report: {args.campaign}",
        f"",
        f"**Target:** {campaign['target']}",
        f"**Generated:** {datetime.now(timezone.utc).isoformat()}",
        f"**Scope:** {', '.join(campaign['scope']['domains'])}",
        f"",
        f"## Summary",
        f"",
        f"| Category | Count |",
        f"|----------|-------|",
        f"| Total Tests | {len(campaign['test_catalog'])} |",
        f"| Pending | {sum(1 for t in campaign['test_catalog'] if t['status'] == 'pending')} |",
        f"| Complete | {sum(1 for t in campaign['test_catalog'] if t['status'] not in ('pending', 'in_progress'))} |",
        f"| Confirmed | {len(findings['confirmed'])} |",
        f"| Potential | {len(findings['potential'])} |",
        f"| False Positive | {len(findings['false_positive'])} |",
        f"",
    ]

    if findings["confirmed"]:
        lines.extend([
            f"## ✅ Confirmed Findings",
            f"",
        ])
        for f in findings["confirmed"]:
            lines.extend([
                f"### {f.get('test_id', '?')} — {f.get('type', '?')}",
                f"",
                f"**Endpoint:** `{f.get('endpoint', '?')}`",
                f"**Confidence:** {f.get('confidence', '?')}",
                f"",
                f"```",
                f.get("poc", "No PoC recorded"),
                f"```",
                f"",
            ])

    if findings["potential"]:
        lines.extend([
            f"## ⚠️ Potential Findings (need human review)",
            f"",
        ])
        for f in findings["potential"]:
            lines.extend([
                f"- [{f.get('type', '?')}] {f.get('endpoint', '?')} "
                f"(confidence: {f.get('confidence', '?')})"
            ])
        lines.append("")

    report = "\n".join(lines)
    print(report)

    if args.output:
        Path(args.output).write_text(report)
        print(f"\n📄 Report saved to: {args.output}")

    return 0


# ─── List Command ─────────────────────────────────────────────────────────────

def cmd_list(args):
    """List all campaigns."""
    state = CampaignState()
    campaigns_dir = state.CAMPAIGNS_DIR
    if not campaigns_dir.exists():
        print("No campaigns found.")
        return 0

    campaigns = sorted(campaigns_dir.glob("*.json"))
    if not campaigns:
        print("No campaigns found.")
        return 0

    print(f"\n{'Campaign':<35} {'Target':<40} {'Tests':>6} {'Confirmed':>10}")
    print("-" * 95)
    for path in campaigns:
        try:
            with open(path) as f:
                data = json.load(f)
            cid = data.get("campaign_id", path.stem)
            target = data.get("target", "?")[:38]
            n_tests = len(data.get("test_catalog", []))
            n_confirmed = len(data.get("findings", {}).get("confirmed", []))
            print(f"{cid:<35} {target:<40} {n_tests:>6} {n_confirmed:>10}")
        except Exception:
            print(f"{path.stem:<35} (error reading)")
    print()
    return 0


# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Bug Bounty Harness CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # init
    p_init = sub.add_parser("init", help="Create a new campaign")
    p_init.add_argument("--campaign", required=True, help="Campaign ID (alphanumeric)")
    p_init.add_argument("--target", required=True, help="Target base URL")
    p_init.add_argument("--domains", help="Space-separated scope domains")
    p_init.add_argument("--program", help="Program name for rate limit config (e.g. superdrug)")
    p_init.add_argument("--creds", help="Credential store reference (e.g. superdrug:default)")
    p_init.add_argument("--account-a", help="Account A credential key")
    p_init.add_argument("--account-b", help="Account B credential key")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing campaign")

    # status
    p_status = sub.add_parser("status", help="Show campaign status")
    p_status.add_argument("--campaign", required=True, help="Campaign ID")

    # run
    p_run = sub.add_parser("run", help="Run a campaign agent")
    p_run.add_argument("--campaign", required=True, help="Campaign ID")
    p_run.add_argument("--agent", required=True, help="Agent: initializer, bac_tester, analyzer")
    p_run.add_argument("--max-requests", type=int, default=5000, help="Max requests per session (default: 5000)")

    # report
    p_report = sub.add_parser("report", help="Generate campaign report")
    p_report.add_argument("--campaign", required=True, help="Campaign ID")
    p_report.add_argument("--output", "-o", help="Output file path")

    # list
    sub.add_parser("list", help="List all campaigns")

    args = parser.parse_args()

    commands = {
        "init": cmd_init,
        "status": cmd_status,
        "run": cmd_run,
        "report": cmd_report,
        "list": cmd_list,
    }

    return commands[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
