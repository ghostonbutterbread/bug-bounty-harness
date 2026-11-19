"""Verify actual BBH → selected policy → BBH recovery routes, offline.

Usage: python tests/verify_captcha_recovery_projection.py POLICY_REPOSITORY_ROOT
This checks selected source text and route targets; it does not activate skills.
"""
from pathlib import Path
import sys

BBH = Path(__file__).resolve().parents[1]


def read(root, relative):
    return " ".join((root / relative).read_text(encoding="utf-8").split())


def require(text, *phrases):
    for phrase in phrases:
        if phrase not in text:
            raise AssertionError(f"missing route or boundary: {phrase}")


def forbid(text, *phrases):
    for phrase in phrases:
        if phrase in text:
            raise AssertionError(f"stale route or boundary: {phrase}")


def verify(policy_root):
    owner = read(policy_root, "skills/security/live-testing/captcha-policy/SKILL.md")
    browser = read(policy_root, "skills/universal/browser-session-policy/SKILL.md")
    details = read(policy_root, "skills/universal/browser-session-policy/references/operating-details.md")
    account = read(policy_root, "skills/security/core/account-testing-policy/references/operating-details.md")
    status = read(policy_root, "skills/security/live-testing/http-status-live-policy/SKILL.md")
    proxy = read(policy_root, "skills/universal/proxy-routing-policy/SKILL.md")
    triage = read(BBH, "skills/error-triage/SKILL.md")
    chromium = read(BBH, "skills/chromium-test/SKILL.md")
    handoff = read(BBH, "skills/chromium-handoff/SKILL.md")
    nebula = read(BBH, "skills/nebula-browser-lane/SKILL.md")
    mullvad = read(BBH, "skills/mullvad/SKILL.md")
    require(browser, "`captcha-policy`")
    require(details, "For CAPTCHA, follow `captcha-policy` before any revisit", "inspection-only", "retain and renew the lease during a same-task operator handoff")
    require(account, "`captcha-policy`", "`chromium-handoff`")
    require(triage, "`captcha-policy`", "429", "operator_review")
    require(owner, "try solving it in the browser; retry once", "hand the same browser to the operator", "Preserve the browser's session and effective egress", "inspection only", "`operator_review`", "explicit authorized reset", "`chromium-handoff`", "`nebula-browser-lane`", "Do not switch host or egress, rotate IPs", "CAPTCHA control itself is the in-scope security question")
    forbid(owner, "skip rotation", "in-page WebGL")
    require(status, "A 403 or CAPTCHA alone is not evidence of an IP block", "baseline is unknown", "`mullvad`", "A host snapshot is not proxy-egress proof", "`captcha-policy` independently")
    require(proxy, "label its result host-direct, not proxy egress", "does not authorize direct target traffic")
    require(chromium, "`captcha-policy`", "CAPTCHA alone is not evidence of an IP-related block", "independent evidence makes an IP-related block plausible", "load `mullvad`", "task-proxy incident prototype is offline-only", "CAPTCHA handling is governed by `captcha-policy`, not this GPU workflow", "Do not make WebGL verification a prerequisite", "A same-task operator handoff is not terminal")
    forbid(chromium, "If `captcha-policy` selects an egress comparison")
    require(handoff, "`captcha-policy`", "inspection-only", "do not interact with the target", "securely prefill", "interrupted challenge is ineligible")
    require(nebula, "Ryushe is at Nebula's screen", "not an unattended device capability", "Do not rotate", "Never drop Mullvad")
    require(nebula, "human-controlled physical-screen flow", "human performs the egress check and target interactions", "Prefer a task-scoped MITM", "do not make it mandatory", "may use the verified VPN directly, even if a proxy is available", "record that traffic is unproxied", "Nebula-only exception", "429 cooldown", "still prohibits the corresponding target interaction", "actual browser proxy route and exact CA trust", "launch command below does not establish or verify")
    forbid(nebula, "do not drive network traffic without the agent-proxy gate")
    require(mullvad, "`egress_inspect.py`", "read-only IPv4 local snapshot", "regardless of whether a host baseline can be captured", "non-secret incident context in the run record", "helper is unavailable or recording fails", "baseline is unknown", "deduplicates only the host-direct path", "whether a remote proxy path changed", "Do not force rotation", "Do not log raw IPs")
    # Ensure the route check rejects a removed handoff edge.
    try:
        require(owner.replace("`chromium-handoff`", ""), "`chromium-handoff`")
    except AssertionError:
        pass
    else:
        raise AssertionError("removed handoff edge was not detected")
    # Reject a reintroduced CAPTCHA-to-egress route even when other edges exist.
    try:
        forbid(chromium + " If `captcha-policy` selects an egress comparison", "If `captcha-policy` selects an egress comparison")
    except AssertionError:
        pass
    else:
        raise AssertionError("stale CAPTCHA egress route was not detected")
    print("verified selected policy/BBH CAPTCHA and separate IP-incident routes, missing-edge and stale-route rejection; offline text only")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    verify(Path(sys.argv[1]).resolve(strict=True))
