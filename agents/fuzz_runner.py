import sys

sys.path.insert(0, "/home/ryushe/workspace/bug_bounty_harness")

try:
    from scope_validator import ScopeValidator
except ImportError:
    ScopeValidator = None
try:
    from rate_limiter import RateLimiter
except ImportError:
    RateLimiter = None

import fcntl
import time
import json
import os
import re
import subprocess
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

from harness_core import CampaignState, HarnessConstraints, HarnessViolation


FFUF_PATH = "/home/linuxbrew/.linuxbrew/bin/ffuf"
WORDLIST_ROOT = Path("~/wordlists/SecLists/Discovery/Web-Content/").expanduser()
DEFAULT_WORDLISTS = [
    "common.txt",
    "raft-small-words.txt",
    "directory-list-2.3-small.txt",
    "raft-medium-words.txt",
    "directory-list-2.3-medium.txt",
]
INTERESTING_KEYWORDS = (
    "admin",
    "api",
    "debug",
    "test",
    "config",
    "backup",
    "internal",
    "v1",
    "v2",
    "v3",
    ".env",
    ".git",
    "swagger",
    "metrics",
)
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")
RESULT_LINE_RE = re.compile(
    r"^(?P<path>\S.*?)\s+\[Status:\s*(?P<status>\d{3})"
    r"(?:,\s*Size:\s*(?P<size>\d+))?"
    r"(?:,\s*Words:\s*(?P<words>\d+))?"
    r"(?:,\s*Lines:\s*(?P<lines>\d+))?.*$"
)


class FuzzAgent:
    def __init__(self, campaign_id: str, program: str = ""):
        self.campaign_id = campaign_id
        self.state = CampaignState()
        self.campaigns_root = self.state.CAMPAIGNS_DIR
        self.campaign_dir = self.campaigns_root / campaign_id
        self.campaign_dir.mkdir(parents=True, exist_ok=True)
        self._lock_path = self.campaign_dir / ".ffuf.lock"
        self._lock_path.touch(exist_ok=True)

        # Load scope
        if program and ScopeValidator is not None:
            self.scope = ScopeValidator(program)
        else:
            self.scope = None

        # Setup rate limiter (ffuf handles its own rate; this covers pre-checks)
        self.limiter = RateLimiter(requests_per_second=5) if RateLimiter else None

    def is_in_scope(self, url: str) -> bool:
        """Check if URL is in scope. Skip if no scope loaded."""
        if not self.scope:
            return True
        return self.scope.is_in_scope(url)

    def run(self, max_requests: int = 500) -> dict:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        raw_path = self.campaign_dir / f"fuzz_raw_{timestamp}.txt"
        findings_path = self.campaign_dir / f"fuzz_findings_{timestamp}.txt"
        summary = {
            "campaign_id": self.campaign_id,
            "raw_output": str(raw_path),
            "findings_output": str(findings_path),
            "requests_planned": 0,
            "interesting_findings": 0,
            "rate_limited": False,
            "deferred": False,
        }
        commit_message = f"Fuzz agent: session completed for {self.campaign_id}"

        with self._campaign_lock():
            try:
                campaign = self.state.load(self.campaign_id)
                constraints = HarnessConstraints(campaign)
                fuzz_state = self._ensure_fuzz_state(campaign)
                self._persist_campaign(campaign)

                if self._is_backed_off(fuzz_state):
                    summary["deferred"] = True
                    commit_message = f"Fuzz agent: deferred for {self.campaign_id} due to backoff"
                    self._write_findings_summary(findings_path, [], fuzz_state, summary_note="Deferred by backoff")
                    return summary

                wordlists = self._resolve_wordlists()
                if not wordlists:
                    raise FileNotFoundError(
                        f"No wordlists found under {WORDLIST_ROOT}"
                    )

                fuzz_state["wordlist_paths"] = [str(path) for path in wordlists]
                targets = self._resolve_targets(campaign)
                findings = []

                with open(raw_path, "w", encoding="utf-8") as raw_file:
                    for target in targets:
                        target_result = self._run_target(
                            campaign=campaign,
                            constraints=constraints,
                            fuzz_state=fuzz_state,
                            target=target,
                            max_requests=max_requests - summary["requests_planned"],
                            raw_file=raw_file,
                        )
                        summary["requests_planned"] += target_result["requests_used"]
                        summary["interesting_findings"] += len(target_result["findings"])
                        findings.extend(target_result["findings"])

                        if target not in fuzz_state["targets_tested"]:
                            fuzz_state["targets_tested"].append(target)

                        if target_result["rate_limited"]:
                            summary["rate_limited"] = True
                            commit_message = (
                                f"Fuzz agent: rate limited for {self.campaign_id}"
                            )
                            break

                        if summary["requests_planned"] >= max_requests:
                            break

                self._record_findings(campaign, findings)
                self._finalize_fuzz_state(fuzz_state, findings)
                self._sync_constraint_state(campaign, constraints)
                self._persist_campaign(campaign)
                self._write_findings_summary(findings_path, findings, fuzz_state)

                if findings:
                    commit_message = (
                        f"Fuzz agent: {len(findings)} findings for {self.campaign_id}"
                    )
                return summary
            finally:
                self.state.git_commit(self.campaign_id, commit_message)

    @contextmanager
    def _campaign_lock(self):
        with open(self._lock_path, "a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def _ensure_fuzz_state(self, campaign: dict) -> dict:
        fuzz_state = campaign.setdefault("fuzz_state", {})
        fuzz_state.setdefault("wordlist_idx", 0)
        fuzz_state.setdefault("wordlist_paths", [])
        fuzz_state.setdefault("paths_tested", [])
        fuzz_state.setdefault("targets_tested", [])
        fuzz_state.setdefault("findings_interesting", 0)
        fuzz_state.setdefault("rate_limit_events", 0)
        fuzz_state.setdefault("backoff_until", None)
        fuzz_state.setdefault("session_start", self._iso_now())
        fuzz_state.setdefault("last_wordlist", None)
        fuzz_state.setdefault("tested_pairs", [])
        return fuzz_state

    def _is_backed_off(self, fuzz_state: dict) -> bool:
        backoff_until = fuzz_state.get("backoff_until")
        if not backoff_until:
            return False
        return time.time() < float(backoff_until)

    def _resolve_wordlists(self) -> list[Path]:
        resolved = []
        for name in DEFAULT_WORDLISTS:
            candidate = WORDLIST_ROOT / name
            if candidate.exists():
                resolved.append(candidate)
        return resolved

    def _resolve_targets(self, campaign: dict) -> list[str]:
        targets = []
        primary = campaign.get("target")
        if isinstance(primary, str) and primary:
            targets.append(primary.rstrip("/"))
        for extra in campaign.get("targets", []):
            if isinstance(extra, str) and extra:
                normalized = extra.rstrip("/")
                if normalized not in targets:
                    targets.append(normalized)
        return targets

    def _run_target(
        self,
        campaign: dict,
        constraints: HarnessConstraints,
        fuzz_state: dict,
        target: str,
        max_requests: int,
        raw_file,
    ) -> dict:
        result = {"findings": [], "requests_used": 0, "rate_limited": False}
        if max_requests <= 0:
            return result

        if not self.is_in_scope(target):
            print(f"[SKIP] Out of scope: {target}")
            return result
        if not constraints.check_scope(target):
            raise HarnessViolation(f"SCOPE VIOLATION: {target} is not in scope")
        if not constraints.check_budget():
            raise HarnessViolation("BUDGET EXHAUSTED: no requests remaining")
        if constraints.should_defer(target):
            return result

        wordlists = [Path(p) for p in fuzz_state["wordlist_paths"]]
        if not wordlists:
            return result

        start_idx = min(fuzz_state.get("wordlist_idx", 0), len(wordlists) - 1)
        for wordlist_idx in range(start_idx, len(wordlists)):
            fuzz_state["wordlist_idx"] = wordlist_idx
            wordlist = wordlists[wordlist_idx]
            candidates = self._load_candidates(wordlist)
            remaining = self._filter_candidates(target, fuzz_state, candidates)
            if not remaining:
                continue

            run_remaining = max_requests - result["requests_used"]
            budget_remaining = constraints.max_requests_session - constraints.state["stats"]["requests_this_session"]
            rate_remaining = constraints.rate_limit_rpm - self._current_rate_count(constraints, target)
            if run_remaining <= 0 or budget_remaining <= 0 or rate_remaining <= 0:
                break
            batch_size = min(run_remaining, budget_remaining, rate_remaining, len(remaining))
            if batch_size <= 0:
                break

            batch = remaining[:batch_size]
            # Mark ALL batch paths as tested BEFORE ffuf runs — even if ffuf crashes
            # or exits early due to rate limit, we don't retry these paths
            for path in batch:
                self._mark_path_tested(target, path, fuzz_state)

            batch_start_time = time.time()
            run_result = self._execute_ffuf(
                target=target,
                wordlist=wordlist,
                batch=batch,
                rate_sensitive=fuzz_state.get("rate_limit_events", 0) > 0,
                raw_file=raw_file,
            )
            fuzz_state["last_wordlist"] = str(wordlist)
            result["findings"].extend(run_result["findings"])
            result["requests_used"] += batch_size

            if run_result["rate_limited"]:
                fuzz_state["rate_limit_events"] += 1
                fuzz_state["backoff_until"] = time.time() + 60
                fuzz_state["wordlist_idx"] = max(0, wordlist_idx - 1)
                result["rate_limited"] = True
                self._record_attempts(constraints, target, min(len(run_result["findings"]) or 1, batch_size))
                break

            self._record_attempts(constraints, target, batch_size)

            # Pace at the program's allowed rate: sleep if we completed faster than the rate limit
            if constraints.rate_limit_rps > 0:
                expected_duration = batch_size / constraints.rate_limit_rps
                elapsed = time.time() - batch_start_time
                sleep_time = expected_duration - elapsed
                if sleep_time > 0.05:  # only sleep if more than 50ms
                    time.sleep(sleep_time)
            batch_start_time = time.time()

            if result["requests_used"] >= max_requests:
                break

        return result

    def _load_candidates(self, wordlist: Path) -> list[str]:
        candidates = []
        with open(wordlist, encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                entry = line.strip()
                if not entry or entry.startswith("#"):
                    continue
                if not entry.startswith("/"):
                    entry = f"/{entry}"
                candidates.append(entry)
        return candidates

    def _filter_candidates(self, target: str, fuzz_state: dict, candidates: list[str]) -> list[str]:
        tested_paths = set(fuzz_state.get("paths_tested", []))
        tested_pairs = set(fuzz_state.get("tested_pairs", []))
        pair_tracking_enabled = bool(tested_pairs)
        remaining = []
        for candidate in candidates:
            pair_key = self._tested_pair_key(target, candidate)
            if pair_key in tested_pairs:
                continue
            if not pair_tracking_enabled and candidate in tested_paths:
                continue
            remaining.append(candidate)
        return remaining

    def _execute_ffuf(
        self,
        target: str,
        wordlist: Path,
        batch: list[str],
        rate_sensitive: bool,
        raw_file,
    ) -> dict:
        findings = []
        seen_paths = set()
        rate_limited = False
        threads = "5" if rate_sensitive else "20"
        ffuf_args = [
            FFUF_PATH,
            "-u",
            urljoin(f"{target.rstrip('/')}/", "FUZZ"),
            "-w",
            "",
            "-t",
            threads,
            "-mc",
            "200-299,301,302,307,401,403,405,429,500",
            "-fc",
            "404",
            "-fs",
            "0",
            "-c",
            "-v",
        ]
        if rate_sensitive:
            ffuf_args.append("-r")

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
            prefix="ffuf_batch_",
            suffix=".txt",
            dir=self.campaign_dir,
        ) as temp_wordlist:
            temp_wordlist.write("\n".join(path.lstrip("/") for path in batch))
            temp_wordlist.write("\n")
            temp_wordlist_path = temp_wordlist.name

        ffuf_args[4] = temp_wordlist_path

        try:
            process = subprocess.Popen(
                ffuf_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            assert process.stdout is not None
            for line in process.stdout:
                raw_file.write(line)
                raw_file.flush()
                finding = self._parse_ffuf_line(target, line)
                if finding:
                    if finding["status"] == 429:
                        rate_limited = True
                    if finding["path"] not in seen_paths and self._is_interesting(finding):
                        seen_paths.add(finding["path"])
                        findings.append(finding)
                elif "429" in line or "Too Many Requests" in line:
                    rate_limited = True
            return_code = process.wait()
            if return_code not in (0,):
                raw_file.write(f"[ffuf exited with code {return_code}]\n")
                raw_file.flush()
        finally:
            os.unlink(temp_wordlist_path)

        return {"findings": findings, "rate_limited": rate_limited}

    def _parse_ffuf_line(self, target: str, line: str) -> dict | None:
        clean_line = ANSI_ESCAPE_RE.sub("", line).strip()
        match = RESULT_LINE_RE.match(clean_line)
        if not match:
            return None

        path = match.group("path").strip()
        if not path.startswith("/"):
            path = f"/{path.lstrip('/')}"

        status = int(match.group("status"))
        size_text = match.group("size")
        size = int(size_text) if size_text else 0
        return {
            "type": "fuzz",
            "category": "fuzz",
            "target": target,
            "path": path,
            "url": urljoin(f"{target.rstrip('/')}/", path.lstrip("/")),
            "status": status,
            "content_length": size,
            "raw": clean_line,
            "signal": self._signal_for(path, status, size),
        }

    def _is_interesting(self, finding: dict) -> bool:
        path = finding["path"].lower()
        status = finding["status"]
        size = finding.get("content_length", 0)
        keyword_hit = any(keyword in path for keyword in INTERESTING_KEYWORDS)
        if status in {301, 302, 307, 401, 403, 405, 500, 429}:
            return True
        if status == 200 and keyword_hit:
            return True
        if status == 200 and any(token in path for token in (".env", ".git", "backup", "config")) and size > 0:
            return True
        if keyword_hit and size > 0:
            return True
        return False

    def _signal_for(self, path: str, status: int, size: int) -> str:
        lowered = path.lower()
        if status == 429:
            return "rate_limit"
        if status in {301, 302, 307}:
            return "redirect"
        if status in {401, 403}:
            return "auth_boundary"
        if status == 405:
            return "method_probe"
        if status == 500:
            return "server_error"
        if status == 200 and any(token in lowered for token in (".env", ".git", "backup", "config")) and size > 0:
            return "sensitive_asset"
        return "interesting_path"

    def _record_findings(self, campaign: dict, findings: list[dict]) -> None:
        existing = {
            (
                item.get("target"),
                item.get("path"),
                item.get("status"),
            )
            for item in campaign.get("findings", {}).get("potential", [])
            if item.get("category") == "fuzz"
        }
        for finding in findings:
            key = (finding["target"], finding["path"], finding["status"])
            if key in existing:
                continue
            finding_copy = dict(finding)
            finding_copy["endpoint"] = finding["url"]
            campaign["findings"]["potential"].append(finding_copy)
            existing.add(key)

    def _finalize_fuzz_state(self, fuzz_state: dict, findings: list[dict]) -> None:
        interesting_count = len(findings)
        fuzz_state["findings_interesting"] += interesting_count
        fuzz_state["session_start"] = self._iso_now()
        if findings and fuzz_state["wordlist_paths"] and not self._is_backed_off(fuzz_state):
            fuzz_state["wordlist_idx"] = min(
                fuzz_state.get("wordlist_idx", 0) + 1,
                len(fuzz_state["wordlist_paths"]) - 1,
            )
        if not self._is_backed_off(fuzz_state):
            fuzz_state["backoff_until"] = None

    def _sync_constraint_state(self, campaign: dict, constraints: HarnessConstraints) -> None:
        campaign["stats"] = constraints.state["stats"]
        campaign["_rate_tracker"] = constraints.state["_rate_tracker"]
        campaign["last_session"] = self._iso_now()

    def _persist_campaign(self, campaign: dict) -> None:
        self.state.save(self.campaign_id, campaign)
        snapshot_path = self.campaign_dir / "campaign.json"
        tmp_path = snapshot_path.with_name(f"{snapshot_path.name}.tmp")
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(campaign, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        tmp_path.replace(snapshot_path)

    def _write_findings_summary(
        self,
        findings_path: Path,
        findings: list[dict],
        fuzz_state: dict,
        summary_note: str | None = None,
    ) -> None:
        lines = [
            f"campaign_id: {self.campaign_id}",
            f"generated_at: {self._iso_now()}",
            f"wordlist_idx: {fuzz_state.get('wordlist_idx', 0)}",
            f"rate_limit_events: {fuzz_state.get('rate_limit_events', 0)}",
            f"backoff_until: {fuzz_state.get('backoff_until')}",
            f"last_wordlist: {fuzz_state.get('last_wordlist')}",
        ]
        if summary_note:
            lines.append(f"note: {summary_note}")
        lines.append("")
        if not findings:
            lines.append("No interesting findings.")
        else:
            for finding in findings:
                lines.append(
                    f"[{finding['status']}] {finding['url']} signal={finding['signal']} size={finding['content_length']}"
                )
        with open(findings_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
            handle.write("\n")

    def _mark_path_tested(self, target: str, path: str, fuzz_state: dict) -> None:
        normalized_path = path if path.startswith("/") else f"/{path.lstrip('/')}"
        if normalized_path not in fuzz_state["paths_tested"]:
            fuzz_state["paths_tested"].append(normalized_path)
        pair_key = self._tested_pair_key(target, normalized_path)
        if pair_key not in fuzz_state["tested_pairs"]:
            fuzz_state["tested_pairs"].append(pair_key)

    def _record_attempts(self, constraints: HarnessConstraints, target: str, attempts: int) -> None:
        for _ in range(max(0, attempts)):
            constraints.record_request(target)

    def _current_rate_count(self, constraints: HarnessConstraints, target: str) -> int:
        key = constraints._get_endpoint_key(target, "GET")
        tracker = constraints.state.get("_rate_tracker", {}).get(key, {})
        return int(tracker.get("count", 0))

    def _tested_pair_key(self, target: str, path: str) -> str:
        parsed = urlparse(target)
        host = parsed.netloc or target
        return f"{host}::{path}"

    def _iso_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()
