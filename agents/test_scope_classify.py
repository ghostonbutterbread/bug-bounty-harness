"""Scope matcher fixes (export annotations, host globs, speed) and the classify CLI."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from agents import scope_validator as SV
from agents.scope_seed_files import scope_line_rules
from agents.scope_validator import ScopeValidator

REPO = Path(__file__).resolve().parents[1]


def make_scope(base: Path, program: str, allow: str | None, deny: str | None = None) -> Path:
    directory = base / program
    directory.mkdir(parents=True, exist_ok=True)
    if allow is not None:
        (directory / "in-scope.txt").write_text(allow, encoding="utf-8")
    if deny is not None:
        (directory / "out-of-scope.txt").write_text(deny, encoding="utf-8")
    return directory


def validator(tmp_path: Path, allow: str, deny: str | None = None) -> ScopeValidator:
    make_scope(tmp_path / "scopes", "p", allow, deny)
    return ScopeValidator("p", scopes_base=tmp_path / "scopes", legacy_recon_base=tmp_path / "legacy")


# ── Line normalization ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "line, expected",
    [
        ("https://a.acme.example.test/api/* | api | In Scope | in-scope | tags: API Testing,JSON",
         ["https://a.acme.example.test/api/*"]),
        ("https://*.pages.example.test/* | website | In Scope | in-scope", ["https://*.pages.example.test/*"]),
        ("Acme Infrastructure - 192.0.2.0/28 | other | In Scope | in-scope", ["192.0.2.0/28"]),
        ("Acme AWS/S3 Assets | other | In Scope | in-scope", []),
        ("Third party vendors", []),
        ("Mobile (iOS)", []),
        ("*.acme.example.test\t | website | Out of Scope", ["*.acme.example.test"]),
        ("a.acme.example.test, b.acme.example.test", ["a.acme.example.test", "b.acme.example.test"]),
        ("acme.example.test", ["acme.example.test"]),
        ("not_a_host", ["not_a_host"]),  # whitespace-free values keep existing validation
        ("", []),
    ],
)
def test_scope_line_rules(line, expected):
    assert scope_line_rules(line) == expected


def test_pipe_annotated_export_rules_are_live(tmp_path):
    v = validator(
        tmp_path,
        "https://a.acme.example.test/api/* | api | In Scope | in-scope | tags: API Testing,JSON\n"
        "https://acme.example.test/* | website | In Scope | in-scope\n"
        "https://*.pages.example.test/* | website | In Scope | in-scope\n"
        "Acme Infrastructure - 192.0.2.0/28 | other | In Scope | in-scope\n"
        "Acme AWS/S3 Assets | other | In Scope | in-scope\n",
        "https://acme.example.test/private/* | website | Out of Scope | out-of-scope\n"
        "Social engineering of staff\n",
    )
    assert v.is_in_scope("https://a.acme.example.test/api/v1")
    assert not v.is_in_scope("https://a.acme.example.test/other")
    assert v.is_in_scope("https://acme.example.test/")
    assert not v.is_in_scope("https://acme.example.test/private/x")
    assert v.is_in_scope("https://x.pages.example.test/a")
    assert v.is_in_scope("192.0.2.5")
    assert not v.is_in_scope("192.0.2.99")
    # Description words never become domain entries.
    assert [e.raw for e in v._entries if e.entry_type == "domain"] == []
    assert len(v._out_of_scope) == 1
    assert v.skipped_scope_lines == [
        ("grant", "Acme AWS/S3 Assets | other | In Scope | in-scope"),
        ("exclusion", "Social engineering of staff"),
    ]


def test_whitespace_free_invalid_exclusion_still_denies_all(tmp_path):
    v = validator(tmp_path, "*.acme.example.test\n", "bad_host!.example.test\n")
    assert not v.is_in_scope("https://a.acme.example.test/")


# ── Host globs ─────────────────────────────────────────────────────────────


def test_infix_include_glob_matches_within_one_label(tmp_path):
    v = validator(tmp_path, "app*.hub.example.test\napi-*.sound.example.test\n")
    assert v.is_in_scope("app1.hub.example.test")
    assert v.is_in_scope("https://app-eu1.hub.example.test/x")
    assert v.is_in_scope("api-v2.sound.example.test")
    assert not v.is_in_scope("app.hub.example.test")  # one or more characters
    assert not v.is_in_scope("app1.x.hub.example.test")  # no dot spanning
    assert not v.is_in_scope("x.app1.hub.example.test")
    assert not v.is_in_scope("api-.sound.example.test")


def test_infix_exclusion_glob_spans_dots_and_only_excludes_matches(tmp_path):
    v = validator(tmp_path, "*.isp.example.test\n", "customer.*.isp.example.test\n")
    assert not v.is_in_scope("customer.foo.isp.example.test")
    assert not v.is_in_scope("customer.a.b.isp.example.test")
    assert v.is_in_scope("other.isp.example.test")
    assert v.is_in_scope("customer.isp.example.test")


def test_leading_wildcard_meaning_is_unchanged(tmp_path):
    v = validator(tmp_path, "*.acme.example.test\n", "*.int.acme.example.test\n")
    assert v.is_in_scope("acme.example.test")
    assert v.is_in_scope("a.b.acme.example.test")
    assert not v.is_in_scope("int.acme.example.test")
    assert not v.is_in_scope("x.int.acme.example.test")


def test_url_pattern_host_globs(tmp_path):
    v = validator(
        tmp_path,
        "https://api-*.acme.example.test/v1/*\nhttps://*.pages.example.test\n",
        "https://*-staging.acme.example.test/*\n",
    )
    assert v.is_in_scope("https://api-eu.acme.example.test/v1/users")
    assert not v.is_in_scope("https://api-eu.acme.example.test/v2/users")
    assert not v.is_in_scope("https://api-.acme.example.test/v1/users")
    assert v.is_in_scope("https://a.pages.example.test/")
    assert not v.is_in_scope("https://pages.example.test/")  # URL allow wildcard needs a label
    v2 = validator(tmp_path / "2", "*.acme.example.test\n", "https://*-staging.acme.example.test/*\n")
    assert not v2.is_in_scope("https://api-staging.acme.example.test/x")
    assert not v2.is_in_scope("https://a.b-staging.acme.example.test/x")
    assert v2.is_in_scope("https://api.acme.example.test/x")


def test_invalid_glob_is_invalid_authority(tmp_path):
    v = validator(tmp_path, "*.acme.example.test\n", "-*.acme.example.test\n")
    assert not v.is_in_scope("a.acme.example.test")  # invalid exclusion still denies all


# ── Performance ────────────────────────────────────────────────────────────


def _big_scope(tmp_path: Path) -> ScopeValidator:
    allow = [f"198.18.{i}.0/24" for i in range(20)]
    allow += [f"*.svc{i}.example.test" for i in range(20)]
    allow += [f"https://api{i}.example.test/v1/*" for i in range(10)]
    allow += [f"app{i}*.example.test" for i in range(10)]
    deny = [f"blog{i}.svc{i}.example.test" for i in range(5)] + ["customer.*.svc1.example.test"]
    return validator(tmp_path, "\n".join(allow) + "\n", "\n".join(deny) + "\n")


def _hosts(count: int) -> list[str]:
    hosts = []
    for i in range(count):
        kind = i % 4
        if kind == 0:
            hosts.append(f"198.18.{i % 40}.{i % 250}")
        elif kind == 1:
            hosts.append(f"h{i}.svc{i % 30}.example.test")
        elif kind == 2:
            hosts.append(f"https://api{i % 15}.example.test/v1/item?id={i}")
        else:
            hosts.append(f"unrelated{i}.other.example.test")
    return hosts


def test_matching_5000_targets_against_60_rules_is_fast(tmp_path):
    v = _big_scope(tmp_path)
    assert len(v._entries) == 60
    targets = _hosts(5000)
    started = time.perf_counter()
    accepted, rejected = v.partition(targets)
    classified = [v.classify_target(t) for t in targets]
    elapsed = time.perf_counter() - started
    assert accepted and rejected and len(classified) == 5000
    assert elapsed < 5.0, f"5000 targets took {elapsed:.2f}s"


# ── classify ───────────────────────────────────────────────────────────────


def run_classify(base: Path, program: str, targets, raw: str | None = None):
    stdin = io.StringIO(raw if raw is not None else json.dumps({"targets": targets}))
    out, err = io.StringIO(), io.StringIO()
    with patch.object(sys, "stdin", stdin), patch.object(sys, "stdout", out), patch.object(sys, "stderr", err):
        code = SV.main(["classify", program, "--scopes-base", str(base), "--json"])
    return code, (json.loads(out.getvalue()) if code == 0 else None), err.getvalue()


@pytest.fixture
def acme(tmp_path):
    base = tmp_path / "scopes"
    make_scope(
        base,
        "acme_corp",
        "*.acme.example.test\n"
        "https://a.api.example.test/api/* | api | In Scope | in-scope\n"
        "https://root.example.test\n",
        "blog.acme.example.test\nhttps://shop.acme.example.test/admin/*\n",
    )
    (base / "acme").symlink_to("acme_corp")
    return base


def test_classify_contract_shape_and_verdicts(acme):
    targets = [
        "api.acme.example.test",
        "https://www.acme.example.test/a?b=1",
        "blog.acme.example.test",
        "evil.example.test",
        "a.api.example.test",
        "https://a.api.example.test/api/v1",
        "https://a.api.example.test/other",
        "shop.acme.example.test",
        "https://shop.acme.example.test/admin/x",
        "https://shop.acme.example.test/cart",
        "root.example.test",
        "api.acme.example.test",
        "weird\x00 target",
        "",
        "https://user@acme.example.test/",
    ]
    code, data, _ = run_classify(acme, "acme", targets)
    assert code == 0
    assert data["version"] == 1
    assert data["program"] == "acme"
    assert data["scope_dir"] == str((acme / "acme_corp").resolve())
    assert data["scope_state"] == "loaded"
    assert data["entries"] == 3 and data["exclusions"] == 2
    assert len(data["signature"]) == 64
    results = data["results"]
    assert [r["target"] for r in results] == targets
    states = [r["state"] for r in results]
    assert states == [
        "in", "in", "out", "out", "partial", "in", "out", "partial", "out", "in", "in", "in", "out", "out", "out",
    ]
    by_target = {r["target"]: r for r in results}
    assert by_target["api.acme.example.test"]["rule"] == "*.acme.example.test"
    assert by_target["blog.acme.example.test"]["rule"] == "blog.acme.example.test"
    assert by_target["blog.acme.example.test"]["reason"] == "excluded by blog.acme.example.test"
    assert by_target["evil.example.test"] == {
        "target": "evil.example.test", "state": "out", "rule": None, "reason": "no in-scope rule matches",
    }
    assert by_target["a.api.example.test"]["rule"] == "https://a.api.example.test/api/*"
    assert by_target["a.api.example.test"]["reason"] == "only paths under /api/ are in scope"
    assert "/admin/" in by_target["shop.acme.example.test"]["reason"]
    for result in results:
        assert set(result) == {"target", "state", "rule", "reason"}
        assert "—" not in result["reason"]
        if result["target"].startswith("http"):
            assert result["state"] in ("in", "out")


@pytest.mark.parametrize("make", ["missing", "empty", "prose-only", "invalid-only"])
def test_classify_without_usable_scope_is_unchecked(tmp_path, make):
    base = tmp_path / "scopes"
    base.mkdir()
    if make == "empty":
        make_scope(base, "acme", "", "")
    elif make == "prose-only":
        make_scope(base, "acme", "Acme AWS/S3 Assets | other | In Scope\n")
    elif make == "invalid-only":
        make_scope(base, "acme", "bad_host!.example.test\n")
    code, data, _ = run_classify(base, "acme", ["a.acme.example.test", "https://x.example.test/"])
    assert code == 0
    assert data["scope_state"] == ("missing" if make == "missing" else "empty")
    assert data["entries"] == (1 if make == "invalid-only" else 0)
    assert all(r == {"target": r["target"], "state": "unchecked", "rule": None, "reason": "no scope on file"}
               for r in data["results"])


def test_classify_ignores_legacy_scope_locations(tmp_path):
    base = tmp_path / "scopes"
    base.mkdir()
    legacy = tmp_path / "legacy" / "acme" / "scope"
    legacy.mkdir(parents=True)
    (legacy / "in-scope.txt").write_text("*.acme.example.test\n")
    make_scope(base, "acme", None, "")
    with patch.object(ScopeValidator, "LEGACY_RECON_BASE", tmp_path / "legacy"):
        code, data, _ = run_classify(base, "acme", ["a.acme.example.test"])
    assert code == 0 and data["scope_state"] == "empty"


def test_classify_signature_tracks_scope_files(acme):
    _, first, _ = run_classify(acme, "acme", [])
    _, again, _ = run_classify(acme, "acme", [])
    assert first["signature"] == again["signature"]
    (acme / "acme_corp" / "rules-of-engagement.json").write_text("{}")
    _, roe, _ = run_classify(acme, "acme", [])
    assert roe["signature"] == first["signature"]
    with (acme / "acme_corp" / "out-of-scope.txt").open("a") as handle:
        handle.write("x.acme.example.test\n")
    _, changed, _ = run_classify(acme, "acme", [])
    assert changed["signature"] != first["signature"]


@pytest.mark.parametrize(
    "raw, needle",
    [
        ("not json", "not valid JSON"),
        ("[]", "JSON object"),
        ('{"targets": "a"}', "list of strings"),
        ('{"targets": [1]}', "list of strings"),
        ('{"other": []}', "JSON object"),
    ],
)
def test_classify_usage_errors(acme, raw, needle):
    code, _, err = run_classify(acme, "acme", None, raw=raw)
    assert code == 2
    assert needle in err and err.count("\n") == 1


def test_classify_target_limit(acme):
    code, data, _ = run_classify(acme, "acme", ["a.acme.example.test"] * SV.CLASSIFY_MAX_TARGETS)
    assert code == 0 and len(data["results"]) == SV.CLASSIFY_MAX_TARGETS
    code, _, err = run_classify(acme, "acme", ["a"] * (SV.CLASSIFY_MAX_TARGETS + 1))
    assert code == 2 and "too many targets" in err


@pytest.mark.parametrize("program", ["..", "a/b", ""])
def test_classify_rejects_non_directory_program_names(acme, program):
    code, _, err = run_classify(acme, program, [])
    assert code == 2 and "program" in err


def test_classify_unreadable_scope_file_is_io_error(tmp_path):
    base = tmp_path / "scopes"
    (base / "acme" / "in-scope.txt").mkdir(parents=True)
    code, _, err = run_classify(base, "acme", ["a.acme.example.test"])
    assert code == 1
    assert err.strip() and err.count("\n") == 1


def test_classify_is_read_only(acme):
    before = sorted((p.relative_to(acme), p.stat().st_mtime_ns) for p in acme.rglob("*"))
    with patch.object(subprocess, "run", side_effect=AssertionError("no subprocess")):
        code, _, _ = run_classify(acme, "acme", ["a.acme.example.test"])
    assert code == 0
    assert sorted((p.relative_to(acme), p.stat().st_mtime_ns) for p in acme.rglob("*")) == before


def test_classify_cli_runs_as_script_and_through_bbh_launcher(acme):
    payload = json.dumps({"targets": ["api.acme.example.test", "evil.example.test"]})
    env = {**os.environ, "BBH_SKIP_DEP_CHECK": "1"}
    env.pop("PYTHONPATH", None)
    commands = [[sys.executable, str(REPO / "agents" / "scope_validator.py")]]
    if (REPO / ".venv" / "bin" / "python").exists():
        commands.append([str(REPO / "scripts" / "bbh"), "agents/scope_validator.py"])
    for prefix in commands:
        proc = subprocess.run(
            [*prefix, "classify", "acme", "--scopes-base", str(acme), "--json"],
            input=payload, capture_output=True, text=True, env=env, timeout=60, check=False,
        )
        assert proc.returncode == 0, proc.stderr
        data = json.loads(proc.stdout)
        assert [r["state"] for r in data["results"]] == ["in", "out"]
