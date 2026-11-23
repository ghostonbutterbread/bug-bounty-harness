"""Prove a converted skill-markdown test still guards what it claims.

    bbh scripts/verify_skill_test_conversion.py tests/test_x.py [more...]

Run this on any test converted to normalised matching (agents/skill_text.py).
A test is VERIFIED only when it passes as-is, still passes after the markdown
it reads is reflowed, and every negative assertion fails when its phrase is
injected. The third check is what catches a half-conversion, where a needle no
longer matches the normalised haystack and a `not in` assertion passes
vacuously. It found exactly that in two CLI guards during this work.

Three checks, all in a throwaway copy of the repo:
  1. passes as-is
  2. still passes after the skills it reads are reflowed at two widths
  3. every negative needle ("not in" / absent) is DETECTED when injected

Check 3 is the one that catches a half-conversion: if a needle no longer matches
the normalised haystack, the negative assertion passes vacuously and guards
nothing. Injecting the phrase must make the test fail.
"""
import pathlib, re, shutil, subprocess, sys, tempfile, textwrap

VP = "/home/ryushe/projects/bug_bounty_harness-runtime-beta/.venv/bin/python"
SRC = pathlib.Path(".").resolve()
PAY = re.compile(r"<script|onerror|<img|<svg|WEBHOOK_URL|fetch\(|document\.|https?://|--[a-z]")


def md_targets(test_rel: str) -> list[str]:
    """Every markdown file the test reads, however the path is spelled."""
    txt = (SRC / test_rel).read_text()
    found = set(re.findall(r'"(skills/[^"]+\.md)"', txt))
    # path-join forms: (SKILLS / "a" / "references" / "b.md"), (ROOT / "skills" / ...)
    for chain in re.findall(r'\(\s*(?:SKILLS|ROOT)\s*((?:/\s*"[^"]+"\s*)+)\)', txt):
        parts = re.findall(r'"([^"]+)"', chain)
        for base in ("skills/", ""):
            cand = base + "/".join(parts)
            cand = cand.replace("skills/skills/", "skills/")
            if cand.endswith(".md") and (SRC / cand).is_file():
                found.add(cand)
    # helper forms: skill("a"), _skill("a"), text("a/b.md"), read("a/b.md")
    for n in re.findall(r'(?:^|[^\w])_?(?:skill|text|read|doc)\(\s*"([^"]+)"', txt):
        for cand in (n, f"skills/{n}/SKILL.md", f"skills/{n}"):
            if cand.endswith(".md") and (SRC / cand).is_file():
                found.add(cand)
    # bare skill names used as a list of routes
    for name in re.findall(r'"([a-z0-9][a-z0-9_-]{2,})"', txt):
        cand = f"skills/{name}/SKILL.md"
        if (SRC / cand).is_file():
            found.add(cand)
    return sorted(found)


def negatives(test_rel: str) -> list[str]:
    """Needles from genuine negative assertions only.

    Parse the operator rather than substring-matching "not in", which also
    matches positive assertions whose own text contains "not infer" or
    "not invent".
    """
    txt = (SRC / test_rel).read_text()
    out = []
    # assert "X" not in Y
    out += re.findall(r'assert\s+"([^"\n]{6,})"\s+not\s+in\s', txt)
    # self.assertNotIn("X", Y)
    out += re.findall(r'assertNotIn\(\s*"([^"\n]{6,})"', txt)
    # absent(text, "X", "Y") -- every literal in the call
    for call in re.findall(r'absent\(([^)]*)\)', txt, re.S):
        out += [s for s in re.findall(r'"([^"\n]{6,})"', call)]
    return [s for s in dict.fromkeys(out) if len(s.split()) >= 2]


def sandbox(test_rel, mutate=None, restore_from=None):
    with tempfile.TemporaryDirectory() as td:
        d = pathlib.Path(td) / "r"
        shutil.copytree(SRC, d, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        if restore_from:
            o = subprocess.run(["git", "show", f"{restore_from}:{test_rel}"],
                               capture_output=True, text=True, cwd=SRC).stdout
            if o:
                (d / test_rel).write_text(o)
        if mutate:
            mutate(d)
        r = subprocess.run([VP, "-m", "pytest", test_rel, "-q", "--no-header"],
                           cwd=d, capture_output=True, text=True)
        return r.returncode == 0, (r.stdout.strip().splitlines() or ["?"])[-1]


def reflow(targets, width):
    def go(d):
        for rel in targets:
            p = d / rel
            if not p.is_file():
                continue
            out, buf = [], []
            for ln in p.read_text().split("\n"):
                prose = (ln.strip() and not ln.startswith(("#", "|", "-", "*", ">", "`"))
                         and not ln.startswith("  ") and not PAY.search(ln))
                if prose:
                    buf.append(ln.strip()); continue
                if buf:
                    out += textwrap.wrap(" ".join(buf), width=width,
                                         break_on_hyphens=False, break_long_words=False)
                    buf = []
                out.append(ln)
            if buf:
                out += textwrap.wrap(" ".join(buf), width=width,
                                     break_on_hyphens=False, break_long_words=False)
            p.write_text("\n".join(out))
    return go


def inject(targets, phrase):
    """Append the phrase to every markdown file the test could possibly read.

    Deliberately over-broad: resolving exactly which file an assertion reads is
    unreliable, and over-injection can only produce a false "guard fires",
    never a false "disarmed". A guard that still does not fire after this is
    genuinely vacuous.
    """
    def go(d):
        roots = ("skills", "docs", "prompts", "references", "agent_shared")
        for p in [q for r in roots for q in (d / r).rglob("*.md")]:
            p.write_text(p.read_text(errors="replace") + f"\n\n{phrase}\n")
    return go


def verify(test_rel: str) -> bool:
    targets = md_targets(test_rel)
    print(f"\n{test_rel}\n  reads {len(targets)} markdown file(s)")
    ok, line = sandbox(test_rel)
    print(f"  [1] as-is                      {'PASS' if ok else 'FAIL'}  {line}")
    if not ok:
        return False
    good = True
    for w in (68, 79):
        ok, line = sandbox(test_rel, reflow(targets, w))
        print(f"  [2] reflow width {w}            {'PASS' if ok else 'FAIL'}  {line}")
        good &= ok
    negs = negatives(test_rel)
    disarmed = []
    for phrase in negs:
        ok, _ = sandbox(test_rel, inject(targets, phrase))
        if ok:
            disarmed.append(phrase)
    print(f"  [3] negative guards ({len(negs):>2} checked) "
          f"{'PASS' if not disarmed else 'FAIL'}  "
          f"{'all detected' if not disarmed else f'DISARMED: {disarmed[:3]}'}")
    return good and not disarmed


if __name__ == "__main__":
    results = {f: verify(f) for f in sys.argv[1:]}
    print("\n" + "=" * 60)
    for f, ok in results.items():
        print(f"  {'VERIFIED' if ok else 'NOT VERIFIED'}  {f}")
    sys.exit(0 if all(results.values()) else 1)
