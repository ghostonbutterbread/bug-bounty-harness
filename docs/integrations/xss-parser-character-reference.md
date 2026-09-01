# XSS Parser Character Reference Integration Dossier

## Intent

Add a compact, evidence-based reference for character representation, decoding,
normalization, and parser-stage differentials to `xss-payload-engineering`.

## Branch and target

- Feature branch: `docs/xss-parser-character-reference`
- Worktree: `/home/ryushe/worktrees/bbh-xss-parser-character-reference`
- Base: `a9db75eee30ffa8948e49c15887cc45c90afdcff` (`origin/beta`)
- Intended target: `beta`

## Contract

The reference must distinguish parser-active ASCII delimiters from Unicode
lookalikes, explain representation-family preconditions, and direct agents to
measure transformation order rather than use an undifferentiated character list.
It must cite WHATWG HTML/Encoding, Unicode UAX #15 and UTS #39, and OWASP.

## Evidence and verification

- Research: WHATWG HTML/Encoding, Unicode UAX #15/UTS #39, OWASP XSS Filter Evasion.
- Parent-skill link added at `skills/xss-payload-engineering/SKILL.md`.
- Local skill-reference contract and `git diff --check` passed.
- Independent review: no critical/high/medium findings; the parent link, code-point claims, whitespace checks, and five primary-spec URLs were verified. The OWASP URL was bot-protected to automated retrieval, but its syntax was valid.
- Pending: inspect staged diff and commit the focused documentation change.

## Activation boundary

This changes only canonical skill guidance. Runtime availability remains dependent
on the existing beta-selected skill projection after integration.

## Resume point

Create the parent-skill link, validate the focused docs, inspect the staged diff,
and commit the reference and dossier.
