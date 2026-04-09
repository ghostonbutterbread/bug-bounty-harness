#!/usr/bin/env python3
"""
Code Review Agent — Read-only code analysis without modifications.

Usage:
    python3 code_review.py --file /path/to/file.py
    python3 code_review.py --file /path/to/file.py --agent claude
"""

import argparse
import math
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path.home() / "projects" / "bounty-tools"))
try:
    from subagent_logger import SubagentLogger, compute_pte_lite
except ImportError:  # pragma: no cover
    SubagentLogger = None

    def compute_pte_lite(**kwargs) -> int:
        return (
            int(kwargs.get("prompt_tokens") or 0)
            + int(kwargs.get("completion_tokens") or 0)
            + int(kwargs.get("tool_output_tokens") or 0)
        )


_REVIEW_LOGGER = None


SYSTEM_PROMPT = """You are a code reviewer analyzing a bug bounty hunting tool.

## RULES (STRICT)
1. DO NOT modify any files — this is read-only analysis
2. DO NOT create or delete any files
3. DO NOT suggest running code that could be harmful

## FOCUS AREAS
- Logic errors and bugs
- Security concerns (injection, auth bypasses, exposed secrets, unsafe exec)
- Performance issues (N+1 queries, blocking calls, memory leaks)
- Edge cases not handled (None checks, empty inputs, race conditions)
- Error handling gaps
- Code quality and maintainability

## OUTPUT FORMAT
Provide your review in this structure:

## What It Does Well
- [Specific positive aspects with line references if possible]

## Potential Issues
- **Bug** [LOCATION]: [Description of the bug]
- **Security** [LOCATION]: [Description of security concern]
- **Performance** [LOCATION]: [Description of performance issue]
- **Error Handling** [LOCATION]: [What's not caught]

## Suggested Improvements
1. [Specific, actionable suggestion]
2. [Specific, actionable suggestion]
3. [Specific, actionable suggestion]

## Edge Cases to Consider
- [What inputs or conditions might cause unexpected behavior]
- [What might break in production]

## Notes for Bug Bounty Context
- Are there opportunities for command injection?
- Could this be used to attack systems beyond the target scope?
- Any sensitive data that might be logged or exposed?
"""

USER_PROMPT_TEMPLATE = """Review this code file: {filepath}

```python
{content}
```

Provide a thorough review following the format above."""


def _estimate_tokens_from_text(text: str | bytes | None) -> int:
    if text is None:
        return 0
    if isinstance(text, bytes):
        size = len(text)
    else:
        size = len(str(text).encode("utf-8", errors="replace"))
    return max(0, math.ceil(size / 4))


def _safe_log_span(**fields) -> None:
    if _REVIEW_LOGGER is None:
        return
    try:
        _REVIEW_LOGGER.log_span(**fields)
    except Exception:
        pass


def _build_logger(agent: str, target: str):
    if SubagentLogger is None:
        return None
    try:
        logger = SubagentLogger("code_review", "general", agent)
    except Exception:
        return None
    try:
        logger.start(target=target)
    except Exception:
        pass
    return logger


def read_file(filepath: str) -> str:
    """Read and return file contents."""
    path = Path(filepath).expanduser()
    if not path.exists():
        print(f"Error: File not found: {filepath}")
        sys.exit(1)
    start = time.time()
    content = path.read_text(errors="replace")
    _safe_log_span(
        span_type="tool",
        level="STEP",
        message=f"Tool: read_file {path}",
        tool_name="read_file",
        tool_category="file_read",
        input_bytes=len(str(path).encode("utf-8", errors="replace")),
        output_bytes=len(content.encode("utf-8", errors="replace")),
        latency_ms=int((time.time() - start) * 1000),
        success=True,
    )
    return content


def review_with_codex(content: str, filepath: str) -> str:
    """Use Codex to review the code."""
    prompt = f"""You are a code reviewer. Read this file and provide a thorough analysis WITHOUT modifying anything.

File: {filepath}

```python
{content}
```

{ReviewAgent._system_prompt}

Provide your review now:"""

    _context_tokens_before = _estimate_tokens_from_text(prompt)
    _start = time.time()
    try:
        result = subprocess.run(
            ["codex", "exec", prompt],
            capture_output=True,
            text=True,
            timeout=120,
        )
        response_text = result.stdout if result.returncode == 0 else (result.stderr or result.stdout or "")
        _duration = int((time.time() - _start) * 1000)
        _prompt_tokens = _context_tokens_before
        _completion_tokens = _estimate_tokens_from_text(response_text)
        _context_tokens_after = _context_tokens_before + _completion_tokens
        _output_bytes = len(str(response_text).encode("utf-8", errors="replace"))
        _tool_output_tokens = max(0, math.ceil(_output_bytes / 4))
        _safe_log_span(
            span_type="model",
            level="STEP",
            message="Model call: codex",
            model_name="codex",
            prompt_tokens=_prompt_tokens,
            completion_tokens=_completion_tokens,
            context_tokens_before=_context_tokens_before,
            context_tokens_after=_context_tokens_after,
            tool_output_tokens=_tool_output_tokens,
            pte_lite=compute_pte_lite(
                prompt_tokens=_prompt_tokens,
                completion_tokens=_completion_tokens,
                tool_output_tokens=_tool_output_tokens,
                context_tokens_after=_context_tokens_after,
            ),
            latency_ms=_duration,
            output_bytes=_output_bytes,
            success=result.returncode == 0,
        )
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Codex error: {result.stderr}"
    except FileNotFoundError:
        return "Error: Codex not found. Install with: npm install -g @anthropic-ai/codex"
    except subprocess.TimeoutExpired:
        return "Error: Codex timed out after 120 seconds"
    except Exception as e:
        return f"Error running Codex: {e}"


def review_with_claude(content: str, filepath: str) -> str:
    """Use Claude CLI to review the code."""
    prompt = USER_PROMPT_TEMPLATE.format(filepath=filepath, content=content)

    _context_tokens_before = _estimate_tokens_from_text(prompt)
    _start = time.time()
    try:
        result = subprocess.run(
            [
                "claude",
                "--print",
                "--permission-mode", "bypassPermissions",
                "--output-format", "json",
                f"SYSTEM: {SYSTEM_PROMPT}\n\nUSER: {prompt}"
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        response_text = result.stdout if result.returncode == 0 else (result.stderr or result.stdout or "")
        _duration = int((time.time() - _start) * 1000)
        _prompt_tokens = _context_tokens_before
        _completion_tokens = _estimate_tokens_from_text(response_text)
        _context_tokens_after = _context_tokens_before + _completion_tokens
        _output_bytes = len(str(response_text).encode("utf-8", errors="replace"))
        _tool_output_tokens = max(0, math.ceil(_output_bytes / 4))
        _safe_log_span(
            span_type="model",
            level="STEP",
            message="Model call: claude",
            model_name="claude",
            prompt_tokens=_prompt_tokens,
            completion_tokens=_completion_tokens,
            context_tokens_before=_context_tokens_before,
            context_tokens_after=_context_tokens_after,
            tool_output_tokens=_tool_output_tokens,
            pte_lite=compute_pte_lite(
                prompt_tokens=_prompt_tokens,
                completion_tokens=_completion_tokens,
                tool_output_tokens=_tool_output_tokens,
                context_tokens_after=_context_tokens_after,
            ),
            latency_ms=_duration,
            output_bytes=_output_bytes,
            success=result.returncode == 0,
        )
        if result.returncode == 0:
            # Claude returns JSON with the answer
            try:
                import json
                data = json.loads(result.stdout)
                return data.get("completion", result.stdout)
            except:
                return result.stdout
        else:
            return f"Claude error: {result.stderr}"
    except FileNotFoundError:
        return "Error: Claude CLI not found."
    except subprocess.TimeoutExpired:
        return "Error: Claude timed out after 120 seconds"
    except Exception as e:
        return f"Error running Claude: {e}"


def main():
    global _REVIEW_LOGGER
    parser = argparse.ArgumentParser(description="Code Review Agent — Read-only analysis")
    parser.add_argument("--file", "-f", required=True, help="File to review")
    parser.add_argument("--agent", "-a", default="claude",
                       choices=["codex", "claude"],
                       help="Which agent to use (default: claude)")
    args = parser.parse_args()
    _REVIEW_LOGGER = _build_logger(f"code_review_{args.agent}", args.file)

    print(f"Reading {args.file}...")
    content = read_file(args.file)

    print(f"Reviewing with {args.agent}...")
    if args.agent == "codex":
        review = review_with_codex(content, args.file)
    else:
        review = review_with_claude(content, args.file)

    print("\n" + "="*60)
    print(f"REVIEW: {args.file}")
    print("="*60)
    print(review)


if __name__ == "__main__":
    main()
