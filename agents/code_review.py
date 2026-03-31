#!/usr/bin/env python3
"""
Code Review Agent — Read-only code analysis without modifications.

Usage:
    python3 code_review.py --file /path/to/file.py
    python3 code_review.py --file /path/to/file.py --agent claude
"""

import argparse
import subprocess
import sys
from pathlib import Path


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


def read_file(filepath: str) -> str:
    """Read and return file contents."""
    path = Path(filepath).expanduser()
    if not path.exists():
        print(f"Error: File not found: {filepath}")
        sys.exit(1)
    return path.read_text(errors="replace")


def review_with_codex(content: str, filepath: str) -> str:
    """Use Codex to review the code."""
    prompt = f"""You are a code reviewer. Read this file and provide a thorough analysis WITHOUT modifying anything.

File: {filepath}

```python
{content}
```

{ReviewAgent._system_prompt}

Provide your review now:"""

    try:
        result = subprocess.run(
            ["codex", "exec", prompt],
            capture_output=True,
            text=True,
            timeout=120,
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
    parser = argparse.ArgumentParser(description="Code Review Agent — Read-only analysis")
    parser.add_argument("--file", "-f", required=True, help="File to review")
    parser.add_argument("--agent", "-a", default="claude",
                       choices=["codex", "claude"],
                       help="Which agent to use (default: claude)")
    args = parser.parse_args()

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
