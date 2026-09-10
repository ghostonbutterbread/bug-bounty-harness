# Proxy Curl Scripts

## `raw_to_curl.py`

- **Purpose:** Convert one raw HTTP proxy request into an ordered, shell-quoted
  curl command while preserving request shape.
- **Inputs:** Raw request file or stdin plus transport and body-file options.
- **Outputs:** A curl command on stdout and, only when requested, a body file.
- **Mutates:** No external system; `--body-file` writes the declared local file.
  The generated command is not executed automatically.
- **Example:** `bbh skills/proxy-curl/scripts/raw_to_curl.py request.raw`
- **Verification:** `scripts/bbh skills/proxy-curl/scripts/raw_to_curl.py --help`
- **Owner/scope:** Proxy Curl skill.
- **Last verified:** 2026-09-10.
- **Coverage:** Conversion covers the parsed request shape; it does not prove
  replay safety, authentication portability, or endpoint behavior.
