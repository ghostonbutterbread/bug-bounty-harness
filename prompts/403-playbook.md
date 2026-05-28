# 403 Playbook

Use this after `/403` classifies the lane or when writing a report.

## Safety Boundary

- In-scope endpoint only.
- Concrete observed `403` only.
- Owned, approved-account, or server/API endpoint only.
- One mutation family at a time.
- Stop before destructive actions or non-owned data.

## Method

1. Capture direct baseline denial.
2. Capture intended-role or approved-account comparison when available.
3. Choose one lane from `prompts/403-context-pack.md`.
4. Apply a small mutation set.
5. Compare status, redirect target, body length, route-specific content, response headers, and side effects.
6. Minimize any working mutation.

## Primary Harness

```bash
python agents/bypass_harness.py --target https://target.example/admin \
  --type 403 --program target --concurrency 5 --rps 1
```

Prefer lower request rates when rules are unclear.

## Report Fields

- full target URL
- scope rule used
- baseline `403` request/response
- resource ownership decision
- loaded lane/reference pack
- successful mutation and why it differs
- minimized reproducible request
- affected account/role/object boundary
- security impact
- raw artifacts path
