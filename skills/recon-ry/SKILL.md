---
name: recon-ry
description: "Run Ryushe's recon-ry on Hoster and ingest completed outputs into canonical recon artifact directories."
---

# Recon Ry

Use when Ryushe asks to run `recon-ry`, install/check the Hoster recon box, or import a completed `recon-ry` project into the Ghost bounty pipeline.

This skill is a long-running recon wrapper. Start scans and return the PID/log path; do not watch the scan until completion.

## Load Order

1. Read `$HARNESS_ROOT/prompts/recon-ry-playbook.md`.
2. Confirm target scope/rate policy from program notes or `/pullscope` artifacts.
3. Use Hoster via `ryushe@hoster` and `/home/ryushe/.ssh/hoster`.
4. Use `agents/recon_ry.py` for start/status/ingest actions.
5. Store raw recon artifacts under canonical recon paths; do not write high-volume output into the findings ledger.

## Commands

Start a remote run and return immediately:

```bash
python3 agents/recon_ry.py start <program> --url <scoped-domain-or-url> --profile full
```

The start command fails closed if saved scope is missing or the URL is out of scope. It also writes a project-local `rate_limit.conf` before launch. Use `--rate-limit-rps` only after checking the program policy; use `--allow-unscoped` only after explicit Ryushe approval.

Check remote status/log names:

```bash
python3 agents/recon_ry.py status
```

Ingest a completed Hoster project:

```bash
python3 agents/recon_ry.py ingest <program> \
  --source ryushe@hoster:/home/ryushe/bounties/<program> \
  --target <target-host>
```

## Output

Ingest writes:

```text
~/Shared/web_bounty/{program}/web/recon/recon-ry/{target}/runs/{YYYY-MM-DD}/{run_id}/
├── command.txt
├── stdout.txt
├── stderr.txt
├── raw/
├── parsed/
└── manifest.json
```

## Rules

- Treat `recon-ry` outputs as recon artifacts, not confirmed vulnerabilities.
- Promote to the findings ledger only after a separate high-confidence validation step.
- Keep Hoster logs on Hoster; ingest completed project directories when Ryushe asks or when the run is done.
- Stop before running high-volume recon on a target without explicit scope/rate approval.
- Never bypass the saved-scope check unless Ryushe explicitly approves the target and rate limit.
