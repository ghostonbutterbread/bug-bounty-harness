# Recon Skill

## Description
Reconnaissance — enumerate targets, discover endpoints, map attack surface.

## Playbook
`../prompts/recon-playbook.md`

## Findings
`~/Shared/bounty_recon/{program}/ghost/skills/recon/findings.md`

## Tools
- Crawler: `~/workspace/scripts/url_probe.py`
- Screenshot: `~/projects/bug_bounty_harness/agents/screenshot_tool.py`
- Subdomain: `~/projects/bug_bounty_harness/agents/subdomain_agent.py`

## Usage
```markdown
Read prompts/recon-playbook.md for methodology.
Test target: {program}
Read findings from: ~/Shared/bounty_recon/{program}/ghost/skills/recon/findings.md
Update knowledge: ~/Shared/bounty_recon/{program}/ghost/knowledge.md
```
