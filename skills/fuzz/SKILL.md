# Fuzz Skill

## Description
Discover hidden endpoints, parameters, and files through enumeration.

## Playbook
`../prompts/fuzz-playbook.md`

## Findings
`~/Shared/bounty_recon/{program}/ghost/skills/fuzz/findings.md`

## Tools
- ffuf: `ffuf -u TARGET/FUZZ -w WORDLIST -mc 200,204,301,302,307,401,403 -fc 404 -c -v`
- Wordlists: `~/wordlists/SecLists/Discovery/Web-Content/common.txt`

## Usage
```markdown
Read prompts/fuzz-playbook.md for methodology.
Test target: {program}
Read findings from: ~/Shared/bounty_recon/{program}/ghost/skills/fuzz/findings.md
Update knowledge: ~/Shared/bounty_recon/{program}/ghost/knowledge.md
```
