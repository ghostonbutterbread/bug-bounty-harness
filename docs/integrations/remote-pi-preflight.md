# Remote-pi preflight routing

- Intent: Ryu clarified `pi-cordinator` is mandatory before all remote-pi multi-agent mesh actions, not just resource messages; retain peer vulnerability privacy.
- Branch/worktree: `fix/remote-pi-preflight` at `/home/ryushe/worktrees/bbh-remote-pi-preflight`; base `6dc9ce83314c6f13bf13082956b7721206398e1d`; target `beta`.
- Contract: preflight skill owns peer-disclosure and resource-only boundary, including alternate resource selection when occupied/missing; upstream remote-pi `agent-network` retains transport semantics. BBH `agents/index.md` and registry route load order. No extension code, new mesh transport, or automatic runtime hook.
- Alignment checked: BBH entry card, hunter-loop peer presence, upstream remote-pi docs and Hoster's generated `~/.pi/remote/skills/agent-network/SKILL.md` (its first step is `list_peers` and it has no preflight route). Independent review of initial tip found ambiguous peer-disclosure escape via “operator-approved private channel”; removed and tightened resource-only peer use.
- Blocker: Root `AGENTS.md` insertion was refused by protected-file approval timeout. Do not retry that edit this turn. The BBH entry card route will not guarantee every remote-pi agent reads it before tools, especially outside BBH. The actual upstream `agent-network` package also has no preflight link. This must be reported rather than claiming universal enforcement.
- Verification: pending focused assertions, independent review, beta merge, Hoster projection/read-back. Fresh consumer check remains conditional.
- Next action: review and integrate the non-protected skill/entry change; report root-context approval/universal enforcement gap for owner resolution.
