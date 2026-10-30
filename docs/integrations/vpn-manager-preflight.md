# VPN manager preflight — blocked checkpoint

- **Owner / branch:** Hermes; `fix/vpn-manager-preflight` in this worktree.
- **Base / target:** BBH `origin/beta` at `d03e13b`; target `beta`.
- **Intent:** Before external traffic identify the actual egress manager and preserve the verified path; do not switch managers merely to start work. Unknown/conflicting routes stop external traffic. VPN-manager changes need explicit operator direction and existing recovery safeguards.
- **Changed contract:** `skills/mullvad/SKILL.md` and `prompts/mullvad-playbook.md` align the specialist guidance. This is an instruction, not network-layer enforcement.
- **Evidence:** On the authoring host local Tailscale exit and effective IPv4/IPv6 routes were active, standalone Mullvad was disconnected, and a public Mullvad status probe reported a Mullvad exit. No VPN settings were changed.
- **Scope decision:** Ryushe narrowed this work to the Mullvad skill and its playbook. Do not change or sync protected root-context templates. The resulting guidance applies when the skill or playbook is loaded; it is not a universal pre-internet hook.
- **Independent review:** Multiple read-only reviews identified absent-manager ambiguity, recovery and probe gating, recipe ordering, and a public lookup during disconnect; each was corrected. Independent reviewer approved `4b082cb` against locally fetched `origin/beta`, with no remaining concrete blocking safety flaws. No live failure tests or runtime activation were claimed.
- **Runtime activation blocker:** The active BBH skill projection points to a dirty beta checkout 87 commits behind the fetched remote. Do not reset, discard changes, repoint profiles, or advance that shared checkout without coordination. Review/integrate this branch and safely reconcile the active source before claiming activation.
- **Deferred verification:** Run repository policy/skill checks, re-fetch and compare beta before integration, and verify runtime path and fresh consumer load. No live network switch or failure injection is authorized by this checkpoint.
- **Next:** Coordinate the unrelated dirty checkout change, then reconcile the selected beta integration checkout without disturbing it and follow the repository integration workflow. Verify the active skill projection and load.
