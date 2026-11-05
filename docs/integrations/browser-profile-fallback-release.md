# Browser profile storage fallback release handoff

- Intent: use the mounted local program artifact root for new browser profiles when available; otherwise choose a restricted node-local root. Preserve existing profile identities and avoid Shared or network-backed live profiles.
- Branch: `fix/browser-profile-fallback-release`; base `db96b4a13f77383e06e8d95b2f3f7475cff66362`; target `beta`.
- Contract: resolve local filesystem and mount status; keep known paths, refuse unsafe or missing running profiles, and keep historical auto-slot identity. The runtime lease and skill preflight make the same Shared-path decision. No existing profile is moved.
- Evidence: the portable source and test diff is byte-identical to the independently reviewed feature diff excluding its private handoff. The final correction at `74d8cab290eed4bfeba3362e5e7f9efdc29b6017` passed an independent targeted review. This checkout installed its own dependencies and passed 189 focused cases. Independent release equivalence/privacy review remains pending.
- Deferred: mount presence does not prove historical device identity, filesystem state can change after preflight, and the lease database is node-local. A disposable full browser smoke is not yet verified. Runtime source publication and activation are separate; preserve unrelated active work and do not restart existing processes.
- Next: run focused release-checkout tests, review equivalence/privacy, then integrate into beta with this handoff removed. Activate only after checking the actual runtime source and existing-session boundary.
