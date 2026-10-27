# Reusable agent definitions

The regular `bunny-*.md` files in this directory are the canonical Bunny worker
roles. Edit them here once. AI Skill Sync projects these Markdown definitions
into explicitly configured, compatible agent directories, starting with
Claude's `~/.claude/agents/`.

This is also BBH's existing Python runner directory. Its Python modules and
`index.md` are **not** native agent definitions. Agent discovery must require
frontmatter with a matching `name` and a nonempty `description`, not sync every
file in this directory.

`skills/bunny/agents/bunny-*.md` are relative compatibility symlinks to these
files, not separate editable definitions. They preserve existing skill/package
lookups, including the Pi role package, without maintaining duplicate bodies.
Keep the complete BBH checkout when distributing that package: copying only
`skills/bunny/` without its canonical `agents/` targets is not supported.

The Hoster Claude roles were older minimal stubs. Their names/descriptions match
these definitions; the migration retains BBH's already-reviewed collaborative
checkpoints, evidence ownership, and reporting boundaries rather than reverting
them to those stubs. Runtime adoption must back up any existing local files
before linking; an agent name does not grant authority or change its model.

Agent formats differ between runtimes. Configure only consumers that accept the
supplied format; syncing Markdown is not a Codex/Hermes role conversion, runtime
restart, or proof of model dispatch. Use the Bunny dispatch workflow for those
consumer-specific execution checks.
