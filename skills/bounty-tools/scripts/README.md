# Bounty Tools Script Categories

This is the category catalog for **Bounty Tools**: reusable bug bounty scripts
that do not already belong to a vulnerability class, capability, or program
skill.

## Ownership precedence

Before adding a tool here:

1. Reuse an existing maintained script that owns the same behavior.
2. If a vulnerability or capability skill owns the job, use that skill's
   `scripts/` directory—for example, XSS under `skills/xss/scripts/` and Recon
   under `skills/recon/scripts/`.
3. If a program skill owns it, use `skills/<program-skill>/scripts/`.
4. Only otherwise place the abstract reusable tool in a focused category here.

BBH infrastructure and cross-skill harness launchers remain in the repository
root `scripts/` directory.

## Category rules

- Put executable scripts directly in `scripts/<category>/`; do not put them
  beside this README or in nested subdirectories.
- Use a short, responsibility-based lowercase kebab-case category name.
- Reuse a category when its responsibility fits. If none fits, create a narrow
  category; do not use `misc`, `general`, or `other`.
- Give every category its own `README.md` inventory using the repository's
  standard script record fields.
- Add the category index to the catalog below in the same change.
- Follow the repository root `SCRIPT_POLICY.md`; this catalog cannot weaken it
  or authorize policy edits.

## Categories

No abstract Bounty Tools categories exist yet. Add the first category and its
index when a concrete reusable tool requires one; do not create empty category
directories speculatively.
