#!/bin/bash
# Sync skills to provider-specific directories
# Run this after adding or updating skills

set -e

SKILLS_DIR="$(dirname "$0")"

echo "Syncing skills to provider directories..."

for skill in xss idor sqli ssrf fuzz recon; do
    if [ -f "$SKILLS_DIR/skills/$skill/SKILL.md" ]; then
        cp "$SKILLS_DIR/skills/$skill/SKILL.md" "$SKILLS_DIR/.claude/skills/$skill/SKILL.md"
        cp "$SKILLS_DIR/skills/$skill/SKILL.md" "$SKILLS_DIR/.agents/skills/$skill/SKILL.md"
        echo "  ✓ $skill"
    else
        echo "  ✗ $skill (not found)"
    fi
done

echo "Done!"
