#!/bin/bash
# Sync skills to provider-specific directories
# Usage: ./sync_skills.sh [--claude] [--codex] [--all] [--dry-run]
#
# Paths by OS:
#   Claude Code (Desktop/CLI):
#     macOS/Linux: ~/.claude/skills/
#     Windows: %USERPROFILE%\.claude\skills\
#   Codex:
#     macOS/Linux: ~/.codex/skills/
#     Windows: %USERPROFILE%\.codex\skills\

set -e

# Default: sync all
SYNC_CLAUDE=true
SYNC_CODEX=true
DRY_RUN=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --claude)
            SYNC_CLAUDE=true
            SYNC_CODEX=false
            shift
            ;;
        --codex)
            SYNC_CODEX=true
            SYNC_CLAUDE=false
            shift
            ;;
        --all)
            SYNC_CLAUDE=true
            SYNC_CODEX=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--claude] [--codex] [--all] [--dry-run]"
            echo ""
            echo "Options:"
            echo "  --claude    Sync only to Claude Code"
            echo "  --codex     Sync only to Codex"
            echo "  --all       Sync to both (default)"
            echo "  --dry-run   Show what would be copied without copying"
            echo "  --help      Show this help message"
            echo ""
            echo "Paths:"
            echo "  Claude Code: ~/.claude/skills/"
            echo "  Codex: ~/.codex/skills/"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Darwin*)
            echo "macos"
            ;;
        Linux*)
            echo "linux"
            ;;
        CYGWIN*|MINGW*|MSYS*)
            echo "windows"
            ;;
        *)
            echo "linux"  # Default to linux
            ;;
    esac
}

# Get home directory (cross-platform)
get_home() {
    if [ "$(detect_os)" = "windows" ]; then
        echo "$USERPROFILE"
    else
        echo "$HOME"
    fi
}

# Copy function (respects dry-run)
do_copy() {
    local src="$1"
    local dest="$2"
    
    if [ "$DRY_RUN" = true ]; then
        echo "  [DRY-RUN] Would copy: $src -> $dest"
    else
        mkdir -p "$(dirname "$dest")"
        cp "$src" "$dest"
        echo "  ✓ $dest"
    fi
}

SKILLS_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILLS_DIR="$SKILLS_DIR/skills"

# Check if skills directory exists
if [ ! -d "$SKILLS_DIR" ]; then
    echo "Error: skills directory not found at $SKILLS_DIR"
    exit 1
fi

# Get list of skills
SKILLS=$(ls -d "$SKILLS_DIR"/*/ 2>/dev/null | xargs -n1 basename || echo "")

if [ -z "$SKILLS" ]; then
    echo "Error: No skills found in $SKILLS_DIR"
    exit 1
fi

OS=$(detect_os)
HOME_DIR=$(get_home)

echo "========================================"
echo "Bug Bounty Harness - Skill Sync"
echo "========================================"
echo "OS detected: $OS"
echo "Home directory: $HOME_DIR"
echo ""

# Sync Claude Code skills
if [ "$SYNC_CLAUDE" = true ]; then
    echo "Syncing to Claude Code..."
    
    case "$OS" in
        macos|linux)
            CLAUDE_SKILLS_DIR="$HOME_DIR/.claude/skills"
            ;;
        windows)
            CLAUDE_SKILLS_DIR="$HOME_DIR/.claude/skills"
            ;;
    esac
    
    if [ "$DRY_RUN" = true ]; then
        echo "  Target: $CLAUDE_SKILLS_DIR"
    fi
    
    for skill in $SKILLS; do
        if [ -f "$SKILLS_DIR/$skill/SKILL.md" ]; then
            do_copy "$SKILLS_DIR/$skill/SKILL.md" "$CLAUDE_SKILLS_DIR/$skill/SKILL.md"
        fi
    done
    echo ""
fi

# Sync Codex skills
if [ "$SYNC_CODEX" = true ]; then
    echo "Syncing to Codex..."
    
    case "$OS" in
        macos|linux)
            CODEX_SKILLS_DIR="$HOME_DIR/.codex/skills"
            ;;
        windows)
            CODEX_SKILLS_DIR="$HOME_DIR/.codex/skills"
            ;;
    esac
    
    if [ "$DRY_RUN" = true ]; then
        echo "  Target: $CODEX_SKILLS_DIR"
    fi
    
    for skill in $SKILLS; do
        if [ -f "$SKILLS_DIR/$skill/SKILL.md" ]; then
            do_copy "$SKILLS_DIR/$skill/SKILL.md" "$CODEX_SKILLS_DIR/$skill/SKILL.md"
        fi
    done
    echo ""
fi

# Also sync to local .agents/skills for repo-specific Codex
echo "Syncing to local .agents/skills (repo-specific)..."
for skill in $SKILLS; do
    if [ -f "$SKILLS_DIR/$skill/SKILL.md" ]; then
        do_copy "$SKILLS_DIR/$skill/SKILL.md" "$SKILLS_DIR/../.agents/skills/$skill/SKILL.md"
    fi
done
echo ""

if [ "$DRY_RUN" = true ]; then
    echo "========================================"
    echo "Dry run complete - no files copied"
    echo "========================================"
else
    echo "========================================"
    echo "Sync complete!"
    echo "========================================"
fi
