#!/bin/bash
# =============================================================================
# Sync skills to provider-specific directories
# =============================================================================
# Usage: ./sync_skills.sh [--claude] [--codex] [--ghost] [--all] [--dry-run]
#
# Paths are loaded from:
#   1. Environment variables (highest priority)
#   2. config.env file (created from example if missing)
#   3. Auto-detected defaults
#
# Environment variables:
#   HARNESS_ROOT           - Bug bounty harness repo root (auto-detected)
#   CLAUDE_SKILLS_DIR      - Claude Code skills directory
#   CODEX_SKILLS_DIR       - Codex skills directory
#   GHOST_SKILLS_DIR       - Ghost (OpenClaw) workspace skills directory
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.env"
CONFIG_EXAMPLE="$SCRIPT_DIR/config.env.example"

# Default: sync all
SYNC_CLAUDE=true
SYNC_CODEX=true
SYNC_GHOST=true
DRY_RUN=false

# =============================================================================
# Ensure config exists (create from example if missing)
# =============================================================================

ensure_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        if [ -f "$CONFIG_EXAMPLE" ]; then
            echo "Creating config.env from config.env.example..."
            cp "$CONFIG_EXAMPLE" "$CONFIG_FILE"
        fi
    fi
}

# =============================================================================
# Load config
# =============================================================================

load_config() {
    ensure_config

    # Source config (sets defaults if vars not already set via env)
    if [ -f "$CONFIG_FILE" ]; then
        set -a
        source "$CONFIG_FILE"
        set +a
    fi

    # ALWAYS use script location as HARNESS_ROOT (this is the repo root)
    # This ensures scripts work no matter where user clones the repo
    HARNESS_ROOT="$SCRIPT_DIR"

    : "${CLAUDE_SKILLS_DIR:=${HOME}/.claude/skills}"
    : "${CODEX_SKILLS_DIR:=${HOME}/.agents/skills}"
    : "${GHOST_SKILLS_DIR:=${HOME}/.openclaw/workspace/skills}"
}

# =============================================================================
# OS detection
# =============================================================================

detect_os() {
    case "$(uname -s)" in
        Darwin*)  echo "macos" ;;
        Linux*)   echo "linux" ;;
        CYGWIN*|MINGW*|MSYS*) echo "windows" ;;
        *)        echo "linux" ;;
    esac
}

# =============================================================================
# Copy function
# =============================================================================

do_copy() {
    local src="$1"
    local dest="$2"

    if [ "$DRY_RUN" = true ]; then
        echo "  [DRY-RUN] Would copy: $src -> $dest"
    else
        if [ -e "$dest" ] && [ "$(readlink -f "$src")" = "$(readlink -f "$dest")" ]; then
            echo "  - $(basename "$dest") (already linked)"
            return 0
        fi
        mkdir -p "$(dirname "$dest")"
        cp "$src" "$dest"
        echo "  ✓ $(basename "$dest")"
    fi
}

# =============================================================================
# Sync a skill (full skill directory so bundled scripts/references/assets are available)
# =============================================================================

sync_skill() {
    local skill="$1"
    local dest_dir="$2"

    local src_dir="$HARNESS_ROOT/skills/$skill"

    if [ -d "$src_dir" ]; then
        if [ ! -f "$src_dir/SKILL.md" ]; then
            echo "  - $skill (skipped: missing SKILL.md)"
            return 0
        fi
        if [ "$DRY_RUN" = true ]; then
            echo "  [DRY-RUN] Would copy directory: $src_dir -> $dest_dir/$skill"
        else
            if [ -e "$dest_dir/$skill" ] && [ "$(readlink -f "$src_dir")" = "$(readlink -f "$dest_dir/$skill")" ]; then
                echo "  - $skill (already linked)"
                return 0
            fi
            mkdir -p "$dest_dir/$skill"
            cp -a "$src_dir/." "$dest_dir/$skill/"
            echo "  ✓ $skill"
        fi
    else
        echo "  ✗ $skill (not found: $src_dir)"
    fi
}

# =============================================================================
# Parse arguments
# =============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --claude)
                SYNC_CLAUDE=true
                SYNC_CODEX=false
                SYNC_GHOST=false
                shift
                ;;
            --codex)
                SYNC_CODEX=true
                SYNC_CLAUDE=false
                SYNC_GHOST=false
                shift
                ;;
            --ghost)
                SYNC_GHOST=true
                SYNC_CLAUDE=false
                SYNC_CODEX=false
                shift
                ;;
            --all)
                SYNC_CLAUDE=true
                SYNC_CODEX=true
                SYNC_GHOST=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [--claude] [--codex] [--ghost] [--all] [--dry-run]"
                echo ""
                echo "Options:"
                echo "  --claude    Sync only to Claude Code"
                echo "  --codex     Sync only to Codex"
                echo "  --ghost     Sync only to Ghost workspace"
                echo "  --all       Sync to all (default)"
                echo "  --dry-run   Show what would be copied"
                echo ""
                echo "Paths:"
                echo "  HARNESS_ROOT:       $SCRIPT_DIR"
                echo "  CLAUDE_SKILLS_DIR:  ${CLAUDE_SKILLS_DIR}"
                echo "  CODEX_SKILLS_DIR:   ${CODEX_SKILLS_DIR}"
                echo "  GHOST_SKILLS_DIR:   ${GHOST_SKILLS_DIR}"
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

# =============================================================================
# Main
# =============================================================================

main() {
    load_config
    parse_args "$@"

    local OS="$(detect_os)"

    echo "========================================"
    echo "Bug Bounty Harness - Skill Sync"
    echo "========================================"
    echo "OS detected: $OS"
    echo "HARNESS_ROOT: $HARNESS_ROOT"
    echo ""
    # Auto-pull latest changes from git unless this is a dry run.
    if [ "$DRY_RUN" = true ]; then
        echo "Dry run: skipping git pull"
    else
        echo "Pulling latest changes from origin..."
        if git pull --ff-only 2>/dev/null; then
            echo "  ✓ Updated from origin/master"
        else
            echo "  - Up to date or local changes (git pull skipped)"
        fi
    fi
    echo ""

    # Skills source directory
    local SKILLS_DIR="$HARNESS_ROOT/skills"

    # Check if skills directory exists
    if [ ! -d "$SKILLS_DIR" ]; then
        echo "Error: skills directory not found at $SKILLS_DIR"
        exit 1
    fi

    # Get list of skills
    local SKILLS=$(ls -d "$SKILLS_DIR"/*/ 2>/dev/null | xargs -n1 basename || echo "")

    if [ -z "$SKILLS" ]; then
        echo "Error: No skills found in $SKILLS_DIR"
        exit 1
    fi

    # Sync Claude Code skills
    if [ "$SYNC_CLAUDE" = true ]; then
        echo "Syncing to Claude Code..."
        echo "  Target: $CLAUDE_SKILLS_DIR"
        for skill in $SKILLS; do
            sync_skill "$skill" "$CLAUDE_SKILLS_DIR"
        done
        echo ""
    fi

    # Sync Codex skills
    if [ "$SYNC_CODEX" = true ]; then
        echo "Syncing to Codex..."
        echo "  Target: $CODEX_SKILLS_DIR"
        for skill in $SKILLS; do
            sync_skill "$skill" "$CODEX_SKILLS_DIR"
        done
        echo ""
    fi

    # Sync to Ghost workspace (OpenClaw)
    if [ "$SYNC_GHOST" = true ]; then
        echo "Syncing to Ghost workspace..."
        echo "  Target: $GHOST_SKILLS_DIR"
        for skill in $SKILLS; do
            sync_skill "$skill" "$GHOST_SKILLS_DIR"
        done
        echo ""
    fi

    if [ "$DRY_RUN" = true ]; then
        echo "========================================"
        echo "Dry run complete - no files copied"
        echo "========================================"
    else
        echo "========================================"
        echo "Sync complete!"
        echo "========================================"
    fi
}

main "$@"
