#!/bin/bash
# =============================================================================
# Sync skills to provider-specific directories
# =============================================================================
# Usage: ./sync_skills.sh [--claude] [--codex] [--all] [--dry-run]
#
# Paths are loaded from:
#   1. Environment variables (highest priority)
#   2. config.env file
#   3. Defaults (lowest priority)
#
# Environment variables:
#   HARNESS_ROOT           - Bug bounty harness repo root
#   CLAUDE_SKILLS_DIR      - Claude Code skills directory
#   CODEX_SKILLS_DIR       - Codex skills directory
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.env"
CONFIG_EXAMPLE="$SCRIPT_DIR/config.env.example"

# Default: sync all
SYNC_CLAUDE=true
SYNC_CODEX=true
DRY_RUN=false

# =============================================================================
# Ensure config exists (create from example if missing)
# =============================================================================

ensure_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        if [ -f "$CONFIG_EXAMPLE" ]; then
            cp "$CONFIG_EXAMPLE" "$CONFIG_FILE"
        fi
    fi
}

# =============================================================================
# Load config (env vars override config file)
# =============================================================================

load_config() {
    ensure_config
    
    # If config file exists, source it (env vars already win due to : syntax in config)
    if [ -f "$CONFIG_FILE" ]; then
        set -a
        source "$CONFIG_FILE"
        set +a
    fi
    
    # Apply defaults if still not set or if using placeholder
    # Default HARNESS_ROOT to where this script actually lives (the repo root)
    if [ -z "$HARNESS_ROOT" ] || [ "$HARNESS_ROOT" = "detected_from_script" ]; then
        HARNESS_ROOT="$SCRIPT_DIR"
    fi
    : "${CLAUDE_SKILLS_DIR:=${HOME}/.claude/skills}"
    : "${CODEX_SKILLS_DIR:=${HOME}/.codex/skills}"
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
                echo "  --dry-run   Show what would be copied"
                echo ""
                echo "Paths (from env or config.env):"
                echo "  HARNESS_ROOT:       $HARNESS_ROOT"
                echo "  CLAUDE_SKILLS_DIR:  $CLAUDE_SKILLS_DIR"
                echo "  CODEX_SKILLS_DIR:   $CODEX_SKILLS_DIR"
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
        mkdir -p "$(dirname "$dest")"
        cp "$src" "$dest"
        echo "  ✓ $(basename "$dest")"
    fi
}

# =============================================================================
# Sync a skill to a directory
# =============================================================================

sync_skill() {
    local skill="$1"
    local dest_dir="$2"
    
    local src_file="$HARNESS_ROOT/skills/$skill/SKILL.md"
    
    if [ -f "$src_file" ]; then
        do_copy "$src_file" "$dest_dir/$skill/SKILL.md"
    else
        echo "  ✗ $skill (not found: $src_file)"
    fi
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
    echo "Config file: $CONFIG_FILE"
    [ -f "$CONFIG_FILE" ] && echo "  (loaded)" || echo "  (not found)"
    echo ""
    
    # Skills source directory
    local SKILLS_DIR="$HARNESS_ROOT/skills"
    
    # Check if skills directory exists
    if [ ! -d "$SKILLS_DIR" ]; then
        echo "Error: skills directory not found at $SKILLS_DIR"
        echo "Hint: Set HARNESS_ROOT env var if your repo is elsewhere"
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
    
    # Also sync to local .agents/skills for repo-specific Codex
    echo "Syncing to local .agents/skills (repo-specific)..."
    for skill in $SKILLS; do
        sync_skill "$skill" "$HARNESS_ROOT/.agents/skills"
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
}

main "$@"
