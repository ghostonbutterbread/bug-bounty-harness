#!/bin/bash
# =============================================================================
# Bug Bounty Harness Setup
# =============================================================================
# Usage: ./setup.sh [OPTIONS]
#
# Options:
#   --init          Initialize directories and sync skills
#   --sync          Sync skills to Claude Code and Codex
#   --prompt        Display agent prompt (use --prompt --program NAME for custom)
#   --config        Show current config
#   --help          Show this help message
#
# Environment variables (override config.env):
#   HARNESS_ROOT           - Bug bounty harness repo root (auto-detected)
#   HARNESS_SHARED_BASE    - Base for bounty recon data
#   HARNESS_WORDLISTS      - Wordlists directory
#   CLAUDE_SKILLS_DIR      - Claude Code skills directory
#   CODEX_SKILLS_DIR       - Codex skills directory
#
# Examples:
#   ./setup.sh --init                    # Full setup
#   ./setup.sh --sync                   # Just sync skills
#   ./setup.sh --prompt --program xss-lab # Show agent prompt for program
#   HARNESS_ROOT=/custom/path ./setup.sh --sync  # Override with env var
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.env"
CONFIG_EXAMPLE="$SCRIPT_DIR/config.env.example"

# =============================================================================
# Load config
# =============================================================================

load_config() {
    # Create config from example if missing
    if [ ! -f "$CONFIG_FILE" ]; then
        if [ -f "$CONFIG_EXAMPLE" ]; then
            echo "Creating config.env from config.env.example..."
            cp "$CONFIG_EXAMPLE" "$CONFIG_FILE"
        fi
    fi
    
    # Source config (sets defaults if vars not already set via env)
    if [ -f "$CONFIG_FILE" ]; then
        set -a
        source "$CONFIG_FILE"
        set +a
    fi
    
    # ALWAYS use script location as HARNESS_ROOT (this is the repo root)
    # This ensures scripts work no matter where user clones the repo
    HARNESS_ROOT="$SCRIPT_DIR"
    
    : "${HARNESS_SHARED_BASE:=${HOME}/Shared/bounty_recon}"
    : "${HARNESS_WORDLISTS:=${HOME}/wordlists}"
    : "${CLAUDE_SKILLS_DIR:=${HOME}/.claude/skills}"
    : "${CODEX_SKILLS_DIR:=${HOME}/.codex/skills}"
}

# =============================================================================
# Detect OS
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
# Create directories
# =============================================================================

create_directories() {
    echo "Creating directories..."
    
    local dirs=(
        "$HARNESS_SHARED_BASE"
        "$HARNESS_WORDLISTS"
        "$CLAUDE_SKILLS_DIR"
        "$CODEX_SKILLS_DIR"
    )
    
    for dir in "${dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            echo "  ✓ $dir"
        else
            echo "  - $dir (exists)"
        fi
    done
    
    echo ""
}

# =============================================================================
# Sync skills to providers
# =============================================================================

sync_skills() {
    # Auto-pull latest changes from git
    echo "Pulling latest changes from origin..."
    if git pull --ff-only 2>/dev/null; then
        echo "  ✓ Updated from origin/master"
    else
        echo "  - Up to date or local changes (git pull skipped)"
    fi
    echo ""
    echo "Syncing skills..."
    
    if [ -x "$SCRIPT_DIR/sync_skills.sh" ]; then
        "$SCRIPT_DIR/sync_skills.sh"
    else
        echo "  sync_skills.sh not found or not executable"
        return 1
    fi
    
    echo ""
}

# =============================================================================
# Show config
# =============================================================================

show_config() {
    echo "========================================"
    echo "Bug Bounty Harness - Current Config"
    echo "========================================"
    echo ""
    echo "Config file: $CONFIG_FILE"
    [ -f "$CONFIG_FILE" ] && echo "  (exists)" || echo "  (not found)"
    echo ""
    echo "Paths:"
    echo "  HARNESS_ROOT:        $HARNESS_ROOT (auto-detected)"
    echo "  HARNESS_SHARED_BASE: $HARNESS_SHARED_BASE"
    echo "  HARNESS_WORDLISTS:   $HARNESS_WORDLISTS"
    echo "  CLAUDE_SKILLS_DIR:   $CLAUDE_SKILLS_DIR"
    echo "  CODEX_SKILLS_DIR:    $CODEX_SKILLS_DIR"
    echo ""
    echo "OS: $(detect_os)"
    echo ""
}

# =============================================================================
# Show agent prompt
# =============================================================================

show_prompt() {
    local program="${1:-}"
    local placeholder="{program}"
    
    if [ -f "$SCRIPT_DIR/agent_shared/AGENT_PROMPT.md" ]; then
        echo ""
        echo "========================================"
        echo "Agent Prompt — Bug Bounty Hunting"
        echo "========================================"
        echo ""
        if [ -n "$program" ]; then
            # Replace placeholder with actual program name
            sed "s|$placeholder|$program|g" "$SCRIPT_DIR/agent_shared/AGENT_PROMPT.md"
        else
            sed "s|$placeholder|PROGRAM_NAME|g" "$SCRIPT_DIR/agent_shared/AGENT_PROMPT.md"
            echo ""
            echo "Tip: Run with --program NAME to customize for a specific program"
        fi
        echo ""
    else
        echo "Error: AGENT_PROMPT.md not found at $SCRIPT_DIR/agent_shared/"
        return 1
    fi
}

# =============================================================================
# Initialize (create dirs + sync)
# =============================================================================

init() {
    create_directories
    sync_skills
    
    echo "========================================"
    echo "Setup complete!"
    echo "========================================"
    echo ""
    echo "Next steps:"
    echo "  1. Edit $CONFIG_FILE for your paths (optional)"
    echo "  2. Run: ./setup.sh --sync  (after updating skills)"
    echo "  3. Run: ./setup.sh --prompt  (to get agent prompt)"
    echo "  4. Start hunting!"
    echo ""
}

# =============================================================================
# Main
# =============================================================================

main() {
    load_config
    
    # Handle --prompt specially since it takes an argument
    if [ "${1:-}" = "--prompt" ] || [ "${1:-}" = "--show-prompt" ]; then
        # Format: --prompt [--program NAME] or --prompt NAME
        local prompt_arg=""
        if [ "${2:-}" = "--program" ] || [ "${2:-}" = "-p" ]; then
            prompt_arg="${3:-}"
        else
            prompt_arg="${2:-}"
        fi
        show_prompt "$prompt_arg"
        exit 0
    fi
    
    case "${1:-}" in
        --init|-i)
            init
            ;;
        --sync|-s)
            sync_skills
            ;;
        --config|-c)
            show_config
            ;;
        --help|-h)
            head -30 "${BASH_SOURCE[0]}" | grep "^#" | grep -v "^#!/bin/bash" | sed 's/^# //'
            ;;
        "")
            head -30 "${BASH_SOURCE[0]}" | grep "^#" | grep -v "^#!/bin/bash" | sed 's/^# //'
            ;;
        *)
            echo "Unknown option: $1"
            echo "Run: $0 --help"
            exit 1
            ;;
    esac
}

main "$@"
