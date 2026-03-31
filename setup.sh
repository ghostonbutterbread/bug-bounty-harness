#!/bin/bash
# =============================================================================
# Bug Bounty Harness Setup
# =============================================================================
# Usage: ./setup.sh [OPTIONS]
#
# Options:
#   --init          Initialize directories and sync skills
#   --sync          Sync skills to Claude Code and Codex
#   --config        Show current config (from env or config.env)
#   --help          Show this help message
#
# Environment variables (override config.env):
#   HARNESS_SHARED_BASE    Base for bounty recon data
#   HARNESS_ROOT           Bug bounty harness repo root
#   HARNESS_WORDLISTS      Wordlists directory
#   CLAUDE_SKILLS_DIR      Claude Code skills directory
#   CODEX_SKILLS_DIR       Codex skills directory
#
# Examples:
#   ./setup.sh --init                    # Full setup
#   ./setup.sh --sync                    # Just sync skills
#   HARNESS_ROOT=/custom/path ./setup.sh --sync  # Override with env var
#
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.env"
CONFIG_EXAMPLE="$SCRIPT_DIR/config.env.example"

# =============================================================================
# Ensure config exists (create from example if missing)
# =============================================================================

ensure_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        if [ -f "$CONFIG_EXAMPLE" ]; then
            echo "Creating config.env from config.env.example..."
            cp "$CONFIG_EXAMPLE" "$CONFIG_FILE"
            echo "✓ Created $CONFIG_FILE"
            echo ""
            echo "Edit $CONFIG_FILE to customize your paths."
            echo ""
        else
            echo "Error: config.env not found and config.env.example missing"
            exit 1
        fi
    fi
}

# =============================================================================
# Load config (env vars always win, config file provides defaults)
# =============================================================================

load_config() {
    # Ensure config exists first
    ensure_config
    
    # If config file exists, source it (env vars already win due to : syntax in config)
    if [ -f "$CONFIG_FILE" ]; then
        set -a
        source "$CONFIG_FILE"
        set +a
    fi
    
    # Default HARNESS_ROOT to where this script actually lives (the repo root)
    if [ -z "$HARNESS_ROOT" ] || [ "$HARNESS_ROOT" = "detected_from_script" ]; then
        HARNESS_ROOT="$SCRIPT_DIR"
    fi
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
    echo "Syncing skills..."
    
    # Run the sync script with current config
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
    echo "Paths (from env or config):"
    echo "  HARNESS_SHARED_BASE: $HARNESS_SHARED_BASE"
    echo "  HARNESS_ROOT:        $HARNESS_ROOT"
    echo "  HARNESS_WORDLISTS:   $HARNESS_WORDLISTS"
    echo "  CLAUDE_SKILLS_DIR:   $CLAUDE_SKILLS_DIR"
    echo "  CODEX_SKILLS_DIR:    $CODEX_SKILLS_DIR"
    echo ""
    echo "OS: $(detect_os)"
    echo ""
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
    echo "  3. Start hunting!"
    echo ""
}

# =============================================================================
# Main
# =============================================================================

show_help() {
    head -25 "${BASH_SOURCE[0]}" | grep "^#" | grep -v "^#!/bin/bash" | sed 's/^# //'
}

main() {
    load_config
    
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
            show_help
            ;;
        "")
            show_help
            ;;
        *)
            echo "Unknown option: $1"
            echo "Run: $0 --help"
            exit 1
            ;;
    esac
}

main "$@"
