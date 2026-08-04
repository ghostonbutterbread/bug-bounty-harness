#!/usr/bin/env bash
# Publish only the loopback-only Chromium handoff UI to the tailnet.
# CDP itself is never served.
set -euo pipefail

ACTION="${1:-}"
HANDOFF_HOST="${HANDOFF_HOST:-127.0.0.1}"
HANDOFF_PORT="${HANDOFF_PORT:-9231}"
HANDOFF_PATH="${HANDOFF_PATH:-/handoff}"

usage() {
  cat <<'USAGE'
Usage: handoff_transport.sh start|stop|status

Environment overrides:
  HANDOFF_HOST   loopback host only (default: 127.0.0.1)
  HANDOFF_PORT   local handoff UI port (default: 9231)
  HANDOFF_PATH   HTTPS mount path (default: /handoff)

This helper publishes only the handoff UI with Tailscale Serve. It must never
be used for a Chrome CDP port, LAN address, or Tailscale Funnel/public route.
USAGE
}

case "$HANDOFF_HOST" in
  127.0.0.1|localhost) ;;
  *)
    printf 'refusing non-loopback HANDOFF_HOST: %s\n' "$HANDOFF_HOST" >&2
    exit 64
    ;;
esac

if [[ ! "$HANDOFF_PORT" =~ ^[0-9]+$ ]] || (( HANDOFF_PORT < 1024 || HANDOFF_PORT > 65535 )); then
  printf 'invalid HANDOFF_PORT: %s\n' "$HANDOFF_PORT" >&2
  exit 64
fi

if [[ "$HANDOFF_PATH" != /* ]] || [[ "$HANDOFF_PATH" == *'..'* ]]; then
  printf 'invalid HANDOFF_PATH: %s\n' "$HANDOFF_PATH" >&2
  exit 64
fi

case "$ACTION" in
  -h|--help|help|'')
    usage
    exit 0
    ;;
esac

command -v tailscale >/dev/null || {
  printf 'tailscale CLI is unavailable\n' >&2
  exit 69
}

case "$ACTION" in
  start)
    # Refuse to publish a dead or misbound handoff server.
    curl --fail --silent --max-time 3 "http://${HANDOFF_HOST}:${HANDOFF_PORT}/" >/dev/null
    tailscale serve --bg --https=443 --set-path="$HANDOFF_PATH" \
      "http://${HANDOFF_HOST}:${HANDOFF_PORT}"
    tailscale serve status
    ;;
  stop)
    # A missing route is already the desired state.
    tailscale serve --https=443 --set-path="$HANDOFF_PATH" off 2>/dev/null || true
    tailscale serve status
    ;;
  status)
    tailscale serve status
    ;;
  *)
    usage >&2
    exit 64
    ;;
esac
