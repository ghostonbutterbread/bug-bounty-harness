#!/usr/bin/env bash
# Publish one loopback-only Chromium handoff UI to the tailnet.
# CDP itself is never served.
set -euo pipefail

ACTION="${1:-}"
HANDOFF_HOST="${HANDOFF_HOST:-127.0.0.1}"
HANDOFF_PORT="${HANDOFF_PORT:-}"
HANDOFF_PORT_MIN="${HANDOFF_PORT_MIN:-9501}"
HANDOFF_PORT_MAX="${HANDOFF_PORT_MAX:-9599}"

usage() {
  cat <<'USAGE'
Usage: HANDOFF_PORT=<port> handoff_transport.sh start|stop
       handoff_transport.sh status

Environment overrides:
  HANDOFF_HOST      loopback host only (default: 127.0.0.1)
  HANDOFF_PORT      required task-owned handoff UI port
  HANDOFF_PORT_MIN  minimum allowed handoff port (default: 9501)
  HANDOFF_PORT_MAX  maximum allowed handoff port (default: 9599)

A route is deterministically mounted at /handoff/<port>, allowing concurrent
browser handoffs. This helper publishes only the UI with Tailscale Serve. It
must never be used for a Chrome CDP port, LAN address, or Tailscale Funnel.
USAGE
}

case "$ACTION" in
  -h|--help|help|'') usage; exit 0 ;;
esac

case "$HANDOFF_HOST" in
  127.0.0.1|localhost) ;;
  *) printf 'refusing non-loopback HANDOFF_HOST: %s\n' "$HANDOFF_HOST" >&2; exit 64 ;;
esac

if [[ ! "$HANDOFF_PORT_MIN" =~ ^[0-9]+$ ]] || [[ ! "$HANDOFF_PORT_MAX" =~ ^[0-9]+$ ]] ||
   (( HANDOFF_PORT_MIN < 1024 || HANDOFF_PORT_MAX > 65535 || HANDOFF_PORT_MIN > HANDOFF_PORT_MAX )); then
  printf 'invalid handoff port range: %s-%s\n' "$HANDOFF_PORT_MIN" "$HANDOFF_PORT_MAX" >&2
  exit 64
fi

if [[ "$ACTION" == start || "$ACTION" == stop ]]; then
  if [[ ! "$HANDOFF_PORT" =~ ^[0-9]+$ ]] ||
     (( HANDOFF_PORT < HANDOFF_PORT_MIN || HANDOFF_PORT > HANDOFF_PORT_MAX )); then
    printf 'HANDOFF_PORT must be in %s-%s: %s\n' "$HANDOFF_PORT_MIN" "$HANDOFF_PORT_MAX" "$HANDOFF_PORT" >&2
    exit 64
  fi
fi

command -v tailscale >/dev/null || {
  printf 'tailscale CLI is unavailable\n' >&2
  exit 69
}

case "$ACTION" in
  start)
    # Refuse to publish a dead or misbound handoff server.
    curl --fail --silent --max-time 3 "http://${HANDOFF_HOST}:${HANDOFF_PORT}/" >/dev/null
    tailscale serve --bg --https=443 --set-path="/handoff/${HANDOFF_PORT}" \
      "http://${HANDOFF_HOST}:${HANDOFF_PORT}"
    tailscale serve status
    ;;
  stop)
    # A missing route is already the desired state.
    tailscale serve --https=443 --set-path="/handoff/${HANDOFF_PORT}" off 2>/dev/null || true
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
