#!/usr/bin/env bash
# Publish one loopback-only Chromium handoff UI to the tailnet.
# CDP itself is never served.
set -euo pipefail

ACTION="${1:-}"
HANDOFF_HOST="${HANDOFF_HOST:-127.0.0.1}"
HANDOFF_PORT="${HANDOFF_PORT:-}"
HANDOFF_PORT_MIN="${HANDOFF_PORT_MIN:-9501}"
HANDOFF_PORT_MAX="${HANDOFF_PORT_MAX:-9599}"
# Legacy screenshot sessions work below the shared HTTPS listener at a path.
# KasmVNC must instead be root-mounted on a distinct tailnet HTTPS port because
# its browser client uses root-relative asset and WebSocket paths.
HANDOFF_PATH="${HANDOFF_PATH:-}"
HANDOFF_HTTPS_PORT="${HANDOFF_HTTPS_PORT:-}"

usage() {
  cat <<'USAGE'
Usage: HANDOFF_PORT=<port> handoff_transport.sh start|stop
       handoff_transport.sh status

Environment overrides:
  HANDOFF_HOST      loopback host only (default: 127.0.0.1)
  HANDOFF_PORT      required task-owned handoff UI port
  HANDOFF_PORT_MIN  minimum allowed handoff port (default: 9501)
  HANDOFF_PORT_MAX  maximum allowed local handoff port (default: 9599)
  HANDOFF_PATH      legacy HTTPS:443 path (default: /handoff/<port>)
  HANDOFF_HTTPS_PORT dedicated tailnet HTTPS port; required for KasmVNC

Without HANDOFF_HTTPS_PORT, a route is mounted at /handoff/<port>. For KasmVNC,
set HANDOFF_HTTPS_PORT to a unique port (typically 9501-9599): KasmVNC requires
a root-mounted HTTPS origin because its assets and WebSocket are root-relative.
This helper publishes only loopback UI endpoints with Tailscale Serve; it must
never be used for Chrome CDP, LAN addresses, or Tailscale Funnel.
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
  HANDOFF_PATH="${HANDOFF_PATH:-/handoff/${HANDOFF_PORT}}"
  if [[ -n "$HANDOFF_HTTPS_PORT" ]]; then
    if [[ ! "$HANDOFF_HTTPS_PORT" =~ ^[0-9]+$ ]] || (( HANDOFF_HTTPS_PORT < 1024 || HANDOFF_HTTPS_PORT > 65535 )); then
      printf 'HANDOFF_HTTPS_PORT must be in 1024-65535: %s\n' "$HANDOFF_HTTPS_PORT" >&2
      exit 64
    fi
  elif [[ ! "$HANDOFF_PATH" =~ ^/[A-Za-z0-9._/-]+$ ]] || [[ "$HANDOFF_PATH" == *".."* ]]; then
    printf 'invalid HANDOFF_PATH: %s\n' "$HANDOFF_PATH" >&2
    exit 64
  fi
fi

command -v tailscale >/dev/null || {
  printf 'tailscale CLI is unavailable\n' >&2
  exit 69
}

case "$ACTION" in
  start)
    # Refuse to publish a dead or misbound handoff server. KasmVNC correctly
    # returns 401 before its own authenticated browser login; screenshot UI
    # returns 200. Both prove the loopback service is alive.
    health_status="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 3 "http://${HANDOFF_HOST}:${HANDOFF_PORT}/")"
    case "$health_status" in
      200|401) ;;
      *) printf 'handoff UI health check failed (HTTP %s)\n' "$health_status" >&2; exit 69 ;;
    esac
    if [[ -n "$HANDOFF_HTTPS_PORT" ]]; then
      tailscale serve --bg --https="$HANDOFF_HTTPS_PORT" "http://${HANDOFF_HOST}:${HANDOFF_PORT}"
    else
      tailscale serve --bg --https=443 --set-path="$HANDOFF_PATH" "http://${HANDOFF_HOST}:${HANDOFF_PORT}"
    fi
    tailscale serve status
    ;;
  stop)
    # A missing route is already the desired state.
    if [[ -n "$HANDOFF_HTTPS_PORT" ]]; then
      tailscale serve --https="$HANDOFF_HTTPS_PORT" off 2>/dev/null || true
    else
      tailscale serve --https=443 --set-path="$HANDOFF_PATH" off 2>/dev/null || true
    fi
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
