#!/usr/bin/env bash
# Hanif Tines Block Linux

set -euo pipefail

LOG_FILE="/var/ossec/logs/active-responses.log"
LOCK_FILE="/var/ossec/active-response/tines-block.lock"
SOCKET_TAG="tines-block"



log() {
  # Single-line timestamped log (safe even if jq fails)
  printf '%s %s: %s\n' "$(date -Is)" "$SOCKET_TAG" "$*" >> "$LOG_FILE"
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

valid_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r a b c d <<<"$ip"
  for o in "$a" "$b" "$c" "$d"; do
    [[ "$o" -ge 0 && "$o" -le 255 ]] || return 1
  done
  return 0
}


AR_PAYLOAD=""
if IFS= read -r -t 2 AR_PAYLOAD; then
  :
else
  log "ERROR: No input on stdin (timeout)."
  exit 1
fi

log "DEBUG: received payload: ${AR_PAYLOAD}"

# ---- prerequisites ---------------------------------------------------------

if ! have_cmd jq; then
  log "ERROR: jq is required but not found."
  exit 1
fi

# ---- extract fields --------------------------------------------------------

COMMAND="$(jq -r '.command // empty' <<<"$AR_PAYLOAD")"
IOC="$(jq -r '.parameters.alert.data.field.ioc // empty' <<<"$AR_PAYLOAD")"
ALERT_DESC="$(jq -r '.parameters.alert.rule.description // empty' <<<"$AR_PAYLOAD")"
RULE_ID="$(jq -r '.parameters.alert.rule.id // empty' <<<"$AR_PAYLOAD")"

if [[ -z "$COMMAND" ]]; then
  log "ERROR: No 'command' found in AR payload."
  exit 1
fi

if [[ -z "$IOC" ]]; then
  log "ERROR: No IOC found at .parameters.alert.data.field.ioc"
  exit 1
fi

if ! valid_ipv4 "$IOC"; then
  log "ERROR: IOC '$IOC' is not a valid IPv4."
  exit 1
fi

# ---- choose backend --------------------------------------------------------
# Default: iptables. (If you use nftables rules/sets, you can switch below.)
if ! have_cmd iptables; then
  log "ERROR: iptables not found."
  exit 1
fi

# ---- perform action under lock --------------------------------------------

mkdir -p "$(dirname "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
flock -w 5 9 || { log "ERROR: Could not acquire lock."; exit 1; }

ACTION=""
RC=0

case "$COMMAND" in
  add)
    # Insert (wait on xtables lock via -w)
    if iptables -w -C INPUT -s "$IOC" -j DROP 2>/dev/null; then
      log "INFO: INPUT drop for $IOC already present."
    else
      iptables -w -I INPUT   -s "$IOC" -j DROP || RC=$?
    fi
    if iptables -w -C FORWARD -s "$IOC" -j DROP 2>/dev/null; then
      log "INFO: FORWARD drop for $IOC already present."
    else
      iptables -w -I FORWARD -s "$IOC" -j DROP || RC=$?
    fi
    ACTION="blocked"
    ;;
  delete)
    # Delete (may not exist; ignore errors but note them)
    iptables -w -D INPUT   -s "$IOC" -j DROP 2>/dev/null || true
    iptables -w -D FORWARD -s "$IOC" -j DROP 2>/dev/null || true
    ACTION="unblocked"
    ;;
  *)
    log "ERROR: Unknown command '$COMMAND' (expected 'add' or 'delete')."
    exit 1
    ;;
esac

if [[ "$RC" -ne 0 ]]; then
  log "ERROR: iptables returned code $RC during $COMMAND on $IOC."
  exit "$RC"
fi

log "SUCCESS: $ACTION $IOC (rule:$RULE_ID desc:'$ALERT_DESC')"
exit 0
