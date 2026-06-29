#!/bin/sh
# soc-nginx-agent installer — Datadog-style one-liner.
#
#   curl -fsSL http://CENTRAL:8080/install/soc-nginx-agent.sh \
#     | sudo BLOCKLIST_API_URL=http://CENTRAL:8080 ENROLL_SECRET=xxxxx bash
#
# Reads config from the environment (set on the curl line), installs the agent +
# a systemd unit, and starts it. Idempotent — safe to re-run to upgrade. The agent
# self-enrolls with ENROLL_SECRET, gets its own per-node token, and shows up in the
# dashboard «Ноды» tab. No secrets are baked into this script.
set -eu

API="${BLOCKLIST_API_URL:-}"
SECRET="${ENROLL_SECRET:-}"
NODE_ID="${NODE_ID:-$(hostname -s 2>/dev/null || hostname)}"
GROUP="${GROUP:-}"
HTTP_FILE="${HTTP_FILE:-/etc/nginx/conf.d/soc-deny.conf}"
SERVER_FILE="${SERVER_FILE:-/etc/nginx/soc-deny-server.conf}"
TEST_CMD="${TEST_CMD:-nginx -t}"
RELOAD_CMD="${RELOAD_CMD:-nginx -s reload}"
POLL_INTERVAL="${POLL_INTERVAL:-30}"
BIN=/usr/local/bin/soc-nginx-agent.py
ENVF=/etc/soc/agent.env
UNIT=/etc/systemd/system/soc-nginx-agent.service

[ -n "$API" ] || { echo "ERROR: set BLOCKLIST_API_URL" >&2; exit 2; }
[ "$(id -u)" = "0" ] || { echo "ERROR: run as root (use sudo)" >&2; exit 2; }
# This script downloads code and runs it as root. Over plaintext HTTP a network
# attacker can replace it → remote root. Refuse unless explicitly acknowledged.
case "$API" in
  https://*) ;;
  *)
    if [ "${INSECURE:-}" = "1" ]; then
      echo "WARNING: using plaintext HTTP for $API (INSECURE=1). MITM = root RCE." >&2
    else
      echo "ERROR: $API is not HTTPS. Downloading+running code as root over HTTP is unsafe." >&2
      echo "       Use an HTTPS BLOCKLIST_API_URL, or set INSECURE=1 to override on a trusted network." >&2
      exit 2
    fi ;;
esac
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "ERROR: curl is required" >&2; exit 2; }

echo "[soc] installing agent for node '$NODE_ID' (api=$API)"
mkdir -p /etc/soc /var/lib/soc-agent "$(dirname "$BIN")"

# 1) agent binary
curl -fsSL "$API/install/soc-nginx-agent.py" -o "$BIN.tmp"
mv "$BIN.tmp" "$BIN"
chmod 0755 "$BIN"

# 2) env file (0600 — holds the enroll secret until the node token is minted)
umask 077
cat > "$ENVF" <<EOF
BLOCKLIST_API_URL=$API
ENROLL_SECRET=$SECRET
NODE_ID=$NODE_ID
GROUP=$GROUP
TARGET_ID=$NODE_ID
STATE_FILE=/var/lib/soc-agent/state.json
HTTP_FILE=$HTTP_FILE
SERVER_FILE=$SERVER_FILE
TEST_CMD=$TEST_CMD
RELOAD_CMD=$RELOAD_CMD
POLL_INTERVAL=$POLL_INTERVAL
EOF
umask 022

# 3) systemd unit (tolerant: nginx may be managed outside systemd)
cat > "$UNIT" <<EOF
[Unit]
Description=soc-nginx-agent (pull denylist -> local nginx deny + reload)
After=network-online.target nginx.service
Wants=network-online.target nginx.service

[Service]
EnvironmentFile=$ENVF
ExecStart=/usr/bin/env python3 $BIN
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# 4) enable + (re)start
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable --now soc-nginx-agent.service
  echo "[soc] started. status: systemctl status soc-nginx-agent"
else
  echo "[soc] no systemd — run manually: BLOCKLIST_API_URL=$API python3 $BIN"
fi
echo "[soc] done. The node should appear in the dashboard «Ноды» tab shortly."
