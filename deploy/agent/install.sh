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

# 4) wire the deny include into nginx server blocks, so IP bans AND 403-path rules
#    actually apply. Opt out with MANAGE_NGINX=0. Safe: ensures the included file
#    exists, backs up each edited file, gates on `nginx -t`, and reverts on failure.
if [ "${MANAGE_NGINX:-1}" != "0" ] && command -v nginx >/dev/null 2>&1; then
  INC="include $SERVER_FILE;"
  # The server snippet does `if ($soc_blocked) { return 403; }`. $soc_blocked is defined
  # by the http-context geo the agent writes to HTTP_FILE — but at install time (before
  # the agent's first poll) HTTP_FILE may be absent, so the variable would be undefined
  # and `nginx -t` would fail (→ revert, no bans). Guarantee both files exist in a
  # self-consistent minimal state; the agent overwrites them with the real render.
  grep -qs soc_blocked "$HTTP_FILE" 2>/dev/null || \
    printf '# soc placeholder — replaced on first agent poll\ngeo $remote_addr $soc_blocked { default 0; }\n' > "$HTTP_FILE"
  [ -f "$SERVER_FILE" ] || printf '# managed by soc-nginx-agent — populated on first poll\n' > "$SERVER_FILE"
  # Back up OUTSIDE /etc/nginx: nginx does `include sites-enabled/*` (no extension
  # filter), so a backup left next to the file would load as a SECOND server block →
  # "duplicate default server" → nginx -t fails. Keep backups in a temp dir.
  BK="$(mktemp -d 2>/dev/null || echo /tmp/soc-nginx-bak.$$)"; mkdir -p "$BK"
  bkname() { printf '%s' "$1" | tr '/' '_'; }
  soc_changed=0
  for f in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
    [ -f "$f" ] || continue
    grep -qF "$SERVER_FILE" "$f" && continue                       # already included
    grep -qE '^[[:space:]]*server[[:space:]]*\{' "$f" || continue  # no server block here
    cp "$f" "$BK/$(bkname "$f")"
    sed -i -E "s|^([[:space:]]*)server([[:space:]]*)\{|\1server\2{\n\1    $INC|" "$f"
    soc_changed=1
  done
  if [ "$soc_changed" = "1" ]; then
    if nginx -t >/dev/null 2>&1; then
      ( systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null ) || true
      echo "[soc] bans enabled in nginx (added '$INC' to server block(s) + reloaded)"
    else
      for f in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
        [ -f "$BK/$(bkname "$f")" ] && cp "$BK/$(bkname "$f")" "$f"
      done
      echo "[soc] WARN: 'nginx -t' failed after adding the include — reverted. Add it" >&2
      echo "      manually inside your server{} block:  include $SERVER_FILE;" >&2
    fi
  else
    echo "[soc] nginx deny-include already present (or no server{} found) — nothing to do"
  fi
  rm -rf "$BK"
fi

# 5) enable + (re)start the agent
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable --now soc-nginx-agent.service
  echo "[soc] started. status: systemctl status soc-nginx-agent"
else
  echo "[soc] no systemd — run manually: BLOCKLIST_API_URL=$API python3 $BIN"
fi
echo "[soc] done. The node should appear in the dashboard «Ноды» tab shortly."
