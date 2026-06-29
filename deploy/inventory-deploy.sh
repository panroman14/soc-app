#!/usr/bin/env bash
# Fleet installer — push soc-nginx-agent to many nginx VMs over SSH from your PC.
# For one-off hosts, prefer the dashboard one-liner; use this to roll out at scale.
#
# Usage:
#   export BLOCKLIST_API_URL=http://central:8080
#   export ENROLL_SECRET=xxxxx
#   ./inventory-deploy.sh hosts.txt
#
# hosts.txt — one host per line, '#' comments allowed. Optional 2nd/3rd columns set
# this node's NODE_ID and ban GROUP (else NODE_ID defaults to the remote hostname):
#   root@web1.example.com
#   ubuntu@10.0.0.5    web2     origins
#   deploy@edge.lan    edge-eu  europe
set -euo pipefail

HOSTS_FILE="${1:-hosts.txt}"
API="${BLOCKLIST_API_URL:-}"
SECRET="${ENROLL_SECRET:-}"
SSH_OPTS="${SSH_OPTS:--o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new}"

[ -n "$API" ] || { echo "ERROR: export BLOCKLIST_API_URL" >&2; exit 2; }
[ -n "$SECRET" ] || { echo "ERROR: export ENROLL_SECRET" >&2; exit 2; }
[ -f "$HOSTS_FILE" ] || { echo "ERROR: hosts file '$HOSTS_FILE' not found" >&2; exit 2; }

ok=0; fail=0
while read -r host node group _rest; do
  case "$host" in ""|\#*) continue;; esac
  echo "==> $host (node=${node:-<hostname>} group=${group:-default})"
  # shellcheck disable=SC2086
  if ssh $SSH_OPTS "$host" \
       "curl -fsSL '$API/install/soc-nginx-agent.sh' \
        | sudo BLOCKLIST_API_URL='$API' ENROLL_SECRET='$SECRET' \
               NODE_ID='${node:-}' GROUP='${group:-}' bash"; then
    ok=$((ok+1))
  else
    echo "    !! failed on $host" >&2; fail=$((fail+1))
  fi
done < "$HOSTS_FILE"

echo "done: $ok ok, $fail failed"
[ "$fail" -eq 0 ]
