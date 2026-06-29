#!/usr/bin/env bash
# Deploy the WHOLE thing from your laptop, given two SSH targets:
#   --dashboard  the central VM (Loki + dashboard + ban orchestrator)
#   --nginx      your nginx VM (ships logs + enforces bans via the agent)
#
# Example:
#   ./deploy/remote-deploy.sh --dashboard root@203.0.113.10 --nginx root@203.0.113.20
#
# It copies the repo to each VM over rsync, brings up the central stack (generating
# secrets automatically), reads back the enroll secret, and wires the nginx VM to it.
# Re-runnable. Requires: ssh + rsync locally; docker on BOTH VMs; sudo on the nginx VM.
#
#   --ip <addr>     IP the nginx VM uses to reach the central VM (default: host part of
#                   --dashboard). Pass the PRIVATE IP here when the VMs share a private
#                   network — logs/bans then travel over it, not the public internet.
#   --ufw           lock the central firewall: Loki/blocklist reachable ONLY from the
#                   nginx VM's IP (ufw must be installed; SSH stays open).
#   --admin-cidr    with --ufw, restrict the dashboard (8077) to this ip/cidr.
#   --update        redeploy after code changes: re-push + rebuild images + restart.
#   --node <name>   node id for the nginx VM (default: its hostname)
#   --env <name>    environment/pool the nginx VM joins (prod, dev…) — its bans use
#                   that env's CF token / rules / notification channels
#   DRY_RUN=1       print the ssh/rsync commands instead of running them
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"          # repo root
REMOTE_DIR="soc"
SSH_OPTS="-o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new"
RSYNC_EXCL=(--exclude '.git' --exclude '*.venv' --exclude '.venv' --exclude '__pycache__'
            --exclude 'deploy/.env' --exclude 'node_modules' --exclude '*.db*' --exclude '.DS_Store')
DASH="" NGINX="" CENTRAL_IP="" NODE="" ENV=""

die() { echo "ERROR: $*" >&2; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --dashboard) DASH="$2"; shift 2;;
    --nginx)     NGINX="$2"; shift 2;;
    --ip)        CENTRAL_IP="$2"; shift 2;;
    --node)      NODE="$2"; shift 2;;
    --env)       ENV="$2"; shift 2;;
    --admin-cidr) ADMIN_CIDR="$2"; shift 2;;
    --install-docker) INSTALL_DOCKER=1; shift;;
    --update)    UPDATE=1; shift;;
    --ufw)       UFW=1; shift;;
    *) die "unknown arg: $1";;
  esac
done
[ -n "$DASH" ] && [ -n "$NGINX" ] || die "usage: $0 --dashboard user@DASH_IP --nginx user@NGINX_IP [--ip ADDR] [--node NAME]"
command -v ssh >/dev/null && command -v rsync >/dev/null || die "need ssh + rsync locally"
CENTRAL_IP="${CENTRAL_IP:-${DASH##*@}}"

RENV=""; [ "${INSTALL_DOCKER:-}" = "1" ] && RENV="INSTALL_DOCKER=1 "
[ "${UPDATE:-}" = "1" ] && RENV="${RENV}REBUILD=1 "        # --update → rebuild images from new code
# central gets the same env + (with --ufw) firewall rules locked to the nginx VM's IP
DENV="$RENV"
[ "${UFW:-}" = "1" ] && DENV="${DENV}MANAGE_UFW=1 ALLOW_FROM=${NGINX##*@} ${ADMIN_CIDR:+ADMIN_CIDR=$ADMIN_CIDR }"
RUN() { if [ "${DRY_RUN:-}" = "1" ]; then echo "+ $*"; else "$@"; fi; }
push() { RUN rsync -az --delete -e "ssh $SSH_OPTS" "${RSYNC_EXCL[@]}" "$HERE/" "$1:$REMOTE_DIR/"; }
on()   { local h="$1"; shift; RUN ssh $SSH_OPTS "$h" "$*"; }

echo "==> [1/3] dashboard VM ($DASH) — copy repo + bring up central"
push "$DASH"
on "$DASH" "cd $REMOTE_DIR && ${DENV}./deploy/quickstart.sh central $CENTRAL_IP"

echo "==> [2/3] read back the enroll secret"
if [ "${DRY_RUN:-}" = "1" ]; then ENROLL="<from-dashboard-.env>"; PASS="<generated>";
else
  ENROLL="$(ssh $SSH_OPTS "$DASH" "grep '^ENROLL_SECRET=' $REMOTE_DIR/deploy/.env | cut -d= -f2")"
  PASS="$(ssh $SSH_OPTS "$DASH" "grep '^BASIC_AUTH_PASS=' $REMOTE_DIR/deploy/.env | cut -d= -f2")"
  [ -n "$ENROLL" ] || die "could not read ENROLL_SECRET from the dashboard VM"
fi

echo "==> [3/3] nginx VM ($NGINX) — copy repo + ship logs + install agent"
push "$NGINX"
on "$NGINX" "cd $REMOTE_DIR && ${RENV}./deploy/quickstart.sh nginx $CENTRAL_IP $ENROLL ${NODE:-\$(hostname -s)} ${ENV}"

cat <<EOF

────────────────────────────────────────────────────────────────────
✅ Done.
   Dashboard:  http://$CENTRAL_IP:8077   (login: admin / $PASS)
   Open the dashboard → «🖥️ Ноды»; the nginx VM should be online shortly.

   Two one-time nginx steps still needed on $NGINX (the agent printed them):
     • access_log … soc_json;  (or PROMTAIL_CONFIG=promtail-combined.yml for stock logs)
     • include /etc/nginx/soc-deny-server.conf;  inside server{}  → nginx -t && reload
   Firewall: dashboard VM must allow 3100 + 8080 from the nginx VM.
────────────────────────────────────────────────────────────────────
EOF
