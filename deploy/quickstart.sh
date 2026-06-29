#!/usr/bin/env bash
# soc — one-command deploy. Run on each VM; just give the central IP.
#
#   On the dashboard VM (central):
#       ./quickstart.sh central [PUBLIC_IP]
#     → generates secrets + deploy/.env, brings up Loki+dashboard+blocklist,
#       prints the dashboard URL/login and the exact command to run on nginx VMs.
#
#   On each nginx VM:
#       ./quickstart.sh nginx <CENTRAL_IP> <ENROLL_SECRET> [NODE_ID]
#     → ships logs (Promtail) + installs the ban agent (self-enroll). The
#       central command above prints this line filled in for you.
#
# Idempotent: re-running keeps existing secrets in deploy/.env. Set SKIP_UP=1 to
# only write config (no docker compose up). Bans default to local nginx (DEPLOY_MODE
# =nginx); for Cloudflare instead, see the note printed at the end / README.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"        # deploy/
ENVF="$HERE/.env"
ROLE="${1:-}"

die() { echo "ERROR: $*" >&2; exit 2; }
have() { command -v "$1" >/dev/null 2>&1; }
gen()  { openssl rand -hex 24 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# set_env KEY VALUE — upsert into deploy/.env (no sed-escaping headaches)
set_env() {
  local k="$1" v="$2"
  [ -f "$ENVF" ] || : > "$ENVF"
  grep -vE "^${k}=" "$ENVF" > "$ENVF.tmp" 2>/dev/null || true
  mv "$ENVF.tmp" "$ENVF"
  printf '%s=%s\n' "$k" "$v" >> "$ENVF"
}
get_env() { grep -E "^$1=" "$ENVF" 2>/dev/null | head -1 | cut -d= -f2-; }
# keep an existing real secret; (re)generate if missing or still a placeholder
ensure_secret() {
  local cur; cur="$(get_env "$1")"
  case "$cur" in ""|changeme*|CHANGE*|*_HERE) set_env "$1" "$(gen)";; esac
}
compose_up() {
  [ "${SKIP_UP:-}" = "1" ] && { echo "[quickstart] SKIP_UP=1 — wrote config only"; return; }
  have docker || die "docker not found — install Docker, or deploy via systemd (see deploy/README.md)"
  ( cd "$HERE/compose" && docker compose "$@" up -d )
}

case "$ROLE" in
  central)
    IP="${2:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
    [ -n "$IP" ] || die "could not detect IP — pass it: ./quickstart.sh central <PUBLIC_IP>"
    [ -f "$ENVF" ] || cp "$HERE/.env.example" "$ENVF"
    ensure_secret BLOCKLIST_TOKEN
    ensure_secret ENROLL_SECRET
    ensure_secret BASIC_AUTH_PASS
    ADMIN="$(get_env BLOCKLIST_TOKEN)"; ENROLL="$(get_env ENROLL_SECRET)"; PASS="$(get_env BASIC_AUTH_PASS)"
    set_env DEPLOY_MODE nginx
    set_env COMPOSE_PROFILES "loki,soc,blocklist"
    set_env LOKI_URL "http://loki:3100"
    set_env BLOCKLIST_API_URL "http://blocklist:8080"
    set_env BLOCKLIST_API_TOKEN "$ADMIN"
    set_env PUBLIC_URL "http://$IP:8080"
    set_env BASIC_AUTH_USER admin
    compose_up --profile loki --profile soc --profile blocklist
    cat <<EOF

────────────────────────────────────────────────────────────────────
✅ Central up.  Dashboard:  http://$IP:8077   (login: admin / $PASS)
   Open firewall to nginx VMs:  3100 (Loki) and 8080 (blocklist).

On EACH nginx VM run (repo cloned there):
   ./deploy/quickstart.sh nginx $IP $ENROLL \$(hostname -s)
────────────────────────────────────────────────────────────────────
EOF
    ;;

  nginx|edge)
    CENTRAL="${2:-}"; ENROLL="${3:-}"; NODE="${4:-$(hostname -s 2>/dev/null || hostname)}"
    [ -n "$CENTRAL" ] && [ -n "$ENROLL" ] || die "usage: ./quickstart.sh nginx <CENTRAL_IP> <ENROLL_SECRET> [NODE_ID]"
    [ -f "$ENVF" ] || cp "$HERE/.env.example" "$ENVF"
    set_env COMPOSE_PROFILES promtail
    set_env LOKI_PUSH_URL "http://$CENTRAL:3100/loki/api/v1/push"
    set_env VM_LABEL "$NODE"
    compose_up --profile promtail
    echo "[quickstart] installing ban agent (self-enroll as '$NODE')…"
    if [ "${SKIP_UP:-}" != "1" ]; then
      curl -fsSL "http://$CENTRAL:8080/install/soc-nginx-agent.sh" \
        | sudo INSECURE=1 BLOCKLIST_API_URL="http://$CENTRAL:8080" \
               ENROLL_SECRET="$ENROLL" NODE_ID="$NODE" bash
    fi
    cat <<EOF

────────────────────────────────────────────────────────────────────
✅ '$NODE' shipping logs + enrolled. It should appear in the «Ноды» tab.
   Two one-time nginx steps on this VM:
     1) log JSON:  cp deploy/nginx/soc-logging.conf /etc/nginx/conf.d/ and add
                   'access_log /var/log/nginx/access.json.log soc_json;'
                   (or keep stock logs: set PROMTAIL_CONFIG=promtail-combined.yml
                    + NGINX_ACCESS_LOG=/var/log/nginx/access.log in deploy/.env)
     2) enable bans: add 'include /etc/nginx/soc-deny-server.conf;' inside server{}
   then:  nginx -t && systemctl reload nginx
────────────────────────────────────────────────────────────────────
EOF
    ;;

  *)
    die "usage: ./quickstart.sh central [PUBLIC_IP]  |  ./quickstart.sh nginx <CENTRAL_IP> <ENROLL_SECRET> [NODE_ID]"
    ;;
esac
