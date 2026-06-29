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
# Firewall: opt-in (MANAGE_UFW=1). Restrict Loki:3100 + blocklist:8080 to the nginx
# VMs (ALLOW_FROM=<ip/cidr>), dashboard:8077 to you (ADMIN_CIDR=<ip/cidr>). SSH(22) is
# always allowed first so enabling ufw can't lock you out.
setup_ufw() {
  [ "${MANAGE_UFW:-}" = "1" ] || return 0
  have ufw || { echo "[ufw] ufw not installed — skip"; return 0; }
  echo "[ufw] configuring (opt-in via MANAGE_UFW=1)…"
  ufw allow 22/tcp >/dev/null 2>&1 || true
  local DP="${SOC_PORT:-8077}" BP="${BLOCKLIST_PORT:-8080}" LP="${LOKI_PORT:-3100}"
  if [ -n "${ADMIN_CIDR:-}" ]; then ufw allow from "$ADMIN_CIDR" to any port "$DP" proto tcp >/dev/null 2>&1 || true
  else ufw allow "$DP"/tcp >/dev/null 2>&1 || true; fi
  if [ -n "${ALLOW_FROM:-}" ]; then
    ufw allow from "$ALLOW_FROM" to any port "$BP" proto tcp >/dev/null 2>&1 || true
    ufw allow from "$ALLOW_FROM" to any port "$LP" proto tcp >/dev/null 2>&1 || true
    echo "[ufw] Loki:$LP + blocklist:$BP restricted to $ALLOW_FROM"
  else
    ufw allow "$BP"/tcp >/dev/null 2>&1 || true; ufw allow "$LP"/tcp >/dev/null 2>&1 || true
    echo "[ufw] WARNING: $LP/$BP open to ALL — set ALLOW_FROM=<nginx ip/cidr> to lock down"
  fi
  ufw --force enable >/dev/null 2>&1 || true
  echo "[ufw] enabled."
}
compose_up() {
  [ "${SKIP_UP:-}" = "1" ] && { echo "[quickstart] SKIP_UP=1 — wrote config only"; return; }
  if ! have docker; then
    if [ "${INSTALL_DOCKER:-}" = "1" ]; then
      echo "[quickstart] Docker not found — installing via get.docker.com…"
      curl -fsSL https://get.docker.com | sh || die "Docker install failed"
      systemctl enable --now docker 2>/dev/null || true
    else
      die "docker not found — re-run with INSTALL_DOCKER=1 to auto-install it, or install Docker yourself / deploy via systemd (deploy/README.md)"
    fi
  fi
  docker compose version >/dev/null 2>&1 || die "the 'docker compose' plugin is missing — install Docker Compose v2"
  # REBUILD=1 (redeploy of code changes) → rebuild images before starting.
  local build=""; [ "${REBUILD:-}" = "1" ] && build="--build"
  # --env-file: compose interpolates ${VARS} (e.g. PROMTAIL_CONFIG) from the file next
  # to docker-compose.yml by default, NOT from our deploy/.env — point it here explicitly.
  ( cd "$HERE/compose" && docker compose --env-file "$ENVF" "$@" up -d $build )
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
    setup_ufw
    cat <<EOF

────────────────────────────────────────────────────────────────────
✅ Central up.  Dashboard:  http://$IP:8077   (login: admin / $PASS)
   Open firewall to nginx VMs:  3100 (Loki) and 8080 (blocklist).

On EACH nginx VM run (repo cloned there) — last arg is the env/pool (prod, dev…):
   ./deploy/quickstart.sh nginx $IP $ENROLL \$(hostname -s) prod
   (ноды одного env банятся вместе и используют его CF-токен / правила / уведомления)
────────────────────────────────────────────────────────────────────
EOF
    ;;

  nginx|edge)
    CENTRAL="${2:-}"; ENROLL="${3:-}"; NODE="${4:-$(hostname -s 2>/dev/null || hostname)}"; ENV="${5:-}"
    [ -n "$CENTRAL" ] && [ -n "$ENROLL" ] || die "usage: ./quickstart.sh nginx <CENTRAL_IP> <ENROLL_SECRET> [NODE_ID] [ENV]"
    [ -f "$ENVF" ] || cp "$HERE/.env.example" "$ENVF"
    set_env COMPOSE_PROFILES promtail
    set_env LOKI_PUSH_URL "http://$CENTRAL:3100/loki/api/v1/push"
    set_env VM_LABEL "$NODE"
    set_env ENV_LABEL "$ENV"             # logs labelled env=<ENV> → dashboard env switcher
    # Default to reading the STOCK nginx combined log → works with zero nginx changes.
    # (For richer fields — host, real client IP, timings — switch to soc_json: see the
    #  note printed below, then set PROMTAIL_CONFIG=promtail.yml + the .json.log path.)
    set_env PROMTAIL_CONFIG promtail-combined.yml
    set_env NGINX_ACCESS_LOG /var/log/nginx/access.log
    compose_up --profile promtail
    echo "[quickstart] installing ban agent (self-enroll as '$NODE')…"
    if [ "${SKIP_UP:-}" != "1" ]; then
      curl -fsSL "http://$CENTRAL:8080/install/soc-nginx-agent.sh" \
        | sudo INSECURE=1 BLOCKLIST_API_URL="http://$CENTRAL:8080" \
               ENROLL_SECRET="$ENROLL" NODE_ID="$NODE" GROUP="$ENV" bash
    fi
    cat <<EOF

────────────────────────────────────────────────────────────────────
✅ '$NODE' shipping logs (stock nginx combined — no nginx change), enrolled, and
   bans auto-enabled (the installer added the deny include to your server block(s)
   and reloaded nginx). Requests show on the dashboard shortly.
   • If you DON'T want the installer touching nginx, re-run the agent install with
     MANAGE_NGINX=0 and add 'include /etc/nginx/soc-deny-server.conf;' yourself.
   • Optional richer data (host / real client IP / timings): cp
     deploy/nginx/soc-logging.conf to /etc/nginx/conf.d/, add
     'access_log /var/log/nginx/access.json.log soc_json;', and in deploy/.env set
     PROMTAIL_CONFIG=promtail.yml + NGINX_ACCESS_LOG=/var/log/nginx/access.json.log.
────────────────────────────────────────────────────────────────────
EOF
    ;;

  *)
    die "usage: ./quickstart.sh central [PUBLIC_IP]  |  ./quickstart.sh nginx <CENTRAL_IP> <ENROLL_SECRET> [NODE_ID]"
    ;;
esac
