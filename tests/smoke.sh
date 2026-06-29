#!/usr/bin/env bash
# soc — end-to-end smoke test for blocklist-api: auth scopes, node enrollment,
# group-routed bans, auto-promotion, and per-node snippet pull. No Kubernetes /
# Cloudflare / nginx needed (STORE=file, enforcement degrades to noop/agent-pull).
#
#   ./tests/smoke.sh
#
# Exits non-zero on the first failed assertion. Safe to run repeatedly.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API_DIR="$ROOT/blocklist-api"
PORT="${PORT:-8137}"
BASE="http://127.0.0.1:$PORT"
TMP="$(mktemp -d)"
ADMIN=admin-smoke
ENROLL=enroll-smoke
PUB="$BASE"

PY="$API_DIR/.venv/bin/python"
if [ ! -x "$PY" ]; then
  echo "[smoke] creating venv…"
  python3 -m venv "$API_DIR/.venv"
  "$API_DIR/.venv/bin/pip" -q install -r "$API_DIR/requirements.txt" 2>/dev/null || \
    "$API_DIR/.venv/bin/pip" -q install fastapi 'uvicorn[standard]' httpx
fi

pass=0; fail=0
check() { # check <desc> <actual> <expected>
  if [ "$2" = "$3" ]; then echo "  ✓ $1"; pass=$((pass+1));
  else echo "  ✗ $1 — got [$2] want [$3]"; fail=$((fail+1)); fi
}
jget() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }

echo "[smoke] starting blocklist-api on :$PORT (STORE=file $TMP)"
STORE=file STORE_DIR="$TMP/store" BLOCKLIST_TOKEN="$ADMIN" ENROLL_SECRET="$ENROLL" PUBLIC_URL="$PUB" \
  "$API_DIR/.venv/bin/uvicorn" app.main:app --app-dir "$API_DIR" --host 127.0.0.1 --port "$PORT" --log-level warning &
SRV=$!
trap 'kill $SRV 2>/dev/null || true; rm -rf "$TMP"' EXIT
for i in $(seq 1 30); do curl -fsS "$BASE/healthz" >/dev/null 2>&1 && break; sleep 0.3; done

AH="Authorization: Bearer $ADMIN"; EH="Authorization: Bearer $ENROLL"; JH="Content-Type: application/json"

echo "[auth]"
check "healthz open" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/healthz")" "200"
check "installer public" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/install/soc-nginx-agent.sh")" "200"
check "nodes needs auth" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/nodes")" "401"
check "nodes admin ok" "$(curl -s -o /dev/null -w '%{http_code}' -H "$AH" "$BASE/nodes")" "200"

echo "[enroll]"
NTOK="$(curl -s -XPOST "$BASE/enroll" -H "$EH" -H "$JH" -d '{"node_id":"web1","group":"origins"}' | jget "d['token']")"
check "got node token" "$([ -n "$NTOK" ] && echo yes)" "yes"
NH="Authorization: Bearer $NTOK"
check "bad enroll secret 401" "$(curl -s -o /dev/null -w '%{http_code}' -XPOST "$BASE/enroll" -H 'Authorization: Bearer nope' -H "$JH" -d '{"node_id":"x"}')" "401"

echo "[scope]"
check "node cannot block" "$(curl -s -o /dev/null -w '%{http_code}' -XPOST "$BASE/block" -H "$NH" -H "$JH" -d '{"cidr":"1.2.3.4/32"}')" "401"
check "node heartbeat ok" "$(curl -s -o /dev/null -w '%{http_code}' -XPOST "$BASE/heartbeat" -H "$NH" -H "$JH" -d '{"metrics":{"load1":0.2}}')" "200"

echo "[group ban + auto-promotion]"
TGTS="$(curl -s -XPOST "$BASE/block" -H "$AH" -H "$JH" -d '{"cidr":"45.137.21.9/32","group":"origins"}' | jget "','.join(d['targets'])")"
check "ban routed to enrolled node" "$TGTS" "web1"
SNIP="$(curl -s "$BASE/nginx_snippet" -H "$NH" | jget "str(d['count'])+'|'+('45.137.21.9' in d['http'] and 'Y' or 'N')")"
check "node pulls its CIDR" "$SNIP" "1|Y"

echo "[settings]"
check "set CF token (secret)" "$(curl -s -XPOST "$BASE/settings" -H "$AH" -H "$JH" -d '{"updates":{"CF_API_TOKEN":"tok123"}}' | jget "d['ok']")" "True"
check "secret redacted on read" "$(curl -s "$BASE/settings" -H "$AH" | jget "d['settings']['CF_API_TOKEN'].get('set') and 'value' not in d['settings']['CF_API_TOKEN']")" "True"

echo
echo "[smoke] $pass passed, $fail failed"
[ "$fail" -eq 0 ]
