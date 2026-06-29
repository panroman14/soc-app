# soc — deployment

Modular on purpose: ship the **whole stack with Docker**, ship **only Promtail**
to an nginx box, or install **bare systemd** — same config vars everywhere
(`deploy/.env` is the single source of truth; systemd hosts get a per-component
slice of it under `/etc/soc/*.env`).

```
nginx VM(s)                         central VM
┌───────────────────┐               ┌──────────────────────────────┐
│ nginx (json/comb) │   logs        │ Loki  ← all promtails push     │
│ promtail ─────────┼──────push────►│ soc-backend (Loki→LLM→UI)      │
│ soc-nginx-agent   │◄──pull────────┤ blocklist-api → Cloudflare/... │
│   enroll/heartbeat├──────────────►│   node registry → «Ноды» tab   │
└───────────────────┘               └──────────────────────────────┘
```

## Easiest: `quickstart.sh` (just give the IP)

Clone the repo on both VMs, then:

```bash
# on the dashboard VM (central) — generates secrets + .env, brings it all up
./deploy/quickstart.sh central <CENTRAL_IP>
#   → prints the dashboard URL + login, and the exact line to run on nginx VMs:

# on each nginx VM — ships logs + installs the ban agent (self-enroll)
./deploy/quickstart.sh nginx <CENTRAL_IP> <ENROLL_SECRET> [NODE_ID]
```

Re-running is safe (keeps existing secrets). `SKIP_UP=1` writes config without
starting containers. Bans default to local nginx; for Cloudflare set
`DEPLOY_MODE=cloudflare` and add the token in **⚙️ Настройки**. The two one-time nginx
steps (log format + `include`) are printed at the end. Everything below is the manual
equivalent if you want finer control.

## 0. One-time: nginx logs

**Recommended — soc_json** (full fields: host, XFF, CF client IP, timings):

```bash
cp deploy/nginx/soc-logging.conf /etc/nginx/conf.d/soc-logging.conf
# in the server/http block:  access_log /var/log/nginx/access.json.log soc_json;
nginx -t && systemctl reload nginx
```

The field names in `soc-logging.conf` are what the backend's `loki.py` parses —
don't rename them without updating that file.

**Or keep the stock `combined` log** (no nginx change): set
`PROMTAIL_CONFIG=promtail-combined.yml` and `NGINX_ACCESS_LOG=/var/log/nginx/access.log`
— Promtail normalizes the line into the same JSON shape at the edge.

## A. Docker (pick profiles per host)

```bash
cp deploy/.env.example deploy/.env && $EDITOR deploy/.env
cd deploy/compose

# central collector
docker compose --profile loki --profile soc --profile blocklist up -d
# an nginx edge VM (Promtail only)
docker compose --profile promtail up -d
# everything on one box
COMPOSE_PROFILES=loki,promtail,soc,blocklist docker compose up -d
```

Profiles: `loki`, `promtail`, `soc`, `blocklist`. Anything not selected isn't created.

## B. Bare systemd (no Docker)

Each component reads `/etc/soc/<name>.env` (copy the matching `*.env.example`).

```bash
# nginx VM — Promtail only
install -m755 promtail /usr/local/bin/promtail
mkdir -p /etc/soc && cp deploy/promtail/promtail.yml /etc/soc/
cp deploy/promtail/promtail.env.example /etc/soc/promtail.env   # edit
cp deploy/promtail/promtail.service /etc/systemd/system/
systemctl enable --now promtail

# central VM — Loki
install -m755 loki /usr/local/bin/loki
cp deploy/loki/loki-config.yml /etc/soc/
cp deploy/loki/loki.env.example /etc/soc/loki.env
cp deploy/loki/loki.service /etc/systemd/system/
systemctl enable --now loki

# central VM — soc backend (see project README for the venv build)
# Layout matters: soc.service runs from /opt/soc/backend and serves the dashboard
# from /opt/soc/frontend (sibling). Copy BOTH, or the API starts with no UI.
mkdir -p /opt/soc
cp -r backend /opt/soc/backend
cp -r frontend /opt/soc/frontend
python3 -m venv /opt/soc/backend/.venv
/opt/soc/backend/.venv/bin/pip install -r /opt/soc/backend/requirements.txt
cp deploy/soc.env.example /etc/soc/soc.env   # edit
cp deploy/soc.service /etc/systemd/system/
systemctl enable --now soc

# nginx VM — soc-nginx-agent: just use the one-liner (see § Nodes) — no manual unit.
```

## Nodes (Datadog-style enroll)

The easiest install on each nginx VM is the dashboard one-liner (**🖥️ Ноды → +
Добавить ноду**), which the installer at `GET /install/soc-nginx-agent.sh` backs:

```bash
curl -fsSL http://CENTRAL:8080/install/soc-nginx-agent.sh \
  | sudo BLOCKLIST_API_URL=http://CENTRAL:8080 ENROLL_SECRET=*** \
         NODE_ID=web1 GROUP=origins bash
```

It downloads the agent, writes `/etc/soc/agent.env` (0600), installs + starts the
systemd unit. The agent **self-enrolls** with `ENROLL_SECRET`, receives its own
per-node token, and the node appears in **Ноды** with live CPU/RAM/load. An enrolled
node is **auto-promoted to an `nginx-file` target** (joining `GROUP`), so it starts
enforcing without editing `BAN_TARGETS`.

Requirements on the central side: `ENROLL_SECRET` and `PUBLIC_URL` (the address VMs
reach blocklist-api at) must be set.

**Fleet rollout** — push to many hosts over SSH from your machine:

```bash
export BLOCKLIST_API_URL=http://CENTRAL:8080 ENROLL_SECRET=***
deploy/inventory-deploy.sh hosts.txt        # one "user@host [NODE_ID] [GROUP]" per line
```

The agent pulls `GET /nginx_snippet`, writes `/etc/nginx/conf.d/soc-deny.conf`
(auto-included) + a server file, runs `nginx -t`, reloads — rolling back if the test
fails (nginx never breaks on a bad render). One-time, include the server file inside
each `server{}` block, then reload nginx:

```nginx
include /etc/nginx/soc-deny-server.conf;
```

## Mixing modes

The pieces only talk over HTTP, so modes mix freely — e.g. Loki + soc in Docker on
the central VM, Promtail via systemd on each nginx host. Just make `LOKI_PUSH_URL`
/ `LOKI_URL` / `BLOCKLIST_API_URL` point at reachable addresses (not `localhost`
across hosts).

| Var | Who needs it | Notes |
|-----|--------------|-------|
| `LOKI_PUSH_URL` | Promtail | central Loki `/loki/api/v1/push` |
| `LOKI_URL` | soc backend | central Loki base URL |
| `VM_LABEL` | Promtail | unique per nginx host |
| `NGINX_LOG_APP` / `INGRESS_SELECTOR` | both | must agree (`ingress-nginx`) |
| `BLOCKLIST_API_URL` / `_TOKEN` | soc ↔ blocklist | shared token |
