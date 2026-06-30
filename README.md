# SOC Dashboard

Self-hosted, AI-assisted SOC for **nginx / ingress-nginx** traffic. It ships access
& error logs into Loki, aggregates attack/traffic signals, runs them through a local
LLM (Gemma on Ollama) for plain-language insight + robust anomaly detection, serves a
web dashboard with Prometheus metrics, and **applies IP/path bans to one or more
enforcement targets — Cloudflare, plain nginx, or Kubernetes ingress-nginx — routed
by group.**

Think *Datadog for nginx bans*: stand up one central collector, then drop a one-line
agent onto each nginx VM — it self-enrolls, appears in the **Nodes** tab with live host
load, and starts enforcing bans. Almost everything is configurable from the dashboard
(**Settings**), with environment variables as the defaults underneath. The UI is
English by default with a one-click **RU/EN** toggle.

**Highlights**

- 🎯 **Grouped, multi-target enforcement** — Cloudflare (IP list + WAF) · plain nginx · ingress-nginx, routed per ban by **target group** (built in a GUI).
- 🌐 **Environments** — each environment is its own bundle: nodes, Cloudflare token, Loki, rules and alert channels; switch in the top bar.
- ⛔ **Auto-ban engine** — rules by path / regex / signature-family / **request-rate** / **country (GeoIP)**, with dry-run preview before you arm it.
- 📡 **Threat-intel feeds** — import Spamhaus / Tor / custom IP-CIDR lists into a ban group (self-syncing via TTL).
- 🚫 **403 path rules** — block scanner paths at the nginx/ingress layer, scoped per target group.
- 🛡️ **WAF / CRS panel** — per-IP OWASP ModSecurity offenders with attack-family chips and one-click ban.
- 🔎 **IP intelligence** — GeoIP flag, ASN/org, datacenter/VPN/Tor reputation in the IP profile drawer.
- 🔔 **Notifications** — Slack / Telegram, with per-event × env × severity routing rules.
- 🤖 **LLM analyst** — insights + suspect triage; a global toggle hides every AI mention when off.

```
 nginx VM(s)                              central VM
┌────────────────────┐                  ┌─────────────────────────────────────┐
│ nginx (json/comb.) │── logs ──push───►│ Loki  ◄── all promtails push          │
│ promtail           │                  │ soc-backend  (Loki→LLM→dashboard→/metrics)
│ soc-nginx-agent    │── enroll/beat ──►│ blocklist-api  (ban orchestrator)     │
│   ▲ pulls denylist │◄── /nginx_snippet┤        │                              │
└───┼────────────────┘                  └────────┼──────────────────────────────┘
    │  local nginx 403                           ├─► Cloudflare API (IP List + WAF)
    └────────────────────────────────────────────┴─► ingress-nginx ConfigMap (k8s)
```

Universal by design — the same code runs in **Kubernetes** (ConfigMap store +
ingress-nginx enforcement) and on **plain VMs** (file/sqlite store + local nginx
and/or Cloudflare). You enable only the pieces your topology needs.

---

## Quickstart (Docker, plain VMs)

**1. Central VM** — Loki + dashboard + ban orchestrator:

```bash
git clone <this-repo> soc && cd soc/deploy
cp .env.example .env && $EDITOR .env       # set tokens + PUBLIC_URL (see below)
cd compose
docker compose --profile loki --profile soc --profile blocklist up -d
```

Open `http://CENTRAL:8077` (dashboard). Set `BASIC_AUTH_USER/PASS` for real use.

**2. Each nginx VM** — open **🖥️ Ноды → + Добавить ноду** in the dashboard and run the
one-liner it shows:

```bash
curl -fsSL http://CENTRAL:8080/install/soc-nginx-agent.sh \
  | sudo BLOCKLIST_API_URL=http://CENTRAL:8080 ENROLL_SECRET=*** bash
```

The agent self-enrolls, gets its **own per-node token**, ships logs (if you also run
Promtail there), reports CPU/RAM/load, and applies bans. For a fleet, use
[`deploy/inventory-deploy.sh`](deploy/inventory-deploy.sh) to push to many hosts over SSH.

Full deployment guide (Docker profiles · bare systemd · Kubernetes · mixing):
**[`deploy/README.md`](deploy/README.md)**.

---

## Choose your topology

| You want to… | Set this |
|---|---|
| **Ban in Cloudflare**, logs from VMs | `STORE=sqlite`, add a `cloudflare` target (token in **Настройки**), run Promtail on each nginx VM |
| **Ban in local nginx** on each VM | enroll nodes (auto-promoted to `nginx-file` targets); the agent renders + reloads nginx |
| **Kubernetes ingress-nginx** | `STORE=configmap`, `ENFORCE=ingress-cm`; bans render into the controller ConfigMap |
| **Read an existing Loki, ban in Cloudflare** | point `LOKI_URL` at your Loki, skip Promtail; one `cloudflare` target |
| **Several of the above at once** | define multiple `BAN_TARGETS` and route with **groups** (below) |

---

## Bans: targets + groups

A **target** is where a ban is applied. Types:

- **`cloudflare`** — CF API. You provide only the API **token**; the IP List + WAF
  custom rule (`ip.src in $list`) are **auto-created** on the first ban (modes
  `ip-list` or `access-rules`). Verify with **Settings → Check connection**.
  Optional `CF_EDGE_PATHS=on` also blocks the 403 scanner paths routed to this target
  at the CF **edge** via a managed WAF rule (needs a CF plan with WAF `matches`; off by
  default — IP-only otherwise).
- **`nginx-file`** — a plain nginx VM. The enrolled `soc-nginx-agent` pulls
  `GET /nginx_snippet`, writes deny includes, runs `nginx -t`, reloads (rolls back on
  failure). **Enrolled nodes become `nginx-file` targets automatically.**
- **`ingress-cm`** — Kubernetes: renders into the ingress-nginx controller ConfigMap.
- **`noop`** — store only (state served via `/list`; enforced out-of-band).

A **group** maps a name to a subset of targets. Every ban carries a `group` → applied
to exactly those targets. No group → `BAN_GROUP_DEFAULT`; an unknown group → **all**
targets (safe maximum). Per-target failures are isolated — a Cloudflare blip never
loses a ban; the periodic resync re-applies it.

```jsonc
BAN_TARGETS = [{"id":"edge-cf","type":"cloudflare","mode":"ip-list"},
               {"id":"web1","type":"nginx-file"},
               {"id":"k8s","type":"ingress-cm"}]
BAN_GROUPS  = {"default":["edge-cf"], "origins":["web1"], "all":["edge-cf","web1","k8s"]}
```

These (and the CF token, ingress ConfigMap name, LLM endpoint, …) are editable from
the dashboard — see Configuration. The **target-group builder** (Auto-ban view) lets
you create groups and assign targets visually; the auto-ban rule form, the 403 rule
form, and the manual-ban panel all expose a group selector.

---

## Detection & response

| Capability | Where | What it does |
|---|---|---|
| **Auto-ban rules** | Auto-ban | Ban IPs that match a condition ≥ N times over a window. Condition types: `path contains` · `regex` · `signature family` (scanner/payload) · **`rate`** (any path) · optional **status** and **country (GeoIP)** filters. Each rule targets a group + a ban TTL. Disarmed by default — **dry-run preview** shows who *would* be banned before you arm it. |
| **403 path rules** | 403 rules | Return `403` for scanner/exploit paths (`/.env`, `/wp-login`, jndi…) at the **nginx / ingress** layer across all domains. Rendered per **target group** (Cloudflare is IP-only and never gets path rules). A live "where it applies" list shows the affected targets. |
| **Threat-intel feeds** | Auto-ban → Threat feeds | Periodically fetch external block lists (Spamhaus DROP, Tor exit nodes, custom IP/CIDR) and ban them into a chosen group. Self-syncing: entries re-banned each cycle with a multi-cycle TTL, so a dropped entry simply expires. |
| **WAF / CRS triggers** | Overview | Per-IP OWASP ModSecurity offenders ("Inbound Anomaly Score Exceeded") with the attack families each tripped (SQLi/XSS/RCE/LFI/…) and a one-click ban. |
| **Anomaly detection** | Overview / alerts | Rolling **robust baseline** (median + MAD modified z-score) over snapshot history — a metric flags only when it clears a floor *and* is a statistically significant outlier, cutting false alarms on bursty traffic. |
| **IP intelligence** | IP profile drawer | GeoIP flag + city/country, ASN/org/ISP, and a datacenter/VPN/Tor **reputation** verdict (ip-api.com, cached). Surfaced on ban candidates, suspects, and the country map too. |
| **Notifications** | Settings → Notifications | Slack & Telegram channels + routing rules (event × environment × min-severity → channel), with a per-channel test. |

---

## Configuration — hybrid ENV + GUI

Operational config follows a simple rule:

- **ENV** seeds the defaults (good for declarative / GitOps deploys).
- The **dashboard (⚙️ Настройки)** overrides them at runtime and persists the override
  in the store — no redeploy. Editable: Cloudflare token/zone/mode, ingress ConfigMap
  namespace+name, ban targets/groups, default group, LLM endpoint + model.
- Set **`CONFIG_LOCK=env`** to freeze this: the GUI becomes read-only and ENV is the
  single source of truth.

**Where do tokens go?** Bootstrap secrets that gate the service stay in ENV
(`BLOCKLIST_TOKEN` admin token, `BASIC_AUTH_*` dashboard auth, `ENROLL_SECRET`).
Operational secrets like the **Cloudflare token** can be typed into the GUI (stored
write-only — never shown back) *or* provided via ENV. The **LLM endpoint** (e.g. your
Ollama IP) is just a setting — change it in the GUI any time.

> Security note: GUI-entered secrets are persisted in the `STORE` backend in
> plaintext. On Kubernetes with `STORE=configmap` that means a ConfigMap (not a
> Secret) — there, prefer providing the CF token via ENV + `CONFIG_LOCK=env`, or use a
> file/sqlite store on a restricted volume.

---

## Logs: JSON or stock `combined`

The backend parses one canonical field set. Two ways to feed it:

- **`soc_json`** (recommended) — install [`deploy/nginx/soc-logging.conf`](deploy/nginx/soc-logging.conf)
  and point a site at it. Carries host, X-Forwarded-For, real CF client IP, and timings.
- **stock `combined`** — no nginx change. Set `PROMTAIL_CONFIG=promtail-combined.yml`;
  Promtail parses the default access line and re-emits it as the same JSON shape at the
  edge. (combined lacks host / XFF / CF-IP / timings — those fields come through empty.)

## Node enrollment & visibility

- One **`ENROLL_SECRET`** lets agents self-register; each then authenticates with its
  own **per-node token** (least privilege — a node token can only pull *its* snippet
  and post *its* heartbeat, never block/unblock).
- The **Nodes** tab shows every node: online/offline, CPU load, RAM, uptime, bans
  applied, and an `nginx -t ✗` badge if its config is broken. **Revoke** kills a
  node's token instantly. The dashboard host itself appears as a `dashboard` node.
- A node joins an **environment** at install time (`--env`). An environment bundles its
  nodes with their own Cloudflare token, Loki source, rules, and alert channels —
  switch between them from the top-bar selector.

---

## Components

| Component | Role |
|-----------|------|
| **promtail** | tails nginx logs on each VM → pushes to central Loki |
| **Loki** | central log store (single-binary VM, or your existing k8s Loki) |
| **soc backend** (`backend/`) | Loki aggregator + LLM insight + dashboard + `/metrics` + auto-ban executor |
| **blocklist-api** (`blocklist-api/`) | ban orchestrator + node registry; fans bans to targets by group |
| **soc-nginx-agent** (`deploy/agent/`) | on each nginx VM: enroll, heartbeat, pull denylist, render + reload nginx |

## Backend (dev run)

```bash
cd backend
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt
./.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8077
```

Key endpoints — `GET /metrics` · `GET /api/summary` · `GET /api/insights` ·
`GET /api/status` · `GET /api/nodes[/install]` · `POST /api/nodes/delete` ·
`GET|POST /api/settings` · `GET|POST /api/environments` · `GET|POST /api/notify_config` ·
`GET /api/ban_targets[/check]` · `POST /api/block[_bulk]` ·
`GET|POST /api/autoban/rules` · `GET /api/ban_candidates` · `GET /api/crs_offenders` ·
`GET|POST /api/threat_feeds[/refresh]` · `GET|POST /api/path_rules` ·
LLM switch `GET /api/llm` · `POST /api/llm/toggle`.

The common variables are documented in **[`deploy/.env.example`](deploy/.env.example)**;
advanced tunables (intervals, ASN/Tor lookups, safety prefixes) read sane defaults
straight from `backend/app/config.py` and `blocklist-api/app/config.py`.

## Status

- [x] LLM insights + robust (MAD/z-score) anomaly detection, dashboard, `/metrics`, HTTP Basic auth, LLM on/off.
- [x] VM deployment: nginx logs → Promtail → Loki; modular Docker/systemd; combined-log support.
- [x] Pluggable denylist storage (configmap / file / sqlite).
- [x] Pluggable, grouped ban enforcement (ingress-cm / nginx-file / cloudflare); Cloudflare auto-setup; GUI group builder.
- [x] Node enrollment (per-node tokens), heartbeat/host-load, **Nodes** tab, one-liner + fleet installer.
- [x] Hybrid ENV+GUI config (**Settings**), `CONFIG_LOCK`, auto-promotion of enrolled nodes to targets.
- [x] Multi-environment model (per-env CF token / Loki / rules / channels), top-bar switcher.
- [x] Auto-ban rules: path / regex / family / **rate** / **country (GeoIP)**, per-rule group + TTL, dry-run preview.
- [x] 403 path rules scoped per target group; threat-intel feed import; WAF/CRS offender panel with one-click ban.
- [x] GeoIP/ASN/reputation IP profiles; Slack/Telegram notifications with routing rules.
- [x] Bilingual UI (EN default + RU toggle), in-app dialogs, customizable/collapsible cards.

## Security notes

- Set `BLOCKLIST_TOKEN` and `BASIC_AUTH_*`. With no token the API is **unauthenticated**
  (it logs a loud warning on startup) — fine for a laptop, not for anything reachable.
- The agent installer downloads + runs code as **root**; over plaintext HTTP a MITM is
  remote root. The installer refuses non-HTTPS unless `INSECURE=1`. Use HTTPS
  (`PUBLIC_URL=https://…`) for anything crossing an untrusted network.
- Node agents authenticate with their own scoped token (pull their snippet + heartbeat
  only — never ban). Revoke a node in the **Ноды** tab to kill its token.
- GUI-entered secrets (e.g. the Cloudflare token) are stored in the `STORE` backend in
  plaintext. On Kubernetes with `STORE=configmap` that is a ConfigMap, not a Secret —
  prefer the CF token via ENV + `CONFIG_LOCK=env`, or a file/sqlite store on a
  restricted volume.

## License

[MIT](LICENSE) © 2026 panroman14.
