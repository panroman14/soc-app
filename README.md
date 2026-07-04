# SOC Dashboard

*Datadog for nginx bans.* Self-hosted SOC for **nginx / ingress-nginx**: ships logs to Loki,
surfaces attacks, and **bans IPs/paths on Cloudflare, nginx, or Kubernetes ingress** — from one
dashboard. Bilingual UI (EN/RU).

![Logs explorer](docs/screenshots/logs.svg?v=2)
![Auto-ban](docs/screenshots/autoban.svg?v=1)
![403 rules](docs/screenshots/rules-403.svg?v=1)
![System map](docs/screenshots/system-map.svg?v=1)

## What you can do

- **Block the most-scanned paths.** One 403 rule returns `403` for `/wp-login`, `/.env`, `/.git`, jndi… at the nginx/ingress layer, on every site — seed the common scanner set in a click.
- **Wire up auto-bans by condition.** *IF* path hit ≥ N in a window · *IF* rate > N/min · *IF* signature family (SQLi/XSS/RCE) · *IF* country ≠ home → ban to a target group for a TTL. Dry-run shows who'd be hit before you arm it.
- **Investigate traffic, no query language.** Click any path / IP / status in the log explorer to filter; catch 4xx/5xx spikes on the chart.
- **Ban across everything at once.** Group targets (Cloudflare + nginx + ingress); one ban fans out to all of them, per-target failures auto-resync.
- **Pull threat lists.** Spamhaus / Tor / custom IP-CIDR feeds, self-syncing via TTL.
- **Triage attackers.** WAF/CRS offenders with attack families, plus GeoIP / ASN / VPN-Tor reputation — one-click ban.
- **Get told.** Slack / Telegram alerts routed by event × severity.
- **Ask the LLM.** Plain-language insight + anomaly detection; one toggle hides all AI.

## Deploy

Bring up the central stack (Loki + dashboard + ban orchestrator):

```bash
git clone <this-repo> soc && cd soc/deploy
cp .env.example .env && $EDITOR .env        # BASIC_AUTH_*, BLOCKLIST_TOKEN, SECRET_KEY, PUBLIC_URL
cd compose && docker compose --profile loki --profile soc --profile blocklist up -d
```

→ `http://CENTRAL:8077`. Then pick a scenario:

**1) Dashboard only → ban at the edge (Cloudflare / ingress).**
Point it at your Loki (or ship logs to it), then add a **Cloudflare** target (paste the API token in
Settings — the IP List + WAF rule auto-create) or connect a **k8s ingress**. Manage bans, 403 rules
and auto-ban from the GUI — or script them over the API (bash/curl) if you prefer.

**2) Dashboard + nginx targets → ban on nginx.**
Open **Resources → add node** and run the one-liner it shows on each nginx VM. The agent self-enrolls
as an `nginx-file` target, ships logs, and enforces bans locally (writes deny includes, `nginx -t`,
reloads). Fleets: [`deploy/inventory-deploy.sh`](deploy/inventory-deploy.sh).

**3) Mix.** Register several targets and route each ban with **groups** — e.g. auto-ban to Cloudflare,
manual bans to origins, 403 rules everywhere.

Config is hybrid: ENV = defaults, dashboard overrides live (no redeploy); `CONFIG_LOCK=env` freezes it.
Store options: `STORE=sqlite|file` (VMs) or `configmap` (k8s). Full guide + all variables →
**[`deploy/README.md`](deploy/README.md)**.

## Notes

- Set `BLOCKLIST_TOKEN` + `BASIC_AUTH_*` — no token = unauthenticated API.
- Use `PUBLIC_URL=https://…` across untrusted networks (the agent installer runs as root).
- Set `SECRET_KEY` (e.g. `openssl rand -hex 32`) to encrypt GUI-entered secrets (Cloudflare token) at rest with Fernet — key stays in ENV, store keeps only ciphertext; comma-separated keys rotate. Without it they're plaintext (startup warns).

[MIT](LICENSE) © 2026 panroman14
