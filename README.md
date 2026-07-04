# SOC Dashboard

*Datadog for nginx bans.* Self-hosted SOC for **nginx / ingress-nginx**: ships logs to Loki,
surfaces attacks, and **bans IPs/paths on Cloudflare, nginx, or Kubernetes ingress** — from one
dashboard. Bilingual UI (EN/RU).

![Logs explorer](docs/screenshots/logs.svg?v=2)

## What it does

- **Log explorer** — click paths/IPs/status to filter, traffic chart with 4xx/5xx. No query language.
- **Bans everywhere** — Cloudflare · nginx · ingress, grouped per rule, auto-resynced.
- **Auto-ban** — by path / regex / rate / country, with dry-run before arming.
- **403 rules** — block scanner paths (`/.env`, `/wp-login`) at the edge.
- **Threat feeds** — Spamhaus / Tor / custom lists, self-syncing.
- **WAF/CRS + IP intel** — ModSecurity offenders, GeoIP, ASN, VPN/Tor reputation.
- **LLM analyst** — plain-language insight + anomaly detection (toggle off anytime).
- **Alerts** — Slack / Telegram routing.

**403 path rules** — return `403` for scanner paths at the nginx/ingress layer; attach each rule to any targets, toggle on/off, star a default.

![403 rules](docs/screenshots/rules-403.svg?v=1)

## Deploy

**Central** (Loki + dashboard + bans):

```bash
git clone <this-repo> soc && cd soc/deploy
cp .env.example .env && $EDITOR .env        # BASIC_AUTH_*, BLOCKLIST_TOKEN, PUBLIC_URL
cd compose && docker compose --profile loki --profile soc --profile blocklist up -d
```

→ `http://CENTRAL:8077`. Then **Resources → add node** and run the one-liner on each nginx VM
(self-enrolls, ships logs, applies bans). Fleets: [`deploy/inventory-deploy.sh`](deploy/inventory-deploy.sh).

**Pick your setup** — same code, enable only what you need:

| Want | Set |
|---|---|
| Ban in **Cloudflare** | `STORE=sqlite` + a `cloudflare` target (token in Settings) |
| Ban in **local nginx** | enroll nodes → auto `nginx-file` targets |
| **Kubernetes** ingress | `STORE=configmap`, `ENFORCE=ingress-cm` |
| **Existing Loki** | point `LOKI_URL` at it, skip Promtail |
| **Mix** | multiple `BAN_TARGETS` + `groups` |

Config is hybrid: ENV = defaults, dashboard overrides live (no redeploy); `CONFIG_LOCK=env` freezes it.
Full guide + all variables → **[`deploy/README.md`](deploy/README.md)**.

## Notes

- Set `BLOCKLIST_TOKEN` + `BASIC_AUTH_*` — no token = unauthenticated API.
- Use `PUBLIC_URL=https://…` across untrusted networks (agent installer runs as root).
- Set `SECRET_KEY` to encrypt GUI-entered secrets (Cloudflare token) at rest — the key stays in ENV, the store keeps only ciphertext. Without it they're plaintext (startup warns).

[MIT](LICENSE) © 2026 panroman14
