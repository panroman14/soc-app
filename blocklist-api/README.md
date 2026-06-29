# blocklist-api (Helm, no image build)

Tiny in-cluster service that lets the soc dashboard block/unblock IPs &
subnets on ingress-nginx — **semi-automatic** (a human clicks "Заблокировать").

**No Docker build:** the app source ships inside a ConfigMap, runs on the stock
`python:3.11-slim` image, and an initContainer pip-installs deps into a shared
volume at pod start. Deployed with Helm.

## How it works

```
dashboard (198.51.100.20, вне кластера)
   │  POST /api/block  (Basic-auth дашборда)
   ▼
soc backend  ──Bearer──►  blocklist-api (in-cluster)
                                   │ 1. validate (allowlist, CIDR, prefix)
                                   │ 2. write soc-denylist CM (source of truth + TTL + audit)
                                   │ 3. render geo → patch ingress-nginx-controller CM
                                   ▼
                              ingress-nginx watches its CM → graceful reload → 403
```

It **owns** two keys in `ingress-nginx-controller`: `http-snippet`
(`geo $soc_blocked {…}`) and `server-snippet` (`if ($soc_blocked){return 403;}`).
Don't hand-edit them. The denylist data lives in the `soc-denylist` ConfigMap
(api self-creates it, so `helm upgrade` never resets your bans).

## Safety rails (`app/safety.py`)
- Never blocks an allowlisted IP (office `192.0.2.10`, monitoring VMs) — or any CIDR covering one.
- Refuses `0.0.0.0/0` and prefixes broader than `/16` (v4) without `force=true`.
- Validates/normalizes CIDR, collapses overlaps, TTL auto-expiry, full audit log.

## Deploy (Helm)

From `blocklist-api/`:

```bash
TOKEN=$(openssl rand -hex 32); echo "save this: $TOKEN"

helm upgrade --install blocklist-api . \
  -n soc --create-namespace \
  --set token="$TOKEN" \
  --set ingress.host=block-api.example.com

kubectl -n soc rollout status deploy/blocklist-api
```

Key `values.yaml` knobs: `controllerNamespace`/`controllerConfigMap`
(ingress-nginx CM to patch), `ingress.host`, `ingress.whitelistSourceRange`
(default 198.51.100.20/32), `ingress.tls.*` (cert-manager), `allowlist`, `pipPackages`.
Reuse an existing token Secret with `--set existingSecret=<name>` instead of `token`.

Then point the dashboard at it (on 198.51.100.20, systemd drop-in):
```
BLOCKLIST_API_URL=https://block-api.example.com
BLOCKLIST_API_TOKEN=<same TOKEN>
```
`systemctl restart soc` → the "Денлист" panel + ⛔ buttons light up.

## Smoke test (no dashboard)
```bash
kubectl -n soc port-forward deploy/blocklist-api 8080:8080 &
curl -s localhost:8080/healthz
curl -s -XPOST localhost:8080/block -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"cidr":"203.0.113.7","reason":"test","ttl":300}'
POD=$(kubectl get pod -n ingress-nginx -l app.kubernetes.io/component=controller -o name | head -1)
kubectl exec -n ingress-nginx $POD -- grep 203.0.113.7 /etc/nginx/nginx.conf   # должно найтись
curl -s -XPOST localhost:8080/unblock -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"cidr":"203.0.113.7"}'
```

## Notes
- Enforcement is at ingress (real client IP), **not** cloud firewall — behind the
  LB the node sees the LB IP, not the client.
- `geo` change → graceful nginx reload. Fine at low traffic; for zero-reload / full
  auto-ban later, switch to lua-shared-dict or external-auth + Redis.
- `requirements.txt` is kept only for local dev/tests; in-cluster deps come from
  `pipPackages` in `values.yaml`.
- Needs egress to PyPI at pod start (for the initContainer). If your cluster has no
  internet egress, switch back to a prebuilt image.
