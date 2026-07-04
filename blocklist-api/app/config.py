"""blocklist-api configuration (env-overridable).

Universal: runs in Kubernetes (ConfigMap store + ingress-cm enforcement) and on a
plain VM (file/sqlite store + nginx-file/cloudflare/noop enforcement). State and
enforcement are independent (see storage.py / enforce.py).
"""
import json
import os


def _env(name, default):
    v = os.environ.get(name)
    return v if v not in (None, "") else default


# Hybrid config: ENV values below are DEFAULTS the dashboard can override at runtime
# (stored in the settings doc — see settings.py). Set CONFIG_LOCK=env to freeze that:
# overrides are ignored and ENV is the single source of truth (declarative / GitOps).
CONFIG_LOCK = _env("CONFIG_LOCK", "").strip().lower() in ("1", "true", "env", "yes", "lock")


def _env_json(name, default):
    raw = os.environ.get(name)
    if raw in (None, ""):
        return default
    try:
        return json.loads(raw)
    except Exception as e:
        raise RuntimeError("%s must be valid JSON: %s" % (name, e))


# --- DEPLOY_MODE: one knob that picks sane STORE/ENFORCE defaults for a topology.
# It only sets DEFAULTS — any explicit STORE/ENFORCE/BAN_TARGETS env still wins, so
# advanced users keep full control. Leave empty for the classic per-var behavior.
#   k8s        → STORE=configmap, ENFORCE=ingress-cm   (Kubernetes ingress-nginx)
#   cloudflare → STORE=sqlite,    ENFORCE=cloudflare    (ban via CF API; set CF_API_TOKEN)
#   nginx      → STORE=sqlite,    ENFORCE=noop          (plain nginx; enrolled agents enforce)
DEPLOY_MODE = _env("DEPLOY_MODE", "").strip().lower()
_MODE_DEFAULTS = {
    "k8s":        {"store": "configmap", "enforce": "ingress-cm"},
    "kubernetes": {"store": "configmap", "enforce": "ingress-cm"},
    "cloudflare": {"store": "sqlite",    "enforce": "cloudflare"},
    "nginx":      {"store": "sqlite",    "enforce": "noop"},
}
_MODE = _MODE_DEFAULTS.get(DEPLOY_MODE, {})

# --- STORAGE: where the denylist STATE (entries/audit/path_rules) is persisted ---
# Keep it universal — the SAME service runs in k8s and on a plain VM:
#   configmap : k8s ConfigMap (DENYLIST_NS/CM)        — default in-cluster
#   file      : JSON files under STORE_DIR            — plain VM / Docker volume
#   sqlite    : a single SQLite db at STORE_SQLITE    — plain VM / Docker volume
STORE = _env("STORE", _MODE.get("store", "configmap")).lower()
STORE_DIR = _env("STORE_DIR", "/data/denylist")          # for STORE=file
STORE_SQLITE = _env("STORE_SQLITE", "/data/denylist.db")  # for STORE=sqlite

# --- ENFORCEMENT TARGETS + GROUPS ---------------------------------------------
# A target is a place bans are applied: {"id": "...", "type": "...", ...params}.
# Types: ingress-cm | nginx-file | cloudflare | noop.  Groups route bans to a
# subset of targets ("such bans → there"): a block carries a `group`, and is
# applied to every target the group resolves to. No group → BAN_GROUP_DEFAULT;
# an unknown/empty group resolves to ALL targets (safe maximum).
#
#   BAN_TARGETS='[{"id":"edge-cf","type":"cloudflare","mode":"ip-list"},
#                 {"id":"web1","type":"nginx-file"},
#                 {"id":"k8s","type":"ingress-cm"}]'
#   BAN_GROUPS='{"default":["edge-cf"],"origins":["web1"],"all":["edge-cf","web1","k8s"]}'
#
# Back-compat: if BAN_TARGETS is unset, targets are synthesized from the simpler
# ENFORCE list (comma-separated type names, each its own id). ENFORCE itself
# defaults from STORE: configmap→ingress-cm, file/sqlite→noop.
_ENFORCE_DEFAULT = _MODE.get("enforce") or ("ingress-cm" if STORE == "configmap" else "noop")
ENFORCE = [x.strip() for x in _env("ENFORCE", _ENFORCE_DEFAULT).split(",") if x.strip()]

BAN_TARGETS = _env_json("BAN_TARGETS", [{"id": t, "type": t} for t in ENFORCE])
BAN_GROUPS = _env_json("BAN_GROUPS", {})        # group -> [target id]; {} = all-to-all
BAN_GROUP_DEFAULT = _env("BAN_GROUP_DEFAULT", "")   # "" = no named default group; a group-less ban applies to all targets

# --- where the rendered nginx snippet goes (ingress-nginx controller CM) ---
CONTROLLER_NS = _env("CONTROLLER_NS", "ingress-nginx")
CONTROLLER_CM = _env("CONTROLLER_CM", "ingress-nginx-controller")

# --- where we persist the denylist data (k8s configmap store only) ---
DENYLIST_NS = _env("DENYLIST_NS", "soc")
DENYLIST_CM = _env("DENYLIST_CM", "soc-denylist")

# nginx variable + managed-block markers (so we only touch our own content)
GEO_VAR = "$soc_blocked"
MARKER = "soc managed denylist — DO NOT edit by hand"

# Real-client-behind-Cloudflare support. We can't change $remote_addr (it's the CF
# edge for proxied hosts), so we derive our own "$soc_real_ip": the CF-Connecting-IP
# header WHEN the connection comes from a Cloudflare edge, else $remote_addr. The
# blocklist geo is then keyed on $soc_real_ip → one list bans direct AND behind-CF.
CF_FLAG_VAR = "$soc_is_cf"
REAL_IP_VAR = "$soc_real_ip"
# Cloudflare published edge ranges (https://www.cloudflare.com/ips/). $remote_addr of a
# CF-proxied request is always one of these, so a spoofed CF-Connecting-IP from a NON-CF
# client is ignored (its $remote_addr won't match → $soc_real_ip stays $remote_addr).
CF_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]

# --- Cloudflare (type=cloudflare targets) ------------------------------------
# You set only CF_API_TOKEN; zone/account ids and the IP List + WAF rule are
# discovered or CREATED on first ban. Per-target overrides live in BAN_TARGETS.
CF_API_TOKEN = _env("CF_API_TOKEN", "")
CF_MODE = _env("CF_MODE", "ip-list")          # ip-list | access-rules
CF_ZONE_ID = _env("CF_ZONE_ID", "")           # optional; else discovered
CF_ZONE_NAME = _env("CF_ZONE_NAME", "")       # optional; pick zone by name
CF_ACCOUNT_ID = _env("CF_ACCOUNT_ID", "")     # optional; else from zone
CF_LIST_NAME = _env("CF_LIST_NAME", "soc_blocklist")
CF_RULE_DESC = _env("CF_RULE_DESC", "soc blocklist")
# also 403 scanner paths at the CF edge via a WAF custom rule (needs a plan with
# WAF `matches`). off = Cloudflare blocks IPs only (the safe default).
CF_EDGE_PATHS = _env("CF_EDGE_PATHS", "off")  # off | on

# --- auth ---
# Two privilege levels:
#   TOKEN (BLOCKLIST_TOKEN) — ADMIN: dashboard/backend; full access (block/unblock…).
#   per-node tokens          — minted at /enroll; may ONLY read their own /nginx_snippet
#                              and POST their own /heartbeat (least privilege, revocable).
#   ENROLL_SECRET            — the "API key" an agent presents to /enroll to self-register
#                              and receive its node token. Empty → enrollment disabled.
TOKEN = _env("BLOCKLIST_TOKEN", "")  # required; empty → FAILS CLOSED unless DEV_NO_AUTH
ENROLL_SECRET = _env("ENROLL_SECRET", "")        # one shared key agents use to enroll
# Encrypts GUI-entered secrets (CF API token) at rest in the STORE (see crypto.py).
# Lives only in the environment, never on disk. Empty → secrets stored as plaintext
# (backward compatible; a startup warning is logged).
SECRET_KEY = _env("SECRET_KEY", "")
# Empty TOKEN fails closed (503 on everything but /healthz). Opt into an open API
# on a trusted host ONLY with an explicit flag — never silently, it's a ban API.
DEV_NO_AUTH = _env("DEV_NO_AUTH", "") not in ("0", "", "false", "False")

# Public URL agents on nginx VMs use to reach THIS api (for the install one-liner
# the dashboard shows). Often differs from the in-cluster BLOCKLIST_API_URL.
PUBLIC_URL = _env("PUBLIC_URL", "")

# A node is considered offline if its last heartbeat is older than this (seconds).
NODE_OFFLINE_AFTER = int(_env("NODE_OFFLINE_AFTER", "120"))


def _first_existing(*paths):
    for p in paths:
        if p and os.path.isfile(p):
            return p
    return paths[-1] if paths else ""


# Files served at /install/* for the agent one-liner. Resolve to the in-image copy
# (Docker) or the repo checkout (bare/dev), overridable by env.
_HERE = os.path.dirname(os.path.abspath(__file__))            # blocklist-api/app
_REPO = os.path.dirname(os.path.dirname(_HERE))               # repo root (soc-app)
AGENT_PATH = _env("AGENT_PATH", _first_existing(
    "/opt/soc/soc-nginx-agent.py",
    os.path.join(_REPO, "deploy", "agent", "soc-nginx-agent.py")))
INSTALLER_PATH = _env("INSTALLER_PATH", _first_existing(
    "/opt/soc/install.sh",
    os.path.join(_REPO, "deploy", "agent", "install.sh")))

# --- safety rails ---
# IPs that can NEVER be blocked (covers any CIDR that would include them).
_DEFAULT_ALLOW = "192.0.2.10,198.51.100.10,198.51.100.20,192.0.2.20"
ALLOWLIST = [x.strip() for x in _env("ALLOWLIST", _DEFAULT_ALLOW).split(",") if x.strip()]

# Reject CIDRs broader than these prefixes unless force=true.
MIN_PREFIX_V4 = int(_env("MIN_PREFIX_V4", "16"))
MIN_PREFIX_V6 = int(_env("MIN_PREFIX_V6", "32"))

# TTL pruning cadence (seconds) and audit cap.
PRUNE_INTERVAL = int(_env("PRUNE_INTERVAL", "60"))
AUDIT_MAX = int(_env("AUDIT_MAX", "500"))

# Auto-resync: periodically re-render our geo into the controller CM so the
# managed section self-heals if a `kubectl apply` of the ingress CM wiped it.
RESYNC_INTERVAL = int(_env("RESYNC_INTERVAL", "300"))
