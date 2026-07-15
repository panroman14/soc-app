"""Node registry — enrolled soc-nginx-agents (one per nginx VM).

A node = an agent bound to an nginx-file target id. It is stored via the SAME
pluggable storage backend as the denylist (storage.py), so node visibility works
identically in Kubernetes (ConfigMap), on a file-backed VM, or in SQLite.

Each node has its own scoped token, minted at enroll and revocable by deleting the
node. A node token may ONLY fetch that node's /nginx_snippet and POST its own
/heartbeat — it can never block/unblock (that needs the admin BLOCKLIST_TOKEN).

This gives the Datadog-style flow: one ENROLL_SECRET installs an agent anywhere; the
agent self-registers and from then on authenticates with its own per-node credential.
"""
import json
import re
import secrets
import threading
import time

from . import config, storage

DOC = "nodes.json"
_LOCK = threading.Lock()
_ID_RE = re.compile(r"[^a-zA-Z0-9_.-]+")

# Short read-through cache: the registry is read very often (resolve_group runs it
# per-entry during a render) but changes rarely. TTL keeps cross-worker staleness
# tiny; writes invalidate it immediately in-process.
_CACHE_TTL = 1.0
_cache = {"t": 0.0, "d": None}


def _st():
    return storage.get_backend()


def _load():
    c = _cache
    if c["d"] is not None and (time.time() - c["t"]) < _CACHE_TTL:
        return c["d"]
    raw = _st().load([DOC]).get(DOC)
    d = {}
    if raw:
        try:
            d = json.loads(raw)
            if not isinstance(d, dict):
                d = {}
        except Exception:
            d = {}
    c["d"], c["t"] = d, time.time()
    return d


def _save(d):
    _st().save({DOC: json.dumps(d, ensure_ascii=False)})
    _cache["d"] = None        # invalidate → next read reloads authoritative state


def _slug(s):
    return _ID_RE.sub("-", (s or "").strip()).strip("-")[:64]


def _str(s, n=200):
    return str(s or "")[:n]


# Only these metric keys are stored, each coerced to a bounded number/bool, so a
# rogue/compromised agent can't bloat the store with arbitrary heartbeat payloads.
_METRIC_KEYS = ("load1", "load5", "load15", "ncpu", "mem_total_mb", "mem_used_pct",
                "uptime_s", "applied_cidrs")


def _clean_metrics(m):
    out = {}
    if not isinstance(m, dict):
        return out
    for k in _METRIC_KEYS:
        if k in m:
            v = m[k]
            if isinstance(v, bool):
                out[k] = v
            elif isinstance(v, (int, float)):
                out[k] = round(float(v), 2)
    if isinstance(m.get("nginx_ok"), bool):
        out["nginx_ok"] = m["nginx_ok"]
    return out


def _clean_files(f):
    if not isinstance(f, dict):
        return {}
    return {_str(k, 64): _str(v, 256) for k, v in list(f.items())[:8]}


def _decorate(nid, n, now):
    n = dict(n)
    n["id"] = nid
    n["online"] = bool(n.get("last_seen")) and (now - int(n["last_seen"])) <= config.NODE_OFFLINE_AFTER
    return n


def all_nodes(redact=True):
    """Every enrolled node, newest-heartbeat-first, with a derived `online` flag.
    Tokens are stripped unless redact=False (never expose them to the dashboard)."""
    d = _load()
    now = int(time.time())
    out = [_decorate(nid, n, now) for nid, n in list(d.items())]
    if redact:
        for n in out:
            n.pop("token", None)
    out.sort(key=lambda n: n.get("last_seen") or 0, reverse=True)
    return out


def get(nid):
    n = _load().get(nid)
    return _decorate(nid, n, int(time.time())) if n else None


def token_owner(token):
    """Node id whose per-node token matches `token`, else None (constant-time)."""
    if not token:
        return None
    for nid, n in list(_load().items()):
        t = n.get("token") or ""
        if t and secrets.compare_digest(t, token):
            return nid
    return None


# Enrolled agents are pull-mode nginx-file targets by definition (see module docstring).
# They may NOT self-declare a privileged enforcement type: a node claiming
# target_type="ingress-cm"/"cloudflare" would otherwise be auto-promoted into the ban
# fan-out and drive the k8s/CF adapters (S5). Lock every enrolled node to nginx-file.
_ENROLL_TYPE = "nginx-file"


def enroll(node_id="", hostname="", group="", target_type="nginx-file",
           files=None, agent_version="", ip=""):
    """Register (or re-register) a node and return its record INCLUDING the token.

    Re-enrolling an existing id MINTS A FRESH token and invalidates the old one — the
    endpoint never returns a node's pre-existing token, so a holder of ENROLL_SECRET
    cannot read a live node's credential by re-enrolling its id (S4). The installer
    writes the returned token on each run, so idempotent reruns still yield a working
    agent (they just rotate the credential)."""
    nid = _slug(node_id) or _slug(hostname)
    if not nid:
        raise ValueError("node_id or hostname required")
    now = int(time.time())
    with _LOCK:
        d = _load()
        rec = d.get(nid, {})
        token = secrets.token_hex(24)     # always fresh → no token disclosure on re-enroll
        rec.update({
            "hostname": _str(hostname, 253) or rec.get("hostname", ""),
            "group": _slug(group) or rec.get("group", ""),
            "target_type": _ENROLL_TYPE,   # enrolled nodes are always nginx-file (S5)
            "files": _clean_files(files) or rec.get("files", {}),
            "agent_version": _str(agent_version, 32) or rec.get("agent_version", ""),
            "token": token,
            "enrolled_at": rec.get("enrolled_at", now),
            "last_seen": rec.get("last_seen", 0),
            "ip": ip or rec.get("ip", ""),
        })
        d[nid] = rec
        _save(d)
    out = dict(rec)
    out["id"] = nid
    return out


def heartbeat(nid, metrics=None, agent_version="", ip=""):
    """Record a liveness ping + host metrics. Returns the node, or None if unknown."""
    now = int(time.time())
    with _LOCK:
        d = _load()
        n = d.get(nid)
        if not n:
            return None
        n["last_seen"] = now
        if metrics:
            n["metrics"] = _clean_metrics(metrics)
        if agent_version:
            n["agent_version"] = _str(agent_version, 32)
        if ip:
            n["ip"] = _str(ip, 64)
        d[nid] = n
        _save(d)
    return _decorate(nid, n, now)


def delete(nid):
    """Revoke a node (removes its token). Returns True if it existed."""
    with _LOCK:
        d = _load()
        existed = d.pop(nid, None) is not None
        if existed:
            _save(d)
    return existed
