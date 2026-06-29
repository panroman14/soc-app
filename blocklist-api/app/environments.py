"""Environments — the top-level tenant unit (env = pool = project).

An environment groups everything: the nodes that enroll into it (their `group` IS
the env id), the ban backends it uses (local nginx via those nodes, and optionally
its OWN Cloudflare and/or ingress-nginx), its Loki source, and its notification
routing (handled in notify.py, matched by env). Per-env config lives here; the node
↔ env link and the actual ban fan-out stay in nodes.py / enforce.py.

Stored in the pluggable store (environments.json). The Cloudflare token is a secret:
get()/get_cf() expose it server-side (enforcement needs it); public_view() never does.
"""
import json
import re
import threading
import time

from . import storage

DOC = "environments.json"
_LOCK = threading.Lock()
_ID_RE = re.compile(r"[^a-z0-9_.-]+")
_cache = {"t": 0.0, "d": None}
_CACHE_TTL = 2.0


def _st():
    return storage.get_backend()


def _slug(s):
    return _ID_RE.sub("-", (s or "").strip().lower()).strip("-")[:48]


def _load():
    c = _cache
    if c["d"] is not None and (time.time() - c["t"]) < _CACHE_TTL:
        return c["d"]
    raw = _st().load([DOC]).get(DOC)
    d = {}
    if raw:
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                d = obj
        except Exception:
            pass
    c["d"], c["t"] = d, time.time()
    return d


def _save(d):
    _st().save({DOC: json.dumps(d, ensure_ascii=False)})
    _cache["d"] = None


def all_envs():
    """Raw env records (INCLUDING secrets) — internal use (enforcement/cloudflare)."""
    return [dict(v, id=k) for k, v in sorted(_load().items())]


def get(env_id):
    e = _load().get(env_id)
    return dict(e, id=env_id) if e else None


def get_cf(env_id):
    """The env's Cloudflare config (with token) if enabled, else None."""
    e = _load().get(env_id) or {}
    cf = e.get("cloudflare") or {}
    return cf if cf.get("enabled") and cf.get("token") else None


def upsert(env_id="", name="", loki_url="", cloudflare=None, ingress=None):
    """Create/update an env. Blank cloudflare.token keeps the existing one."""
    eid = _slug(env_id) or _slug(name)
    if not eid:
        raise ValueError("env id or name required")
    now = int(time.time())
    with _LOCK:
        d = _load()
        rec = d.get(eid, {})
        cf = dict(rec.get("cloudflare") or {})
        if cloudflare is not None:
            tok = cloudflare.get("token")
            cf.update({k: v for k, v in cloudflare.items() if k != "token"})
            if tok:                                  # blank → keep existing token
                cf["token"] = tok
        ing = dict(rec.get("ingress") or {})
        if ingress is not None:
            ing.update(ingress)
        rec.update({
            "name": name or rec.get("name", "") or eid,
            "loki_url": loki_url if loki_url is not None else rec.get("loki_url", ""),
            "cloudflare": cf,
            "ingress": ing,
            "created": rec.get("created", now),
            "updated": now,
        })
        d[eid] = rec
        _save(d)
    return dict(rec, id=eid)


def delete(env_id):
    with _LOCK:
        d = _load()
        existed = d.pop(env_id, None) is not None
        if existed:
            _save(d)
    return existed


def public_view():
    """For the dashboard — Cloudflare token redacted to a boolean."""
    out = []
    for e in all_envs():
        cf = dict(e.get("cloudflare") or {})
        token_set = bool(cf.pop("token", ""))
        cf["token_set"] = token_set
        out.append({"id": e["id"], "name": e.get("name", e["id"]),
                    "loki_url": e.get("loki_url", ""), "cloudflare": cf,
                    "ingress": e.get("ingress") or {}})
    return out
