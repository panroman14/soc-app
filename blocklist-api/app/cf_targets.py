"""Named Cloudflare targets — a registry decoupled from environments.

Each entry is a Cloudflare account/zone you name in the GUI (e.g. "nginx-aaa-cloudflare")
and then attach to ban groups / 403 rules like any other target. The API token is a
secret: get()/all_full() expose it server-side (enforcement needs it); public_view()
never does.

Stored in the pluggable storage backend (cf_targets.json) as:
  {"migrated": true, "targets": {"<id>": {name, token, mode, zone_id, zone_name,
                                          account_id, list_name, rule_desc, env?,
                                          created, updated}}}
`env` is set only on entries auto-migrated from a per-env Cloudflare config — it keeps
those targets in their env group so existing ban routing is unchanged. GUI-created
targets have no env (fully standalone; attach them explicitly).
"""
import json
import re
import threading
import time

from . import storage

DOC = "cf_targets.json"
_LOCK = threading.Lock()
_ID_RE = re.compile(r"[^a-z0-9_.:-]+")
_cache = {"t": 0.0, "d": None}
_CACHE_TTL = 2.0

# fields safe to expose to the dashboard (everything except the token)
_PUBLIC = ("name", "mode", "zone_id", "zone_name", "account_id",
           "list_name", "rule_desc", "env", "created", "updated")


def _st():
    return storage.get_backend()


def _slug(s):
    return _ID_RE.sub("-", (s or "").strip().lower()).strip("-")[:48]


def _load():
    c = _cache
    if c["d"] is not None and (time.time() - c["t"]) < _CACHE_TTL:
        return c["d"]
    raw = _st().load([DOC]).get(DOC)
    d = {"migrated": False, "targets": {}}
    if raw:
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict) and isinstance(obj.get("targets"), dict):
                d = {"migrated": bool(obj.get("migrated")), "targets": obj["targets"]}
        except Exception:
            pass
    c["d"], c["t"] = d, time.time()
    return d


def _save(d):
    _st().save({DOC: json.dumps(d, ensure_ascii=False)})
    _cache["d"] = None     # invalidate → next read reloads authoritative state


def all_full():
    """All registered CF targets WITH tokens (server-side only): {id: entry}."""
    return dict(_load()["targets"])


def get(target_id):
    """One CF target's full config (incl. token) or None."""
    return _load()["targets"].get(target_id)


def public_view():
    """List for the dashboard — token redacted to a `token_set` boolean."""
    out = []
    for tid, e in _load()["targets"].items():
        pub = {k: e.get(k) for k in _PUBLIC if e.get(k) is not None}
        pub["id"] = tid
        pub["token_set"] = bool(e.get("token"))
        out.append(pub)
    return sorted(out, key=lambda x: x["id"])


def ids():
    """Just the registered target ids (for enforce.targets())."""
    return list(_load()["targets"].keys())


_ALLOWED = ("name", "token", "mode", "zone_id", "zone_name",
            "account_id", "list_name", "rule_desc", "env")


def upsert(target_id, fields):
    """Create or update a named CF target. A blank `token` on update keeps the
    existing one (so the redacted dashboard value never wipes the secret)."""
    tid = _slug(target_id) or _slug(fields.get("name") or "")
    if not tid:
        raise ValueError("нужен id или имя CF-таргета")
    now = int(time.time())
    with _LOCK:
        d = _load()
        cur = dict(d["targets"].get(tid) or {})
        for k in _ALLOWED:
            if k in fields and fields[k] is not None:
                v = fields[k]
                if k == "token" and not str(v).strip():
                    continue            # blank token → keep existing
                cur[k] = v.strip() if isinstance(v, str) else v
        if (cur.get("mode") or "") not in ("ip-list", "access-rules"):
            cur["mode"] = "ip-list"
        cur.setdefault("created", now)
        cur["updated"] = now
        d["targets"][tid] = cur
        _save(d)
    return {"id": tid, **{k: cur.get(k) for k in _PUBLIC if cur.get(k) is not None},
            "token_set": bool(cur.get("token"))}


def delete(target_id):
    with _LOCK:
        d = _load()
        existed = target_id in d["targets"]
        if existed:
            d["targets"].pop(target_id)
            _save(d)
    return existed


def migrate_from_envs():
    """One-time, idempotent: copy every per-env Cloudflare config into the registry as
    a named target id `cf:<env>` (keeping `env` so group routing is unchanged). After
    this, enforce stops synthesizing CF from environments — the registry is the source
    of truth. Safe to call on every startup; the `migrated` sentinel makes re-runs no-op."""
    d = _load()
    if d.get("migrated"):
        return 0
    from . import environments
    n = 0
    with _LOCK:
        d = _load()                       # re-read under lock
        if d.get("migrated"):
            return 0
        for e in environments.all_envs():
            cf = e.get("cloudflare") or {}
            if not (cf.get("enabled") and cf.get("token")):
                continue
            tid = "cf:" + e["id"]
            if tid in d["targets"]:
                continue
            now = int(time.time())
            d["targets"][tid] = {
                "name": (e.get("name") or e["id"]) + " · Cloudflare",
                "token": cf.get("token"), "mode": cf.get("mode") or "ip-list",
                "zone_id": cf.get("zone_id") or "", "zone_name": cf.get("zone_name") or "",
                "account_id": cf.get("account_id") or "",
                "list_name": cf.get("list_name") or "", "rule_desc": cf.get("rule_desc") or "",
                "env": e["id"], "created": now, "updated": now}
            n += 1
        d["migrated"] = True
        _save(d)
    return n
