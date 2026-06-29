"""Hybrid runtime config — GUI overrides on top of ENV defaults.

The dashboard can edit operational config (Cloudflare token, ban targets/groups,
ingress ConfigMap name…) without redeploying. Overrides are persisted in the same
pluggable storage backend as the denylist (settings.json doc), so they survive
restarts and work in k8s / file / sqlite alike.

Resolution for a key:
  CONFIG_LOCK=env  → always the ENV default (GUI is read-only; declarative/GitOps)
  otherwise        → stored override if set, else the ENV default

Secrets (CF_API_TOKEN) are write-only over the API: POST accepts a new value, GET
never returns it (only whether one is set). The seam is small on purpose — only the
keys in SPEC are editable; everything else stays pure ENV in config.py.
"""
import json
import threading
import time

from . import config, storage

DOC = "settings.json"
_LOCK = threading.Lock()
_CACHE_TTL = 1.0
_cache = {"t": 0.0, "d": None}

# key -> metadata. `env` is the compiled-in default from config.py; `type` drives
# parsing + UI; `secret` keeps the value write-only.
SPEC = {
    # Cloudflare
    "CF_API_TOKEN":  {"type": "secret", "group": "cloudflare", "env": config.CF_API_TOKEN,
                      "label": "Cloudflare API token"},
    "CF_MODE":       {"type": "str", "group": "cloudflare", "env": config.CF_MODE,
                      "label": "CF режим", "choices": ["ip-list", "access-rules"]},
    "CF_ZONE_ID":    {"type": "str", "group": "cloudflare", "env": config.CF_ZONE_ID, "label": "CF zone id"},
    "CF_ZONE_NAME":  {"type": "str", "group": "cloudflare", "env": config.CF_ZONE_NAME, "label": "CF zone name"},
    "CF_ACCOUNT_ID": {"type": "str", "group": "cloudflare", "env": config.CF_ACCOUNT_ID, "label": "CF account id"},
    "CF_LIST_NAME":  {"type": "str", "group": "cloudflare", "env": config.CF_LIST_NAME, "label": "CF IP List name"},
    "CF_RULE_DESC":  {"type": "str", "group": "cloudflare", "env": config.CF_RULE_DESC, "label": "CF rule description"},
    # ingress-nginx (k8s)
    "CONTROLLER_NS": {"type": "str", "group": "ingress", "env": config.CONTROLLER_NS,
                      "label": "ingress-nginx namespace"},
    "CONTROLLER_CM": {"type": "str", "group": "ingress", "env": config.CONTROLLER_CM,
                      "label": "ingress-nginx ConfigMap"},
    # ban routing
    "BAN_TARGETS":      {"type": "json", "group": "bans", "env": config.BAN_TARGETS, "label": "Targets"},
    "BAN_GROUPS":       {"type": "json", "group": "bans", "env": config.BAN_GROUPS, "label": "Groups"},
    "BAN_GROUP_DEFAULT": {"type": "str", "group": "bans", "env": config.BAN_GROUP_DEFAULT,
                          "label": "Группа по умолчанию"},
}


def _overrides():
    if config.CONFIG_LOCK:
        return {}
    c = _cache
    if c["d"] is not None and (time.time() - c["t"]) < _CACHE_TTL:
        return c["d"]
    raw = storage.get_backend().load([DOC]).get(DOC)
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


def get(key):
    """Resolved value for a SPEC key (override if unlocked + set, else ENV)."""
    spec = SPEC.get(key)
    env_default = spec["env"] if spec else None
    ov = _overrides()
    return ov[key] if key in ov else env_default


def is_set(key):
    """Whether a non-empty value is resolved (for secrets: is a token configured?)."""
    v = get(key)
    return bool(v)


def _validate_json(key, val):
    """Parse (if stringified) and shape-check a json-typed setting. Raises ValueError
    with a clear, per-field message so a single bad field never aborts a whole batch
    after partial writes (validation happens before anything is persisted)."""
    if isinstance(val, str):
        try:
            val = json.loads(val)
        except Exception as e:
            raise ValueError("%s: невалидный JSON (%s)" % (key, e))
    if key == "BAN_TARGETS":
        if not isinstance(val, list) or not all(
                isinstance(t, dict) and t.get("id") and t.get("type") for t in val):
            raise ValueError("BAN_TARGETS: ожидается список объектов с полями id и type")
    elif key == "BAN_GROUPS":
        if not isinstance(val, dict) or not all(isinstance(v, list) for v in val.values()):
            raise ValueError("BAN_GROUPS: ожидается объект {имя: [target id, ...]}")
    return val


def set_many(updates):
    """Apply operator edits. Refused when CONFIG_LOCK=env. Empty string clears an
    override (reverts to ENV); for secrets, empty string is ignored (keep current)."""
    if config.CONFIG_LOCK:
        raise PermissionError("config locked (CONFIG_LOCK=env) — edit ENV, not the GUI")
    # Pass 1 — validate EVERYTHING before touching the store (atomic: all-or-nothing).
    staged = []  # (key, action, value)  action ∈ {set, clear, skip}
    for key, val in (updates or {}).items():
        spec = SPEC.get(key)
        if not spec:
            continue
        if spec["type"] == "secret" and (val is None or val == ""):
            continue                              # blank secret = leave as-is
        if spec["type"] == "secret" and config.STORE == "configmap":
            # A ConfigMap is NOT a Secret — refuse to persist a credential there in
            # plaintext. The operator must supply it via ENV (optionally + CONFIG_LOCK).
            raise ValueError(
                "%s: секрет нельзя хранить в configmap-сторе (ConfigMap — это открытый "
                "текст). Задайте его через переменную окружения." % key)
        if val is None or val == "":
            staged.append((key, "clear", None))   # revert to ENV default
        elif spec["type"] == "json":
            staged.append((key, "set", _validate_json(key, val)))  # may raise → 400, nothing saved
        else:
            staged.append((key, "set", val))
    # Pass 2 — apply under lock.
    with _LOCK:
        raw = storage.get_backend().load([DOC]).get(DOC)
        try:
            cur = json.loads(raw) if raw else {}
            if not isinstance(cur, dict):
                cur = {}
        except Exception:
            cur = {}
        applied = []
        for key, action, val in staged:
            if action == "clear":
                cur.pop(key, None)
            else:
                cur[key] = val
            applied.append(key)
        storage.get_backend().save({DOC: json.dumps(cur, ensure_ascii=False)})
        _cache["d"] = None        # invalidate read-through cache
        # CF discovery cache may now be stale (token/zone changed) → drop it.
        try:
            from . import cloudflare
            cloudflare._resolved.clear()
        except Exception:
            pass
        return applied


def public_view():
    """Settings for the dashboard: every key's source + value (secrets redacted)."""
    ov = _overrides()
    out = {}
    for key, spec in SPEC.items():
        locked = config.CONFIG_LOCK
        overridden = (not locked) and key in ov
        item = {"group": spec["group"], "type": spec["type"], "label": spec["label"],
                "locked": locked, "source": "override" if overridden else "env"}
        if "choices" in spec:
            item["choices"] = spec["choices"]
        if spec["type"] == "secret":
            item["set"] = is_set(key)
            # secrets can't be written into a ConfigMap store (plaintext) — env only
            item["writable"] = (not locked) and config.STORE != "configmap"
        else:
            item["value"] = get(key)
        out[key] = item
    return out
