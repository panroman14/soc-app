"""Cloudflare API client + reconciler. You supply only CF_API_TOKEN; everything
else (account id, zone id, the IP List, the WAF rule) is discovered or CREATED on
first use. Two strategies:

  ip-list      : an account IP List + ONE zone WAF custom rule `ip.src in $list`.
                 Bans = list items (PUT replaces the whole set → clean reconcile).
                 Supports arbitrary CIDRs; the recommended mode.
  access-rules : one zone firewall access_rule per CIDR (mode=block). CF only takes
                 /16 and /24 ranges here; we reconcile by diffing our tagged rules.

A target dict from BAN_TARGETS may override per-target params; missing values fall
back to env. Discovered ids are cached per target id for the process lifetime
(discovery is idempotent — always by name/description, never duplicated).
"""
import json
import urllib.error
import urllib.request

from . import config

API = "https://api.cloudflare.com/client/v4"
TAG = "soc-managed"  # marks access_rules / list / rule we own


class CFError(Exception):
    pass


# ── low-level request ─────────────────────────────────────────────────────────
def _req(token, method, path, body=None):
    url = API + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            payload = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode())
        except Exception:
            raise CFError("HTTP %s on %s %s" % (e.code, method, path))
    except Exception as e:
        raise CFError("%s %s: %s" % (method, path, e))
    if not payload.get("success", False):
        errs = "; ".join(str(x.get("message", x)) for x in payload.get("errors", [])) or "unknown error"
        raise CFError(errs)
    return payload.get("result")


# ── per-target resolved config (discovery + cache) ────────────────────────────
_resolved = {}  # target_id -> {token, account_id, zone_id, mode, list_name, rule_desc, list_id, rule_id}


def _cfg(target):
    """Resolve a target's CF config + token. Resolution order:
      1. the named cf_targets registry (matched by target id) — the source of truth;
      2. a per-env Cloudflare config (legacy `env` set) — fallback during migration;
      3. the global GUI/ENV settings.
    The token is never taken from the exposed target dict."""
    from . import settings, environments, cf_targets
    reg = cf_targets.get(target.get("id")) if target.get("id") else None
    if reg and reg.get("token"):
        return {
            "token": reg.get("token"),
            "mode": target.get("mode") or reg.get("mode") or settings.get("CF_MODE"),
            "zone_id": reg.get("zone_id") or "",
            "zone_name": reg.get("zone_name") or "",
            "account_id": reg.get("account_id") or "",
            "list_name": reg.get("list_name") or settings.get("CF_LIST_NAME"),
            "rule_desc": reg.get("rule_desc") or ("soc %s" % target.get("id")),
        }
    env = target.get("env")
    cf = environments.get_cf(env) if env else None
    if cf:
        return {
            "token": cf.get("token"),
            "mode": target.get("mode") or cf.get("mode") or settings.get("CF_MODE"),
            "zone_id": cf.get("zone_id") or "",
            "zone_name": cf.get("zone_name") or "",
            "account_id": cf.get("account_id") or "",
            "list_name": cf.get("list_name") or settings.get("CF_LIST_NAME"),
            "rule_desc": cf.get("rule_desc") or ("soc %s" % env),
        }
    return {
        "token": settings.get("CF_API_TOKEN"),
        "mode": target.get("mode") or settings.get("CF_MODE"),
        "zone_id": target.get("zone_id") or settings.get("CF_ZONE_ID"),
        "zone_name": target.get("zone_name") or settings.get("CF_ZONE_NAME"),
        "account_id": target.get("account_id") or settings.get("CF_ACCOUNT_ID"),
        "list_name": target.get("list_name") or settings.get("CF_LIST_NAME"),
        "rule_desc": target.get("rule_desc") or settings.get("CF_RULE_DESC"),
    }


def _discover_zone(c):
    """Fill zone_id/account_id from the token if not given explicitly."""
    if c["zone_id"] and c["account_id"]:
        return
    zones = _req(c["token"], "GET", "/zones?per_page=50") or []
    if c["zone_id"]:
        z = next((z for z in zones if z["id"] == c["zone_id"]), None)
    elif c["zone_name"]:
        z = next((z for z in zones if z["name"] == c["zone_name"]), None)
    elif len(zones) == 1:
        z = zones[0]
    else:
        raise CFError("несколько зон у токена — задай CF_ZONE_ID или CF_ZONE_NAME")
    if not z:
        raise CFError("зона не найдена (CF_ZONE_ID/CF_ZONE_NAME)")
    c["zone_id"] = z["id"]
    c["account_id"] = c["account_id"] or z.get("account", {}).get("id")


def _resolve(target, ensure=False):
    """Resolve (and cache) a target's CF config. ensure=True also CREATES the IP
    List + WAF rule (ip-list mode) if missing.

    The per-process cache is keyed implicitly on the token: if the live token differs
    from the cached one (operator rotated it, possibly in another worker), the cache is
    bypassed and the config re-discovered — so a stale token is never used silently."""
    tid = target["id"]
    cached = _resolved.get(tid)
    live = _cfg(target)
    if cached and cached.get("token") == live.get("token"):
        c = dict(cached)
    else:
        c = live
    if not c.get("token"):
        raise CFError("CF_API_TOKEN не задан")
    _discover_zone(c)
    if c["mode"] == "ip-list":
        _ensure_list(c, create=ensure)
        if ensure:
            _ensure_rule(c)
    _resolved[tid] = c
    return c


# ── ip-list strategy ──────────────────────────────────────────────────────────
def _ensure_list(c, create=False):
    if not c["account_id"]:
        raise CFError("нет account_id для IP List")
    lists = _req(c["token"], "GET", "/accounts/%s/rules/lists" % c["account_id"]) or []
    found = next((l for l in lists if l["name"] == c["list_name"]), None)
    if not found and create:
        found = _req(c["token"], "POST", "/accounts/%s/rules/lists" % c["account_id"],
                     {"name": c["list_name"], "kind": "ip",
                      "description": "soc-managed blocklist"})
    c["list_id"] = found["id"] if found else None
    return c["list_id"]


def _ensure_rule(c):
    """Ensure a WAF custom rule `ip.src in $list_name` (action block) exists in the
    zone's http_request_firewall_custom entrypoint ruleset."""
    if not c.get("list_id"):
        return None
    phase = "http_request_firewall_custom"
    expr = "(ip.src in $%s)" % c["list_name"]
    base = "/zones/%s/rulesets" % c["zone_id"]
    try:
        ep = _req(c["token"], "GET", base + "/phases/%s/entrypoint" % phase)
    except CFError:
        ep = None
    if not ep:
        ep = _req(c["token"], "POST", base, {
            "name": "soc custom firewall", "kind": "zone", "phase": phase, "rules": []})
    rules = ep.get("rules") or []
    found = next((r for r in rules if r.get("description") == c["rule_desc"]
                  or r.get("expression") == expr), None)
    if found:
        c["rule_id"] = found["id"]
        return c["rule_id"]
    created = _req(c["token"], "POST", base + "/%s/rules" % ep["id"],
                   {"expression": expr, "action": "block", "description": c["rule_desc"]})
    # the POST returns the whole ruleset; find our rule
    for r in (created.get("rules") or []):
        if r.get("description") == c["rule_desc"]:
            c["rule_id"] = r["id"]
    return c.get("rule_id")


def _put_list_items(c, cidrs):
    items = [{"ip": x} for x in cidrs]
    # PUT replaces ALL items in one call (async op; we don't poll — eventual)
    _req(c["token"], "PUT", "/accounts/%s/rules/lists/%s/items" % (c["account_id"], c["list_id"]),
         items)


# ── access-rules strategy ─────────────────────────────────────────────────────
def _access_rules(c):
    out, page = [], 1
    while True:
        res = _req(c["token"], "GET",
                   "/zones/%s/firewall/access_rules/rules?per_page=100&page=%d&mode=block" % (c["zone_id"], page)) or []
        out.extend(res)
        if len(res) < 100:
            break
        page += 1
    return [r for r in out if TAG in (r.get("notes") or "")]


def _sync_access_rules(c, cidrs):
    existing = {}
    for r in _access_rules(c):
        cfg = r.get("configuration") or {}
        existing[cfg.get("value")] = r["id"]
    want = set(cidrs)
    have = set(existing)
    for cidr in want - have:
        target = "ip_range" if "/" in cidr else "ip"
        _req(c["token"], "POST", "/zones/%s/firewall/access_rules/rules" % c["zone_id"],
             {"mode": "block", "notes": TAG,
              "configuration": {"target": target, "value": cidr}})
    for cidr in have - want:
        _req(c["token"], "DELETE", "/zones/%s/firewall/access_rules/rules/%s" % (c["zone_id"], existing[cidr]))


# ── edge path/UA blocking (WAF custom rule) ───────────────────────────────────
def _paths_rule_desc(c):
    return (c.get("rule_desc") or "soc") + " — paths"


def _path_expr(patterns):
    """One WAF expression that blocks request URIs matching ANY of the 403 path
    regexes. Matches on http.request.uri (path+query) so the same `(\\?|$)` anchors
    the nginx rules use still apply. Needs a CF plan whose WAF supports `matches`."""
    alt = "|".join(p.replace('"', "").replace("`", "") for p in patterns if p)
    return '(http.request.uri matches "%s")' % alt


def reconcile_paths(target, patterns):
    """Manage a WAF custom rule (action block) for the 403 path patterns routed to
    this Cloudflare target — so scanner paths are 403'd at the EDGE, not just at the
    origin. Empty patterns → the managed rule is removed. Idempotent (matched by
    description). Caller gates this on the CF_EDGE_PATHS setting."""
    c = _resolve(target, ensure=False)
    if not c.get("zone_id"):
        raise CFError("нет zone_id для edge-path правила")
    phase = "http_request_firewall_custom"
    base = "/zones/%s/rulesets" % c["zone_id"]
    desc = _paths_rule_desc(c)
    try:
        ep = _req(c["token"], "GET", base + "/phases/%s/entrypoint" % phase)
    except CFError:
        ep = None
    patterns = [p for p in (patterns or []) if p]
    if not ep:
        if not patterns:
            return
        ep = _req(c["token"], "POST", base, {
            "name": "soc custom firewall", "kind": "zone", "phase": phase, "rules": []})
    found = next((r for r in (ep.get("rules") or []) if r.get("description") == desc), None)
    if not patterns:                       # nothing to block → delete our rule if present
        if found:
            _req(c["token"], "DELETE", base + "/%s/rules/%s" % (ep["id"], found["id"]))
        return
    expr = _path_expr(patterns)
    if found:
        if found.get("expression") != expr:
            _req(c["token"], "PATCH", base + "/%s/rules/%s" % (ep["id"], found["id"]),
                 {"expression": expr, "action": "block", "description": desc})
    else:
        _req(c["token"], "POST", base + "/%s/rules" % ep["id"],
             {"expression": expr, "action": "block", "description": desc})


# ── public: reconcile + check ─────────────────────────────────────────────────
def reconcile(target, cidrs):
    """Make Cloudflare match the desired CIDR set for this target."""
    c = _resolve(target, ensure=True)
    if c["mode"] == "access-rules":
        _sync_access_rules(c, cidrs)
    else:
        _put_list_items(c, cidrs)


def check(target):
    """Probe the integration for the dashboard's «проверить» button. Never raises —
    returns a structured status describing what exists and what's wrong."""
    from . import settings
    out = {"id": target.get("id"), "mode": (target.get("mode") or settings.get("CF_MODE")),
           "ok": False, "token_valid": False, "zone_id": None, "account_id": None,
           "list_id": None, "rule_id": None, "items": None, "error": None}
    c = _cfg(target)
    if not c["token"]:
        out["error"] = "CF_API_TOKEN не задан"
        return out
    try:
        v = _req(c["token"], "GET", "/user/tokens/verify")
        out["token_valid"] = (v or {}).get("status") == "active"
        _discover_zone(c)
        out["zone_id"], out["account_id"] = c["zone_id"], c["account_id"]
        if c["mode"] == "ip-list":
            _ensure_list(c, create=False)
            out["list_id"] = c.get("list_id")
            if c.get("list_id"):
                items = _req(c["token"], "GET",
                             "/accounts/%s/rules/lists/%s/items" % (c["account_id"], c["list_id"])) or []
                out["items"] = len(items)
            # rule presence (read-only, don't create)
            try:
                ep = _req(c["token"], "GET",
                          "/zones/%s/rulesets/phases/http_request_firewall_custom/entrypoint" % c["zone_id"])
                rd = c["rule_desc"]
                out["rule_id"] = next((r["id"] for r in (ep.get("rules") or [])
                                       if r.get("description") == rd), None)
            except CFError:
                pass
            out["ok"] = bool(out["token_valid"] and out["list_id"] and out["rule_id"])
            if out["token_valid"] and not out["list_id"]:
                out["error"] = "список «%s» ещё не создан (создастся при первом бане)" % c["list_name"]
            elif out["list_id"] and not out["rule_id"]:
                out["error"] = "WAF-правило ещё не создано (создастся при первом бане)"
        else:
            out["items"] = len(_access_rules(c))
            out["ok"] = bool(out["token_valid"] and out["zone_id"])
    except CFError as e:
        out["error"] = str(e)
    return out
