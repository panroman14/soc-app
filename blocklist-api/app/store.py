"""Denylist state: persisted in the soc-denylist ConfigMap, rendered into
the ingress-nginx controller ConfigMap on every change.

Entry shape: {cidr, reason, added_by, ts, ttl}
  ttl = seconds to keep (0 = permanent). Expired entries are pruned + un-rendered.
"""
import json
import secrets
import threading
import time

from . import config, enforce, notify, safety, settings, storage

_lock = threading.Lock()


def _now():
    return int(time.time())


def _st():
    return storage.get_backend()


def _load_raw():
    data = _st().load(["entries.json", "audit.json"])
    # Fail-safe: a corrupt entries.json must NOT silently fall back to [] —
    # that would re-render an empty geo and wipe all live blocks. Abort instead
    # (we never patch the controller, so existing config stays intact).
    raw = data.get("entries.json")
    if raw is None:
        entries = []
    else:
        try:
            entries = json.loads(raw)
            if not isinstance(entries, list):
                raise ValueError("entries.json is not a list")
        except Exception as e:
            raise RuntimeError("denylist повреждён (entries.json): %s — отказ, "
                               "чтобы не стереть активные блокировки" % e)
    # audit is non-critical; tolerate corruption.
    try:
        audit = json.loads(data.get("audit.json", "[]"))
        if not isinstance(audit, list):
            audit = []
    except Exception:
        audit = []
    return entries, audit


def _save_raw(entries, audit):
    _st().save({
        "entries.json": json.dumps(entries, ensure_ascii=False),
        "audit.json": json.dumps(audit[-config.AUDIT_MAX:], ensure_ascii=False),
    })


def _active(entries, now=None):
    now = now or _now()
    return [e for e in entries if not e.get("ttl") or e["ts"] + e["ttl"] > now]


def _cidrs_for_target(active, target_id, resolved=None):
    """Collapsed CIDR set routed to one target: every active entry whose group
    resolves to include this target. `resolved` is an optional {group: set(target_ids)}
    memo (resolve_group is O(targets+nodes); reuse it across targets in one render)."""
    if resolved is None:
        member = lambda g: target_id in enforce.resolve_group(g)
    else:
        member = lambda g: target_id in resolved.get(g, ())
    return safety.collapse([e["cidr"] for e in active if member(e.get("group"))])


def _render(entries, path=None):
    """Render BOTH the IP denylist (geo) and the path-403 rules (if) to EACH
    configured enforcement target — every target gets only the CIDRs routed to it
    via its group(s). `path` is the {enabled, rules} dict; loaded if not supplied."""
    if path is None:
        # IP-ban is the critical function — a corrupt path_rules.json must NOT block it.
        # Path mutations pass `path` explicitly (and validate it strictly themselves).
        try:
            path = _load_path()
        except Exception as e:
            print("[render] path_rules load failed, rendering without path-403:", e, flush=True)
            path = {"enabled": True, "rules": []}
    active = _active(entries)
    # Resolve each DISTINCT group once (not per entry × per target) — big saving when
    # many bans share a group, since resolve_group walks targets + enrolled nodes.
    resolved = {}
    for e in active:
        g = e.get("group")
        if g not in resolved:
            resolved[g] = set(enforce.resolve_group(g))
    tids = enforce.all_target_ids()
    # per-target desired CIDR sets (routed by each ban's group)
    per_target = {tid: _cidrs_for_target(active, tid, resolved) for tid in tids}
    # per-target 403 patterns: a path rule renders only to targets in its group
    # (empty/unknown group → ALL, via resolve_group — keeps prior global behaviour).
    per_target_patterns = _patterns_per_target(path, tids)
    enforce.apply(per_target, per_target_patterns, bool(path.get("enabled", True)))
    # the overall active set (for counts / API responses)
    return safety.collapse([e["cidr"] for e in active])


def _audit(audit, action, cidr, who, extra=""):
    """Append an action event and RETURN it, so the caller can attach the enforcement
    `result` after the render runs (did it actually apply to the targets, or fail?)."""
    ev = {"ts": _now(), "action": action, "cidr": cidr, "by": who, "note": extra}
    audit.append(ev)
    return ev


def _emit_ban(cidr, env, who, reason, result):
    """Fire a notification for a ban (best-effort, env-aware). Type/severity reflect
    whether enforcement actually applied to the env's targets."""
    failed = result and not result.get("ok")
    etype = "ban_failed" if failed else ("autoban" if who == "autoban" else "ban")
    fields = {"by": who}
    if reason:
        fields["причина"] = reason
    if result and result.get("targets"):
        fields["таргеты"] = ", ".join(result["targets"])
    if failed:
        fields["ошибка"] = "; ".join("%s: %s" % (t, e) for t, e in (result.get("failed") or {}).items())
    notify.emit({"type": etype, "env": env, "severity": "warning" if failed else "notice",
                 "title": ("Бан не применился" if failed else "IP забанен") + " " + cidr,
                 "text": "", "fields": fields})


def _enf_result(group=None):
    """Outcome of the LAST render for the relevant targets: did enforcement succeed
    everywhere, and if not, which target failed with what error. `group` limits it to
    that group's targets (a single ban); None = all targets (bulk/unblock/path)."""
    errs = enforce.last_errors()
    tids = enforce.resolve_group(group) if group is not None else enforce.all_target_ids()
    failed = {t: errs[t] for t in tids if errs.get(t)}
    return {"ok": not failed, "targets": tids, "failed": failed}


def list_active(target=None):
    """Active blocks. With `target`, only entries whose group routes to that
    target id (used by the nginx-file pull-agent: GET /list?target=web1)."""
    with _lock:
        entries, _ = _load_raw()
        act = _active(entries)
    if target:
        act = [e for e in act if target in enforce.resolve_group(e.get("group"))]
    return act


def audit_log(limit=100):
    with _lock:
        _, audit = _load_raw()
        return list(reversed(audit[-limit:]))


def block(cidr, reason="", added_by="dashboard", ttl=0, force=False, group=None):
    cidr = safety.validate(cidr, force=force)  # raises BlockError
    group = group or settings.get("BAN_GROUP_DEFAULT")
    with _lock:
        entries, audit = _load_raw()
        entries = [e for e in entries if e["cidr"] != cidr]  # replace if exists
        entries.append({"cidr": cidr, "reason": reason, "added_by": added_by,
                        "ts": _now(), "ttl": int(ttl or 0), "group": group})
        ev = _audit(audit, "block", cidr, added_by, reason)
        cidrs = _render(entries)
        ev["result"] = _enf_result(group)
        _save_raw(entries, audit)
        out = {"cidr": cidr, "active": len(cidrs), "group": group,
               "targets": enforce.resolve_group(group), "result": ev["result"]}
    _emit_ban(cidr, group, added_by, reason, out["result"])   # outside lock (network)
    return out


def block_many(cidrs=None, items=None, reason="", added_by="dashboard", ttl=0, force=False, group=None):
    """Block several CIDRs with a SINGLE render/reload. Invalid ones are skipped.

    Either `cidrs` (list, shared `reason`) or `items` ([{cidr, reason}], per-CIDR reason).
    An item may carry its own `group`; otherwise the call's `group` (or default).
    """
    dflt_group = group or settings.get("BAN_GROUP_DEFAULT")
    pairs = []
    if items:
        pairs = [(it.get("cidr", ""), it.get("reason", reason), it.get("group", dflt_group)) for it in items]
    else:
        pairs = [(c, reason, dflt_group) for c in (cidrs or [])]
    valid, skipped = [], []
    for c, rs, g in pairs:
        try:
            valid.append((safety.validate(c, force=force), rs, g))
        except safety.BlockError as e:
            skipped.append({"cidr": c, "error": str(e)})
    with _lock:
        entries, audit = _load_raw()
        now = _now()
        added, seen, evs = [], set(), []
        for c, rs, g in valid:
            if c in seen:
                continue
            seen.add(c)
            entries = [e for e in entries if e["cidr"] != c]
            entries.append({"cidr": c, "reason": rs, "added_by": added_by,
                            "ts": now, "ttl": int(ttl or 0), "group": g})
            evs.append(_audit(audit, "block", c, added_by, rs))
            added.append(c)
        active = _render(entries) if added else _active(entries)
        res = {"ok": True, "targets": [], "failed": {}}
        if added:
            res = _enf_result()
            for ev in evs:
                ev["result"] = res
            _save_raw(entries, audit)
        out = {"blocked": added, "skipped": skipped, "active": len(active), "result": res}
    if added:
        failed = not res.get("ok")
        notify.emit({"type": "ban_failed" if failed else ("autoban" if added_by == "autoban" else "ban"),
                     "env": dflt_group, "severity": "warning" if failed else "notice",
                     "title": "Забанено %d IP%s" % (len(added), " (с ошибкой применения)" if failed else ""),
                     "text": "", "fields": {"by": added_by, "пример": ", ".join(added[:5]),
                                            **({"ошибка": "; ".join("%s: %s" % (t, e) for t, e in (res.get("failed") or {}).items())} if failed else {})}})
    return out


def unblock(cidr, by="dashboard"):
    cidr = safety.normalize_cidr(cidr)
    with _lock:
        entries, audit = _load_raw()
        before = len(entries)
        entries = [e for e in entries if e["cidr"] != cidr]
        removed = before - len(entries)
        if removed:
            ev = _audit(audit, "unblock", cidr, by)
            cidrs = _render(entries)
            ev["result"] = _enf_result()
            _save_raw(entries, audit)
            out = {"cidr": cidr, "removed": removed, "active": len(cidrs), "result": ev["result"]}
        else:
            out = {"cidr": cidr, "removed": 0}
    if out.get("removed"):
        notify.emit({"type": "unban", "env": "", "severity": "info",
                     "title": "IP разбанен " + cidr, "text": "", "fields": {"by": by}})
    return out


def clear_all(by="dashboard"):
    """Remove ALL managed blocks (our geo section emptied). App's static deny untouched."""
    with _lock:
        entries, audit = _load_raw()
        n = len(entries)
        if n:
            evs = [_audit(audit, "unblock", e["cidr"], by, "clear-all") for e in entries]
            _render([])
            res = _enf_result()
            for ev in evs:
                ev["result"] = res
            _save_raw([], audit)
        return {"removed": n}


def resync():
    """Re-render the current denylist into the controller CM (self-heal after a
    `kubectl apply` of the ingress CM wiped our managed section). Data unchanged."""
    with _lock:
        entries, _ = _load_raw()
        cidrs = _render(_active(entries))
        return {"active": len(cidrs)}


def prune():
    """Drop expired entries; re-render only if something changed."""
    with _lock:
        entries, audit = _load_raw()
        now = _now()
        active = _active(entries, now)
        if len(active) == len(entries):
            return 0
        expired = [e["cidr"] for e in entries if e not in active]
        evs = [_audit(audit, "expire", c, "ttl") for c in expired]
        _render(active)
        res = _enf_result()
        for ev in evs:
            ev["result"] = res
        _save_raw(active, audit)
        return len(expired)


# ── path-403 rules ────────────────────────────────────────────────────────────
# Path patterns that 403 at the server level (e.g. /\.env, /wp-login, jndi). Stored
# in the SAME denylist CM under `path_rules.json` = {"enabled": bool, "rules": [...]}.
# Rule shape: {id, name, pattern, enabled, added_by, ts}.
PATH_KEY = "path_rules.json"


def _load_path():
    raw = _st().load([PATH_KEY]).get(PATH_KEY)
    if not raw:
        return {"enabled": True, "rules": []}
    try:
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            raise ValueError("path_rules.json is not an object")
        obj.setdefault("enabled", True)
        if not isinstance(obj.get("rules"), list):
            obj["rules"] = []
        return obj
    except Exception as e:
        # Fail-safe like the denylist: a corrupt file must NOT silently render an
        # empty set (would drop all path-403 rules). Abort so live config stays.
        raise RuntimeError("path_rules.json повреждён: %s — отказ" % e)


def _save_path(obj):
    _st().save({PATH_KEY: json.dumps(obj, ensure_ascii=False)})


def _new_path_id(rules):
    ids = {r.get("id") for r in rules}
    while True:
        i = secrets.token_hex(4)
        if i not in ids:
            return i


def list_path_rules():
    with _lock:
        return _load_path()


def _patterns_per_target(path, tids):
    """{target_id: [pattern,...]} — each enabled path rule routed to its group's
    targets. Empty/unknown group resolves to ALL targets (resolve_group), so a rule
    with no group applies everywhere (back-compat)."""
    out = {tid: [] for tid in tids}
    cache = {}
    for r in path.get("rules", []):
        if not r.get("enabled"):
            continue
        g = r.get("group") or ""
        if g not in cache:
            cache[g] = set(enforce.resolve_group(g))
        for tid in tids:
            if tid in cache[g]:
                out[tid].append(r["pattern"])
    return out


def patterns_for_target(target_id, path=None):
    """Enabled 403 patterns that apply to ONE target (used by the nginx-file pull
    agent's /nginx_snippet). Routed by each rule's group; empty group = all."""
    if path is None:
        path = _load_path()
    pats, cache = [], {}
    for r in path.get("rules", []):
        if not r.get("enabled"):
            continue
        g = r.get("group") or ""
        if g not in cache:
            cache[g] = set(enforce.resolve_group(g))
        if target_id in cache[g]:
            pats.append(r["pattern"])
    return pats


def path_render_status():
    """Health of the 403-path section: are the enabled rules actually present in
    the live controller server-snippet? Detects drift / a wiped managed section
    (e.g. after someone `kubectl apply`-ed the ingress CM) — surfaced as metrics."""
    with _lock:
        path = _load_path()
        rules = path.get("rules", [])
        enabled_n = sum(1 for r in rules if r.get("enabled"))
        master = bool(path.get("enabled", True))
        per_target_patterns = _patterns_per_target(path, enforce.all_target_ids())
        st = enforce.render_status(per_target_patterns, master)
        return {"enabled": master, "count": len(rules), "enabled_count": enabled_n, **st}


def upsert_path_rule(id=None, name="", pattern="", enabled=True, force=False, by="dashboard", group=None):
    pattern = safety.validate_pattern(pattern, force=force)  # raises BlockError
    group = (group or "").strip()       # "" = applies to ALL targets (back-compat)
    with _lock:
        entries, audit = _load_raw()
        path = _load_path()
        rules = path["rules"]
        if id:
            found = next((r for r in rules if r.get("id") == id), None)
            if not found:
                raise safety.BlockError("правило не найдено: %s" % id)
            found.update({"name": name or found.get("name", ""),
                          "pattern": pattern, "enabled": bool(enabled), "group": group})
        else:
            # dedup: identical pattern already exists → no-op, return it (no duplicate)
            dup = next((r for r in rules if r.get("pattern") == pattern), None)
            if dup:
                return {"id": dup.get("id"), "rules": len(rules), "duplicate": True}
            id = _new_path_id(rules)
            rules.append({"id": id, "name": name, "pattern": pattern,
                          "enabled": bool(enabled), "group": group, "added_by": by, "ts": _now()})
        ev = _audit(audit, "path_rule", id, by, (name or pattern)[:80])
        _render(entries, path)
        ev["result"] = _enf_result()
        _save_path(path)
        _save_raw(entries, audit)
        return {"id": id, "rules": len(rules), "result": ev["result"]}


def delete_path_rule(id, by="dashboard"):
    with _lock:
        entries, audit = _load_raw()
        path = _load_path()
        before = len(path["rules"])
        path["rules"] = [r for r in path["rules"] if r.get("id") != id]
        removed = before - len(path["rules"])
        if removed:
            ev = _audit(audit, "path_rule_del", id, by)
            _render(entries, path)
            ev["result"] = _enf_result()
            _save_path(path)
            _save_raw(entries, audit)
        return {"removed": removed}


def toggle_path_rule(id, enabled, by="dashboard"):
    with _lock:
        entries, _ = _load_raw()
        path = _load_path()
        r = next((x for x in path["rules"] if x.get("id") == id), None)
        if not r:
            raise safety.BlockError("правило не найдено: %s" % id)
        r["enabled"] = bool(enabled)
        _render(entries, path)
        _save_path(path)
        return {"id": id, "enabled": r["enabled"]}


def set_path_master(enabled, by="dashboard"):
    with _lock:
        entries, audit = _load_raw()
        path = _load_path()
        path["enabled"] = bool(enabled)
        ev = _audit(audit, "path_master", "*", by, "on" if enabled else "off")
        _render(entries, path)
        ev["result"] = _enf_result()
        _save_path(path)
        _save_raw(entries, audit)
        return {"enabled": path["enabled"]}
