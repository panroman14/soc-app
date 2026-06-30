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


def _entry_target_ids(e, gcache, all_ids):
    """Target ids a denylist ENTRY enforces on. New attachment model (groups[]/
    targets[]/all) mirrors the 403 path rules; falls back to the legacy single
    `group`. `gcache` memoizes resolve_group across entries in one render."""
    def _grp(g):
        if g not in gcache:
            gcache[g] = set(enforce.resolve_group(g))
        return gcache[g]
    if e.get("all"):
        return set(all_ids)
    if "groups" in e or "targets" in e:
        ids = set(e.get("targets") or [])
        for g in (e.get("groups") or []):
            ids |= _grp(g)
        return ids & set(all_ids)
    return set(_grp(e.get("group")))   # legacy single-group entry


def _cidrs_for_target(active, target_id, ent_ids):
    """Collapsed CIDR set routed to one target: every active entry whose resolved
    target set includes this target. `ent_ids` is the {id(entry): set(target_ids)}
    memo computed once per render."""
    return safety.collapse([e["cidr"] for e in active if target_id in ent_ids.get(id(e), ())])


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
    tids = enforce.all_target_ids()
    all_ids = set(tids)
    # Resolve each entry's target set ONCE (group memo shared across entries — a big
    # saving when many bans share a group, since resolve_group walks targets+nodes).
    gcache = {}
    ent_ids = {id(e): _entry_target_ids(e, gcache, all_ids) for e in active}
    # per-target desired CIDR sets (routed by each ban's attachment)
    per_target = {tid: _cidrs_for_target(active, tid, ent_ids) for tid in tids}
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
        gcache, all_ids = {}, set(enforce.all_target_ids())
        act = [e for e in act if target in _entry_target_ids(e, gcache, all_ids)]
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


def _attach_for(src, dflt_group, has_attach):
    """Build the routing field(s) stored on an entry from a call/item dict `src`.
    New model (groups/targets/all) when any attachment key is present anywhere;
    otherwise the legacy single `group`."""
    if has_attach and any(k in src for k in ("groups", "targets", "all")):
        return {"groups": [str(g).strip() for g in (src.get("groups") or []) if str(g).strip()],
                "targets": [str(t).strip() for t in (src.get("targets") or []) if str(t).strip()],
                "all": bool(src.get("all"))}
    return {"group": src.get("group", dflt_group)}


def block_many(cidrs=None, items=None, reason="", added_by="dashboard", ttl=0, force=False,
               group=None, groups=None, targets=None, all=False):
    """Block several CIDRs with a SINGLE render/reload. Invalid ones are skipped.

    Either `cidrs` (list, shared `reason`) or `items` ([{cidr, reason}], per-CIDR reason).
    Attachment (where the ban enforces) is the call-level groups/targets/all, overridable
    per item; falls back to the legacy single `group` when no attachment is supplied.
    """
    dflt_group = group or settings.get("BAN_GROUP_DEFAULT")
    call_attach = {"groups": groups, "targets": targets, "all": all}
    has_attach = bool(groups or targets or all) or bool(items and any(
        k in it for it in items for k in ("groups", "targets", "all")))
    pairs = []   # (cidr, reason, attach_dict)
    if items:
        for it in items:
            src = {**call_attach, **{k: it[k] for k in ("groups", "targets", "all", "group") if k in it}}
            pairs.append((it.get("cidr", ""), it.get("reason", reason),
                          _attach_for(src, dflt_group, has_attach)))
    else:
        att = _attach_for(call_attach, dflt_group, has_attach)
        pairs = [(c, reason, att) for c in (cidrs or [])]
    valid, skipped = [], []
    for c, rs, att in pairs:
        try:
            valid.append((safety.validate(c, force=force), rs, att))
        except safety.BlockError as e:
            skipped.append({"cidr": c, "error": str(e)})
    with _lock:
        entries, audit = _load_raw()
        now = _now()
        added, seen, evs = [], set(), []
        for c, rs, att in valid:
            if c in seen:
                continue
            seen.add(c)
            entries = [e for e in entries if e["cidr"] != c]
            entries.append({"cidr": c, "reason": rs, "added_by": added_by,
                            "ts": now, "ttl": int(ttl or 0), **att})
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
        return {"enabled": True, "rules": [], "off_types": []}
    try:
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            raise ValueError("path_rules.json is not an object")
        obj.setdefault("enabled", True)
        # backend types where 403 enforcement is switched off (per-type kill switch)
        if not isinstance(obj.get("off_types"), list):
            obj["off_types"] = []
        if not isinstance(obj.get("rules"), list):
            obj["rules"] = []
        # migrate single `group` → attachment model {groups:[], targets:[], all:bool}.
        # Legacy rule with an empty group used to mean "all targets" → keep that via all=True
        # so an upgrade never silently drops existing path protection.
        for r in obj["rules"]:
            if "groups" not in r and "all" not in r:
                g = (r.get("group") or "").strip()
                r["groups"] = [g] if g else []
                r["targets"] = []
                r["all"] = not g          # old empty-group == applied everywhere
            r.setdefault("groups", [])
            r.setdefault("targets", [])
            r.setdefault("all", False)
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


def _rule_target_ids(r, gcache, all_ids):
    """The set of target ids an enabled path rule applies to, from its attachment:
    union of its groups' members + its individual targets. `all`=True → every target.
    Empty attachment → NOTHING (a rule does nothing until it's attached)."""
    if r.get("all"):
        return all_ids
    ids = set(r.get("targets") or [])
    for g in (r.get("groups") or []):
        if not g:
            continue
        if g not in gcache:
            gcache[g] = set(enforce.resolve_group(g))
        ids |= gcache[g]
    return ids


def _type_of(tids):
    """{target_id: type} for the given ids (used to honour the per-type kill switch)."""
    by = {t["id"]: t.get("type") for t in enforce.targets()}
    return {tid: by.get(tid) for tid in tids}


def _patterns_per_target(path, tids):
    """{target_id: [pattern,...]} — each enabled path rule routed to the targets it is
    attached to (groups ∪ targets, or all). Unattached rules render nowhere. Targets
    whose backend type is in `off_types` get no patterns (per-type kill switch)."""
    out = {tid: [] for tid in tids}
    gcache, all_ids = {}, set(tids)
    off = set(path.get("off_types") or [])
    types = _type_of(tids) if off else {}
    for r in path.get("rules", []):
        if not r.get("enabled"):
            continue
        rt = _rule_target_ids(r, gcache, all_ids)
        for tid in tids:
            if tid in rt and types.get(tid) not in off:
                out[tid].append(r["pattern"])
    return out


def patterns_for_target(target_id, path=None):
    """Enabled 403 patterns that apply to ONE target (used by the nginx-file pull
    agent's /nginx_snippet). Routed by each rule's attachment (groups ∪ targets/all)."""
    if path is None:
        path = _load_path()
    # per-type kill switch: if this target's backend type is off, render nothing
    off = set(path.get("off_types") or [])
    if off and _type_of([target_id]).get(target_id) in off:
        return []
    pats, gcache = [], {}
    all_ids = set(enforce.all_target_ids())
    for r in path.get("rules", []):
        if not r.get("enabled"):
            continue
        if target_id in _rule_target_ids(r, gcache, all_ids):
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
        return {"enabled": master, "off_types": list(path.get("off_types") or []),
                "count": len(rules), "enabled_count": enabled_n, **st}


def set_path_type(type_, enabled, by="dashboard"):
    """Per-backend-type 403 kill switch: turn 403 enforcement on/off for ALL targets
    of a given type (nginx-file / ingress-cm / cloudflare). Enabling a type also lifts
    the global section kill switch so the toggle does what the operator expects."""
    type_ = str(type_ or "").strip()
    if not type_:
        raise safety.BlockError("пустой тип таргета")
    with _lock:
        entries, audit = _load_raw()
        path = _load_path()
        off = set(path.get("off_types") or [])
        if enabled:
            off.discard(type_)
            path["enabled"] = True
        else:
            off.add(type_)
        path["off_types"] = sorted(off)
        ev = _audit(audit, "path_type", type_, by, "on" if enabled else "off")
        _render(entries, path)
        ev["result"] = _enf_result()
        _save_path(path)
        _save_raw(entries, audit)
        return {"off_types": path["off_types"], "enabled": path["enabled"]}


def _norm_attach(groups, targets, all_):
    """Normalize an attachment from the API into (groups[], targets[], all)."""
    gl = [str(g).strip() for g in (groups or []) if str(g).strip()]
    tl = [str(t).strip() for t in (targets or []) if str(t).strip()]
    return gl, tl, bool(all_)


def upsert_path_rule(id=None, name="", pattern="", enabled=True, force=False, by="dashboard",
                     groups=None, targets=None, all=False):
    pattern = safety.validate_pattern(pattern, force=force)  # raises BlockError
    gl, tl, al = _norm_attach(groups, targets, all)          # attachment ('' all = nothing)
    with _lock:
        entries, audit = _load_raw()
        path = _load_path()
        rules = path["rules"]
        if id:
            found = next((r for r in rules if r.get("id") == id), None)
            if not found:
                raise safety.BlockError("правило не найдено: %s" % id)
            found.update({"name": name or found.get("name", ""), "pattern": pattern,
                          "enabled": bool(enabled), "groups": gl, "targets": tl, "all": al})
            found.pop("group", None)
        else:
            # dedup: identical pattern already exists → no-op, return it (no duplicate)
            dup = next((r for r in rules if r.get("pattern") == pattern), None)
            if dup:
                return {"id": dup.get("id"), "rules": len(rules), "duplicate": True}
            id = _new_path_id(rules)
            rules.append({"id": id, "name": name, "pattern": pattern, "enabled": bool(enabled),
                          "groups": gl, "targets": tl, "all": al, "added_by": by, "ts": _now()})
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
