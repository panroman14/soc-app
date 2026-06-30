"""Enforcement seam — WHERE active bans are applied, separate from WHERE state is
stored (storage.py).

Targets + groups
----------------
A *target* is a destination (`{id, type, ...params}` from config.BAN_TARGETS). Each
type has an adapter that is a full-state reconciler: given the desired set of CIDRs
routed to that target (+ enabled 403 path patterns) it makes its side match,
idempotently. A *group* (config.BAN_GROUPS) maps a name to a subset of target ids;
a ban carries a `group` and is applied to exactly those targets.

Types shipped:
  ingress-cm : render geo/if into the ingress-nginx controller ConfigMap (k8s)
  noop       : do nothing — state is served via /list for pull-agents (nginx-file
               agent) or enforced out-of-band
  nginx-file : (Phase 5) rendered on the VM by the pull-agent → behaves as noop here
  cloudflare : (Phase 4) not yet implemented → behaves as noop here

Unknown/not-yet-implemented types degrade to noop so a forward-looking config never
crashes the service.
"""
from . import config, render, settings


def _ingress_ns_cm():
    return settings.get("CONTROLLER_NS"), settings.get("CONTROLLER_CM")


# ── adapters: (apply_fn, status_fn) keyed by target TYPE ──────────────────────
def _ingress_apply(target, cidrs, patterns, path_enabled):
    from . import k8s
    ns, cm = _ingress_ns_cm()
    cur = k8s.get_cm_data(ns, cm)
    patch = render.controller_patch(cidrs, patterns, path_enabled,
                                    cur.get("http-snippet", ""), cur.get("server-snippet", ""))
    k8s.patch_cm_data(ns, cm, patch["data"])


def _ingress_status(target, patterns, master):
    from . import k8s
    ns, cm = _ingress_ns_cm()
    expected = render.path_if_body(patterns, master).strip()
    reachable, snip = True, ""
    try:
        snip = k8s.get_cm_data(ns, cm).get("server-snippet", "")
    except Exception:
        reachable = False
    m = render._SECTION.search(snip)
    managed = m.group(0) if m else ""
    present = (expected in managed) if expected else ("request_uri ~*" not in managed)
    return {"controller_reachable": reachable, "rendered_present": present,
            "rendered_ok": bool(reachable and present)}


def _noop_apply(target, cidrs, patterns, path_enabled):
    pass


def _noop_status(target, patterns, master):
    return {"controller_reachable": True, "rendered_present": True, "rendered_ok": True}


def _cf_apply(target, cidrs, patterns, path_enabled):
    from . import cloudflare
    cloudflare.reconcile(target, cidrs)   # path-403 is not a CF concept; IPs only


def _cf_status(target, patterns, master):
    from . import cloudflare
    st = cloudflare.check(target)
    return {"controller_reachable": bool(st.get("token_valid")),
            "rendered_present": bool(st.get("ok")),
            "rendered_ok": bool(st.get("ok"))}


_ADAPTERS = {
    "ingress-cm": (_ingress_apply, _ingress_status),
    "noop": (_noop_apply, _noop_status),
    "nginx-file": (_noop_apply, _noop_status),   # Phase 5: VM pull-agent renders it
    "cloudflare": (_cf_apply, _cf_status),
}

# last apply() error per target id (None = ok) — surfaced via /targets and check.
_last_errors = {}


def last_errors():
    return dict(_last_errors)


# ── targets + group resolution ────────────────────────────────────────────────
def _enrolled_nodes():
    """Enrolled nginx-VM agents, as auto-promoted nginx-file targets. Lazy import to
    avoid an import cycle (nodes → storage; enforce is imported by store)."""
    try:
        from . import nodes
        return nodes.all_nodes()
    except Exception:
        return []


def _env_targets():
    """Synthetic per-environment targets: each env that enables its own Cloudflare or
    ingress-nginx backend contributes one target tagged with that env. No secrets are
    placed here (cloudflare.py looks the token up by env) — safe to expose via /targets."""
    try:
        from . import environments
        envs = environments.all_envs()
    except Exception:
        return []
    out = []
    for e in envs:
        cf = e.get("cloudflare") or {}
        if cf.get("enabled") and cf.get("token"):
            out.append({"id": "cf:" + e["id"], "type": "cloudflare", "env": e["id"],
                        "mode": cf.get("mode") or ""})
        ing = e.get("ingress") or {}
        if ing.get("enabled"):
            out.append({"id": "ingress:" + e["id"], "type": "ingress-cm", "env": e["id"],
                        "ns": ing.get("ns") or "", "cm": ing.get("cm") or ""})
    return out


def targets():
    """Configured targets + auto-promoted enrolled nodes + per-env backends.

    A freshly enrolled agent becomes an nginx-file target automatically (its `group`
    is its env). Each env that enables Cloudflare/ingress adds a synthetic target.
    Explicit config wins if an id collides."""
    out = [dict(t) for t in (settings.get("BAN_TARGETS") or []) if t.get("id") and t.get("type")]
    have = {t["id"] for t in out}
    for n in _enrolled_nodes():
        if n["id"] not in have:
            out.append({"id": n["id"], "type": n.get("target_type") or "nginx-file",
                        "group": n.get("group") or "", "env": n.get("group") or "", "enrolled": True})
            have.add(n["id"])
    for t in _env_targets():
        if t["id"] not in have:
            out.append(t)
            have.add(t["id"])
    return out


def all_target_ids():
    return [t["id"] for t in targets()]


def _adapter(t):
    return _ADAPTERS.get(t.get("type"), _ADAPTERS["noop"])


def _effective_groups():
    """BAN_GROUPS overlaid with env membership: every target tagged with an env (an
    enrolled node, or a synthetic per-env Cloudflare/ingress backend) is added to that
    env's group, so a ban routed to env `prod` fans out to all of prod's backends."""
    groups_cfg = dict(settings.get("BAN_GROUPS") or {})
    for t in targets():
        env = t.get("env")
        if env:
            groups_cfg.setdefault(env, [])
            if t["id"] not in groups_cfg[env]:
                groups_cfg[env] = list(groups_cfg[env]) + [t["id"]]
    return groups_cfg


def resolve_group(group):
    """Group name → list of target ids it applies to.
      - explicit group → its members (intersected with real targets)
      - None/empty/unknown → ALL targets (safe maximum)
    """
    ids = set(all_target_ids())
    eff = _effective_groups()
    if group and group in eff:
        return [tid for tid in eff[group] if tid in ids]
    if group:
        # Unknown/typo'd/renamed group → ALL targets (safe maximum). Since enrolled
        # nodes now auto-join, "ALL" can include Cloudflare + every VM — surface it so
        # a stale group name doesn't silently over-ban.
        print("[enforce] group %r not found → routing ban to ALL %d targets" %
              (group, len(ids)), flush=True)
    return list(ids)


def groups():
    """All known group names → resolved target ids (incl. the implicit default)."""
    out = {g: resolve_group(g) for g in _effective_groups()}
    default = settings.get("BAN_GROUP_DEFAULT")
    if default:                          # never inject a blank/None group key
        out.setdefault(default, resolve_group(default))
    return out


# ── apply / status ────────────────────────────────────────────────────────────
def _patterns_for(per_target_patterns, tid):
    """Back-compat: callers may pass a per-target dict {tid:[pat]} OR a flat list
    (same patterns for every target)."""
    if isinstance(per_target_patterns, dict):
        return per_target_patterns.get(tid, [])
    return per_target_patterns or []


def apply(per_target_cidrs, per_target_patterns, path_enabled):
    """Reconcile each configured target to its routed CIDR set + its 403 patterns.
    per_target_cidrs: {target_id: [cidr, ...]} (already collapsed).
    per_target_patterns: {target_id: [pattern, ...]} (routed by each rule's group);
      a flat list is also accepted and applied to every target.

    Per-target failures are isolated: a remote target (e.g. Cloudflare) being down
    must NOT abort the ban or block other targets — the entry is still saved and the
    periodic resync re-applies it. The error is recorded for the check endpoint."""
    for t in targets():
        cidrs = per_target_cidrs.get(t["id"], [])
        try:
            _adapter(t)[0](t, cidrs, _patterns_for(per_target_patterns, t["id"]), path_enabled)
            _last_errors[t["id"]] = None
        except Exception as e:
            _last_errors[t["id"]] = str(e)
            print("[enforce] target %s (%s) apply failed: %s" % (t["id"], t.get("type"), e), flush=True)


def render_status(per_target_patterns, master):
    """Aggregate 403-render health across targets that enforce paths (worst wins).
    Also returns per-target detail for the dashboard. Accepts a per-target dict
    {tid:[pat]} or a flat list (same patterns for every target)."""
    detail = {}
    for t in targets():
        detail[t["id"]] = {"type": t["type"], **_adapter(t)[1](t, _patterns_for(per_target_patterns, t["id"]), master)}
    vals = list(detail.values()) or [{"controller_reachable": True,
                                      "rendered_present": True, "rendered_ok": True}]
    return {
        "targets": detail,
        "controller_reachable": all(v["controller_reachable"] for v in vals),
        "rendered_present": all(v["rendered_present"] for v in vals),
        "rendered_ok": all(v["rendered_ok"] for v in vals),
    }
