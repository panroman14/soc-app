"""blocklist-api — tiny in-cluster service the dashboard calls to (un)block IPs.

It renders the active denylist into the ingress-nginx controller ConfigMap;
ingress-nginx watches that CM and reloads automatically (no manual reload).

Endpoints (Bearer auth, except /healthz):
  GET  /healthz
  GET  /list                          -> active blocks
  GET  /audit?limit=                  -> recent actions
  POST /block   {cidr,reason,ttl,force,added_by}
  POST /unblock {cidr}
"""
import secrets
import threading
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import config, enforce, environments, nodes, notify, safety, settings, store

app = FastAPI(title="blocklist-api", version="0.1.0")

# Endpoints an agent's per-node token may reach (besides /healthz). Everything else
# requires the admin token. /enroll is gated by ENROLL_SECRET (handled below).
_NODE_PATHS = {"/heartbeat", "/nginx_snippet"}


def _bearer(request):
    hdr = request.headers.get("authorization", "")
    return hdr[7:] if hdr.startswith("Bearer ") else ""


@app.middleware("http")
async def auth(request: Request, call_next):
    path = request.url.path
    # Open: health + the agent installer/binary (carry no secrets; secrets are passed
    # via env on the curl line, never embedded).
    if path == "/healthz" or path.startswith("/install/"):
        return await call_next(request)

    # Dev mode: no admin token configured → open (preserves prior behavior).
    if not config.TOKEN:
        return await call_next(request)

    token = _bearer(request)
    if token and secrets.compare_digest(token, config.TOKEN):
        request.state.scope = "admin"
        return await call_next(request)

    # Enrollment: present the shared ENROLL_SECRET to mint a per-node token.
    if path == "/enroll":
        if config.ENROLL_SECRET and token and secrets.compare_digest(token, config.ENROLL_SECRET):
            request.state.scope = "enroll"
            return await call_next(request)
        return JSONResponse({"error": "enrollment unauthorized"}, status_code=401)

    # Per-node token: limited to that node's own snippet + heartbeat.
    if path in _NODE_PATHS:
        nid = nodes.token_owner(token)
        if nid:
            request.state.scope = "node"
            request.state.node_id = nid
            return await call_next(request)

    return JSONResponse({"error": "unauthorized"}, status_code=401)


@app.get("/healthz")
def healthz():
    return {"ok": True}


def _serve_file(path, media_type):
    from fastapi.responses import PlainTextResponse
    try:
        with open(path, "r", encoding="utf-8") as f:
            return PlainTextResponse(f.read(), media_type=media_type)
    except Exception:
        return PlainTextResponse("# not found\n", status_code=404, media_type=media_type)


@app.get("/install/soc-nginx-agent.sh")
def install_sh():
    """The agent installer (the curl|bash one-liner the dashboard shows)."""
    return _serve_file(config.INSTALLER_PATH, "text/x-shellscript")


@app.get("/install/soc-nginx-agent.py")
def install_agent():
    """The agent source — downloaded by install.sh onto each nginx VM."""
    return _serve_file(config.AGENT_PATH, "text/x-python")


@app.get("/list")
def list_blocks(target: str = ""):
    """Active blocks. `?target=<id>` filters to entries routed to that target —
    used by the nginx-file pull-agent to fetch only its own CIDRs."""
    return {"blocks": store.list_active(target or None), "target": target or None}


@app.get("/targets")
def list_targets():
    """Configured enforcement targets + groups (for the dashboard + agents)."""
    return {"targets": enforce.targets(), "groups": enforce.groups(),
            "default_group": config.BAN_GROUP_DEFAULT,
            "last_errors": enforce.last_errors()}


@app.get("/targets/check")
def check_targets(id: str = ""):
    """«Проверить» button: probe target connectivity/setup. Cloudflare targets get
    a live API probe (token valid? list/rule present? item count); others report
    their last apply error. `?id=` checks one target, else all."""
    from . import cloudflare
    errs = enforce.last_errors()
    out = []
    for t in enforce.targets():
        if id and t["id"] != id:
            continue
        if t.get("type") == "cloudflare":
            out.append({"type": "cloudflare", **cloudflare.check(t)})
        else:
            le = errs.get(t["id"])
            out.append({"id": t["id"], "type": t.get("type"), "ok": le is None,
                        "error": le})
    return {"checks": out}


@app.get("/nginx_snippet")
def nginx_snippet(request: Request, target: str = ""):
    """Rendered nginx config for a target's CIDR set — pulled by soc-nginx-agent on
    each VM. Render lives here (DRY: same geo/CF logic as ingress, one source of CF
    ranges). The agent writes `http` into conf.d (http context) and `server` into a
    file it includes inside the server block, then reloads nginx.
      http   : geo/map blocks → sets $soc_blocked (CF-aware real client IP)
      server : if ($soc_blocked) { return 403; } + optional 403 path rules
    """
    from . import render, safety
    # A per-node token may only read its OWN snippet; admin may read any target.
    # Default to the RESTRICTIVE scope — never fail open to admin.
    if getattr(request.state, "scope", "node") == "node":
        target = getattr(request.state, "node_id", "") or target
    blocks = store.list_active(target or None)
    cidrs = safety.collapse([b["cidr"] for b in blocks])
    path = store.list_path_rules()
    # only the 403 patterns whose group routes to THIS node (empty group = all)
    patterns = store.patterns_for_target(target or "", path) if target else \
        [r["pattern"] for r in path.get("rules", []) if r.get("enabled")]
    return {"target": target or None, "count": len(cidrs),
            "http": render.geo_body(cidrs),
            "server": render.if_body(patterns, bool(path.get("enabled", True)))}


@app.get("/audit")
def audit(limit: int = 100):
    return {"audit": store.audit_log(min(max(limit, 1), config.AUDIT_MAX))}


# ── node enrollment + visibility ──────────────────────────────────────────────
@app.post("/enroll")
async def enroll(request: Request):
    """An agent self-registers with the shared ENROLL_SECRET and gets a per-node
    token back. Idempotent: re-enrolling the same id returns the same token."""
    body = await request.json()
    try:
        rec = nodes.enroll(
            node_id=body.get("node_id", ""), hostname=body.get("hostname", ""),
            group=body.get("group", ""), target_type=body.get("target_type", "nginx-file"),
            files=body.get("files"), agent_version=body.get("agent_version", ""),
            ip=request.client.host if request.client else "")
        return {"ok": True, "node_id": rec["id"], "token": rec["token"]}
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.post("/heartbeat")
async def heartbeat(request: Request):
    """Agent liveness + host metrics. Node-scoped: the id ALWAYS comes from the token,
    never the request body — so no caller can write metrics for another node."""
    body = await request.json()
    nid = getattr(request.state, "node_id", "")
    if not nid:
        return JSONResponse({"ok": False, "error": "heartbeat requires a node token"},
                            status_code=403)
    n = nodes.heartbeat(nid, metrics=body.get("metrics"),
                        agent_version=body.get("agent_version", ""),
                        ip=request.client.host if request.client else "")
    if not n:
        return JSONResponse({"ok": False, "error": "unknown node"}, status_code=404)
    return {"ok": True, "node_id": nid}


@app.get("/nodes")
def list_nodes():
    """Enrolled nodes (tokens redacted) — for the dashboard «Ноды» tab."""
    return {"nodes": nodes.all_nodes(), "offline_after": config.NODE_OFFLINE_AFTER,
            "enroll_configured": bool(config.ENROLL_SECRET)}


@app.post("/node_delete")
async def node_delete(request: Request):
    """Revoke a node (deletes its token)."""
    body = await request.json()
    return {"ok": True, "deleted": nodes.delete(body.get("id", ""))}


@app.get("/settings")
def get_settings():
    """Operator-editable config (GUI override over ENV). Secrets redacted."""
    return {"settings": settings.public_view(), "locked": config.CONFIG_LOCK}


@app.post("/settings")
async def post_settings(request: Request):
    """Persist GUI edits (refused when CONFIG_LOCK=env)."""
    body = await request.json()
    try:
        applied = settings.set_many(body.get("updates") or body)
        return {"ok": True, "applied": applied}
    except PermissionError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=409)
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


@app.get("/environments")
def get_environments():
    """Environments (env=pool=project) for the dashboard — CF token redacted."""
    return {"environments": environments.public_view()}


@app.post("/environments")
async def post_environment(request: Request):
    body = await request.json()
    try:
        e = environments.upsert(env_id=body.get("id", ""), name=body.get("name", ""),
                                loki_url=body.get("loki_url"), cloudflare=body.get("cloudflare"),
                                ingress=body.get("ingress"))
        # a CF token change may invalidate the per-env discovery cache
        try:
            from . import cloudflare
            cloudflare._resolved.clear()
        except Exception:
            pass
        return {"ok": True, "id": e["id"]}
    except ValueError as ex:
        return JSONResponse({"ok": False, "error": str(ex)}, status_code=400)
    except Exception as ex:
        return JSONResponse({"ok": False, "error": str(ex)}, status_code=500)


@app.post("/environments/delete")
async def delete_environment(request: Request):
    body = await request.json()
    return {"ok": True, "deleted": environments.delete(body.get("id", ""))}


@app.get("/notify_config")
def get_notify_config():
    """Channels + rules for the dashboard (secrets redacted, last-send status)."""
    return notify.public_view()


@app.post("/notify_config")
async def post_notify_config(request: Request):
    body = await request.json()
    try:
        return {"ok": True, **notify.save_config(body.get("channels"), body.get("rules"))}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)


@app.post("/notify/test")
async def notify_test(request: Request):
    body = await request.json()
    return notify.test_channel(body.get("channel", ""))


@app.post("/notify")
async def notify_dispatch(request: Request):
    """Admin endpoint for the soc backend to push events (autoban / anomaly) into the
    same env-aware rule engine."""
    body = await request.json()
    notify.emit({"type": body.get("type", ""), "env": body.get("env", ""),
                 "severity": body.get("severity", "info"), "title": body.get("title", ""),
                 "text": body.get("text", ""), "fields": body.get("fields") or {}})
    return {"ok": True}


@app.get("/enroll_info")
def enroll_info():
    """Admin-only: data the dashboard needs to render the «Add node» install
    one-liner (the enroll secret + the URL agents should use to reach us)."""
    return {"enroll_configured": bool(config.ENROLL_SECRET),
            "enroll_secret": config.ENROLL_SECRET,
            "public_url": config.PUBLIC_URL}


@app.post("/block")
async def block(request: Request):
    body = await request.json()
    try:
        res = store.block(
            cidr=body.get("cidr", ""), reason=body.get("reason", ""),
            added_by=body.get("added_by", "dashboard"),
            ttl=body.get("ttl", 0), force=bool(body.get("force", False)),
            group=body.get("group"))
        return {"ok": True, **res}
    except safety.BlockError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.post("/block_bulk")
async def block_bulk(request: Request):
    body = await request.json()
    try:
        res = store.block_many(
            cidrs=body.get("cidrs"), items=body.get("items"),
            reason=body.get("reason", ""), added_by=body.get("added_by", "dashboard"),
            ttl=body.get("ttl", 0), force=bool(body.get("force", False)),
            group=body.get("group"))
        return {"ok": True, **res}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.post("/unblock")
async def unblock(request: Request):
    body = await request.json()
    try:
        return {"ok": True, **store.unblock(body.get("cidr", ""))}
    except safety.BlockError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.post("/unblock_all")
async def unblock_all(request: Request):
    try:
        return {"ok": True, **store.clear_all(by="dashboard")}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.post("/resync")
async def resync(request: Request):
    try:
        return {"ok": True, **store.resync()}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/path_rules")
def path_rules():
    return store.list_path_rules()


@app.get("/path_status")
def path_status():
    return store.path_render_status()


@app.post("/path_rule")
async def path_rule(request: Request):
    body = await request.json()
    try:
        # back-compat: a lone `group` string still works (→ groups=[group])
        groups = body.get("groups")
        if groups is None and body.get("group"):
            groups = [body.get("group")]
        res = store.upsert_path_rule(
            id=body.get("id"), name=body.get("name", ""),
            pattern=body.get("pattern", ""), enabled=bool(body.get("enabled", True)),
            force=bool(body.get("force", False)),
            groups=groups, targets=body.get("targets"), all=bool(body.get("all", False)))
        return {"ok": True, **res}
    except safety.BlockError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.post("/path_rule_delete")
async def path_rule_delete(request: Request):
    body = await request.json()
    try:
        return {"ok": True, **store.delete_path_rule(body.get("id", ""))}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.post("/path_rule_toggle")
async def path_rule_toggle(request: Request):
    body = await request.json()
    try:
        return {"ok": True, **store.toggle_path_rule(
            body.get("id", ""), bool(body.get("enabled", True)))}
    except safety.BlockError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.post("/path_master")
async def path_master(request: Request):
    body = await request.json()
    try:
        return {"ok": True, **store.set_path_master(bool(body.get("enabled", True)))}
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


def _prune_loop():
    while True:
        try:
            n = store.prune()
            if n:
                print("[prune] expired %d entries" % n, flush=True)
        except Exception as e:
            print("[prune] error:", e, flush=True)
        time.sleep(config.PRUNE_INTERVAL)


def _resync_loop():
    while True:
        time.sleep(config.RESYNC_INTERVAL)
        try:
            store.resync()
        except Exception as e:
            print("[resync] error:", e, flush=True)


_node_state = {}  # node id → last-seen {offline, nginx_bad} to notify only on transitions


def _node_watch_loop():
    """Notify once when a node goes offline or its nginx -t starts failing."""
    while True:
        time.sleep(max(15, config.NODE_OFFLINE_AFTER // 2))
        try:
            for n in nodes.all_nodes():
                st = _node_state.setdefault(n["id"], {"offline": False, "nginx_bad": False})
                offline = not n.get("online")
                if offline and not st["offline"] and n.get("last_seen"):
                    notify.emit({"type": "node_offline", "env": n.get("group", ""),
                                 "severity": "warning", "title": "Нода офлайн: " + n["id"],
                                 "text": "", "fields": {"молчит_с": int(time.time()) - int(n.get("last_seen") or 0)}})
                st["offline"] = offline
                nb = (n.get("metrics") or {}).get("nginx_ok") is False
                if nb and not st["nginx_bad"]:
                    notify.emit({"type": "node_offline", "env": n.get("group", ""),
                                 "severity": "warning", "title": "nginx -t упал на " + n["id"],
                                 "text": "", "fields": {}})
                st["nginx_bad"] = nb
        except Exception as e:
            print("[node-watch] error:", e, flush=True)


@app.on_event("startup")
def _startup():
    if not config.TOKEN:
        print("[auth] WARNING: BLOCKLIST_TOKEN is empty — this API is UNAUTHENTICATED "
              "(anyone can ban IPs / change Cloudflare settings). Dev only; set a token "
              "in production.", flush=True)
    if config.ENROLL_SECRET and config.PUBLIC_URL and not config.PUBLIC_URL.startswith("https://"):
        print("[enroll] WARNING: PUBLIC_URL is not https:// — the agent install one-liner "
              "downloads + runs code over plaintext HTTP (MITM = root RCE on nginx VMs). "
              "Use HTTPS for any deployment crossing an untrusted network.", flush=True)
    threading.Thread(target=_prune_loop, daemon=True).start()
    threading.Thread(target=_resync_loop, daemon=True).start()
    threading.Thread(target=_node_watch_loop, daemon=True).start()
