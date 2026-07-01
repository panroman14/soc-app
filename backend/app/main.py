"""soc backend (Phase 1).

FastAPI service that:
  - polls Loki on a background loop and aggregates a traffic/attack summary,
  - persists snapshots to SQLite,
  - exposes /metrics (Prometheus, compatible with the old exporter),
  - exposes /api/summary and /api/history for the dashboard.

Phase 2 adds the LLM insight worker; Phase 3 adds the web UI; Phase 4 auth.
"""
import base64
import ipaddress
import json
import os
import re
import secrets
import urllib.parse
import threading
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import analyze, config, db, llm, loki, logging_conf, metrics

log = logging_conf.setup()

app = FastAPI(title="soc", version="0.4.0")

# GUI-override for BLOCKLIST_API_URL/TOKEN: env vars are the default, but an
# operator can point the dashboard at blocklist-api from Resources → Ingress
# without touching the dashboard's own deploy config. Stored in the same
# settings table as branding; applied to the config module attribute directly
# (every call site does config.BLOCKLIST_API_URL/TOKEN at call time, so a live
# mutation takes effect immediately — no restart needed).
def _apply_blocklist_override():
    o = db.setting_get("blocklist_api_override", {}) or {}
    if o.get("url"):
        config.BLOCKLIST_API_URL = o["url"]
    if o.get("token"):
        config.BLOCKLIST_API_TOKEN = o["token"]


_apply_blocklist_override()


@app.middleware("http")
async def no_cache_html(request: Request, call_next):
    """Always revalidate the SPA shell so browsers pick up new deploys (no stale UI)."""
    resp = await call_next(request)
    p = request.url.path
    if p == "/" or p.endswith(".html"):
        resp.headers["Cache-Control"] = "no-cache, must-revalidate"
    return resp


_CSP = ("default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
        "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "
        "base-uri 'self'; form-action 'self'; frame-ancestors 'none'")


@app.middleware("http")
async def security(request: Request, call_next):
    """Security headers on every response + CSRF Origin check on mutations.

    S4: the dashboard has no CSRF token and (with Basic auth) browsers replay creds,
    so a malicious page could POST bans. Reject mutating requests whose browser
    Origin doesn't match the site. Non-browser clients (curl) send no Origin → allowed.
    Also stamps a request id (O4) into logs + the X-Request-Id response header.
    """
    rid = (request.headers.get("x-request-id") or uuid.uuid4().hex[:12])
    logging_conf.set_rid(rid)
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("origin")
        if origin:
            o = origin.rstrip("/")
            allowed = (o in config.TRUSTED_ORIGINS) if config.TRUSTED_ORIGINS \
                else (urllib.parse.urlparse(o).netloc == request.headers.get("host", ""))
            if not allowed:
                return JSONResponse({"error": "cross-origin запрос отклонён (CSRF)"}, status_code=403)
    resp = await call_next(request)
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Content-Security-Policy", _CSP)
    resp.headers.setdefault("X-Request-Id", rid)
    return resp


@app.middleware("http")
async def basic_auth(request: Request, call_next):
    """HTTP Basic auth on everything except AUTH_EXEMPT.

    FAILS CLOSED: if no creds are configured, every non-exempt path returns 503
    (this is a ban/settings/backend-control appliance — never open by default).
    Set SOC_DEV_NO_AUTH=1 to intentionally run without auth on a trusted host."""
    if request.url.path in config.AUTH_EXEMPT:
        return await call_next(request)
    if not (config.BASIC_AUTH_USER and config.BASIC_AUTH_PASS):
        if config.DEV_NO_AUTH:
            return await call_next(request)          # explicit dev opt-in
        return JSONResponse(
            {"error": "auth не настроен — задай BASIC_AUTH_USER/BASIC_AUTH_PASS "
                      "(или SOC_DEV_NO_AUTH=1 для доверенного хоста)"},
            status_code=503)
    ok = False
    hdr = request.headers.get("authorization", "")
    if hdr.startswith("Basic "):
        try:
            user, _, pw = base64.b64decode(hdr[6:]).decode().partition(":")
            ok = (secrets.compare_digest(user, config.BASIC_AUTH_USER)
                  and secrets.compare_digest(pw, config.BASIC_AUTH_PASS))
        except Exception:
            ok = False
    if not ok:
        return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="soc"'})
    return await call_next(request)

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "frontend")

_state = {
    "summary": None, "loki_up": False, "updated": 0, "insight": None,
    "loki_error": None, "llm_up": None, "llm_error": None, "last_insight": 0,
    "analytics": None, "analytics_updated": 0,
    "digest": None, "digest_ts": 0,
    "path403": None, "path403_ts": 0,
}
_state_lock = threading.Lock()


def poll_loop():
    db.init()
    while True:
        try:
            summary = loki.collect_summary()
            ts = int(time.time())
            # mark not-yet-seen attacker subnets as "new" (first sighting)
            subs = [x["subnet"] for x in summary.get("top_subnets", [])]
            fresh = db.new_subnets(subs, ts)
            for x in summary.get("top_subnets", []):
                x["new"] = x["subnet"] in fresh
            with _state_lock:
                _state.update(summary=summary, loki_up=True, updated=ts, loki_error=None)
            db.save_snapshot(ts, summary)
            if ts % 3600 < config.POLL_INTERVAL:
                db.prune()
        except Exception as e:
            with _state_lock:
                _state.update(loki_up=False, loki_error=str(e))
            log.warning("[poll] error:", e)
        time.sleep(config.POLL_INTERVAL)


def _refresh_path403():
    """Poll blocklist-api for 403-path render health → cached for /metrics + /api/status.
    Off the Loki poll path (a blocklist-api stall must not delay data freshness)."""
    if not config.BLOCKLIST_API_URL:
        return
    try:
        _, ps = _blocklist_call("GET", "/path_status")
        if ps and "rendered_ok" in ps:
            with _state_lock:
                _state["path403"] = ps
                _state["path403_ts"] = int(time.time())
    except Exception as e:
        log.warning("[path403] status error:", e)


def analytics_loop():
    while True:
        try:
            data = loki.collect_analytics()
            with _state_lock:
                _state["analytics"] = data
                _state["analytics_updated"] = int(time.time())
        except Exception as e:
            log.warning("[analytics] error:", e)
        time.sleep(config.ANALYTICS_INTERVAL)


def insight_loop():
    while True:
        try:
            history = db.recent_snapshots(config.HISTORY_BASELINE)
            with _state_lock:
                latest = _state["summary"]
            if not (latest and history):
                time.sleep(15)   # not warmed up yet — retry soon, don't idle 10 min
                continue
            if not llm.enabled():
                # LLM turned off by the operator — don't poll the model or churn the
                # insight history; just reflect the disabled state and re-check soon.
                with _state_lock:
                    _state["llm_up"] = None
                    _state["llm_error"] = None
                time.sleep(30)
                continue
            severity, signals = analyze.detect(latest, history)
            insight = llm.analyze(latest, severity, signals)
            ts = int(time.time())
            db.save_insight(ts, insight["severity"], insight.get("headline", ""), insight)
            with _state_lock:
                prev_sev = _state.get("last_severity")
                _state["insight"] = {"ts": ts, **insight}
                _state["llm_up"] = insight.get("llm_ok", True)
                _state["llm_error"] = insight.get("llm_error")
                _state["last_insight"] = ts
                _state["last_severity"] = insight.get("severity")
            # Notify only on the transition INTO critical (not every interval).
            if insight.get("severity") == "critical" and prev_sev != "critical":
                _notify({"type": "anomaly_critical", "env": "", "severity": "critical",
                         "title": insight.get("headline", "Критическая аномалия трафика"),
                         "text": insight.get("summary", ""),
                         "fields": {"вредный_трафик": latest.get("malicious_ratio"),
                                    "атакующих_подсетей": latest.get("distinct_attacker_ips")}})
            log.info("[insight] %s: %s (llm_ok=%s)" % (
                insight["severity"], insight.get("headline"), insight.get("llm_ok")))
        except Exception as e:
            with _state_lock:
                _state["llm_up"] = False
                _state["llm_error"] = str(e)
            log.warning("[insight] error:", e)
        time.sleep(config.LLM_INTERVAL)


@app.on_event("startup")
def _startup():
    threading.Thread(target=poll_loop, daemon=True).start()
    threading.Thread(target=analytics_loop, daemon=True).start()
    threading.Thread(target=insight_loop, daemon=True).start()
    threading.Thread(target=autoban_loop, daemon=True).start()   # acts only when armed
    # Tor enrichment is opt-in (TOR_ENABLED=1). When on, keep the exit-list warm in
    # the background so no IP-profile click blocks on the ~700 KB download.
    if config.TOR_ENABLED:
        threading.Thread(target=tor_loop, daemon=True).start()


def tor_loop():
    while True:
        try:
            loki._tor_set(block=True)   # blocking refresh — off the request path
        except Exception as e:
            log.warning("[tor] loop error:", e)
        time.sleep(6 * 3600)


@app.get("/metrics", response_class=PlainTextResponse)
def prometheus_metrics():
    # fleet health from the cache only (never probe on a scrape); labels are backend
    # ids (slugs), not URLs — no secret/host leak on this unauthenticated endpoint.
    hc = _health_cache.get("d")
    backends = (hc or {}).get("backends") if hc else None
    with _state_lock:
        return metrics.render(_state["summary"], _state["loki_up"],
                              _state.get("path403"), backends=backends)


@app.get("/api/summary")
def api_summary(env: str = ""):
    # No env → the cached global snapshot (background poll). An env → a live, env-scoped
    # aggregate (the background loop stays global; per-env is computed on demand).
    if env:
        try:
            with loki.scope(env, _env_loki_url(env)):
                summ = loki.collect_summary()
            return JSONResponse({"updated": int(time.time()), "loki_up": True,
                                 "summary": summ, "env": env})
        except Exception as e:
            return JSONResponse({"updated": int(time.time()), "loki_up": False,
                                 "summary": None, "env": env, "error": str(e)})
    with _state_lock:
        return JSONResponse({
            "updated": _state["updated"],
            "loki_up": _state["loki_up"],
            "summary": _state["summary"],
        })


@app.get("/api/logs")
def api_logs(stream: str = "access", minutes: int = 15, q: str = "", env: str = ""):
    """Raw nginx log lines from Loki for the Logs viewer (env-scoped)."""
    if not config.LOKI_URL:
        return JSONResponse({"enabled": False, "lines": []})
    st = "error" if stream == "error" else "access"
    try:
        with loki.scope(env, _env_loki_url(env)):
            lines = loki.recent_logs(st, min(max(int(minutes), 1), 1440), q, 300)
        return JSONResponse({"enabled": True, "lines": lines})
    except Exception as e:
        return JSONResponse({"enabled": True, "lines": [], "error": str(e)})


# ── Live Logs explorer ────────────────────────────────────────────────────────
@app.get("/api/log_labels")
def api_log_labels(env: str = ""):
    """Label names for the source-picker tree."""
    if not config.LOKI_URL:
        return {"enabled": False, "labels": []}
    with loki.scope(env, _env_loki_url(env)):
        return {"enabled": True, "labels": loki.log_labels()}


@app.get("/api/log_label_values")
def api_log_label_values(name: str, env: str = ""):
    if not config.LOKI_URL:
        return {"enabled": False, "values": []}
    with loki.scope(env, _env_loki_url(env)):
        return {"enabled": True, "name": name, "values": loki.log_label_values(name)}


_FACET_FIELDS = ("status", "method", "path", "ip", "country", "host", "ua")


def _parse_omnibar(text):
    """Datadog-style omnibar → {chips, search, attacks_only}. Grammar: facet:value,
    -facet:value (neq), status:4xx (class), rt:>1.5 (gte), bare words → free-text.
    Values never reach LogQL raw — they become escaped chips (see loki._chip_clause)."""
    import shlex
    chips, words, attacks = [], [], False
    try:
        toks = shlex.split(text or "")
    except ValueError:
        toks = (text or "").split()
    for tok in toks:
        if tok.lower() in ("attacks", "attack", "атаки"):
            attacks = True
            continue
        neg = tok.startswith("-")
        t = tok[1:] if neg else tok
        if ":" in t:
            f, _, v = t.partition(":")
            f = {"code": "status", "url": "path", "uri": "path"}.get(f, f)
            if f in loki._LOG_FIELDS and v:
                if f == "status" and re.match(r"^[2345]xx$", v, re.I):
                    chips.append({"field": "status", "op": "class", "value": v[0]})
                elif f == "status" and re.match(r"^[<>]=?\d{3}$", v):
                    # status:>=400 / >400 / >=500 → class-range digits (Q1). >=N → the
                    # first digit and all higher classes; the "errors" quick button uses this.
                    d = int(v.lstrip("<>=")[0])
                    digits = "".join(str(x) for x in range(d, 6)) if v[0] == ">" else \
                             "".join(str(x) for x in range(1, d + 1))
                    chips.append({"field": "status", "op": "class", "value": digits})
                elif f == "rt" and v[0] in "><=":
                    chips.append({"field": "rt", "op": "gte", "value": re.sub(r"[^\d.]", "", v)})
                else:
                    chips.append({"field": f, "op": "neq" if neg else "eq", "value": v})
                continue
        words.append(tok)
    return {"chips": chips, "search": " ".join(words), "attacks_only": attacks}


def _logql_from_body(body):
    chips = list(body.get("chips") or [])
    search = body.get("search") or ""
    attacks = bool(body.get("attacks_only"))
    if body.get("omnibar"):                       # omnibar text → escaped chips (Logs v2)
        p = _parse_omnibar(body["omnibar"])
        chips += p["chips"]
        search = (search + " " + p["search"]).strip()
        attacks = attacks or p["attacks_only"]
    return loki.build_logql(
        sources=body.get("sources") or {}, chips=chips, search=search,
        regex=bool(body.get("regex")), attacks_only=attacks, raw=body.get("raw") or "")


# ── Loki-source registry: fan logs across N Loki backends (20 VMs + 2 clusters) ──
def _log_sources():
    return db.setting_get("log_sources", {"items": {}}) or {"items": {}}


def _loki_targets(selected=None):
    """[(id, url)] Loki backends to query: registered sources, or config.LOKI_URL as
    implicit id 'default'. `selected` (list of ids) narrows the set."""
    items = _log_sources().get("items") or {}
    lst = [(sid, e.get("url")) for sid, e in items.items() if e.get("url")]
    if not lst and config.LOKI_URL:
        lst = [("default", config.LOKI_URL)]
    if selected:
        sel = set(selected)
        return [t for t in lst if t[0] in sel] or lst
    return lst


def _loki_fanout(fn, selected=None):
    """Run fn() against each Loki source concurrently (loki.scope sets the base URL).
    Returns [(source_id, result_or_None, error_or_None)]."""
    from concurrent.futures import ThreadPoolExecutor
    tg = _loki_targets(selected)
    if not tg:
        return []

    def one(t):
        sid, url = t
        try:
            with loki.scope(sid, url):
                return (sid, fn(), None)
        except Exception as e:
            return (sid, None, str(e))
    with ThreadPoolExecutor(max_workers=min(8, len(tg))) as ex:
        return list(ex.map(one, tg))


@app.get("/api/log_sources")
def api_log_sources_get():
    items = [{"id": sid, "url": e.get("url", ""), "label": e.get("label", sid)}
             for sid, e in (_log_sources().get("items") or {}).items()]
    return {"items": sorted(items, key=lambda x: x["id"]),
            "default": (not items) and bool(config.LOKI_URL)}


@app.post("/api/log_sources")
async def api_log_sources_save(request: Request):
    body = await request.json()
    url = (body.get("url") or "").strip().rstrip("/")
    ok_egress, egress_err = _egress_check(url)      # SSRF guard (reuses S2)
    if not ok_egress:
        return JSONResponse({"ok": False, "error": egress_err}, status_code=400)
    sid = _ing_slug(body.get("id") or body.get("label") or url.split("://", 1)[-1])
    if not sid:
        return JSONResponse({"ok": False, "error": "нужен id/label"}, status_code=400)
    d = _log_sources()
    d.setdefault("items", {})[sid] = {"url": url, "label": (body.get("label") or sid)[:60]}
    db.setting_set("log_sources", d)
    return {"ok": True, "id": sid}


@app.post("/api/log_sources/delete")
async def api_log_sources_delete(request: Request):
    body = await request.json()
    d = _log_sources()
    existed = (body.get("id") or "") in (d.get("items") or {})
    if existed:
        d["items"].pop(body["id"])
        db.setting_set("log_sources", d)
    return {"ok": True, "deleted": existed}


@app.post("/api/logs/query")
async def api_logs_query(request: Request):
    """Structured Live-Logs query fanned across the selected Loki sources, merged
    newest-first and tagged with `source`. Body: {sources, chips, search, omnibar,
    regex, attacks_only, minutes, end_ns, limit, log_sources:[ids]}."""
    if not _loki_targets():
        return {"enabled": False, "rows": []}
    body = await request.json()
    q = _logql_from_body(body)
    mins = min(max(int(body.get("minutes") or 15), 1), 10080)   # up to 7d
    limit = min(int(body.get("limit") or 300), 1000)
    rows, statuses = [], []
    for sid, res, err in _loki_fanout(
            lambda: loki.query_logs(q, mins, end_ns=body.get("end_ns"), limit=limit),
            body.get("log_sources")):
        statuses.append({"id": sid, "ok": err is None, "count": len(res or []), "error": err})
        for r in (res or []):
            r["source"] = sid
            rows.append(r)
    rows.sort(key=lambda r: -r["ts"])
    rows = rows[:limit]
    # cursor in true ns (not reconstructed from ms) so no rows are skipped/dupd across
    # a page boundary within the same millisecond (C4)
    next_cursor = (rows[-1].get("ts_ns", rows[-1]["ts"] * 10**6) - 1) if len(rows) >= limit else None
    return {"enabled": True, "query": q, "rows": rows, "sources": statuses,
            "next_cursor": next_cursor}


@app.post("/api/logs/histogram")
async def api_logs_histogram(request: Request):
    if not _loki_targets():
        return {"enabled": False, "points": []}
    body = await request.json()
    q = _logql_from_body(body)
    mins = min(max(int(body.get("minutes") or 15), 1), 10080)
    by_class = bool(body.get("by_class"))
    end_ns = body.get("end_ns")                   # C2: honor zoom anchor
    fn = (lambda: loki.log_histogram_by_class(q, mins, end_ns=end_ns)) if by_class \
        else (lambda: loki.log_histogram(q, mins, end_ns=end_ns))
    merged_series, merged_pts, step = {}, {}, None
    for _sid, res, err in _loki_fanout(fn, body.get("log_sources")):
        if err or not res:
            continue
        step = res.get("step", step)
        if by_class:                              # sum per-class series across sources
            for cls, pts in (res.get("series") or {}).items():
                acc = merged_series.setdefault(cls, {})
                for p in pts:
                    acc[p["t"]] = acc.get(p["t"], 0) + p["v"]
        else:
            for p in res.get("points") or []:
                merged_pts[p["t"]] = merged_pts.get(p["t"], 0) + p["v"]
    if by_class:
        series = {c: sorted(({"t": t, "v": v} for t, v in d.items()), key=lambda p: p["t"])
                  for c, d in merged_series.items()}
        return {"enabled": True, "step": step or 60, "series": series}
    pts = sorted(({"t": t, "v": v} for t, v in merged_pts.items()), key=lambda p: p["t"])
    return {"enabled": True, "step": step or 60, "points": pts}


@app.post("/api/logs/facets")
async def api_logs_facets(request: Request):
    """Facet value counts (top values per field) across the selected sources."""
    if not _loki_targets():
        return {"enabled": False, "facets": {}}
    body = await request.json()
    q = _logql_from_body(body)
    mins = min(max(int(body.get("minutes") or 15), 1), 10080)
    fields = [f for f in (body.get("fields") or _FACET_FIELDS) if f in loki._LOG_FIELDS]
    end_ns = body.get("end_ns")                   # C2: honor zoom anchor
    merged = {}
    for _sid, res, err in _loki_fanout(lambda: loki.log_facets(q, fields, mins, end_ns=end_ns),
                                       body.get("log_sources")):
        if err or not res:
            continue
        for f, vals in res.items():
            acc = merged.setdefault(f, {})
            for it in vals:
                acc[it["value"]] = acc.get(it["value"], 0) + it["count"]
    facets = {f: sorted(({"value": k, "count": n} for k, n in d.items()),
                        key=lambda x: -x["count"])[:10] for f, d in merged.items()}
    return {"enabled": True, "facets": facets}


@app.get("/api/log_views")
def api_log_views_get():
    """Saved Live-Logs views (sources + chips + range)."""
    return {"views": db.setting_get("log_views", []) or []}


@app.post("/api/log_views")
async def api_log_views_set(request: Request):
    body = await request.json()
    views = body.get("views")
    if not isinstance(views, list):
        return JSONResponse({"ok": False, "error": "ожидается список views"}, status_code=400)
    db.setting_set("log_views", views[:50])
    return {"ok": True, "views": views[:50]}


# ── Custom dashboards (Grafana-style; panels bind to existing /api/* data) ──────
_DASH_DEFAULTS = [{
    "id": "overview", "name": "Overview", "vars": {}, "range": "",
    "panels": [
        {"id": "p1", "type": "stat", "title": "Requests/win", "source": "summary", "metric": "requests_total", "span": 3},
        {"id": "p2", "type": "stat", "title": "Attacker IPs", "source": "summary", "metric": "distinct_attacker_ips", "span": 3},
        {"id": "p3", "type": "stat", "title": "New blocks", "source": "summary", "metric": "forbidden_new", "span": 3},
        {"id": "p4", "type": "stat", "title": "Malicious %", "source": "summary", "metric": "malicious_ratio", "span": 3},
        {"id": "p5", "type": "timeseries", "title": "Traffic over time", "source": "history", "metrics": ["requests_total", "requests_real", "forbidden_new"], "span": 8},
        {"id": "p6", "type": "bar", "title": "Attack types", "source": "analytics", "key": "attack_types", "span": 4},
        {"id": "p7", "type": "table", "title": "Top paths", "source": "analytics", "key": "top_paths", "span": 6},
        {"id": "p8", "type": "bar", "title": "Top talkers (IPs)", "source": "analytics", "key": "top_talkers", "span": 6},
    ],
}]


@app.get("/api/dashboards")
def api_dashboards_get():
    """Custom dashboards (list + default id). Seeds a built-in Overview if empty."""
    d = db.setting_get("dashboards", None)
    if not d or not d.get("list"):
        d = {"list": _DASH_DEFAULTS, "default": "overview"}
    return d


@app.post("/api/dashboards")
async def api_dashboards_set(request: Request):
    body = await request.json()
    lst = body.get("list")
    if not isinstance(lst, list):
        return JSONResponse({"ok": False, "error": "ожидается {list:[…], default}"}, status_code=400)
    db.setting_set("dashboards", {"list": lst[:50], "default": body.get("default", "")})
    return {"ok": True}


@app.get("/api/history")
def api_history(limit: int = 240):
    snaps = db.recent_snapshots(limit)
    # downsample to ~240 points max so charts stay light (24h = 2880 snapshots)
    cap = 240
    if len(snaps) > cap:
        step = len(snaps) // cap + 1
        snaps = snaps[::step]
    return JSONResponse({"snapshots": snaps})


@app.get("/api/insights")
def api_insights(limit: int = 50):
    with _state_lock:
        current = _state.get("insight")
    return JSONResponse({"current": current, "history": db.recent_insights(limit)})


_WINDOWS = {"5m", "15m", "1h", "6h", "8h"}


def _win(w):
    return w if w in _WINDOWS else config.WINDOW


_an_cache = {}  # (window, host) -> (ts, data)
_AN_TTL = 45


@app.get("/api/analytics")
def api_analytics(window: str = "", host: str = "", env: str = ""):
    # default (no params) → cached background snapshot; custom window/host/env → live
    if not window and not host and not env:
        with _state_lock:
            return JSONResponse({"updated": _state["analytics_updated"], "analytics": _state["analytics"]})
    key = (_win(window), host, env)
    now = int(time.time())
    hit = _an_cache.get(key)
    if hit and now - hit[0] < _AN_TTL:
        return JSONResponse({"updated": hit[0], "analytics": hit[1], "cached": True})
    with loki.scope(env, _env_loki_url(env)):
        data = loki.collect_analytics(key[0], host)
    _an_cache[key] = (now, data)
    if len(_an_cache) > 50:
        _an_cache.clear()
    return JSONResponse({"updated": now, "analytics": data})


@app.get("/api/nl")
def api_nl(q: str = ""):
    if not q:
        return JSONResponse({"filters": {}, "requests": []})
    f = llm.nl_to_filters(q)
    mins = f.pop("minutes", 60)
    err = f.pop("error", None)
    try:
        reqs = loki.recent_requests(f.get("host", ""), f.get("path", ""), f.get("status", ""),
                                    f.get("ip", ""), "", 80, mins)
    except Exception as e:
        return JSONResponse({"filters": f, "requests": [], "error": str(e)})
    return JSONResponse({"filters": {**f, "minutes": mins}, "requests": reqs, "llm_error": err})


@app.get("/api/webcheck")
def api_webcheck(job: str = "", url: str = ""):
    """Proxy to the local web-check container (keeps it behind dashboard auth)."""
    import urllib.parse as _up
    import urllib.request as _ur
    if not job or not url:
        return JSONResponse({"error": "job and url required"})
    safe_job = "".join(c for c in job if c.isalnum() or c in "-_")
    q = config.WEBCHECK_URL + "/api/" + safe_job + "?url=" + _up.quote(url, safe="")
    try:
        with _ur.urlopen(q, timeout=30) as r:
            return JSONResponse(json.loads(r.read().decode()))
    except Exception as e:
        return JSONResponse({"error": str(e)})


@app.get("/api/trusted")
def api_trusted():
    return JSONResponse({"trusted": config.TRUSTED_IPS})


# --- SSRF egress guard (S2) ---
# Cloud metadata + link-local are NEVER a legitimate destination — block always.
# Loopback/private ARE legitimate for blocklist-api backends (cluster/LAN), so only
# block them for *external* fetches (threat feeds). Validate URLs at the point they
# enter config (save/test/activate) rather than per-call.
def _egress_check(url, allow_internal=True):
    """(ok, error) for an outbound URL. Always rejects non-http(s), cloud-metadata
    and link-local. With allow_internal=False also rejects loopback/private/reserved
    (for public threat feeds). Resolves + validates every A/AAAA record."""
    import socket
    from urllib.parse import urlparse
    try:
        u = urlparse(url)
    except Exception:
        return False, "плохой URL"
    if u.scheme not in ("http", "https"):
        return False, "только http/https"
    host = u.hostname
    if not host:
        return False, "нет хоста в URL"
    try:
        ips = {sa[0] for _f, _t, _p, _c, sa in socket.getaddrinfo(host, u.port or 0)}
    except Exception as e:
        return False, "DNS не резолвится: %s" % e
    if not ips:
        return False, "DNS не вернул адресов"
    for s in ips:
        try:
            ip = ipaddress.ip_address(s)
        except ValueError:
            continue
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            return False, "адрес метаданных/link-local запрещён"
        if not allow_internal and (ip.is_loopback or ip.is_private or ip.is_reserved):
            return False, "внутренний адрес запрещён для внешних источников"
    return True, None


def _safe_opener(allow_internal):
    """urllib opener that re-runs _egress_check on every redirect hop (X2) — a
    validated URL must not 302 to metadata/loopback."""
    import urllib.request as _ur
    import urllib.error as _ue

    class _Redir(_ur.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            ok, err = _egress_check(newurl, allow_internal=allow_internal)
            if not ok:
                raise _ue.HTTPError(newurl, code, "redirect egress запрещён: %s" % err, headers, fp)
            return super().redirect_request(req, fp, code, msg, headers, newurl)
    return _ur.build_opener(_Redir())


# --- blocklist (proxy to in-cluster blocklist-api) ---
def _bcall_to(base_url, token, method, path, payload=None, timeout=15):
    """Call ONE blocklist-api backend. Returns (status, body)."""
    import urllib.request as _ur
    import urllib.error as _ue
    if not base_url:
        return None, {"error": "blocklist-api не настроен (BLOCKLIST_API_URL пуст)"}
    url = base_url.rstrip("/") + path
    data = json.dumps(payload).encode() if payload is not None else None
    req = _ur.Request(url, data=data, method=method,
                      headers={"Content-Type": "application/json",
                               "Authorization": "Bearer " + (token or "")})
    try:
        with _ur.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except _ue.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {"error": "HTTP %s" % e.code}
    except Exception as e:
        return None, {"error": str(e)}


def _blocklist_call(method, path, payload=None):
    """Call the single active backend (config.*). Kept for writes / non-fan-out
    paths; multi-backend reads use _fanout()."""
    return _bcall_to(config.BLOCKLIST_API_URL, config.BLOCKLIST_API_TOKEN, method, path, payload)


def _backends(scope=None):
    """The blocklist-api fleet as [(id, url, token)]. Sources: the registered
    ingress_apis items, or — if none registered — the env/override default as a
    single implicit backend id 'default'. `scope` (or the stored scope) narrows to
    one backend; '__all__' (default) returns the whole fleet."""
    d = _ing_apis()
    items = d.get("items") or {}
    lst = [(tid, (e.get("url") or "").rstrip("/"), e.get("token") or "")
           for tid, e in items.items() if e.get("url")]
    if not lst and config.BLOCKLIST_API_URL:
        lst = [("default", config.BLOCKLIST_API_URL.rstrip("/"), config.BLOCKLIST_API_TOKEN)]
    sc = scope or d.get("scope") or "__all__"
    if sc and sc != "__all__":
        return [b for b in lst if b[0] == sc] or lst
    return lst


def _fanout(method, path, payload=None, scope=None, timeout=6):
    """Hit every in-scope backend concurrently. Returns [(id, status, body, err)]
    preserving fleet order; err is a string on failure else None. Never raises —
    a dead backend yields an err entry so callers can surface partial results.
    Short default timeout (Pf3): one slow backend must not stall a merged read for
    15s — the partial-result contract degrades it gracefully. Writes keep 15s."""
    from concurrent.futures import ThreadPoolExecutor
    bes = _backends(scope)
    if not bes:
        return []

    def one(b):
        bid, url, tok = b
        st, body = _bcall_to(url, tok, method, path, payload, timeout=timeout)
        ok = st is not None and st < 400
        err = None if ok else ((body or {}).get("error") if isinstance(body, dict) else None) \
            or ("HTTP %s" % st if st else "нет связи")
        return (bid, st, body, err)

    with ThreadPoolExecutor(max_workers=min(8, len(bes))) as ex:
        return list(ex.map(one, bes))


def _fanout_list(path, key, scope=None):
    """GET `path` on each in-scope backend and concatenate body[key] lists, tagging
    every dict row with its `backend` id. Returns (items, errors_by_backend)."""
    items, errors = [], {}
    for bid, _st, body, err in _fanout("GET", path, scope=scope):
        if err:
            errors[bid] = err
            continue
        for row in (body or {}).get(key, []) or []:
            if isinstance(row, dict):
                row = dict(row)
                row.setdefault("backend", bid)
            items.append(row)
    return items, errors


# ── Phase 2: route writes to the backend(s) that own the relevant target/group ──
_ti_cache = {}     # scope -> (ts, (tb, gb)); short TTL so a routed write isn't a fresh fan-out each time
_health_cache = {"t": 0, "k": None, "d": None}   # cached fleet-health probe (Pf2)


def _targets_index(scope=None):
    """Fan out /targets and build {target_id: [backends]} and {group: [backends]}
    from the fleet — the map that tells a write which backend(s) to hit. Cached ~8s
    (Pf2): a burst of routed writes (autoban tick, bulk ban) reuses one fan-out."""
    key = scope or "__all__"
    hit = _ti_cache.get(key)
    if hit and (time.time() - hit[0]) < 8:
        return hit[1]
    tb, gb = {}, {}
    for bid, _st, body, err in _fanout("GET", "/targets", scope=scope):
        if err:
            continue
        for t in (body or {}).get("targets", []) or []:
            tid = t.get("id") if isinstance(t, dict) else None
            if tid:
                tb.setdefault(tid, []).append(bid)
        for gname in ((body or {}).get("groups", {}) or {}).keys():
            gb.setdefault(gname, []).append(bid)
    _ti_cache[key] = (time.time(), (tb, gb))
    return tb, gb


def _route_for(attachment, scope=None):
    """Which backend ids a write with this attachment ({groups,targets,all} or a
    legacy single `group`) should go to.

    - no attachment / 'all' / no groups+targets → whole fleet (intended broadcast,
      e.g. a manual Ban IP with no target).
    - named groups/targets that RESOLVE → their owning backends.
    - named groups/targets that resolve to NOTHING (typo / renamed / stale) → [] so
      the write fails loudly (X3) rather than silently banning fleet-wide."""
    all_ids = [b[0] for b in _backends(scope)]
    if not attachment or attachment.get("all"):
        return all_ids
    groups = attachment.get("groups") or ([attachment["group"]] if attachment.get("group") else [])
    targets = attachment.get("targets") or []
    if not groups and not targets:
        return all_ids                       # nothing specified → broadcast intended
    tb, gb = _targets_index(scope)
    picked = set()
    for g in groups:
        picked.update(gb.get(g, []))
    for t in targets:
        picked.update(tb.get(t, []))
    picked &= set(all_ids)
    if picked:
        return sorted(picked)
    # named-but-unresolved: on a real fleet, fail-closed ([]) so a stale/typo'd group
    # doesn't silently ban everywhere (X3). With ≤1 backend there's no fleet-wide
    # surprise and the backend itself validates the group, so keep the old broadcast.
    return all_ids if len(all_ids) <= 1 else []


def _write_fanout(method, path, payload, backend_ids):
    """Send a write to the given backend ids. One backend → return its body
    verbatim (back-compat with the single-backend response shape). Many → return
    an aggregate {ok, multi:true, results:[{backend,ok,status,resp}]}."""
    bmap = {bid: (url, tok) for bid, url, tok in _backends("__all__")}
    ids = [b for b in backend_ids if b in bmap]
    if not ids:
        return None, {"ok": False, "error": "нет бэкендов для записи"}
    if len(ids) == 1:
        url, tok = bmap[ids[0]]
        return _bcall_to(url, tok, method, path, payload)
    results, bodies, oks = [], [], []
    for bid in ids:
        url, tok = bmap[bid]
        st, body = _bcall_to(url, tok, method, path, payload)
        ok = st is not None and st < 400
        oks.append(ok)
        if isinstance(body, dict):
            bodies.append(body)
        results.append({"backend": bid, "ok": ok, "status": st, "resp": body})
    all_ok = all(oks)
    # Roll up per-backend bodies so the UI's res.blocked/removed/active/skipped keys
    # still work on a fleet: sum numbers, concat lists, first-wins otherwise. Special
    # cases: set-like CIDR lists are UNION-deduped (Q2 — an IP banned on N backends is
    # one ban, not N); backend-local gauges take max not sum (Q3 — "active rules" isn't
    # additive across the fleet). Type mismatches across backend versions are skipped
    # from the aggregate rather than crashing (C5), leaving the truth in results[].
    _UNION = {"blocked", "skipped", "removed", "created", "unblocked", "already"}
    _MAX = {"active"}
    agg = {}
    for b in bodies:
        for k, v in b.items():
            if k in ("ok", "multi", "results", "partial", "backend", "status", "error"):
                continue
            if isinstance(v, bool):
                if k in agg and not isinstance(agg[k], bool):
                    continue
                agg[k] = agg.get(k, False) or v
            elif isinstance(v, (int, float)):
                if k in agg and not isinstance(agg[k], (int, float)):
                    continue
                agg[k] = max(agg.get(k, v), v) if k in _MAX else agg.get(k, 0) + v
            elif isinstance(v, list):
                if k in agg and not isinstance(agg[k], list):
                    continue
                cur = agg.setdefault(k, [])
                if k in _UNION:
                    for x in v:
                        if x not in cur:
                            cur.append(x)
                else:
                    cur += v
            elif k not in agg:
                agg[k] = v
    failed = [r["backend"] for r in results if not r["ok"]]
    out = {**agg, "ok": all_ok, "multi": True, "results": results}
    if failed:                                   # partial failure ≠ success (B2)
        out["partial"] = True
        out["error"] = "не применилось на: " + ", ".join(failed)
    # 200 only if every backend succeeded; partial/none → 502 so the UI shows it.
    return (200 if all_ok else 502), out


@app.get("/api/ban_targets")
def api_ban_targets():
    """Configured enforcement targets + groups across the fleet. Targets are tagged
    with their backend; groups are merged (a name present on several backends routes
    to all of them). Drives the attach UI + write routing."""
    if not _backends("__all__"):
        return JSONResponse({"targets": [], "groups": {}, "enabled": False})
    targets, groups, default_group, cf_edge, errors = [], {}, "", False, {}
    for bid, _st, body, err in _fanout("GET", "/targets"):
        if err:
            errors[bid] = err
            continue
        body = body or {}
        for t in body.get("targets", []) or []:
            if isinstance(t, dict):
                t = dict(t); t.setdefault("backend", bid)
            targets.append(t)
        for gname, members in (body.get("groups", {}) or {}).items():
            # merge members across backends that share a group name
            cur = groups.setdefault(gname, [])
            for m in members or []:
                if m not in cur:
                    cur.append(m)
        default_group = default_group or body.get("default_group", "")
        cf_edge = cf_edge or bool(body.get("cf_edge_paths"))
    return JSONResponse({"enabled": True, "targets": targets, "groups": groups,
                         "default_group": default_group, "cf_edge_paths": cf_edge,
                         "backend_errors": errors})


@app.get("/api/ban_targets/check")
def api_ban_targets_check(id: str = ""):
    """«Проверить» — live probe of targets (CF token/list/rule, last errors)."""
    import urllib.parse as _up
    path = "/targets/check" + ("?id=" + _up.quote(id, safe="") if id else "")
    status, body = _bcall_to(*_scoped_backend(), "GET", path)
    return JSONResponse(body or {"checks": [], "error": "нет ответа"}, status_code=status or 502)


@app.get("/api/settings")
def api_settings():
    """Unified config view: LLM (backend-local, in app_settings) + Cloudflare / bans /
    ingress (proxied from blocklist-api). Secrets are redacted to a boolean."""
    llm_view = {
        "LLM_URL":   {"group": "llm", "type": "str", "label": "LLM endpoint (Ollama/OpenAI-compatible)",
                      "locked": False, "source": "override" if db.setting_get("llm_url") else "env",
                      "value": llm.base_url()},
        "LLM_MODEL": {"group": "llm", "type": "str", "label": "LLM model",
                      "locked": False, "source": "override" if db.setting_get("llm_model") else "env",
                      "value": llm.model()},
    }
    bl = {}
    locked = False
    if config.BLOCKLIST_API_URL:
        _, body = _bcall_to(*_scoped_backend(), "GET", "/settings")
        bl = (body or {}).get("settings", {})
        locked = bool((body or {}).get("locked"))
    return JSONResponse({"settings": {**llm_view, **bl}, "locked": locked,
                         "blocklist_enabled": bool(config.BLOCKLIST_API_URL)})


@app.post("/api/settings")
async def api_settings_save(request: Request):
    body = await request.json()
    updates = body.get("updates") or body
    # LLM keys are backend-local; the rest go to blocklist-api.
    local_map = {"LLM_URL": "llm_url", "LLM_MODEL": "llm_model"}
    applied, remote = [], {}
    for k, v in updates.items():
        if k in local_map:
            if v is None or v == "":
                db.setting_set(local_map[k], "")     # revert to env
            else:
                db.setting_set(local_map[k], v)
            applied.append(k)
        else:
            remote[k] = v
    err = None
    if remote and config.BLOCKLIST_API_URL:
        status, resp = _bcall_to(*_scoped_backend(), "POST", "/settings", {"updates": remote})
        if status and status >= 400:
            err = (resp or {}).get("error", "ошибка blocklist-api")
        else:
            applied += (resp or {}).get("applied", [])
    return JSONResponse({"ok": err is None, "applied": applied, "error": err},
                        status_code=409 if err else 200)


_env_url_cache = {"t": 0.0, "map": {}}


def _env_loki_url(env):
    """Per-env Loki URL override (empty = shared Loki + env label). Cached 30s from the
    environments registry."""
    if not env or not config.BLOCKLIST_API_URL:
        return ""
    if time.time() - _env_url_cache["t"] > 30:
        try:
            _, body = _blocklist_call("GET", "/environments")
            _env_url_cache["map"] = {e["id"]: e.get("loki_url", "")
                                     for e in (body or {}).get("environments", [])}
            _env_url_cache["t"] = time.time()
        except Exception:
            pass
    return _env_url_cache["map"].get(env, "")


def _notify(event):
    """Push an event into the blocklist-api notification engine (best-effort)."""
    if not config.BLOCKLIST_API_URL:
        return
    try:
        _blocklist_call("POST", "/notify", event)
    except Exception:
        pass


@app.get("/api/environments")
def api_environments():
    if not config.BLOCKLIST_API_URL:
        return JSONResponse({"enabled": False, "environments": []})
    # C1: per-backend config → follow the scope picker (was ignoring it via _blocklist_call)
    _, body = _bcall_to(*_scoped_backend(), "GET", "/environments")
    return JSONResponse({"enabled": True, **(body or {})})


@app.post("/api/environments")
async def api_environments_save(request: Request):
    body = await request.json()
    status, resp = _bcall_to(*_scoped_backend(), "POST", "/environments", body)
    return JSONResponse(resp or {"ok": False}, status_code=status or 502)


@app.post("/api/environments/delete")
async def api_environments_delete(request: Request):
    body = await request.json()
    status, resp = _bcall_to(*_scoped_backend(), "POST", "/environments/delete", {"id": body.get("id", "")})
    return JSONResponse(resp or {"ok": False}, status_code=status or 502)


# ── named Cloudflare targets (registry) ─────────────────────────────────────────
@app.get("/api/cf_targets")
def api_cf_targets():
    if not _backends("__all__"):
        return JSONResponse({"enabled": False, "targets": []})
    targets, errors = _fanout_list("/cf_targets", "targets")
    return JSONResponse({"enabled": True, "targets": targets, "backend_errors": errors})


def _one_backend(bid):
    """(url, token) for a backend id, or the active default when unknown/blank."""
    for b in _backends("__all__"):
        if b[0] == bid:
            return b[1], b[2]
    return config.BLOCKLIST_API_URL, config.BLOCKLIST_API_TOKEN


def _scoped_backend():
    """(url, token) for config reads/writes (settings / notify): per-backend data,
    so it follows the picker — the chosen backend when scope is specific, else the
    active/env default. Not merged (backends can hold different config)."""
    sc = (_ing_apis().get("scope") or "__all__")
    if sc != "__all__":
        for b in _backends("__all__"):
            if b[0] == sc:
                return b[1], b[2]
    return config.BLOCKLIST_API_URL, config.BLOCKLIST_API_TOKEN


@app.post("/api/cf_targets")
async def api_cf_targets_save(request: Request):
    body = await request.json()
    url, tok = _one_backend(body.pop("backend", None))   # save to the chosen backend
    status, resp = _bcall_to(url, tok, "POST", "/cf_targets", body)
    return JSONResponse(resp or {"ok": False}, status_code=status or 502)


@app.post("/api/cf_targets/delete")
async def api_cf_targets_delete(request: Request):
    body = await request.json()
    url, tok = _one_backend(body.get("backend"))   # delete on the owning backend
    status, resp = _bcall_to(url, tok, "POST", "/cf_targets/delete", {"id": body.get("id", "")})
    return JSONResponse(resp or {"ok": False}, status_code=status or 502)


@app.get("/api/notify_config")
def api_notify_config():
    if not config.BLOCKLIST_API_URL:
        return JSONResponse({"enabled": False, "channels": [], "rules": []})
    _, body = _bcall_to(*_scoped_backend(), "GET", "/notify_config")
    return JSONResponse({"enabled": True, **(body or {})})


@app.post("/api/notify_config")
async def api_notify_config_save(request: Request):
    body = await request.json()
    status, resp = _bcall_to(*_scoped_backend(), "POST", "/notify_config", body)
    return JSONResponse(resp or {"ok": False}, status_code=status or 502)


@app.post("/api/notify/test")
async def api_notify_test(request: Request):
    body = await request.json()
    status, resp = _bcall_to(*_scoped_backend(), "POST", "/notify/test", {"channel": body.get("channel", "")})
    return JSONResponse(resp or {"ok": False}, status_code=status or 502)


def _dashboard_node():
    """Self-metrics for the SOC-app host itself, shaped like an agent node so the
    dashboard VM shows up alongside the nginx nodes (it runs no agent — stdlib only)."""
    import os, socket, time
    m = {}
    try:
        m["ncpu"] = os.cpu_count() or 0
        m["load1"] = round(os.getloadavg()[0], 2)
    except Exception:
        pass
    try:  # Linux /proc — best effort, skipped on macOS dev
        info = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, _, v = line.partition(":")
                info[k] = int(v.strip().split()[0])  # kB
        total, avail = info.get("MemTotal", 0), info.get("MemAvailable", 0)
        if total:
            m["mem_total_mb"] = round(total / 1024)
            m["mem_used_pct"] = round((total - avail) / total * 100)
        with open("/proc/uptime") as f:
            m["uptime_s"] = int(float(f.read().split()[0]))
    except Exception:
        pass
    ip = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close()
    except Exception:
        pass
    return {
        "id": socket.gethostname() or "soc-dashboard",
        "role": "dashboard", "group": "", "online": True,
        "last_seen": int(time.time()), "metrics": m,
        "hostname": socket.gethostname(), "ip": ip, "agent_version": "soc-app",
    }


@app.get("/api/nodes")
def api_nodes():
    """Enrolled nginx-VM agents + liveness/host metrics (the «Ноды» tab).
    The dashboard host itself is always prepended as a `role:dashboard` node."""
    dash = _dashboard_node()
    if not _backends("__all__"):
        return JSONResponse({"enabled": True, "nodes": [dash]})
    nodes, errors = _fanout_list("/nodes", "nodes")
    return JSONResponse({"enabled": True, "nodes": [dash] + nodes,
                         "backend_errors": errors})


@app.post("/api/nodes/delete")
async def api_nodes_delete(request: Request):
    body = await request.json()
    url, tok = _one_backend(body.get("backend"))   # revoke on the node's own backend
    status, resp = _bcall_to(url, tok, "POST", "/node_delete", {"id": body.get("id", "")})
    return JSONResponse(resp or {"ok": False}, status_code=status or 502)


@app.get("/api/nodes/install")
def api_nodes_install():
    """Build the «Добавить ноду» install one-liner from blocklist-api's enroll info.
    The enroll secret stays server-side until an authed operator opens this."""
    if not config.BLOCKLIST_API_URL:
        return JSONResponse({"enabled": False})
    # blocklist-api renders the one-liner itself now (S3) — the raw ENROLL_SECRET is
    # never returned as a field; we just proxy the rendered command.
    _, info = _blocklist_call("GET", "/enroll_info")
    info = info or {}
    return JSONResponse({"enabled": True, "configured": bool(info.get("enroll_configured")),
                         "public_url": (info.get("public_url") or "").rstrip("/"),
                         "install_cmd": info.get("install_cmd") or "",
                         "needs_public_url": bool(info.get("needs_public_url"))})


@app.get("/api/blocklist")
def api_blocklist():
    if not _backends("__all__"):
        return JSONResponse({"enabled": False, "blocks": []})
    raw, errors = _fanout_list("/list", "blocks")
    # dedup identical CIDRs banned on several backends → one row with backends[].
    merged = {}
    for b in raw:
        k = b.get("cidr") if isinstance(b, dict) else None
        if k is None:
            continue
        if k in merged:
            m = merged[k]
            m["backends"].append(b.get("backend"))
            # keep the longest-lived / most-informative view of the row
            if (b.get("ttl") or 0) == 0:
                m["ttl"] = 0                       # any permanent ban wins
            elif m.get("ttl") and b.get("ttl"):
                m["ttl"] = max(m["ttl"], b["ttl"])
        else:
            row = dict(b)
            row["backends"] = [b.get("backend")]
            merged[k] = row
    blocks = list(merged.values())
    return JSONResponse({"enabled": True, "blocks": blocks, "backend_errors": errors})


@app.get("/api/blocklist_audit")
def api_blocklist_audit(limit: int = 100):
    limit = min(max(int(limit), 1), 1000)
    audit, errors = _fanout_list("/audit?limit=%d" % limit, "audit")
    # newest first across the merged fleet, then trim to `limit` (Pf4 — don't return
    # N×limit rows on a fleet; each backend already capped its own /audit at `limit`)
    audit.sort(key=lambda r: r.get("ts", 0) if isinstance(r, dict) else 0, reverse=True)
    return JSONResponse({"audit": audit[:limit], "backend_errors": errors})


@app.get("/api/reviewed")
def api_reviewed():
    """IPs the operator marked reviewed (last 24h) — frontend dims/marks these rows."""
    return JSONResponse({"ips": db.reviewed_ips()})


@app.post("/api/review")
async def api_review(request: Request):
    body = await request.json()
    ip = (body.get("ip") or "").strip()
    if not ip:
        return JSONResponse({"ok": False, "error": "no ip"}, status_code=400)
    db.mark_reviewed(ip, bool(body.get("reviewed", True)))
    return JSONResponse({"ok": True, "ip": ip, "reviewed": bool(body.get("reviewed", True))})


# --- Auto-ban rules (Cloudflare-style). UI + dry-run ONLY: the executor is not
#     wired, so creating/enabling a rule never bans anyone yet. The global "armed"
#     kill-switch is stored but defaults OFF and is purely informational for now. ---
_AB_WINDOWS = {"1m", "5m", "10m", "15m", "30m", "1h", "8h"}
_AB_WIN_ORDER = ["1m", "5m", "10m", "15m", "30m", "1h", "8h"]
_AB_MATCH = {"substring", "regex", "family", "rate"}


def _autoban_ignore():
    """Защищённые пути — общий список «нельзя трогать»: авто-бан их не считает И в 403
    их нельзя добавить. From app_settings, else default."""
    v = db.setting_get("autoban_ignore_paths", None)
    if isinstance(v, list):
        return [str(p).strip() for p in v if str(p).strip()]
    return list(config.AUTOBAN_IGNORE_PATHS_DEFAULT)


def _path_protected(path):
    """Защищён ли путь? Возвращает совпавшую защищённую запись (подстрока) или None."""
    pl = (path or "").lower()
    for p in _autoban_ignore():
        if p and p.lower() in pl:
            return p
    return None


def _pattern_hits_protected(pattern):
    """Задевает ли 403-regex защищённый путь? Возвращает запись или None.
    Две стороны: (1) защищённая запись — подстрока паттерна (узкий литерал
    `/api/admin` сидит ПОД `/api/`); (2) паттерн матчит защищённый путь (широкий
    `/api/.*`). Достаточно любой."""
    sub = _path_protected(pattern)          # (1) узкий литерал под защитой
    if sub:
        return sub
    import re as _re
    try:
        rx = _re.compile(pattern or "", _re.I)
    except _re.error:
        return None  # битый regex — пусть blocklist-api сам отрапортует
    for p in _autoban_ignore():             # (2) широкий паттерн задевает защиту
        if not p:
            continue
        base = p.rstrip("/")
        for sample in (p, base, base + "/", base + "/x", p + "x"):
            if rx.search(sample):
                return p
    return None


def _autoban_eval(rule, host="", with_paths=True):
    """Single entry point for rule evaluation — always injects the ignore whitelist
    so executor and preview behave identically. The executor passes with_paths=False
    to skip the (display-only) per-path query and halve Loki load."""
    return loki.autoban_eval(rule, host=host, ignore_paths=_autoban_ignore(),
                             with_paths=with_paths)


def _clean_rule(body):
    """Validate/normalize a rule payload from the UI. Raises ValueError on bad input."""
    name = (body.get("name") or "").strip()
    if not name:
        raise ValueError("нужно имя правила")
    mt = body.get("match_type") or "substring"
    if mt not in _AB_MATCH:
        raise ValueError("неизвестный тип условия")
    path = (body.get("path") or "").strip()
    if mt not in ("family", "rate") and not path:
        raise ValueError("укажите путь/паттерн")
    win = body.get("window") or "10m"
    if win not in _AB_WINDOWS:
        raise ValueError("окно: одно из %s" % ", ".join(sorted(_AB_WINDOWS)))
    try:
        thr = max(1, int(body.get("threshold") or 1))
        ttl = max(0, int(body.get("ttl") or 0))
    except (TypeError, ValueError):
        raise ValueError("порог/TTL должны быть числами")
    # normalize multi-path: drop blank OR-lines, cap total length
    if mt != "family":
        path = "\n".join(p.strip() for p in path.split("\n") if p.strip())[:1000]
    # combine: 1 = sum requests across all paths (default), 0 = each path counted alone
    combine = 0 if body.get("combine") in (0, "0", False, "false") else 1
    # LEGACY single group field, kept so old clients still work ('' = default)
    grp = (body.get("group") or "").strip()[:64]
    # optional country scope: comma/space-separated ISO codes, e.g. "CN,RU" ('' = any)
    country = ",".join(re.findall(r"[A-Za-z]{2}", (body.get("country") or "").upper()))[:64]
    out = {"name": name[:80], "match_type": mt, "path": path,
           "status": (body.get("status") or "").strip()[:20], "threshold": thr,
           "window": win, "ttl": ttl, "enabled": 1 if body.get("enabled") else 0,
           "combine": combine, "grp": grp, "country": country}
    # many-to-many attachment (Phase 2). Only include a key if the client sent it, so a
    # partial update (e.g. just renaming) never wipes the attachment.
    if any(k in body for k in ("groups", "targets", "all")):
        out["groups"] = [str(g).strip() for g in (body.get("groups") or []) if str(g).strip()]
        out["targets"] = [str(t).strip() for t in (body.get("targets") or []) if str(t).strip()]
        out["all"] = bool(body.get("all"))
    elif grp:
        # back-compat: a lone legacy `group` seeds the attachment as one group
        out["groups"] = [grp]
        out["targets"] = []
        out["all"] = False
    return out


def _ban_groups():
    """Available ban groups + default, from blocklist-api (for the rule form)."""
    if not config.BLOCKLIST_API_URL:
        return {"groups": [], "default_group": ""}
    try:
        _, body = _blocklist_call("GET", "/targets")
        return {"groups": sorted((body or {}).get("groups", {}).keys()),
                "default_group": (body or {}).get("default_group", "")}
    except Exception:
        return {"groups": [], "default_group": ""}


@app.get("/api/autoban/rules")
def api_autoban_rules():
    return JSONResponse({
        "rules": db.autoban_rules(),
        "armed": bool(db.setting_get("autoban_armed", False)),
        "families": loki.AUTOBAN_FAMILIES,
        "windows": _AB_WIN_ORDER,
        "executor": True,        # executor is wired; it bans only when armed
        "interval": config.AUTOBAN_INTERVAL,
        "max_per_tick": config.AUTOBAN_MAX_PER_TICK,
        "last_run": db.setting_get("autoban_last_run", None),
        "ignore_paths": _autoban_ignore(),
        **_ban_groups(),
    })


@app.get("/api/autoban/why")
def api_autoban_why(ip: str = ""):
    """Why is this IP banned? Finds the covering denylist entry (rule/reason/who/when)
    + its audit trail. Clearly says when the IP is NOT in our denylist (e.g. a 403 that
    comes from the static nginx rule or the app, not from a ban)."""
    ip = (ip or "").strip()
    if not ip:
        return JSONResponse({"ip": ip, "error": "нет ip"}, status_code=400)
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return JSONResponse({"ip": ip, "error": "невалидный IP"}, status_code=400)
    blocks, _ = _fanout_list("/list", "blocks")     # across the whole fleet (B3)
    entry = None
    best_prefix = -1
    for b in blocks:
        try:
            net = ipaddress.ip_network(b["cidr"], strict=False)
            # pick the MOST specific covering block (largest prefixlen) so a /32
            # auto-ban with the real reason wins over a broad manual range
            if addr in net and net.prefixlen > best_prefix:
                entry, best_prefix = b, net.prefixlen
        except Exception:
            pass
    audit_rows, _ = _fanout_list("/audit?limit=500", "audit")
    audit = []
    for e in audit_rows:
        c = e.get("cidr") or ""
        if c == ip or (entry and c == entry["cidr"]) or ("/" not in c and c == ip):
            audit.append(e)
    rule = None
    rule_obj = None
    if entry:
        m = entry.get("reason", "")
        if m.startswith("автобан"):
            parts = [p.strip() for p in m.split("·")]
            rule = parts[1] if len(parts) > 1 else None
        if rule:
            for r in db.autoban_rules():
                if r.get("name") == rule:
                    rule_obj = r
                    break
    # example paths that triggered the ban. Prefer paths captured at ban time
    # (reliable, no live query); fall back to a live 6h lookup for older bans.
    paths = []
    if entry:
        stored = db.setting_get("autoban_ban_paths", {}) or {}
        paths = stored.get(entry.get("cidr")) or []
        if not paths:
            try:
                paths = loki.ip_rule_paths(ip, rule_obj, "6h")
            except Exception:
                paths = []
    return JSONResponse({"ip": ip, "banned": bool(entry), "entry": entry,
                         "rule": rule, "by": entry.get("added_by") if entry else None,
                         "audit": audit[:20], "paths": paths,
                         "static_deny": loki._skip_ip(ip)})


@app.get("/api/autoban/log")
def api_autoban_log(limit: int = 200):
    """Auto-ban audit (by=autoban) enriched with: the example paths captured at ban
    time, and whether the ban is STILL active (so the UI shows 'разбан' only for live
    bans and marks unbanned/expired ones — the audit itself is append-only history)."""
    audit_rows, _ = _fanout_list("/audit?limit=500", "audit")   # whole fleet (B3)
    blocks, _ = _fanout_list("/list", "blocks")
    active = {b.get("cidr") for b in blocks}
    paths_map = db.setting_get("autoban_ban_paths", {}) or {}
    out = []
    for e in sorted(audit_rows, key=lambda r: r.get("ts", 0), reverse=True):
        if (e.get("by") or "").lower() != "autoban":
            continue
        cidr = e.get("cidr") or ""
        out.append({**e, "paths": paths_map.get(cidr, []), "active": cidr in active})
    return JSONResponse({"log": out[:limit]})


@app.post("/api/autoban/ignore")
async def api_autoban_ignore(request: Request):
    """Replace the safety-whitelist of paths the auto-ban never counts."""
    body = await request.json()
    paths = body.get("paths")
    if not isinstance(paths, list):
        return JSONResponse({"ok": False, "error": "ожидается paths: []"}, status_code=400)
    clean = []
    for p in paths:
        p = str(p).strip()[:200]
        if p and p not in clean:
            clean.append(p)
    db.setting_set("autoban_ignore_paths", clean[:100])
    return JSONResponse({"ok": True, "ignore_paths": clean[:100]})


@app.post("/api/autoban/rule")
async def api_autoban_rule(request: Request):
    body = await request.json()
    try:
        fields = _clean_rule(body)
    except ValueError as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    rid = body.get("id")
    if rid:
        db.autoban_update(int(rid), fields)
        return JSONResponse({"ok": True, "id": int(rid), "rule": db.autoban_rule(int(rid))})
    rid = db.autoban_create(fields)
    return JSONResponse({"ok": True, "id": rid, "rule": db.autoban_rule(rid)})


@app.post("/api/autoban/toggle")
async def api_autoban_toggle(request: Request):
    body = await request.json()
    rid = body.get("id")
    if not rid:
        return JSONResponse({"ok": False, "error": "no id"}, status_code=400)
    db.autoban_update(int(rid), {"enabled": 1 if body.get("enabled") else 0})
    return JSONResponse({"ok": True, "id": int(rid), "rule": db.autoban_rule(int(rid))})


@app.post("/api/autoban/add_path")
async def api_autoban_add_path(request: Request):
    """Append a path (from an IP profile / requests view) to an existing rule's
    OR-list. Family rules can't take explicit paths."""
    body = await request.json()
    rid = body.get("id")
    path = (body.get("path") or "").strip()
    if not rid or not path:
        return JSONResponse({"ok": False, "error": "нужны id и path"}, status_code=400)
    rule = db.autoban_rule(int(rid))
    if not rule:
        return JSONResponse({"ok": False, "error": "правило не найдено"}, status_code=404)
    if rule.get("match_type") == "family":
        return JSONResponse({"ok": False, "error": "нельзя добавить путь в правило-семейство"}, status_code=400)
    parts = [p for p in (rule.get("path") or "").split("\n") if p.strip()]
    if path in parts:
        return JSONResponse({"ok": True, "id": int(rid), "rule": rule, "already": True})
    parts.append(path)
    db.autoban_update(int(rid), {"path": "\n".join(parts)[:1000]})
    return JSONResponse({"ok": True, "id": int(rid), "rule": db.autoban_rule(int(rid))})


@app.post("/api/autoban/delete")
async def api_autoban_delete(request: Request):
    body = await request.json()
    rid = body.get("id")
    if not rid:
        return JSONResponse({"ok": False, "error": "no id"}, status_code=400)
    db.autoban_delete(int(rid))
    return JSONResponse({"ok": True, "id": int(rid)})


@app.post("/api/autoban/arm")
async def api_autoban_arm(request: Request):
    """Global kill-switch. Stored only — no executor consumes it yet, so flipping
    this on does NOT start banning. Wired here so the UI is complete."""
    body = await request.json()
    armed = bool(body.get("armed"))
    db.setting_set("autoban_armed", armed)
    return JSONResponse({"ok": True, "armed": armed, "executor": True})


# --- Auto-ban EXECUTOR ---------------------------------------------------------
# Runs every AUTOBAN_INTERVAL but ACTS only when the kill-switch (autoban_armed)
# is ON. Each pass: evaluate every ENABLED rule (dry-run logic, reused), collect
# fresh offenders, and ban them via blocklist-api with added_by="autoban". All the
# guardrails from autoban_eval apply (trusted/private/CF/already-denied excluded);
# already-banned IPs are skipped; at most AUTOBAN_MAX_PER_TICK new bans per pass.
def _autoban_host_cidr(ip):
    a = ipaddress.ip_address(ip)
    return "%s/32" % ip if a.version == 4 else "%s/128" % ip


# ── escalation ladder (#9) ────────────────────────────────────────────────────
_ESCALATE_DEFAULT = [3600, 21600, 86400, 604800, 0]   # offense 1..5+: 1h,6h,24h,7d,forever

def _escalate_enabled():
    return bool(db.setting_get("autoban_escalate", False))

def _escalate_ladder():
    v = db.setting_get("autoban_escalate_ladder", None)
    if isinstance(v, list) and v and all(isinstance(x, (int, float)) for x in v):
        return [max(0, int(x)) for x in v]
    return list(_ESCALATE_DEFAULT)

def _escalate_memory_s():
    try:
        return max(1, int(db.setting_get("autoban_escalate_memory_days", 30) or 30)) * 86400
    except (TypeError, ValueError):
        return 30 * 86400


@app.get("/api/autoban/escalation")
def api_escalation_get():
    return {"enabled": _escalate_enabled(), "ladder": _escalate_ladder(),
            "memory_days": _escalate_memory_s() // 86400, "offenders": db.offender_top(50)}


@app.post("/api/autoban/escalation")
async def api_escalation_set(request: Request):
    body = await request.json()
    if "enabled" in body:
        db.setting_set("autoban_escalate", bool(body["enabled"]))
    if isinstance(body.get("ladder"), list):
        lad = [max(0, int(x)) for x in body["ladder"] if str(x).strip().lstrip("-").isdigit()]
        if lad:
            db.setting_set("autoban_escalate_ladder", lad)
    if body.get("memory_days"):
        try:
            db.setting_set("autoban_escalate_memory_days", max(1, int(body["memory_days"])))
        except (TypeError, ValueError):
            pass
    return {"ok": True, "enabled": _escalate_enabled(), "ladder": _escalate_ladder(),
            "memory_days": _escalate_memory_s() // 86400}


def autoban_run_once():
    rules = [r for r in db.autoban_rules() if r.get("enabled")]
    if not rules:
        db.setting_set("autoban_last_run", {"ts": int(time.time()), "checked_rules": 0,
                                            "candidates": 0, "banned": 0, "deferred": 0, "already": 0})
        return
    nets = _blocked_nets()

    def _already(ip):
        try:
            a = ipaddress.ip_address(ip)
            return any(a in n for n in nets)
        except Exception:
            return True   # unparseable → treat as "skip", never ban

    seen = {}
    already = set()
    for r in rules:
        try:
            data = _autoban_eval(r, with_paths=False)   # executor needs only IP+count
        except Exception as e:
            log.warning("[autoban] rule #%s eval error: %s" % (r.get("id"), e))
            continue
        for m in data.get("matches", []):
            ip = m.get("ip")
            if not ip or ip in seen:
                continue
            if _already(ip):
                already.add(ip)   # matched a rule but already in the denylist
                continue
            # defense-in-depth: autoban_eval already drops these, re-check anyway
            if ip in config.TRUSTED_IPS or loki._skip_ip(ip) or loki._is_cf_ip(ip):
                continue
            seen[ip] = {"ip": ip, "cidr": _autoban_host_cidr(ip),
                        "reason": "автобан · %s · ≥%s/%s" % (
                            r.get("name", "?"), r.get("threshold"), r.get("window")),
                        "ttl": int(r.get("ttl") or 0),
                        # attachment (Phase 2): where this ban enforces. Falls back to the
                        # legacy single group for rules not yet migrated.
                        "groups": list(r.get("groups") or []),
                        "targets": list(r.get("targets") or []),
                        "all": bool(r.get("all")),
                        "grp": (r.get("group") or ""),
                        "_rule": r}
    items = list(seen.values())
    cap = config.AUTOBAN_MAX_PER_TICK
    deferred = max(0, len(items) - cap)
    todo = items[:cap]
    # escalation ladder (#9): a repeat offender (re-banned after a prior ban expired)
    # gets a longer TTL each time. Overrides the rule TTL only when enabled.
    if _escalate_enabled():
        ladder, memory_s = _escalate_ladder(), _escalate_memory_s()
        for it in todo:
            n = db.offender_bump(it["ip"], memory_s)
            if n > 1:                                   # first offense keeps the rule TTL
                it["ttl"] = ladder[min(n - 1, len(ladder) - 1)]
                it["reason"] += " · рецидив #%d" % n
    # BATCH: /block_bulk does ONE reload per call. Group by (ttl, attachment) so each
    # distinct (ttl, where-it-enforces) combo is a single bulk call → each enforcement
    # target reloads at most once per tick. The attachment key is a stable signature of
    # the rule's groups/targets/all (or the legacy single group).
    def _attach_key(it):
        if it.get("all"):
            return ("all",)
        if it.get("groups") or it.get("targets"):
            return ("attach", tuple(sorted(it.get("groups") or [])), tuple(sorted(it.get("targets") or [])))
        return ("grp", it.get("grp") or "")
    by_key = {}
    for it in todo:
        by_key.setdefault((int(it.get("ttl") or 0), _attach_key(it)), []).append(it)
    banned_cidrs = []
    for (ttl, akey), grp_items in by_key.items():
        payload = {"items": [{"cidr": it["cidr"], "reason": it["reason"]} for it in grp_items],
                   "ttl": ttl, "added_by": "autoban", "force": False}
        if akey[0] == "all":
            payload["all"] = True
        elif akey[0] == "attach":
            payload["groups"] = list(akey[1])
            payload["targets"] = list(akey[2])
        elif akey[1]:                     # legacy single group
            payload["group"] = akey[1]
        try:
            # route to the backend(s) that own this attachment (B5) — not just active
            _, resp = _write_fanout("POST", "/block_bulk", payload, _route_for(payload))
            if resp and resp.get("ok"):
                banned_cidrs.extend(resp.get("blocked") or [])
            else:
                log.warning("[autoban] block_bulk failed (ttl=%s attach=%s): %s" % (ttl, akey, resp))
        except Exception as e:
            log.warning("[autoban] block_bulk error (ttl=%s attach=%s): %s" % (ttl, akey, e))
    banned = len(banned_cidrs)
    # capture matched paths for the IPs we actually banned (cheap Loki queries — NOT
    # ingress reloads, so they don't add churn) for the "why banned" view
    if banned_cidrs:
        ban_paths = db.setting_get("autoban_ban_paths", {}) or {}
        bset = set(banned_cidrs)
        for it in todo:
            if it["cidr"] not in bset:
                continue
            try:
                pp = loki.ip_rule_paths(it["cidr"].split("/")[0], it.get("_rule"), "1h", 5)
                if pp:
                    ban_paths[it["cidr"]] = pp
            except Exception:
                pass
        if len(ban_paths) > 500:   # keep the map bounded
            ban_paths = dict(list(ban_paths.items())[-500:])
        db.setting_set("autoban_ban_paths", ban_paths)
    if deferred:
        log.warning("[autoban] cap hit: banned %d, deferred %d (cap=%d)" % (banned, deferred, cap))
    if banned:
        log.info("[autoban] banned %d IP across %d rules (bulk, %d reload(s))" % (
            banned, len(rules), len(by_key)))
    db.setting_set("autoban_last_run", {"ts": int(time.time()), "checked_rules": len(rules),
                                        "candidates": len(items), "banned": banned,
                                        "deferred": deferred, "already": len(already)})


# ── threat-intelligence feeds (#2) ────────────────────────────────────────────
# Periodically import external block lists (Spamhaus DROP, Tor exit nodes, custom
# IP/CIDR lists) and ban them into a chosen group. Self-syncing without diffing:
# each refresh re-bans with a TTL a few cycles long, so an entry that leaves the
# feed simply expires. Banning is gated by an explicit enable toggle.
_TF_GROUP_DEFAULT = "threat-feeds"
_TF_PRESETS = [
    {"name": "Spamhaus DROP", "url": "https://www.spamhaus.org/drop/drop.txt"},
    {"name": "Tor exit nodes", "url": "https://check.torproject.org/torbulkexitlist"},
]

def _threat_feeds():
    v = db.setting_get("threat_feeds", None)
    return v if isinstance(v, list) else []

def _tf_refresh_hours():
    try:
        return max(1, int(db.setting_get("threat_feed_refresh_hours", 6)))
    except (TypeError, ValueError):
        return 6

def _parse_feed_lines(text, cap=200000):
    """Extract valid IPs / CIDRs from a feed body. Tolerates `;` and `#` comments
    and trailing annotations (Spamhaus `1.2.3.0/24 ; SBL123`)."""
    out, seen = [], set()
    for line in text.splitlines():
        line = line.split(";", 1)[0].split("#", 1)[0].strip()
        if not line:
            continue
        tok = line.split()[0]
        try:
            net = ipaddress.ip_network(tok, strict=False) if "/" in tok else ipaddress.ip_address(tok)
        except ValueError:
            continue
        cidr = str(net)
        if cidr not in seen:
            seen.add(cidr); out.append(cidr)
            if len(out) >= cap:
                break
    return out

def _fetch_feed(url, timeout=20, max_bytes=8 * 1024 * 1024):
    import urllib.request
    # threat feeds are public sources → block internal/loopback/metadata (SSRF).
    ok_egress, egress_err = _egress_check(url, allow_internal=False)
    if not ok_egress:
        raise ValueError("egress запрещён: %s" % egress_err)
    req = urllib.request.Request(url, headers={"User-Agent": "soc-threat-feed/1.0"})
    with _safe_opener(allow_internal=False).open(req, timeout=timeout) as r:  # re-check redirects
        return r.read(max_bytes).decode("utf-8", "replace")

def threat_feed_run_once(manual=False):
    """Fetch each enabled feed and ban its IPs/CIDRs into the configured group.
    Returns a per-feed status dict (also persisted for the dashboard)."""
    feeds = [f for f in _threat_feeds() if f.get("enabled") and f.get("url")]
    group = (db.setting_get("threat_feed_group", "") or _TF_GROUP_DEFAULT)
    # TTL = a few refresh cycles, so a dropped entry expires instead of lingering
    ttl = _tf_refresh_hours() * 3600 * 3
    status = dict(db.setting_get("threat_feed_status", {}) or {})
    total = 0
    for f in feeds:
        name = f.get("name") or f.get("url")
        try:
            cidrs = _parse_feed_lines(_fetch_feed(f["url"]))
            if not _backends("__all__"):
                raise RuntimeError("blocklist-api не настроен")
            banned = 0
            ids = _route_for({"group": group})     # owners of the feed's group (B5)
            for i in range(0, len(cidrs), 2000):   # chunk so each bulk call stays sane
                chunk = cidrs[i:i + 2000]
                payload = {"items": [{"cidr": c, "reason": "feed: " + name} for c in chunk],
                           "ttl": ttl, "added_by": "feed", "force": False}
                if group:
                    payload["group"] = group
                _, resp = _write_fanout("POST", "/block_bulk", payload, ids)
                if resp and resp.get("ok"):
                    banned += len(resp.get("blocked") or [])
            total += banned
            status[name] = {"ts": int(time.time()), "ok": True, "count": len(cidrs),
                            "banned": banned, "error": None}
        except Exception as e:
            status[name] = {"ts": int(time.time()), "ok": False, "count": 0,
                            "banned": 0, "error": str(e)}
            log.warning("[feed] %s failed: %s" % (name, e))
    db.setting_set("threat_feed_status", status)
    db.setting_set("threat_feed_last_run", int(time.time()))
    return {"ok": True, "feeds": len(feeds), "banned": total, "status": status, "group": group}

def _threat_feed_tick():
    """Called every autoban tick; fetches only when enabled and the refresh interval
    has elapsed (banning external lists requires its own explicit toggle)."""
    if not db.setting_get("threat_feeds_enabled", False):
        return
    last = db.setting_get("threat_feed_last_run", 0) or 0
    if time.time() - last < _tf_refresh_hours() * 3600:
        return
    try:
        threat_feed_run_once()
    except Exception as e:
        log.warning("[feed] tick error:", e)


@app.get("/api/threat_feeds")
def api_threat_feeds():
    return {"feeds": _threat_feeds(), "enabled": bool(db.setting_get("threat_feeds_enabled", False)),
            "group": db.setting_get("threat_feed_group", "") or _TF_GROUP_DEFAULT,
            "refresh_hours": _tf_refresh_hours(), "presets": _TF_PRESETS,
            "status": db.setting_get("threat_feed_status", {}) or {},
            "last_run": db.setting_get("threat_feed_last_run", None),
            "blocklist_enabled": bool(config.BLOCKLIST_API_URL)}


@app.post("/api/threat_feeds")
async def api_threat_feeds_save(request: Request):
    body = await request.json()
    feeds = []
    for f in (body.get("feeds") or [])[:50]:
        url = (f.get("url") or "").strip()
        if not url.startswith(("http://", "https://")):
            continue
        feeds.append({"name": (f.get("name") or url)[:80], "url": url[:500],
                      "enabled": bool(f.get("enabled", True))})
    db.setting_set("threat_feeds", feeds)
    if "enabled" in body:
        db.setting_set("threat_feeds_enabled", bool(body["enabled"]))
    if body.get("group") is not None:
        db.setting_set("threat_feed_group", (body.get("group") or "").strip()[:64])
    if body.get("refresh_hours"):
        try:
            db.setting_set("threat_feed_refresh_hours", max(1, int(body["refresh_hours"])))
        except (TypeError, ValueError):
            pass
    return {"ok": True, "feeds": feeds}


@app.post("/api/threat_feeds/refresh")
def api_threat_feeds_refresh():
    if not config.BLOCKLIST_API_URL:
        return JSONResponse({"ok": False, "error": "blocklist-api не настроен"}, status_code=400)
    return threat_feed_run_once(manual=True)


def autoban_loop():
    # daemon thread always runs; it only BANS when the kill-switch is armed, so the
    # UI toggle takes effect with no restart. Disarmed = pure no-op (no Loki load).
    while True:
        try:
            if db.setting_get("autoban_armed", False):
                autoban_run_once()
        except Exception as e:
            log.warning("[autoban] loop error:", e)
        _refresh_path403()   # render-health for the 403-path section (runs every tick)
        try:
            _threat_feed_tick()
        except Exception as e:
            log.warning("[feed] loop error:", e)
        time.sleep(config.AUTOBAN_INTERVAL)


@app.get("/api/autoban/preview")
def api_autoban_preview(id: int = 0, match_type: str = "substring", path: str = "",
                        status: str = "", threshold: int = 5, window: str = "10m",
                        combine: int = 1, host: str = ""):
    """Dry-run: who WOULD be banned. Either an existing rule (id) or ad-hoc params
    (for the create form / generator live-preview)."""
    if id:
        rule = db.autoban_rule(id)
        if not rule:
            return JSONResponse({"matches": [], "error": "правило не найдено"})
    else:
        rule = {"match_type": match_type if match_type in _AB_MATCH else "substring",
                "path": path, "status": status, "combine": 1 if combine else 0,
                "threshold": max(1, threshold), "window": window if window in _AB_WINDOWS else "10m"}
    try:
        data = _autoban_eval(rule, host=host)
        # drop IPs already covered by the active denylist (no point re-banning) +
        # report how many were skipped so the operator sees the dedup happened
        nets = _blocked_nets()
        if nets:
            def _blocked(ip):
                try:
                    a = ipaddress.ip_address(ip)
                    return any(a in n for n in nets)
                except Exception:
                    return False
            kept = [m for m in data.get("matches", []) if not _blocked(m["ip"])]
            data["already_banned"] = data.get("total_ips", 0) - len(kept)
            data["matches"] = kept
            data["total_ips"] = len(kept)
            data["total_hits"] = sum(m["count"] for m in kept)
        return JSONResponse(data)
    except Exception as e:
        return JSONResponse({"matches": [], "error": str(e)})


@app.post("/api/block")
async def api_block(request: Request):
    body = await request.json()
    payload = {"cidr": body.get("cidr", ""), "reason": body.get("reason", ""),
               "ttl": body.get("ttl", 0), "force": bool(body.get("force", False)),
               "added_by": "dashboard"}
    if body.get("group"):
        payload["group"] = body["group"]
    ids = _route_for(body)   # by group/targets/all owner, else whole fleet
    status, resp = _write_fanout("POST", "/block", payload, ids)
    return JSONResponse(resp or {"ok": False, "error": "нет ответа"}, status_code=status or 502)


@app.post("/api/unblock")
async def api_unblock(request: Request):
    body = await request.json()
    # an IP may be banned on several backends — unblock everywhere in scope
    # (a backend that doesn't have it just no-ops).
    status, resp = _write_fanout("POST", "/unblock", {"cidr": body.get("cidr", "")},
                                 [b[0] for b in _backends()])
    return JSONResponse(resp or {"ok": False, "error": "нет ответа"}, status_code=status or 502)


@app.post("/api/block_bulk")
async def api_block_bulk(request: Request):
    body = await request.json()
    payload = {"reason": body.get("reason", "сканер (просятся в бан)"),
               "ttl": body.get("ttl", 0), "added_by": "dashboard"}
    if body.get("group"):
        payload["group"] = body["group"]
    if body.get("items"):
        payload["items"] = body["items"]
    else:
        payload["cidrs"] = body.get("cidrs") or []
    ids = _route_for(body)
    status, resp = _write_fanout("POST", "/block_bulk", payload, ids)
    return JSONResponse(resp or {"ok": False, "error": "нет ответа"}, status_code=status or 502)


@app.post("/api/unblock_all")
async def api_unblock_all(request: Request):
    status, resp = _write_fanout("POST", "/unblock_all", {}, [b[0] for b in _backends()])
    return JSONResponse(resp or {"ok": False, "error": "нет ответа"}, status_code=status or 502)


@app.post("/api/resync")
async def api_resync(request: Request):
    status, resp = _write_fanout("POST", "/resync", {}, [b[0] for b in _backends()])
    return JSONResponse(resp or {"ok": False, "error": "нет ответа"}, status_code=status or 502)


# ── path-403 rules (proxied to blocklist-api) ─────────────────────────────────
@app.get("/api/path_rules")
def api_path_rules():
    if not _backends("__all__"):
        return JSONResponse({"enabled": True, "rules": []})
    rules, errors = _fanout_list("/path_rules", "rules")
    return JSONResponse({"enabled": True, "rules": rules, "backend_errors": errors})


@app.get("/api/path_status")
def api_path_status():
    if not _backends("__all__"):
        return JSONResponse({"rendered_ok": False, "error": "нет ответа"})
    targets, off, enabled_all, count, enc, rok, errors = {}, set(), True, 0, 0, True, {}
    for bid, _st, body, err in _fanout("GET", "/path_status"):
        if err:
            errors[bid] = err; rok = False; continue
        body = body or {}
        tg = body.get("targets") or {}
        entries = tg.items() if isinstance(tg, dict) else enumerate(tg)
        for tid, tv in entries:
            if isinstance(tv, dict):
                tv = dict(tv); tv.setdefault("backend", bid)
            targets["%s/%s" % (bid, tid)] = tv   # unique key keeps every target (ids collide)
        enabled_all = enabled_all and bool(body.get("enabled", True))
        off |= set(body.get("off_types") or [])
        count += body.get("count", 0) or 0
        enc += body.get("enabled_count", 0) or 0
        rok = rok and bool(body.get("rendered_ok"))
    return JSONResponse({"enabled": enabled_all, "off_types": sorted(off), "count": count,
                         "enabled_count": enc, "rendered_ok": rok, "targets": targets,
                         "backend_errors": errors})


@app.get("/api/protected_paths")
def api_protected_paths():
    """Общий список защищённых путей (тот же, что у автобана) — для показа в 403."""
    return JSONResponse({"paths": _autoban_ignore()})


@app.post("/api/path_rule")
async def api_path_rule(request: Request):
    body = await request.json()
    # защищённые пути нельзя резать через 403 — жёсткий отказ (без force). Проверяем
    # ТОЛЬКО новые куски: при правке существующего правила старые пути не перепроверяем
    # (иначе ранее добавленный путь под /api/ блокировал бы любую правку).
    new_parts = _re_top_split(_re_unwrap(body.get("pattern", "")))
    rid = body.get("id")
    # where does this write go: an existing rule → its owning backend(s) (from the
    # explicit `backend`, or discovered by id); a new rule → the attachment owners.
    if rid:
        if body.get("backend"):
            ids = [body["backend"]]
        else:
            ids = [bid for bid, _st, d, err in _fanout("GET", "/path_rules")
                   if not err and any(str(x.get("id")) == str(rid) for x in (d or {}).get("rules", []))]
            ids = ids or [b[0] for b in _backends()]
        # subtract already-present parts (per the first owning backend) so an edit
        # doesn't re-trip the protected-path guard on paths added earlier.
        bmap = {b[0]: (b[1], b[2]) for b in _backends("__all__")}
        if ids and ids[0] in bmap:
            u, tk = bmap[ids[0]]
            _, d = _bcall_to(u, tk, "GET", "/path_rules")
            ex = next((x for x in (d or {}).get("rules", []) if str(x.get("id")) == str(rid)), None)
            if ex:
                old = set(_re_top_split(_re_unwrap(ex.get("pattern") or "")))
                new_parts = [p for p in new_parts if p not in old]
    else:
        ids = _route_for(body)
    for part in new_parts:
        hit = _pattern_hits_protected(part)
        if hit:
            return JSONResponse({"ok": False, "error":
                "«%s» задевает защищённый путь «%s» — в 403 нельзя." % (part[:50], hit)},
                status_code=400)
    payload = {"id": body.get("id"), "name": body.get("name", ""),
               "pattern": body.get("pattern", ""),
               "enabled": bool(body.get("enabled", True)),
               "force": bool(body.get("force", False)),
               "groups": body.get("groups"), "targets": body.get("targets"),
               "all": bool(body.get("all", False)), "group": body.get("group", "")}
    status, resp = _write_fanout("POST", "/path_rule", payload, ids)
    return JSONResponse(resp or {"ok": False, "error": "нет ответа"}, status_code=status or 502)


@app.get("/api/blocklist_config")
def api_blocklist_config_get():
    """Where the dashboard points its blocklist-api client. Token is write-only —
    never returned, just whether one is set."""
    o = db.setting_get("blocklist_api_override", {}) or {}
    return {"url": config.BLOCKLIST_API_URL or "", "token_set": bool(config.BLOCKLIST_API_TOKEN),
            "is_override": bool(o.get("url") or o.get("token")),
            "env_url": os.environ.get("BLOCKLIST_API_URL", "")}


@app.post("/api/blocklist_config")
async def api_blocklist_config_set(request: Request):
    body = await request.json()
    url = (body.get("url") or "").strip()
    if url:
        ok_egress, egress_err = _egress_check(url)
        if not ok_egress:
            return JSONResponse({"ok": False, "error": egress_err}, status_code=400)
    o = db.setting_get("blocklist_api_override", {}) or {}
    o["url"] = url  # empty clears the override → falls back to env var on next restart
    if body.get("token"):  # blank = leave the existing token as-is
        o["token"] = body["token"]
    db.setting_set("blocklist_api_override", o)
    # apply live — no restart needed (every call site reads config.* at call time)
    config.BLOCKLIST_API_URL = url or os.environ.get("BLOCKLIST_API_URL", "")
    if body.get("token"):
        config.BLOCKLIST_API_TOKEN = body["token"]
    return {"ok": True, "url": config.BLOCKLIST_API_URL, "token_set": bool(config.BLOCKLIST_API_TOKEN)}


# ── Ingress API registry: several blocklist-api backends the dashboard can talk
# to (one per cluster you ran Setup-cluster against), each registered by hostname.
# Only ONE is "active" at a time — that's the one every existing call site uses
# via config.BLOCKLIST_API_URL/TOKEN (today's single-upstream architecture).
# Registering the others keeps them one click away ("activate") without
# re-typing host/token, and lets you verify a fresh cluster before switching.
import re as _re


def _ing_apis():
    return db.setting_get("ingress_apis", {"items": {}, "active": ""}) or {"items": {}, "active": ""}


def _ing_apis_save(d):
    db.setting_set("ingress_apis", d)


def _ing_slug(s):
    return _re.sub(r"[^a-z0-9_.:-]+", "-", (s or "").strip().lower()).strip("-")[:48]


def _set_active_backend(url, token=None):
    """Point the dashboard at this blocklist-api, live, no restart (mirrors into
    the same override _apply_blocklist_override reads on the next process start)."""
    o = db.setting_get("blocklist_api_override", {}) or {}
    o["url"] = url
    if token:
        o["token"] = token
    db.setting_set("blocklist_api_override", o)
    config.BLOCKLIST_API_URL = url
    if token:
        config.BLOCKLIST_API_TOKEN = token


@app.get("/api/ingress_apis")
def api_ingress_apis_list():
    """Registered blocklist-api backends. Token is write-only (token_set bool only)."""
    d = _ing_apis()
    items = [{"id": tid, "url": e.get("url", ""), "token_set": bool(e.get("token"))}
             for tid, e in d["items"].items()]
    return {"items": sorted(items, key=lambda x: x["id"]), "active": d.get("active", ""),
            "scope": d.get("scope", "__all__")}


@app.get("/api/backend_scope")
def api_backend_scope_get():
    """Current fan-out scope + the fleet the dashboard can read across."""
    d = _ing_apis()
    return {"scope": d.get("scope", "__all__"),
            "backends": [{"id": bid, "url": url} for bid, url, _tok in _backends("__all__")]}


@app.post("/api/backend_scope")
async def api_backend_scope_set(request: Request):
    """Set the read scope: '__all__' (whole fleet) or a specific backend id."""
    body = await request.json()
    sc = (body.get("scope") or "__all__").strip()
    ids = {b[0] for b in _backends("__all__")}
    if sc != "__all__" and sc not in ids:
        return JSONResponse({"ok": False, "error": "неизвестный бэкенд"}, status_code=400)
    d = _ing_apis()
    d["scope"] = sc
    _ing_apis_save(d)
    return {"ok": True, "scope": sc}


@app.get("/api/backends/health")
def api_backends_health():
    """Probe every backend in parallel: reachable (/healthz, no auth) + token valid
    (/targets, Bearer) + round-trip latency. Powers the fleet health indicator and
    the 'data may be incomplete' warning when a backend is down. Cached ~12s (Pf2)
    so the UI's periodic poll doesn't fire 2×N probes every interval."""
    from concurrent.futures import ThreadPoolExecutor
    bes = _backends("__all__")
    if not bes:
        return {"backends": []}
    ckey = tuple(b[0] for b in bes)
    hit = _health_cache.get("d")
    if hit is not None and _health_cache.get("k") == ckey and (time.time() - _health_cache["t"]) < 12:
        return hit

    def probe(b):
        bid, url, tok = b
        t0 = time.perf_counter()
        st, _ = _bcall_to(url, tok, "GET", "/healthz", timeout=5)
        lat = int((time.perf_counter() - t0) * 1000)
        reachable = st is not None and st < 500
        token_ok, err = None, None
        if not reachable:
            err = "нет связи"
        else:
            ts, _b = _bcall_to(url, tok, "GET", "/targets", timeout=5)
            token_ok = ts is not None and ts < 400
            if not token_ok:
                err = "токен не принят (HTTP %s)" % ts if ts else "нет ответа /targets"
        return {"id": bid, "url": url, "reachable": bool(reachable),
                "token_ok": token_ok, "latency_ms": lat, "error": err}

    with ThreadPoolExecutor(max_workers=min(8, len(bes))) as ex:
        out = {"backends": list(ex.map(probe, bes))}
    _health_cache.update({"t": time.time(), "k": ckey, "d": out})
    return out


@app.post("/api/ingress_apis/test")
async def api_ingress_apis_test(request: Request):
    """Probe a blocklist-api endpoint before saving it: reachable (/healthz, no
    auth) + token valid (/targets, Bearer). Works on an unsaved url+token, or by
    `id` to re-test an already-registered one without re-entering its token."""
    import urllib.error
    import urllib.request
    body = await request.json()
    url = (body.get("url") or "").strip().rstrip("/")
    token = body.get("token") or ""
    if body.get("id") and not token:
        token = (_ing_apis()["items"].get(body["id"]) or {}).get("token", "")
    if not url:
        return {"ok": False, "error": "пустой URL"}
    ok_egress, egress_err = _egress_check(url)
    if not ok_egress:
        return {"ok": False, "error": egress_err}
    out = {"ok": False, "reachable": False, "token_valid": False, "error": None}
    try:
        with urllib.request.urlopen(url + "/healthz", timeout=6) as r:
            out["reachable"] = (r.status == 200)
    except Exception as e:
        out["error"] = "нет связи: %s" % e
        return out
    try:
        req = urllib.request.Request(url + "/targets", headers={"Authorization": "Bearer " + token})
        with urllib.request.urlopen(req, timeout=6) as r:
            out["token_valid"] = (r.status == 200)
    except urllib.error.HTTPError as e:
        out["error"] = "токен не принят (HTTP %s)" % e.code
    except Exception as e:
        out["error"] = "ошибка запроса /targets: %s" % e
    out["ok"] = out["reachable"] and out["token_valid"]
    return out


@app.post("/api/ingress_apis")
async def api_ingress_apis_save(request: Request):
    """Register a blocklist-api backend (doesn't activate it — see /activate)."""
    body = await request.json()
    url = (body.get("url") or "").strip().rstrip("/")
    ok_egress, egress_err = _egress_check(url)
    if not ok_egress:
        return JSONResponse({"ok": False, "error": egress_err}, status_code=400)
    tid = _ing_slug(body.get("id") or url.split("://", 1)[-1])
    if not tid:
        return JSONResponse({"ok": False, "error": "не удалось определить id из URL"}, status_code=400)
    d = _ing_apis()
    cur = dict(d["items"].get(tid) or {})
    cur["url"] = url
    if body.get("token"):   # blank = keep existing secret on update
        cur["token"] = body["token"]
    d["items"][tid] = cur
    _ing_apis_save(d)
    return {"ok": True, "id": tid, "url": cur["url"], "token_set": bool(cur.get("token"))}


@app.post("/api/ingress_apis/activate")
async def api_ingress_apis_activate(request: Request):
    """Make this the live backend every dashboard call site talks to."""
    body = await request.json()
    tid = body.get("id") or ""
    d = _ing_apis()
    e = d["items"].get(tid)
    if not e:
        return JSONResponse({"ok": False, "error": "подключение не найдено"}, status_code=404)
    d["active"] = tid
    _ing_apis_save(d)
    _set_active_backend(e.get("url", ""), e.get("token"))
    return {"ok": True, "id": tid}


@app.post("/api/ingress_apis/delete")
async def api_ingress_apis_delete(request: Request):
    body = await request.json()
    tid = body.get("id") or ""
    d = _ing_apis()
    existed = tid in d["items"]
    reset = False
    if existed:
        d["items"].pop(tid)
        if d.get("active") == tid:
            d["active"] = ""
            # the dashboard was pointed at this backend (via _set_active_backend);
            # deleting it must not strand the dashboard on a now-dead URL. Drop the
            # override so every call site falls back to the env-default backend —
            # the one that holds the original nginx nodes / CF targets.
            db.setting_set("blocklist_api_override", {})
            config.BLOCKLIST_API_URL = os.environ.get("BLOCKLIST_API_URL", "")
            config.BLOCKLIST_API_TOKEN = os.environ.get("BLOCKLIST_API_TOKEN", "")
            reset = True
        _ing_apis_save(d)
    return {"ok": True, "deleted": existed, "reset_to_default": reset}


@app.get("/api/branding")
def api_branding_get():
    """Custom dashboard branding (title / subtitle / logo). Logo is a small data: URI."""
    return db.setting_get("branding", {}) or {}


@app.post("/api/branding")
async def api_branding_set(request: Request):
    body = await request.json()
    title = (body.get("title") or "").strip()[:60]
    subtitle = (body.get("subtitle") or "").strip()[:120]
    icon = body.get("icon") or ""
    # only accept a small inline image data URI; reject anything else / oversized
    if icon:
        if not isinstance(icon, str) or not icon.startswith("data:image/") or len(icon) > 256_000:
            return JSONResponse({"ok": False, "error": "иконка должна быть картинкой data:image и < ~190KB"},
                                status_code=400)
    cur = db.setting_get("branding", {}) or {}
    cur.update({"title": title, "subtitle": subtitle})
    # icon: empty string in payload means "leave as is"; explicit null clears it
    if "icon" in body:
        cur["icon"] = icon
    db.setting_set("branding", cur)
    return {"ok": True, **cur}


def _rule_owners(rid, backend=None):
    """Backend(s) owning a path rule id — the explicit `backend`, else discovered by
    id across the fleet, else the whole scope (broadcast fallback). Rule ids collide
    across backends, so routing by owner (not blind broadcast) avoids toggling the
    wrong rule on a sibling cluster."""
    if backend:
        return [backend]
    owners = [bid for bid, _st, d, err in _fanout("GET", "/path_rules")
              if not err and any(str(x.get("id")) == str(rid) for x in (d or {}).get("rules", []))]
    return owners or [b[0] for b in _backends()]


@app.post("/api/path_rule/delete")
async def api_path_rule_delete(request: Request):
    body = await request.json()
    ids = _rule_owners(body.get("id", ""), body.get("backend"))
    status, resp = _write_fanout("POST", "/path_rule_delete", {"id": body.get("id", "")}, ids)
    return JSONResponse(resp or {"ok": False, "error": "нет ответа"}, status_code=status or 502)


@app.post("/api/path_rule/toggle")
async def api_path_rule_toggle(request: Request):
    body = await request.json()
    ids = _rule_owners(body.get("id", ""), body.get("backend"))
    status, resp = _write_fanout("POST", "/path_rule_toggle",
                                 {"id": body.get("id", ""), "enabled": bool(body.get("enabled", True))}, ids)
    return JSONResponse(resp or {"ok": False, "error": "нет ответа"}, status_code=status or 502)


@app.post("/api/path_master")
async def api_path_master(request: Request):
    body = await request.json()   # global kill-switch → every backend in scope
    status, resp = _write_fanout("POST", "/path_master", {"enabled": bool(body.get("enabled", True))},
                                 [b[0] for b in _backends()])
    return JSONResponse(resp or {"ok": False, "error": "нет ответа"}, status_code=status or 502)


@app.post("/api/path_type")
async def api_path_type(request: Request):
    body = await request.json()   # per-type 403 toggle → every backend in scope
    status, resp = _write_fanout("POST", "/path_type",
                                 {"type": body.get("type"), "enabled": bool(body.get("enabled", True))},
                                 [b[0] for b in _backends()])
    return JSONResponse(resp or {"ok": False, "error": "нет ответа"}, status_code=status or 502)


def _path_ids_by_name():
    """name -> id of existing 403 rules, so seeding is idempotent (update, not duplicate)."""
    _, body = _blocklist_call("GET", "/path_rules")
    return {r.get("name"): r.get("id") for r in ((body or {}).get("rules") or []) if r.get("name")}


def _path_upsert_by_name(name, pattern, existing, force=False):
    payload = {"name": name, "pattern": pattern, "force": bool(force)}
    if name in existing:
        payload["id"] = existing[name]          # update in place, no duplicate
    _, resp = _blocklist_call("POST", "/path_rule", payload)
    return resp or {"ok": False, "error": "нет ответа"}


def _autoban_rule_to_pattern(rule):
    """Convert an auto-ban rule's path(s) into a 403 regex fragment, mirroring how
    the executor matches: substring → escaped literals, regex → raw, family → skip."""
    import re as _re
    mt = rule.get("match_type") or "substring"
    if mt == "family":
        return None                              # signature preset, not an enumerable path set
    parts = [p.strip() for p in (rule.get("path") or "").split("\n") if p.strip()]
    if not parts:
        return None
    alt = "|".join(parts) if mt == "regex" else "|".join(_re.escape(p) for p in parts)
    return "(" + alt + ")"


@app.post("/api/path_seed")
async def api_path_seed(request: Request):
    """Seed the canonical scanner-path set as one '403' rule (the regex that used
    to live in the ingress by hand). Idempotent: re-seeding updates 'base-scanners'."""
    existing = _path_ids_by_name()
    resp = _path_upsert_by_name("base-scanners", config.BASE_403_PATTERN, existing)
    return JSONResponse(resp, status_code=200 if resp.get("ok") else 502)


@app.post("/api/path_seed_autoban")
async def api_path_seed_autoban(request: Request):
    """Seed 403 rules FROM auto-ban rules: one 403 rule per auto-ban rule
    ('из автобана: <name>'), built from its paths. Family rules are skipped.
    Body may carry `ids: [...]` to seed only selected rules (else all).
    Idempotent: re-running updates the same-named rules instead of duplicating."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    rules = db.autoban_rules()
    sel = body.get("ids")
    if sel:
        want = {str(x) for x in sel}
        rules = [r for r in rules if str(r.get("id")) in want]
    existing = _path_ids_by_name()
    created, skipped = [], []
    for r in rules:
        pat = _autoban_rule_to_pattern(r)
        nm = (r.get("name") or "").strip()
        if not pat:
            skipped.append({"name": nm, "reason": "семейство/без путей — нечего конвертировать"})
            continue
        name = ("из автобана: " + nm)[:80]
        res = _path_upsert_by_name(name, pat, existing)
        if res.get("ok"):
            created.append(name)
        else:
            skipped.append({"name": nm, "reason": res.get("error", "ошибка")})
    return JSONResponse({"ok": True, "created": created, "skipped": skipped})


# ── обратное направление: наполнить автобан-правила из 403-правил ──────────────
def _re_unwrap(s):
    """Снять один внешний слой (...) если он обрамляет всю строку (escape-aware)."""
    s = (s or "").strip()
    if len(s) < 2 or s[0] != "(" or s[-1] != ")":
        return s
    depth, i = 0, 0
    while i < len(s):
        c = s[i]
        if c == "\\":
            i += 2; continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return s[1:-1] if i == len(s) - 1 else s
        i += 1
    return s


def _re_top_split(s):
    """Разбить по '|' только на глубине 0 (не внутри (...) / [...]), escape-aware."""
    out, cur, depth, incls, i = [], "", 0, False, 0
    while i < len(s):
        c = s[i]
        if c == "\\":
            cur += s[i:i + 2]; i += 2; continue
        if incls:
            cur += c
            if c == "]":
                incls = False
            i += 1; continue
        if c == "[":
            incls = True; cur += c; i += 1; continue
        if c == "(":
            depth += 1; cur += c; i += 1; continue
        if c == ")":
            depth -= 1; cur += c; i += 1; continue
        if c == "|" and depth == 0:
            out.append(cur); cur = ""; i += 1; continue
        cur += c; i += 1
    out.append(cur)
    return [p for p in out if p]


# ── «основная пара»: одно 403-правило + одно автобан-правило, добавление в оба ─
def _re_lit(s):
    """Экранировать путь в литеральный regex-фрагмент (как фронтовый _reEsc)."""
    import re as _re
    return _re.sub(r'([.*+?^${}()|\[\]\\])', r'\\\1', s or "")


@app.get("/api/main_rules")
def api_main_rules():
    return JSONResponse({"path_id": db.setting_get("main_path_rule", None),
                         "autoban_id": db.setting_get("main_autoban_rule", None)})


@app.post("/api/main_rules")
async def api_set_main_rules(request: Request):
    body = await request.json()
    if "path_id" in body:
        db.setting_set("main_path_rule", body.get("path_id"))
    if "autoban_id" in body:
        db.setting_set("main_autoban_rule", body.get("autoban_id"))
    return JSONResponse({"ok": True, "path_id": db.setting_get("main_path_rule", None),
                         "autoban_id": db.setting_get("main_autoban_rule", None)})


@app.post("/api/add_to_main")
async def api_add_to_main(request: Request):
    """Добавить путь СРАЗУ в основное 403-правило И основное автобан-правило (дедуп).
    403 получает экранированный литерал, автобан — сырой путь (движок сам экранирует)."""
    body = await request.json()
    path = (body.get("path") or "").strip()
    if not path:
        return JSONResponse({"ok": False, "error": "нужен path"}, status_code=400)
    prot = _path_protected(path)
    if prot:
        err = {"ok": False, "error": "путь под защитой «%s» — нельзя ни в 403, ни в автобан" % prot}
        return JSONResponse({"ok": True, "protected": prot, "path403": err, "autoban": err})
    res = {"path403": None, "autoban": None}

    # --- 403: основное правило в blocklist-api ---
    pid = db.setting_get("main_path_rule", None)
    if not pid:
        res["path403"] = {"ok": False, "error": "не выбрано основное 403-правило (отметь ★)"}
    else:
        _, d = _blocklist_call("GET", "/path_rules")
        r = next((x for x in (d or {}).get("rules", []) if str(x.get("id")) == str(pid)), None)
        if not r:
            res["path403"] = {"ok": False, "error": "основное 403-правило не найдено"}
        else:
            parts = _re_top_split(_re_unwrap(r.get("pattern") or ""))
            lit = _re_lit(path)
            if lit in parts:
                res["path403"] = {"ok": True, "already": True, "name": r.get("name")}
            else:
                parts.append(lit)
                _, resp = _blocklist_call("POST", "/path_rule", {
                    "id": r["id"], "name": r.get("name"),
                    "pattern": "(" + "|".join(parts) + ")", "enabled": r.get("enabled", True)})
                ok = bool(resp and resp.get("ok"))
                res["path403"] = {"ok": ok, "name": r.get("name"),
                                  "error": None if ok else (resp or {}).get("error", "ошибка")}

    # --- автобан: основное правило в SQLite ---
    aid = db.setting_get("main_autoban_rule", None)
    if not aid:
        res["autoban"] = {"ok": False, "error": "не выбрано основное автобан-правило (отметь ★)"}
    else:
        rule = db.autoban_rule(int(aid))
        if not rule:
            res["autoban"] = {"ok": False, "error": "основное автобан-правило не найдено"}
        elif rule.get("match_type") == "family":
            res["autoban"] = {"ok": False, "error": "основное автобан-правило — семейство, путь не добавить"}
        else:
            parts = [p for p in (rule.get("path") or "").split("\n") if p.strip()]
            if path in parts:
                res["autoban"] = {"ok": True, "already": True, "name": rule.get("name")}
            else:
                parts.append(path)
                db.autoban_update(int(aid), {"path": "\n".join(parts)[:1000]})
                res["autoban"] = {"ok": True, "name": rule.get("name")}
    return JSONResponse({"ok": True, **res})


_BC_WINDOWS = {"1h", "6h", "8h"}
_bc_cache = {}   # (window, host) -> (ts, data)
_BC_TTL = 120    # heavy multi-query → cache hard to spare Loki
_bc_lock = threading.Lock()  # avoid overlapping heavy computes (pile-up → 429)


def _blocked_nets():
    """Active blocklist CIDRs across the whole fleet as ip_network objects (B4) —
    so 'already banned, skip' dedup sees bans on any backend, not just the active."""
    blocks, _ = _fanout_list("/list", "blocks")
    nets = []
    seen = set()
    for b in blocks:
        c = b.get("cidr")
        if not c or c in seen:
            continue
        seen.add(c)
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except Exception:
            pass
    return nets


def _drop_already_blocked(data):
    """Remove candidates whose IP is already covered by the active denylist."""
    nets = _blocked_nets()
    if not nets:
        return data
    def blocked(ip):
        try:
            a = ipaddress.ip_address(ip)
            return any(a in n for n in nets)
        except Exception:
            return False
    cands = [c for c in data.get("candidates", []) if not blocked(c["ip"])]
    return {**data, "candidates": cands, "total_ips": len(cands),
            "total_hits": sum(c.get("count", 0) for c in cands)}


@app.get("/api/ban_candidates")
def api_ban_candidates(window: str = "1h", host: str = "", env: str = ""):
    w = window if window in _BC_WINDOWS else "1h"
    key = (w, host, env)
    now = int(time.time())
    hit = _bc_cache.get(key)
    if hit and now - hit[0] < _BC_TTL:
        return JSONResponse({**_drop_already_blocked(hit[1]), "cached": True})
    # never run two heavy computes at once; if busy, serve stale (or "loading")
    if not _bc_lock.acquire(blocking=False):
        base = hit[1] if hit else {"candidates": [], "top_paths": []}
        return JSONResponse({**_drop_already_blocked(base), "stale": True})
    try:
        with loki.scope(env, _env_loki_url(env)):
            data = loki.ban_candidates(w, host, ignore_paths=_autoban_ignore())
        _bc_cache[key] = (now, data)
        if len(_bc_cache) > 20:
            _bc_cache.clear()
        return JSONResponse(_drop_already_blocked(data))
    except Exception as e:
        return JSONResponse({"candidates": [], "top_paths": [], "error": str(e)})
    finally:
        _bc_lock.release()


@app.get("/api/crs_offenders")
def api_crs_offenders(window: str = "1h", env: str = ""):
    """IPs that tripped OWASP CRS / ModSecurity (WAF panel, one-click ban)."""
    w = window if window in _BC_WINDOWS else "1h"
    try:
        with loki.scope(env, _env_loki_url(env)):
            return JSONResponse({"window": w, "offenders": loki.crs_offenders(w)})
    except Exception as e:
        return JSONResponse({"window": w, "offenders": [], "error": str(e)})


_sc_cache = {}


@app.get("/api/suspect_ips")
def api_suspect_ips(window: str = "1h", host: str = "", env: str = ""):
    w = window if window in _BC_WINDOWS else "1h"
    key = (w, host, env)
    now = int(time.time())
    hit = _sc_cache.get(key)
    if hit and now - hit[0] < _BC_TTL:
        return JSONResponse({**_drop_already_blocked(hit[1]), "cached": True})
    if not _bc_lock.acquire(blocking=False):
        base = hit[1] if hit else {"candidates": [], "top_paths": []}
        return JSONResponse({**_drop_already_blocked(base), "stale": True})
    try:
        with loki.scope(env, _env_loki_url(env)):
            data = loki.suspect_ips(w, host, ignore_paths=_autoban_ignore())
        _sc_cache[key] = (now, data)
        if len(_sc_cache) > 20:
            _sc_cache.clear()
        return JSONResponse(_drop_already_blocked(data))
    except Exception as e:
        return JSONResponse({"candidates": [], "top_paths": [], "error": str(e)})
    finally:
        _bc_lock.release()


_judge_cache = {}  # window -> (ts, verdicts)


@app.get("/api/judge_suspects")
def api_judge_suspects(window: str = "1h"):
    w = window if window in _BC_WINDOWS else "1h"
    now = int(time.time())
    hit = _judge_cache.get(w)
    if hit and now - hit[0] < 300:
        return JSONResponse({"verdicts": hit[1], "cached": True})
    # reuse cached suspect computation if fresh, else compute
    sc = _sc_cache.get((w, ""))
    data = sc[1] if (sc and now - sc[0] < _BC_TTL) else loki.suspect_ips(w, ignore_paths=_autoban_ignore())
    cands = [c for c in data.get("candidates", []) if not c.get("cf")][:12]
    items = []
    for c in cands:
        a = loki.asn_lookup(c["ip"])
        items.append({"ip": c["ip"], "count": c.get("count"), "country": c.get("country"),
                      "paths": c.get("paths"), "isp": a.get("isp") or a.get("org"),
                      "asn": a.get("as"), "hosting": a.get("hosting"), "proxy": a.get("proxy"),
                      "reputation": loki.reputation(c["ip"], a).get("verdict")})
    if not items:
        return JSONResponse({"verdicts": []})
    verdicts = llm.judge_suspects(items)
    _judge_cache[w] = (now, verdicts)
    return JSONResponse({"verdicts": verdicts})


@app.get("/api/verdicts")
def api_verdicts(ips: str = ""):
    """Already-computed AI verdicts (from cache, no LLM) — to restore UI after reload.
    Applies the deterministic scanner override so a stale/weak LLM "user"/"подозрит."
    verdict can't survive once the IP is seen hitting scanner paths (.php/phpmyadmin/…).
    """
    out = {}
    for ip in [x.strip() for x in ips.split(",") if x.strip()][:60]:
        v = db.cache_get("verdict:" + ip, 12 * 3600)
        if not v:
            continue
        if v.get("kind") in ("user", "подозрит."):
            try:
                sh = loki.ip_scanner_hits(ip, "8h", use_cache=True)
            except Exception:
                sh = 0
            if sh > 0:
                v = {"ip": ip, "kind": "scanner", "ban": True, "confidence": "high",
                     "reason": "сканирует уязвимые пути (.php/.env/wp): %d обращений" % sh}
                db.cache_put("verdict:" + ip, v)   # heal the cache
        out[ip] = v
    return JSONResponse({"verdicts": out})


@app.get("/api/judge_ip")
def api_judge_ip(ip: str = "", window: str = "1h", force: int = 0):
    if not ip:
        return JSONResponse({"verdict": None})
    w = window if window in _BC_WINDOWS else "1h"
    # --- deterministic checks FIRST (override LLM + any stale cache) ---
    # 1) reverse-DNS verified good bot → legit, never ban
    vb = loki.verify_bot(ip)
    if vb.get("bot"):
        verdict = {"ip": ip, "kind": "legit-bot", "ban": False, "confidence": "high",
                   "reason": "rDNS подтверждён: %s (%s)" % (vb["bot"], vb.get("ptr") or "")}
        db.cache_put("verdict:" + ip, verdict)
        return JSONResponse({"verdict": verdict, "verified": True})
    # 2) hits scanner paths (.php/.env/wp-…) → it's a scanner, not a legit bot
    sh = loki.ip_scanner_hits(ip, "8h")
    if sh > 0:
        verdict = {"ip": ip, "kind": "scanner", "ban": True, "confidence": "high",
                   "reason": "сканирует уязвимые пути (.php/.env/wp): %d обращений" % sh}
        db.cache_put("verdict:" + ip, verdict)
        return JSONResponse({"verdict": verdict, "deterministic": True})
    # 3) cached LLM verdict — but never trust a cached "legit-bot" (only rDNS may say that);
    #    force=1 bypasses the cache and re-asks the LLM
    if not force:
        cached = db.cache_get("verdict:" + ip, 12 * 3600)
        if cached is not None and cached.get("kind") != "legit-bot":
            return JSONResponse({"verdict": cached, "cached": True})
    cand = None
    sc = _sc_cache.get((w, ""))
    if sc:
        for c in sc[1].get("candidates", []):
            if c.get("ip") == ip:
                cand = c
                break
    a = loki.asn_lookup(ip)
    item = {"ip": ip, "count": (cand or {}).get("count"), "country": (cand or {}).get("country"),
            "paths": (cand or {}).get("paths"), "isp": a.get("isp") or a.get("org"),
            "asn": a.get("as"), "hosting": a.get("hosting"), "proxy": a.get("proxy"),
            "ptr": vb.get("ptr"), "reputation": loki.reputation(ip, a).get("verdict")}
    try:
        v = llm.judge_suspects([item], num_predict=180, timeout=60)
        verdict = v[0] if v else None
        # the LLM can't verify bots (rDNS does) — downgrade its unverified "legit-bot"
        if verdict and verdict.get("kind") == "legit-bot":
            verdict["kind"] = "подозрит."
            verdict["reason"] = "LLM счёл ботом, но rDNS не подтвердил — проверь вручную. " + (verdict.get("reason") or "")
        if verdict:
            db.cache_put("verdict:" + ip, verdict)
        return JSONResponse({"verdict": verdict})
    except Exception as e:
        return JSONResponse({"verdict": None, "error": str(e)})


@app.get("/api/ip_profile")
def api_ip_profile(ip: str = "", window: str = "1h"):
    try:
        return JSONResponse(loki.ip_profile(ip, _win(window) if window in _WINDOWS else "1h"))
    except Exception as e:
        return JSONResponse({"ip": ip, "error": str(e)})


@app.get("/api/crs_samples")
def api_crs_samples(family: str = "", window: str = "1h", limit: int = 30):
    try:
        return JSONResponse({"samples": loki.crs_samples(family, limit, _win(window) if window in _WINDOWS else "1h")})
    except Exception as e:
        return JSONResponse({"samples": [], "error": str(e)})


@app.get("/api/requests")
def api_requests(host: str = "", path: str = "", status: str = "", ip: str = "",
                 ua: str = "", ref: str = "", limit: int = 60, minutes: int = 15, env: str = ""):
    try:
        with loki.scope(env, _env_loki_url(env)):
            return JSONResponse({"requests": loki.recent_requests(host, path, status, ip, ua, ref, limit, minutes)})
    except Exception as e:
        return JSONResponse({"requests": [], "error": str(e)})


@app.get("/api/ips")
def api_ips(country: str = "", limit: int = 20, window: str = "", host: str = ""):
    try:
        return JSONResponse({"country": country,
                             "ips": loki.top_ips(country, limit, _win(window), host)})
    except Exception as e:
        return JSONResponse({"country": country, "ips": [], "error": str(e)})


@app.get("/api/digest")
def api_digest():
    now = int(time.time())
    with _state_lock:
        cached, ts = _state["digest"], _state["digest_ts"]
        stats0 = _state.get("digest_stats")
    if cached and now - ts < config.DIGEST_TTL:
        return JSONResponse({"ts": ts, "digest": cached, "stats": stats0, "cached": True})
    snaps = db.recent_snapshots(288)  # ~ up to a day at 5min spacing of poll snapshots
    stats = _aggregate_period(snaps)
    obj = llm.digest(stats)
    with _state_lock:
        _state["digest"] = obj
        _state["digest_stats"] = stats
        _state["digest_ts"] = now
    return JSONResponse({"ts": now, "digest": obj, "stats": stats, "cached": False})


@app.get("/api/suggest")
def api_suggest():
    with _state_lock:
        summary = _state["summary"]
        analytics = _state["analytics"] or {}
    if not summary:
        return JSONResponse({"deny": [], "waf": [], "rationale": "Нет данных."})
    return JSONResponse(llm.suggest_rules(summary, analytics))


def _aggregate_period(snaps):
    if not snaps:
        return {}
    keys = ["requests_total", "forbidden_new", "crs_detections", "status_404",
            "status_4xx", "status_5xx", "distinct_attacker_ips"]
    agg = {}
    for k in keys:
        vals = [s.get(k, 0) for s in snaps]
        agg[k] = {"max": max(vals), "avg": round(sum(vals) / len(vals), 1)}
    subs = {}
    for s in snaps:
        for x in s.get("top_subnets", []):
            subs[x["subnet"]] = max(subs.get(x["subnet"], 0), x["count"])
    # exclude already-blocked subnets (denylist + static deny ranges) from the digest
    banned = _blocked_nets()
    for d in getattr(config, "DENY_NETS", []):
        try:
            banned.append(ipaddress.ip_network(d))
        except Exception:
            pass

    def _is_banned(subnet):
        try:
            n = ipaddress.ip_network(subnet, strict=False)
            return any(n.overlaps(b) for b in banned)
        except Exception:
            return False
    agg["top_subnets_peak"] = sorted(
        [{"subnet": k, "peak": v} for k, v in subs.items() if not _is_banned(k)],
        key=lambda x: -x["peak"])[:8]
    agg["snapshots"] = len(snaps)
    return agg


@app.get("/api/llm")
def api_llm():
    """Current state of the LLM master switch."""
    return JSONResponse({"enabled": llm.enabled()})


@app.post("/api/llm/toggle")
async def api_llm_toggle(request: Request):
    """Enable/disable the LLM globally. When off, all AI features (insight loop,
    digest, rule suggestions, IP verdicts, NL explorer) skip the model and degrade
    gracefully — the rest of the dashboard keeps working."""
    body = await request.json()
    enabled = bool(body.get("enabled"))
    db.setting_set("llm_enabled", enabled)
    return JSONResponse({"ok": True, "enabled": enabled})


_loki_ping = {"ts": 0.0, "val": None}


def _loki_status():
    """Cached active Loki probe (5s TTL) so many polling dashboards don't multiply
    /ready hits, and a down Loki only costs one timeout per window."""
    now = time.time()
    if _loki_ping["val"] is None or now - _loki_ping["ts"] > 5:
        _loki_ping["val"] = loki.ping()
        _loki_ping["ts"] = now
    return _loki_ping["val"]


@app.get("/api/status")
def api_status():
    """Component health + freshness + last errors for the dashboard."""
    now = int(time.time())
    with _state_lock:
        s = dict(_state)
    poll_age = now - s["updated"] if s["updated"] else None
    insight_age = now - s["last_insight"] if s["last_insight"] else None
    llm_enabled = llm.enabled()
    problems = []
    # Direct reachability probe distinguishes "Loki down" from "query failing".
    lk = _loki_status()
    query_ok = bool(s["loki_up"])
    if not lk["reachable"]:
        problems.append({"component": "Loki", "msg": "недоступен: " + (lk.get("error") or "нет связи")})
    elif not lk["ready"]:
        problems.append({"component": "Loki", "msg": lk.get("error") or "не готов"})
    elif not query_ok:
        problems.append({"component": "Loki",
                         "msg": "доступен, но запрос не прошёл: " + (s.get("loki_error") or "ошибка")})
    # When the LLM is switched off, its staleness/availability is expected — don't
    # report it as a problem.
    if llm_enabled and s["llm_up"] is False:
        problems.append({"component": "LLM", "msg": s.get("llm_error") or "модель недоступна"})
    if poll_age is not None and poll_age > max(90, config.POLL_INTERVAL * 3):
        problems.append({"component": "Сбор данных", "msg": "данные устарели (%sс)" % poll_age})
    if llm_enabled and insight_age is not None and insight_age > config.LLM_INTERVAL * 2.5:
        problems.append({"component": "AI-разбор", "msg": "разбор устарел (%sс)" % insight_age})
    p403 = s.get("path403")
    if p403 and not p403.get("rendered_ok"):
        # name the actual target(s) that aren't rendered — not a hardcoded "ingress"
        # (a deployment may have only nginx and/or Cloudflare and no ingress at all).
        _lbl = {"nginx-file": "nginx", "ingress-cm": "ingress", "cloudflare": "Cloudflare"}
        bad = [(tid, d) for tid, d in (p403.get("targets") or {}).items()
               if not d.get("rendered_ok")]
        if bad:
            who = ", ".join("%s (%s)" % (tid, _lbl.get(d.get("type"), d.get("type") or "?"))
                            for tid, d in bad)
            msg = "403-правила не применены на: %s — нужен ресинк" % who
        else:
            msg = "403-правила не отрендерены — нужен ресинк"
        problems.append({"component": "Правила 403", "msg": msg})
    return JSONResponse({
        "ok": len(problems) == 0,
        "loki_up": s["loki_up"], "loki_error": s.get("loki_error"),
        "loki": {"reachable": lk["reachable"], "ready": lk["ready"], "ms": lk["ms"],
                 "url": lk["url"], "query_ok": query_ok, "error": lk.get("error")},
        "llm_up": s["llm_up"], "llm_error": s.get("llm_error"),
        "llm_enabled": llm_enabled,
        "poll_age": poll_age, "insight_age": insight_age,
        "path403": p403,
        "problems": problems,
    })


@app.get("/api/health")
def health():
    with _state_lock:
        return {"ok": True, "loki_up": _state["loki_up"], "updated": _state["updated"]}


# Serve the dashboard (single-page, no build). Mounted last so /api/* and
# /metrics take precedence.
if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
