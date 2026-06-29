"""Notifications — Slack (incoming webhook) + Telegram (bot) with a configurable
rule engine. Operators define CHANNELS (where) and RULES (what + when + which env →
which channel) entirely from the dashboard; nothing is hardcoded.

Stored in the pluggable store (notify.json), so it works in k8s/file/sqlite alike.
Secrets (webhook URL, bot token) are write-only over the API — never returned.

An EVENT is {type, env, severity, title, text, fields{}}. dispatch(event) sends it
to every enabled rule that matches (event type ∈ rule.events, rule.env empty or ==
event.env, event severity ≥ rule.min_severity). Sending is best-effort and never
raises into the caller (a ban must succeed even if Slack is down).
"""
import json
import threading
import time
import urllib.request

from . import storage

DOC = "notify.json"
_LOCK = threading.Lock()

# event types the engine knows (shown in the rule editor)
EVENTS = ["ban", "ban_failed", "unban", "node_offline", "autoban", "anomaly_critical", "path_rule"]
SEVERITIES = ["info", "notice", "warning", "critical"]
_SEV = {s: i for i, s in enumerate(SEVERITIES)}

_cache = {"t": 0.0, "d": None}
_CACHE_TTL = 2.0
# last delivery status per channel id (for the «тест»/health UI) — process-local
_last = {}


def _st():
    return storage.get_backend()


def _load():
    c = _cache
    if c["d"] is not None and (time.time() - c["t"]) < _CACHE_TTL:
        return c["d"]
    raw = _st().load([DOC]).get(DOC)
    d = {"channels": [], "rules": []}
    if raw:
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                d = {"channels": obj.get("channels") or [], "rules": obj.get("rules") or []}
        except Exception:
            pass
    c["d"], c["t"] = d, time.time()
    return d


def _save(d):
    _st().save({DOC: json.dumps(d, ensure_ascii=False)})
    _cache["d"] = None


# ── senders (stdlib only; never raise) ────────────────────────────────────────
def _post(url, body, headers=None, timeout=10):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status


def _send_slack(ch, text):
    return _post(ch["webhook"], {"text": text})


def _send_telegram(ch, text):
    url = "https://api.telegram.org/bot%s/sendMessage" % ch["bot_token"]
    return _post(url, {"chat_id": ch["chat_id"], "text": text, "parse_mode": "HTML",
                       "disable_web_page_preview": True})


def _send(ch, text):
    """Send to one channel; record + return (ok, detail). Never raises."""
    try:
        if ch.get("type") == "slack":
            _send_slack(ch, text)
        elif ch.get("type") == "telegram":
            _send_telegram(ch, text)
        else:
            return False, "unknown channel type"
        _last[ch.get("id")] = {"ok": True, "ts": int(time.time()), "error": None}
        return True, "ok"
    except Exception as e:
        _last[ch.get("id")] = {"ok": False, "ts": int(time.time()), "error": str(e)}
        return False, str(e)


def _format(ev):
    icon = {"ban": "🚫", "ban_failed": "⚠️", "unban": "✅", "node_offline": "🔌",
            "autoban": "🤖", "anomaly_critical": "🔥", "path_rule": "🛂"}.get(ev.get("type"), "•")
    env = ev.get("env") or "—"
    head = "%s [%s] %s" % (icon, env, ev.get("title") or ev.get("type"))
    lines = [head]
    if ev.get("text"):
        lines.append(ev["text"])
    for k, v in (ev.get("fields") or {}).items():
        lines.append("• %s: %s" % (k, v))
    return "\n".join(lines)


# ── rule matching + dispatch ──────────────────────────────────────────────────
def _channel(cfg, cid):
    return next((c for c in cfg["channels"] if c.get("id") == cid), None)


def _matches(rule, ev):
    if not rule.get("enabled", True):
        return False
    if ev.get("type") not in (rule.get("events") or []):
        return False
    renv = (rule.get("env") or "").strip()
    if renv and renv != (ev.get("env") or ""):
        return False
    if _SEV.get(ev.get("severity", "info"), 0) < _SEV.get(rule.get("min_severity", "info"), 0):
        return False
    return True


def emit(event):
    """Fire-and-forget dispatch on a daemon thread — callers on the ban hot path
    must never block on a slow Slack/Telegram round-trip."""
    threading.Thread(target=dispatch, args=(event,), daemon=True).start()


def dispatch(event):
    """Send an event to all matching channels. Best-effort; returns list of
    {channel, ok, error}. Never raises (callers are on the ban hot path)."""
    try:
        cfg = _load()
        results = []
        sent = set()
        for rule in cfg["rules"]:
            if not _matches(rule, event):
                continue
            ch = _channel(cfg, rule.get("channel"))
            if not ch or ch.get("id") in sent:
                continue
            sent.add(ch.get("id"))
            ok, detail = _send(ch, _format(event))
            results.append({"channel": ch.get("id"), "ok": ok, "error": None if ok else detail})
        return results
    except Exception as e:
        print("[notify] dispatch error:", e, flush=True)
        return []


# ── config API (secrets redacted) ─────────────────────────────────────────────
_SECRET_FIELDS = ("webhook", "bot_token")


def public_view():
    cfg = _load()
    chans = []
    for c in cfg["channels"]:
        item = {k: v for k, v in c.items() if k not in _SECRET_FIELDS}
        item["configured"] = bool(c.get("webhook") or c.get("bot_token"))
        item["last"] = _last.get(c.get("id"))
        chans.append(item)
    return {"channels": chans, "rules": cfg["rules"], "events": EVENTS, "severities": SEVERITIES}


def save_config(channels, rules):
    """Persist channels + rules. A blank secret on an existing channel keeps the old
    value (so the UI never has to re-enter it)."""
    with _LOCK:
        cur = _load()
        old = {c.get("id"): c for c in cur["channels"]}
        merged = []
        for c in (channels or []):
            cid = c.get("id")
            o = old.get(cid, {})
            for sf in _SECRET_FIELDS:
                if not c.get(sf):                 # blank → keep existing secret
                    if o.get(sf):
                        c[sf] = o[sf]
                    else:
                        c.pop(sf, None)
            merged.append(c)
        _save({"channels": merged, "rules": rules or []})
    return {"channels": len(merged), "rules": len(rules or [])}


def test_channel(cid):
    cfg = _load()
    ch = _channel(cfg, cid)
    if not ch:
        return {"ok": False, "error": "канал не найден"}
    ok, detail = _send(ch, "✅ soc: тестовое уведомление (%s)" % (ch.get("label") or cid))
    return {"ok": ok, "error": None if ok else detail}
