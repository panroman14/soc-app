#!/usr/bin/env python3
"""soc-nginx-agent — pulls this VM's denylist from blocklist-api and applies it to
the local nginx, then reloads. Also self-enrolls and reports host metrics so the VM
shows up (and its load) in the dashboard «Ноды» tab. Stdlib only (no deps). Runs as
systemd on each nginx VM (target type=nginx-file). The server does the rendering
(GET /nginx_snippet) so CF logic / geo format stay in one place.

Enrollment (Datadog-style): set ENROLL_SECRET once. On first run the agent calls
POST /enroll, receives its own per-node token, and persists it to STATE_FILE. From
then on it authenticates with that node token (which can ONLY read its own snippet
and post its own heartbeat). If ENROLL_SECRET is unset it falls back to BLOCKLIST_TOKEN
(legacy admin token) and skips heartbeat — the agent still applies bans.

It writes TWO files:
  HTTP_FILE   (default /etc/nginx/conf.d/soc-deny.conf)  — geo/map, http context,
              auto-included because conf.d is included in http{} by stock nginx.
  SERVER_FILE (default /etc/nginx/soc-deny-server.conf)  — `if ($soc_blocked)
              { return 403; }`. Include this ONCE inside each server{} block:
                  include /etc/nginx/soc-deny-server.conf;

Fail-safe: on any fetch error it leaves the current files untouched (never wipes
bans). Before reloading it runs `nginx -t`; if the new config is invalid it rolls
back to the previous files and keeps the old (working) config live.

Env:
  BLOCKLIST_API_URL   e.g. http://central-vm:8080         (required)
  ENROLL_SECRET       shared enroll key → self-register    (recommended)
  BLOCKLIST_TOKEN     admin bearer (legacy fallback)       (used if no ENROLL_SECRET)
  NODE_ID             this node's id (default: hostname)
  GROUP               desired ban group (informational at enroll)
  TARGET_ID           target id to pull (default: NODE_ID)
  STATE_FILE          default /var/lib/soc-agent/state.json (stores node token)
  HTTP_FILE           default /etc/nginx/conf.d/soc-deny.conf
  SERVER_FILE         default /etc/nginx/soc-deny-server.conf
  TEST_CMD            default "nginx -t"
  RELOAD_CMD          default "nginx -s reload"
  POLL_INTERVAL       seconds between polls (default 30)
  ONESHOT             "1" → apply once and exit (for cron / testing)
"""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request

VERSION = "0.2.0"

API = os.environ.get("BLOCKLIST_API_URL", "").rstrip("/")
ENROLL_SECRET = os.environ.get("ENROLL_SECRET", "")
ADMIN_TOKEN = os.environ.get("BLOCKLIST_TOKEN", "")
NODE_ID = os.environ.get("NODE_ID", "") or socket.gethostname()
GROUP = os.environ.get("GROUP", "")
TARGET = os.environ.get("TARGET_ID", "") or NODE_ID
STATE_FILE = os.environ.get("STATE_FILE", "/var/lib/soc-agent/state.json")
HTTP_FILE = os.environ.get("HTTP_FILE", "/etc/nginx/conf.d/soc-deny.conf")
SERVER_FILE = os.environ.get("SERVER_FILE", "/etc/nginx/soc-deny-server.conf")
TEST_CMD = os.environ.get("TEST_CMD", "nginx -t")
RELOAD_CMD = os.environ.get("RELOAD_CMD", "nginx -s reload")
POLL = int(os.environ.get("POLL_INTERVAL", "30"))
ONESHOT = os.environ.get("ONESHOT", "") not in ("", "0", "false", "False")

HEADER = "# managed by soc-nginx-agent — DO NOT edit by hand\n"

# node token persisted across restarts; falls back to the admin token
_node_token = ""


def _log(*a):
    print("[soc-nginx-agent]", *a, flush=True)


# ── persistent state (node token) ─────────────────────────────────────────────
def _load_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_state(st):
    try:
        os.makedirs(os.path.dirname(STATE_FILE) or ".", exist_ok=True)
        tmp = STATE_FILE + ".tmp"
        # state holds the per-node token → keep it private (0600)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(tmp, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(st, f)
        os.replace(tmp, STATE_FILE)
        try:
            os.chmod(STATE_FILE, 0o600)
        except OSError:
            pass
    except Exception as e:
        _log("could not persist state:", e)


def _auth_token():
    return _node_token or ADMIN_TOKEN


def _request(method, path, body=None, token=None):
    url = API + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    tok = token if token is not None else _auth_token()
    if tok:
        req.add_header("Authorization", "Bearer " + tok)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())


# ── enrollment ────────────────────────────────────────────────────────────────
def ensure_enrolled():
    """Self-register if we don't yet hold a node token. No-op (legacy mode) if
    ENROLL_SECRET is unset — then we authenticate with the admin token instead."""
    global _node_token
    st = _load_state()
    if st.get("token") and st.get("node_id") == NODE_ID:
        _node_token = st["token"]
        return
    if not ENROLL_SECRET:
        _log("no ENROLL_SECRET → legacy mode (admin token, no heartbeat)")
        return
    try:
        res = _request("POST", "/enroll", {
            "node_id": NODE_ID, "hostname": socket.gethostname(), "group": GROUP,
            "target_type": "nginx-file", "agent_version": VERSION,
            "files": {"http_file": HTTP_FILE, "server_file": SERVER_FILE},
        }, token=ENROLL_SECRET)
        _node_token = res.get("token", "")
        if _node_token:
            _save_state({"node_id": NODE_ID, "token": _node_token})
            _log("enrolled as node '%s'" % res.get("node_id", NODE_ID))
    except Exception as e:
        _log("enroll failed (will retry):", e)


# ── host metrics (Linux /proc; best-effort) ───────────────────────────────────
def _read_file(p):
    try:
        with open(p, "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""


def collect_metrics(nginx_ok=None):
    m = {}
    try:
        m["load1"], m["load5"], m["load15"] = (round(x, 2) for x in os.getloadavg())
    except Exception:
        pass
    try:
        m["ncpu"] = os.cpu_count()
    except Exception:
        pass
    mi = _read_file("/proc/meminfo")
    if mi:
        kv = {}
        for line in mi.splitlines():
            parts = line.split(":")
            if len(parts) == 2:
                kv[parts[0].strip()] = parts[1].strip().split()[0]
        try:
            total = int(kv.get("MemTotal", 0))
            avail = int(kv.get("MemAvailable", kv.get("MemFree", 0)))
            if total:
                m["mem_total_mb"] = total // 1024
                m["mem_used_pct"] = round((total - avail) * 100.0 / total, 1)
        except Exception:
            pass
    up = _read_file("/proc/uptime")
    if up:
        try:
            m["uptime_s"] = int(float(up.split()[0]))
        except Exception:
            pass
    if nginx_ok is not None:
        m["nginx_ok"] = bool(nginx_ok)
    return m


def _read(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return None


def _write(path, body):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(HEADER + body)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _run(cmd):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


def fetch():
    path = "/nginx_snippet?target=%s" % urllib.parse.quote(TARGET, safe="")
    return _request("GET", path)


def send_heartbeat(nginx_ok=None, count=None):
    if not _node_token:
        return                              # legacy mode: heartbeat needs a node token
    try:
        m = collect_metrics(nginx_ok=nginx_ok)
        if count is not None:
            m["applied_cidrs"] = count
        _request("POST", "/heartbeat", {
            "node_id": NODE_ID, "agent_version": VERSION, "metrics": m})
    except Exception as e:
        _log("heartbeat failed:", e)


def apply_once(state):
    try:
        data = fetch()
    except Exception as e:
        _log("fetch failed, keeping current config:", e)
        send_heartbeat()                    # still report liveness
        return state
    http_body = HEADER + (data.get("http") or "")
    server_body = HEADER + (data.get("server") or "")
    key = (http_body, server_body)
    if key == state.get("last"):
        send_heartbeat(nginx_ok=state.get("nginx_ok"), count=data.get("count"))
        return state                        # nothing changed → no reload churn
    prev_http, prev_server = _read(HTTP_FILE), _read(SERVER_FILE)
    _write(HTTP_FILE, data.get("http") or "")
    _write(SERVER_FILE, data.get("server") or "")
    rc, out = _run(TEST_CMD)
    if rc != 0:
        _log("nginx -t FAILED, rolling back:", out)
        # restore previous (working) files so nginx keeps serving
        if prev_http is not None:
            _write(HTTP_FILE, prev_http[len(HEADER):] if prev_http.startswith(HEADER) else prev_http)
        else:
            try: os.remove(HTTP_FILE)
            except OSError: pass
        if prev_server is not None:
            _write(SERVER_FILE, prev_server[len(HEADER):] if prev_server.startswith(HEADER) else prev_server)
        else:
            try: os.remove(SERVER_FILE)
            except OSError: pass
        state["nginx_ok"] = False
        send_heartbeat(nginx_ok=False, count=data.get("count"))
        return state                        # don't cache a bad state → retry next tick
    rc, out = _run(RELOAD_CMD)
    if rc != 0:
        _log("reload failed:", out)
        send_heartbeat(nginx_ok=True, count=data.get("count"))
        return state
    _log("applied %s CIDR, reloaded nginx" % data.get("count"))
    state["last"] = key
    state["nginx_ok"] = True
    send_heartbeat(nginx_ok=True, count=data.get("count"))
    return state


def main():
    if not API or not TARGET:
        _log("BLOCKLIST_API_URL and TARGET_ID (or NODE_ID) are required"); sys.exit(2)
    ensure_enrolled()
    state = {"last": None, "nginx_ok": None}
    if ONESHOT:
        apply_once(state); return
    _log("started v%s: node=%s target=%s api=%s every %ss" % (VERSION, NODE_ID, TARGET, API, POLL))
    while True:
        try:
            if not _node_token and ENROLL_SECRET:
                ensure_enrolled()           # keep retrying enroll until it lands
            state = apply_once(state)
        except Exception as e:
            _log("loop error:", e)
        time.sleep(POLL)


if __name__ == "__main__":
    main()
