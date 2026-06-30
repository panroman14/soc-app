"""SQLite store for metric snapshots and LLM insights (history / timeline)."""
import json
import sqlite3
import threading
import time

from . import config

_lock = threading.Lock()


def _conn():
    c = sqlite3.connect(config.DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    # WAL: readers (request path) and the single writer (background loops) no longer
    # block each other → far fewer "database is locked". busy_timeout lets a momentary
    # writer-lock wait instead of erroring. NORMAL sync is safe under WAL.
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=5000")
    c.execute("PRAGMA synchronous=NORMAL")
    return c


def init():
    with _lock, _conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS snapshots (
                ts        INTEGER PRIMARY KEY,
                data      TEXT NOT NULL
            )""")
        c.execute("""
            CREATE TABLE IF NOT EXISTS insights (
                ts        INTEGER PRIMARY KEY,
                severity  TEXT,
                summary   TEXT,
                data      TEXT
            )""")
        # persistent caches (survive restarts → no cold-start re-lookups)
        c.execute("CREATE TABLE IF NOT EXISTS kv_cache (k TEXT PRIMARY KEY, data TEXT, ts INTEGER)")
        # IPs the operator marked "reviewed" in the suspect/ban panels (dismiss noise)
        c.execute("CREATE TABLE IF NOT EXISTS reviewed_ips (ip TEXT PRIMARY KEY, ts INTEGER)")
        # auto-ban rules (Cloudflare-style). The EXECUTOR is intentionally not wired —
        # rules + toggles + dry-run only; nothing auto-bans until that's built and armed.
        c.execute("""
            CREATE TABLE IF NOT EXISTS autoban_rules (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT NOT NULL,
                match_type TEXT NOT NULL DEFAULT 'substring',  -- substring | regex | family
                path       TEXT DEFAULT '',                    -- path/pattern (or family key)
                status     TEXT DEFAULT '',                    -- optional status label filter
                threshold  INTEGER NOT NULL DEFAULT 5,         -- N requests
                window     TEXT NOT NULL DEFAULT '10m',        -- time window T
                ttl        INTEGER NOT NULL DEFAULT 86400,     -- ban TTL seconds (0 = forever)
                enabled    INTEGER NOT NULL DEFAULT 0,         -- per-rule on/off toggle
                combine    INTEGER NOT NULL DEFAULT 1,         -- 1=sum across all paths, 0=per-path
                grp        TEXT DEFAULT '',                    -- ban group → enforcement targets ('' = default)
                country    TEXT DEFAULT '',                    -- optional country filter (e.g. "CN,RU") via geoip
                created    INTEGER, updated INTEGER
            )""")
        # migrate older autoban_rules tables that predate added columns
        cols = [r[1] for r in c.execute("PRAGMA table_info(autoban_rules)").fetchall()]
        if "combine" not in cols:
            c.execute("ALTER TABLE autoban_rules ADD COLUMN combine INTEGER NOT NULL DEFAULT 1")
        if "grp" not in cols:
            c.execute("ALTER TABLE autoban_rules ADD COLUMN grp TEXT DEFAULT ''")
        if "country" not in cols:
            c.execute("ALTER TABLE autoban_rules ADD COLUMN country TEXT DEFAULT ''")
        # small key/value settings (e.g. the global auto-ban kill-switch)
        c.execute("CREATE TABLE IF NOT EXISTS app_settings (k TEXT PRIMARY KEY, v TEXT)")
        # repeat-offender ledger for the escalation ladder (#9): how many times an IP
        # has been auto-banned, so a re-offense after a prior ban expired escalates TTL.
        c.execute("""CREATE TABLE IF NOT EXISTS autoban_offenders (
                ip TEXT PRIMARY KEY, count INTEGER NOT NULL DEFAULT 0,
                first_ts INTEGER, last_ts INTEGER )""")


def cache_get(key, max_age):
    with _lock, _conn() as c:
        row = c.execute("SELECT data, ts FROM kv_cache WHERE k=?", (key,)).fetchone()
    if not row or int(time.time()) - row["ts"] > max_age:
        return None
    try:
        return json.loads(row["data"])
    except Exception:
        return None


def cache_put(key, value):
    with _lock, _conn() as c:
        c.execute("INSERT OR REPLACE INTO kv_cache (k, data, ts) VALUES (?, ?, ?)",
                  (key, json.dumps(value, ensure_ascii=False), int(time.time())))


def mark_reviewed(ip, reviewed=True):
    """Mark/unmark an IP as reviewed by the operator (persists across restarts)."""
    with _lock, _conn() as c:
        c.execute("CREATE TABLE IF NOT EXISTS reviewed_ips (ip TEXT PRIMARY KEY, ts INTEGER)")
        if reviewed:
            c.execute("INSERT OR REPLACE INTO reviewed_ips (ip, ts) VALUES (?, ?)", (ip, int(time.time())))
        else:
            c.execute("DELETE FROM reviewed_ips WHERE ip=?", (ip,))


def reviewed_ips(max_age=86400):
    """IPs marked reviewed within max_age seconds (default 24h — a returning IP
    re-surfaces after the mark ages out)."""
    cutoff = int(time.time()) - max_age
    with _lock, _conn() as c:
        c.execute("CREATE TABLE IF NOT EXISTS reviewed_ips (ip TEXT PRIMARY KEY, ts INTEGER)")
        rows = c.execute("SELECT ip FROM reviewed_ips WHERE ts >= ?", (cutoff,)).fetchall()
    return [r["ip"] for r in rows]


# --- app settings (kill-switch etc.) ---
def setting_get(key, default=None):
    with _lock, _conn() as c:
        c.execute("CREATE TABLE IF NOT EXISTS app_settings (k TEXT PRIMARY KEY, v TEXT)")
        row = c.execute("SELECT v FROM app_settings WHERE k=?", (key,)).fetchone()
    if not row:
        return default
    try:
        return json.loads(row["v"])
    except Exception:
        return default


def setting_set(key, value):
    with _lock, _conn() as c:
        c.execute("CREATE TABLE IF NOT EXISTS app_settings (k TEXT PRIMARY KEY, v TEXT)")
        c.execute("INSERT OR REPLACE INTO app_settings (k, v) VALUES (?, ?)",
                  (key, json.dumps(value, ensure_ascii=False)))


# --- auto-ban rules CRUD ---
# Column names (DB uses `grp`; the API/UI field is `group` — translated in main.py).
_RULE_COLS = ("name", "match_type", "path", "status", "threshold", "window", "ttl", "enabled", "combine", "grp", "country")


def _rule_row(r):
    keys = r.keys() if hasattr(r, "keys") else []
    out = {k: r[k] for k in ("id", "name", "match_type", "path", "status",
                             "threshold", "window", "ttl", "enabled", "created", "updated")}
    out["combine"] = r["combine"] if "combine" in keys else 1
    out["group"] = (r["grp"] if "grp" in keys else "") or ""
    out["country"] = (r["country"] if "country" in keys else "") or ""
    return out


def autoban_rules():
    with _lock, _conn() as c:
        rows = c.execute("SELECT * FROM autoban_rules ORDER BY id").fetchall()
    return [_rule_row(r) for r in rows]


def autoban_rule(rule_id):
    with _lock, _conn() as c:
        r = c.execute("SELECT * FROM autoban_rules WHERE id=?", (rule_id,)).fetchone()
    return _rule_row(r) if r else None


def autoban_create(fields):
    now = int(time.time())
    vals = [fields.get(k) for k in _RULE_COLS]
    with _lock, _conn() as c:
        cur = c.execute(
            "INSERT INTO autoban_rules (name, match_type, path, status, threshold, window, ttl, enabled, combine, grp, country, created, updated) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (*vals, now, now))
        return cur.lastrowid


def autoban_update(rule_id, fields):
    sets = [k for k in _RULE_COLS if k in fields]
    if not sets:
        return
    with _lock, _conn() as c:
        c.execute("UPDATE autoban_rules SET %s, updated=? WHERE id=?" %
                  ", ".join("%s=?" % k for k in sets),
                  (*[fields[k] for k in sets], int(time.time()), rule_id))


def autoban_delete(rule_id):
    with _lock, _conn() as c:
        c.execute("DELETE FROM autoban_rules WHERE id=?", (rule_id,))


# --- repeat-offender ledger (escalation ladder, #9) ---
def offender_bump(ip, memory_s):
    """Record an auto-ban of `ip` and return its offense count. If the previous ban
    was longer ago than `memory_s`, the counter resets to 1 (forgiveness window)."""
    now = int(time.time())
    with _lock, _conn() as c:
        r = c.execute("SELECT count, last_ts FROM autoban_offenders WHERE ip=?", (ip,)).fetchone()
        if r and memory_s and (now - (r["last_ts"] or 0)) <= memory_s:
            count = (r["count"] or 0) + 1
            c.execute("UPDATE autoban_offenders SET count=?, last_ts=? WHERE ip=?", (count, now, ip))
        else:
            count = 1
            c.execute("INSERT INTO autoban_offenders (ip, count, first_ts, last_ts) VALUES (?,?,?,?) "
                      "ON CONFLICT(ip) DO UPDATE SET count=1, first_ts=?, last_ts=?",
                      (ip, count, now, now, now, now))
        return count


def offender_top(k=50):
    with _lock, _conn() as c:
        rows = c.execute("SELECT ip, count, first_ts, last_ts FROM autoban_offenders "
                         "ORDER BY count DESC, last_ts DESC LIMIT ?", (k,)).fetchall()
    return [{"ip": r["ip"], "count": r["count"], "first_ts": r["first_ts"], "last_ts": r["last_ts"]} for r in rows]


def new_subnets(subnets, ts):
    """Record subnets; return the set of ones never seen before (first sighting)."""
    if not subnets:
        return set()
    fresh = set()
    with _lock, _conn() as c:
        c.execute("CREATE TABLE IF NOT EXISTS seen_subnets (subnet TEXT PRIMARY KEY, first_seen INTEGER)")
        for sub in subnets:
            row = c.execute("SELECT 1 FROM seen_subnets WHERE subnet=?", (sub,)).fetchone()
            if not row:
                fresh.add(sub)
                c.execute("INSERT OR IGNORE INTO seen_subnets (subnet, first_seen) VALUES (?, ?)", (sub, int(ts)))
    return fresh


def save_snapshot(ts, summary):
    with _lock, _conn() as c:
        c.execute("INSERT OR REPLACE INTO snapshots (ts, data) VALUES (?, ?)",
                  (int(ts), json.dumps(summary, ensure_ascii=False)))


def recent_snapshots(limit=240):
    with _lock, _conn() as c:
        rows = c.execute("SELECT ts, data FROM snapshots ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    return [{"ts": r["ts"], **json.loads(r["data"])} for r in reversed(rows)]


def save_insight(ts, severity, summary, data=None):
    with _lock, _conn() as c:
        c.execute("INSERT OR REPLACE INTO insights (ts, severity, summary, data) VALUES (?, ?, ?, ?)",
                  (int(ts), severity, summary, json.dumps(data or {}, ensure_ascii=False)))


def recent_insights(limit=50):
    with _lock, _conn() as c:
        rows = c.execute("SELECT ts, severity, summary, data FROM insights ORDER BY ts DESC LIMIT ?",
                         (limit,)).fetchall()
    return [{"ts": r["ts"], "severity": r["severity"], "summary": r["summary"],
             "data": json.loads(r["data"] or "{}")} for r in rows]


def prune(days=14):
    cutoff = int(time.time()) - days * 86400
    # kv_cache rows are written with a ts but read with per-key max_age, so stale rows
    # are merely ignored — never deleted — and the table grows unbounded. Drop anything
    # older than the longest TTL we use (ASN/rDNS = 7d) with margin; it'll just re-fetch.
    kv_cutoff = int(time.time()) - 8 * 86400
    with _lock, _conn() as c:
        c.execute("DELETE FROM snapshots WHERE ts < ?", (cutoff,))
        c.execute("DELETE FROM insights WHERE ts < ?", (cutoff,))
        c.execute("DELETE FROM kv_cache WHERE ts < ?", (kv_cutoff,))
