"""Loki client + LogQL aggregations for ingress traffic/attack analysis.

Computes a structured "summary" of the trailing window: traffic volume, blocked
traffic (split by already-denied vs new), attack signatures (404 scan, CRS
payloads), top offending subnets and distinct attacker IPs. Everything that
feeds alerting/anomaly logic excludes the already-denied ranges so we surface
only NOT-yet-handled threats.
"""
import json
import re
import threading
import urllib.error
import urllib.parse
import urllib.request

from . import config

W = config.WINDOW
SEL = config.INGRESS_SELECTOR
DENY_ERR = config.DENY_ERR
DENY_ACC = config.DENY_ACC

BLOCKED = SEL + ' |~ "forbidden|ModSecurity"'
NEW = BLOCKED + ' !~ `' + DENY_ERR + '`'
KNOWN = BLOCKED + ' |~ `' + DENY_ERR + '`'
ACCESS_REAL = SEL + ' |= "remote_addr" !~ `' + DENY_ACC + '`'
CRS = SEL + ' |~ "Inbound Anomaly Score Exceeded" !~ `' + DENY_ERR + '`'
CLIENT_RE = r'client[: ]+\[?(?P<ip>\d+\.\d+\.\d+\.\d+)'
SUBNET_RE = r'client[: ]+\[?(?P<subnet>\d+\.\d+\.\d+)\.\d+'


def ping(timeout=3):
    """Active availability probe — hits Loki's /ready (cheap, query-independent), so
    we can tell "Loki unreachable" apart from "a heavy query failed". Never raises.
    Returns {reachable, ready, ms, detail, error, url}. /ready → 200 "ready" when
    serving; 503 while a component is still starting (reachable but not ready)."""
    import time as _t
    url = config.LOKI_URL.rstrip("/") + "/ready"
    t0 = _t.time()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            ms = int((_t.time() - t0) * 1000)
            body = r.read(200).decode("utf-8", "replace").strip()
            return {"reachable": True, "ready": r.status == 200, "ms": ms,
                    "detail": (body[:80] or ("HTTP %d" % r.status)), "error": None,
                    "url": config.LOKI_URL}
    except urllib.error.HTTPError as e:
        ms = int((_t.time() - t0) * 1000)        # got a response → reachable, not ready
        return {"reachable": True, "ready": False, "ms": ms, "detail": "HTTP %d" % e.code,
                "error": "Loki не готов (HTTP %d)" % e.code, "url": config.LOKI_URL}
    except Exception as e:
        ms = int((_t.time() - t0) * 1000)
        return {"reachable": False, "ready": False, "ms": ms, "detail": None,
                "error": str(e), "url": config.LOKI_URL}


# Per-request scoping: an env filter (label) + an optional per-env Loki URL. Set via
# loki.scope(env, url) at the top of an env-scoped request; every query flows through
# _get, so we inject the `env="…"` matcher into the stream selector + pick the base URL
# in ONE place — no need to thread env through ~40 query builders.
_ctx = threading.local()


class scope:
    def __init__(self, env="", loki_url=""):
        self.env = env or ""
        self.loki_url = loki_url or ""

    def __enter__(self):
        self._prev = (getattr(_ctx, "env", ""), getattr(_ctx, "loki_url", ""))
        _ctx.env, _ctx.loki_url = self.env, self.loki_url
        return self

    def __exit__(self, *a):
        _ctx.env, _ctx.loki_url = self._prev
        return False


def _apply_env(query):
    """Inject env="<id>" into the FIRST stream selector {…} of a LogQL query."""
    env = getattr(_ctx, "env", "")
    if not env:
        return query

    def _repl(m):
        inner = m.group(1)
        sep = "," if inner.strip() else ""
        return "{" + inner + sep + 'env="%s"}' % env
    return re.sub(r"\{([^{}]*)\}", _repl, query, count=1)


def _get(path, params, _retries=2):
    import time as _t
    if "query" in params:
        params = dict(params, query=_apply_env(params["query"]))
    base = getattr(_ctx, "loki_url", "") or config.LOKI_URL
    qs = urllib.parse.urlencode(params)
    url = base + path + "?" + qs
    for attempt in range(_retries + 1):
        try:
            with urllib.request.urlopen(url, timeout=config.HTTP_TIMEOUT) as r:
                return json.load(r).get("data", {}).get("result", [])
        except urllib.error.HTTPError as e:
            # retry transient Loki errors that FAIL FAST (rate-limit + 5xx). Do NOT
            # retry timeouts: a timed-out query already ran ~30s; retrying it while
            # Loki is saturated just amplifies the load (death-spiral). Let it raise
            # so _safe/cache handle it.
            if (e.code == 429 or 500 <= e.code < 600) and attempt < _retries:
                _t.sleep(0.5 * (attempt + 1))
                continue
            raise


def _fmt_ns(ns):
    import datetime
    try:
        return datetime.datetime.fromtimestamp(ns / 1e9).strftime("%H:%M:%S")
    except Exception:
        return ""


def recent_logs(stream="access", minutes=15, q="", limit=300):
    """Raw recent log lines for the Logs viewer. `stream` = access|error (a Promtail
    label). Env scoping is applied by _get. Returns newest-first {time,line,status}."""
    import time as _t
    base = SEL[:-1] + ("," if SEL.strip() not in ("{}", "") else "") + 'stream="%s"}' % stream
    expr = base + (" |~ `%s`" % q.replace("`", "")) if q else base
    end = int(_t.time() * 1e9)
    start = end - int(minutes) * 60 * 10**9
    res = _get("/loki/api/v1/query_range", {"query": expr, "start": str(start),
               "end": str(end), "limit": str(min(int(limit), 500)), "direction": "backward"})
    rows = []
    for s in res:
        for v in s.get("values", []):
            rows.append((int(v[0]), v[1]))
    rows.sort(key=lambda x: -x[0])
    out = []
    for ts_ns, line in rows[:limit]:
        m = re.search(r'"status":"?(\d{3})', line) or re.search(r'"\s(\d{3})\s', line)
        out.append({"time": _fmt_ns(ts_ns), "line": line, "status": m.group(1) if m else ""})
    return out


def scalar(expr):
    """Instant query returning a single number (0 if empty)."""
    res = _get("/loki/api/v1/query", {"query": "sum(count_over_time(" + expr + " [" + W + "]))"})
    return float(res[0]["value"][1]) if res else 0.0


def distinct_ips(expr, ip_re):
    res = _get("/loki/api/v1/query",
               {"query": "count(sum by (ip) (count_over_time(" + expr + " | regexp `" + ip_re + "` [" + W + "])))"})
    return int(float(res[0]["value"][1])) if res else 0


def top_subnets(expr, subnet_re, k=10):
    res = _get("/loki/api/v1/query",
               {"query": "topk(%d, sum by (subnet) (count_over_time(%s | regexp `%s` [%s])))" % (k, expr, subnet_re, W)})
    out = [{"subnet": s["metric"].get("subnet", "?") + ".0/24", "count": int(float(s["value"][1]))} for s in res]
    out.sort(key=lambda x: -x["count"])
    return out


def status_count(code_prefix, exclude_denied=True):
    q = SEL + ' |~ `"status":"' + code_prefix + '`'
    if exclude_denied:
        q += ' !~ `' + DENY_ACC + '`'
    return scalar(q)


def collect_summary():
    """Single aggregated snapshot of the trailing window. Each metric is isolated
    (_safe) so one failing query doesn't drop the whole snapshot."""
    sv = lambda fn: _safe(fn, 0.0)
    total = sv(lambda: scalar(SEL + ' |= "remote_addr"'))
    real = sv(lambda: scalar(ACCESS_REAL))
    forbidden_new = sv(lambda: scalar(NEW))
    denylisted = sv(lambda: scalar(KNOWN))
    s404 = sv(lambda: status_count("404"))
    s4xx = sv(lambda: scalar(SEL + ' |~ `"status":"4` !~ `' + DENY_ACC + '` !~ `"status":"(429|499)"`'))
    s5xx = sv(lambda: scalar(SEL + ' |~ `"status":"5`'))
    crs = sv(lambda: scalar(CRS))
    modsec_denied = sv(lambda: scalar(SEL + ' |~ "ModSecurity: Access denied"'))
    ips = _safe(lambda: distinct_ips(NEW, CLIENT_RE), 0)
    subnets = _safe(lambda: top_subnets(NEW, SUBNET_RE), [])

    s2xx = sv(lambda: scalar(SEL + ' |~ `"status":"2`'))
    s3xx = sv(lambda: scalar(SEL + ' |~ `"status":"3`'))
    lat = _safe(lambda: latency_p95(), 0.0)
    up95 = 0.0  # upstream_response_time quirk → always 0; skip the expensive quantile query
    bytes_mb = _safe(lambda: round(total_bytes() / (1024 * 1024), 1), 0.0)

    malicious_ratio = (forbidden_new + s4xx) / real if real else 0.0
    return {
        "window": W,
        "requests_total": total,
        "requests_real": real,
        "forbidden_new": forbidden_new,
        "blocked_denylisted": denylisted,
        "status_2xx": s2xx,
        "status_3xx": s3xx,
        "status_404": s404,
        "status_4xx": s4xx,
        "status_5xx": s5xx,
        "crs_detections": crs,
        "modsec_denied": modsec_denied,
        "distinct_attacker_ips": ips,
        "top_subnets": subnets,
        "malicious_ratio": round(malicious_ratio, 4),
        "latency_p95": lat,
        "latency_upstream_p95": up95,
        "bytes_mb": bytes_mb,
    }


# ----------------------------------------------------------------------------
# Heavier analytics (run on a slower loop) — breakdowns for the dashboard.
# ----------------------------------------------------------------------------

def _hostf(host):
    return ('|= `%s`' % host.replace("`", "")) if host else ""


import ipaddress as _ipaddr

_DENY_NETS = []
for _n in getattr(config, "DENY_NETS", []):
    try:
        _DENY_NETS.append(_ipaddr.ip_network(_n))
    except ValueError:
        pass


CF_RANGES = []
for _c in ["173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
           "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
           "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
           "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32",
           "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
           "2a06:98c0::/29", "2c0f:f248::/32"]:
    try:
        CF_RANGES.append(_ipaddr.ip_network(_c))
    except ValueError:
        pass


def _is_cf_ip(ip):
    """True if the IP is a Cloudflare edge (real client masked behind it)."""
    try:
        a = _ipaddr.ip_address(ip)
        return any(a in n for n in CF_RANGES)
    except ValueError:
        return False


def _eff_ip(o):
    """Effective client IP: if remote_addr is a CF edge or private (SNAT),
    use the first X-Forwarded-For entry (the real visitor)."""
    ra = o.get("remote_addr") or ""
    xff = (o.get("http_x_forwarded_for") or "").split(",")[0].strip()
    if xff:
        try:
            a = _ipaddr.ip_address(ra)
            if _is_cf_ip(ra) or a.is_private or a.is_loopback:
                return xff
        except ValueError:
            return xff
    return ra


def _eff_real(ra, rip):
    """Real client IP for autoban detection. When the connection is from a Cloudflare
    edge (`ra` in CF ranges), trust real_ip_cloudflare/XFF (the real visitor Cloudflare
    set) — else use remote_addr. ANTI-SPOOF: a direct (non-CF) client's forged XFF is
    ignored, because its `ra` isn't a CF edge, so we never ban/frame the wrong IP."""
    rip = (rip or "").split(",")[0].strip()
    if rip and _is_cf_ip(ra):
        try:
            _ipaddr.ip_address(rip)
            return rip
        except ValueError:
            pass
    return ra


def _skip_ip(ip):
    """True for already-denied ranges and private/loopback/reserved (internal) IPs."""
    try:
        a = _ipaddr.ip_address(ip)
    except ValueError:
        return True
    if a.is_private or a.is_loopback or a.is_reserved or a.is_link_local:
        return True
    return any(a in n for n in _DENY_NETS)


# Paths that almost only scanners/bots request on this (non-PHP) site.
# NOTE: Loki LABEL matchers (`uri=~`/`uri!~`) are ANCHORED (full-value match, like
# Prometheus) — unlike line filters (`|~`, substring). So label regexes MUST be
# wrapped `.*(…).*` to match a substring of request_uri. (Without the wrap they
# silently matched ~nothing — a long-standing bug.)
SCANNER_RE = (r'(?i).*(/\.env|/\.git|/\.aws|/\.ssh|/\.vscode|/\.DS_Store|wp-login|'
              r'wp-admin|wp-includes|wp-content|xmlrpc\.php|\.php|phpmyadmin|'
              r'/vendor/|/actuator|\.bak|\.sql|/\.well-known/openvpn|'
              r'webmin|usermin|pgadmin|adminer|'
              # secrets, cloud-metadata, app-server/CVE probe paths (we run none of these)
              r'id_rsa|\.npmrc|\.htpasswd|web\.config|appsettings\.json|'
              r'169\.254\.169\.254|/latest/meta-data|/computeMetadata|'
              r'/boaform|/HNAP1|/GponForm|/wls-wsat|/manager/html|/console/login|'
              r'OA_HTML|/_cat/indices|/cgi-bin).*')

# Cheap line-level pre-filter (raw bytes) — cuts 99% of logs BEFORE json/regex,
# so the heavy label regex runs on a tiny survivor set (keeps Loki fast).
SCANNER_LINE = (r'(?i)(\.env|\.git|\.aws|/\.ssh|vscode|DS_Store|wp-login|wp-admin|'
                r'wp-includes|wp-content|xmlrpc|\.php|phpmyadmin|/vendor/|/actuator|\.bak|\.sql|'
                r'webmin|usermin|pgadmin|adminer|'
                r'id_rsa|\.npmrc|\.htpasswd|web\.config|appsettings\.json|'
                r'169\.254\.169\.254|/latest/meta-data|/computeMetadata|'
                r'/boaform|/HNAP1|/GponForm|/wls-wsat|/manager/html|/console/login|'
                r'OA_HTML|/_cat/indices|/cgi-bin)')

# Case-INSENSITIVE versions of the line pre-filters are intentionally avoided: a
# `(?i)` regex line filter defeats Loki's literal-substring optimization (~5x slower
# here — 2.5s vs 0.5s/1h). The case-sensitive literal alternation below stays on the
# fast path; the precise (?i) `uri=~`/`ref=~` LABEL regex on the survivor set is the
# authoritative, case-insensitive match. Canonical scanner paths are lowercase.
SCANNER_LINE_CS = (r'(\.env|\.git|\.aws|/\.ssh|vscode|DS_Store|wp-login|wp-admin|'
                   r'wp-includes|wp-content|xmlrpc|\.php|phpmyadmin|/vendor/|/actuator|\.bak|\.sql|'
                   r'webmin|usermin|pgadmin|adminer|'
                   r'id_rsa|\.npmrc|\.htpasswd|web\.config|appsettings\.json|'
                   r'169\.254\.169\.254|/latest/meta-data|/computeMetadata|'
                   r'/boaform|/HNAP1|/GponForm|/wls-wsat|/manager/html|/console/login|'
                   r'OA_HTML|/_cat/indices|/cgi-bin)')
PAYLOAD_LINE_CS = (r'(sleep\(|benchmark\(|waitfor|union|select|information_schema|'
                   r'/\*!|<script|onerror|javascript:|etc/passwd|jndi:|md5\(|0x[0-9a-f]{8}|'
                   r'/bin/|php://|data://|expect://|phar://|/proc/self|\{\{|\$\{)')

# SQLi / XSS / RCE payload signatures (matched in referer, uri or args).
PAYLOAD_RE = (r'(?i).*(sleep\(\d|benchmark\(|waitfor\s+delay|union[\s/*]+select|'
              r'\bselect\b.{0,40}\bfrom\b|from\s+dual|\bor\s+\d+\s*[*=]|information_schema|'
              r'load_file\(|/\*!|0x[0-9a-f]{8}|<script|onerror\s*=|javascript:|'
              r'\.\./\.\./|/etc/passwd|\$\{jndi:|'
              # RCE / SSTI / PHP-wrapper / traversal (clearly hostile inside uri/args/referer)
              r'/bin/(ba)?sh|;\s*(cat|id|wget|curl)\s|php://|data://|expect://|phar://|'
              r'/proc/self/environ|\{\{\s*\d|\$\{(lower|upper|env|sys|::-):).*')
PAYLOAD_LINE = (r'(?i)(sleep\(|benchmark\(|waitfor|union|select|information_schema|'
                r'/\*!|<script|onerror|javascript:|etc/passwd|jndi:|md5\(|0x[0-9a-f]{8}|'
                r'/bin/|php://|data://|expect://|phar://|/proc/self|\{\{|\$\{)')

# Normal-browser noise that produces 4xx but is NOT scanning — excluded from the
# "suspect 4xx" review list so real users (iOS/Safari probing icons, etc.) don't show.
STATIC_NOISE_RE = (r'(?i).*(/apple-touch-icon|/favicon\.|/robots\.txt|/browserconfig\.xml|'
                   r'/site\.webmanifest|/manifest\.json|/sitemap|/ads\.txt|/\.well-known/).*')


def _ban_base(line_re, label, host):
    # case-sensitive literal line filter FIRST (fast — stays on Loki's literal path),
    # then json + precise (?i) label regex on the tiny survivor set. Extract ra+rip so
    # aggregation can resolve the real client behind Cloudflare (CF-aware, like autoban).
    return (SEL + ' |~ `' + line_re + '` |= "remote_addr" ' + _hostf(host) +
            ' | json ra="remote_addr", rip="real_ip_cloudflare", uri="request_uri", '
            'args="args", ref="http_referer", cc="geoip_country_code", st="status" '
            '| ' + label + ' | st!=`403`')


def _agg_by_ip(base, w, k=60):
    q = 'topk(%d, sum by (ip, cc) (count_over_time(%s [%s])))' % (k, base, w)
    out = {}
    for r in _get("/loki/api/v1/query", {"query": q}):
        ip = r["metric"].get("ip")
        if ip:
            out[ip] = (int(float(r["value"][1])), r["metric"].get("cc", ""))
    return out


def _ignore_clause(ignore_paths):
    """LogQL `| uri!~...` to drop whitelisted legit paths from detection (same
    whitelist as the auto-ban). Empty string when no paths."""
    ig = [p.strip().replace("`", "") for p in (ignore_paths or []) if p and p.strip()]
    if not ig:
        return ""
    alt = "|".join(_re2_escape(p) for p in ig)
    return ' | uri!~`(?i).*(' + alt + ').*`'


def ban_candidates(w="6h", host="", k=60, ignore_paths=None):
    """IPs that should be banned: hitting scanner paths (.env, wp-*, .git, .php …)
    OR sending SQLi/XSS payloads (in referer/uri/args). Not-yet-blocked only
    (status!=403); denied ranges, private and trusted IPs excluded.
    ignore_paths: safety-whitelist (same as auto-ban) — never counted.
    """
    ic = _ignore_clause(ignore_paths)
    scan_base = _ban_base(SCANNER_LINE_CS, 'uri=~`' + SCANNER_RE + '`', host) + ic
    pay_base = _ban_base(PAYLOAD_LINE_CS, '(ref=~`' + PAYLOAD_RE + '` or uri=~`' +
                         PAYLOAD_RE + '` or args=~`' + PAYLOAD_RE + '`)', host) + ic
    scan = _safe(lambda: _autoban_agg(scan_base, w, k), {})
    pay = _safe(lambda: _autoban_agg(pay_base, w, k), {})
    per_ip = _safe(lambda: _autoban_paths(scan_base, w), {})

    merged = {}
    for ip, (cnt, cc) in scan.items():
        m = merged.setdefault(ip, {"count": 0, "cc": cc, "sig": set()})
        m["count"] += cnt; m["sig"].add("scanner")
    for ip, (cnt, cc) in pay.items():
        m = merged.setdefault(ip, {"count": 0, "cc": cc, "sig": set()})
        m["count"] += cnt; m["cc"] = m["cc"] or cc; m["sig"].add("payload")

    cands, total = [], 0
    for ip, m in merged.items():
        if _skip_ip(ip) or ip in config.TRUSTED_IPS:
            continue
        cands.append({"ip": ip, "count": m["count"], "country": m["cc"],
                      "paths": [u for u, _ in per_ip.get(ip, [])[:4]],
                      "signals": sorted(m["sig"]), "cf": _is_cf_ip(ip)})
        total += m["count"]
    cands.sort(key=lambda x: -x["count"])
    # derive top scanner paths from per-IP data (no extra Loki query)
    ptot = {}
    for lst in per_ip.values():
        for uri, c in lst:
            ptot[uri] = ptot.get(uri, 0) + c
    top_paths = [{"key": u, "count": c}
                 for u, c in sorted(ptot.items(), key=lambda t: -t[1])[:10]]
    return {"window": w, "candidates": cands, "top_paths": top_paths,
            "total_ips": len(cands), "total_hits": total}


def suspect_ips(w="1h", host="", k=60, min_hits=12, ignore_paths=None):
    """IPs with abnormal 4xx volume (endpoint enumeration / fuzzing), excluding
    known scanner paths (those are the scanner section). Same filters as ban_candidates.
    ignore_paths: safety-whitelist (same as auto-ban) — never counted.
    """
    # cheap substring prefilter to 4xx lines BEFORE json (was json-parsing every
    # access-log line in the window — the reason this scan was slow)
    base = (SEL + ' |= "remote_addr" |= `"status":"4` ' + _hostf(host) +
            ' | json ra="remote_addr", rip="real_ip_cloudflare", uri="request_uri", '
            'cc="geoip_country_code", st="status" '
            '| st!~`403|429|499` | uri!~`' + SCANNER_RE + '` | uri!~`' + STATIC_NOISE_RE + '`'
            + _ignore_clause(ignore_paths))
    agg = _safe(lambda: _autoban_agg(base, w, k), {})
    per_ip = _safe(lambda: _autoban_paths(base, w), {})
    cands, total = [], 0
    for ip, (cnt, cc) in agg.items():
        if cnt < min_hits or _skip_ip(ip) or ip in config.TRUSTED_IPS:
            continue
        cands.append({"ip": ip, "count": cnt, "country": cc,
                      "paths": [u for u, _ in per_ip.get(ip, [])[:4]],
                      "signals": ["4xx"], "cf": _is_cf_ip(ip)})
        total += cnt
    cands.sort(key=lambda x: -x["count"])
    ptot = {}
    for lst in per_ip.values():
        for uri, c in lst:
            ptot[uri] = ptot.get(uri, 0) + c
    top_paths = [{"key": u, "count": c}
                 for u, c in sorted(ptot.items(), key=lambda t: -t[1])[:10]]
    return {"window": w, "candidates": cands, "top_paths": top_paths,
            "total_ips": len(cands), "total_hits": total}


# ---------------------------------------------------------------------------
# Auto-ban rules engine — DRY-RUN evaluator only. Given a rule (path/family +
# threshold N over window T) it returns the IPs that WOULD be banned. Nothing
# here calls blocklist-api: the auto-ban executor is intentionally not wired yet
# (operator builds/arms it as a separate, explicit step). Trusted/private/CF/
# already-denied IPs are always excluded — same guardrails as ban_candidates.
# ---------------------------------------------------------------------------

# "Семейства" сигнатур для генератора/выпадающего списка (FP-безопасные пресеты).
AUTOBAN_FAMILIES = [
    {"key": "scanner", "label": "Сканер-пути (.env/.git/wp-*/.php/phpmyadmin…)",
     "match_type": "family"},
    {"key": "payload", "label": "Payload (SQLi/XSS/RCE/traversal/jndi)",
     "match_type": "family"},
]


def _re2_escape(s):
    """Escape regex metacharacters for RE2 (Loki's engine). Unlike re.escape we
    DON'T escape '-' (RE2 rejects `\\-` outside a character class)."""
    return re.sub(r'([.+*?()\[\]{}^$|\\])', r'\\\1', s)


def _autoban_base(match_type, path, host=""):
    """Build the LogQL stream selector + ip/uri extraction for a rule."""
    if match_type == "family" and path == "payload":
        line = PAYLOAD_LINE_CS
        label = ('(ref=~`' + PAYLOAD_RE + '` or uri=~`' + PAYLOAD_RE +
                 '` or args=~`' + PAYLOAD_RE + '`)')
    elif match_type == "family":   # default family = scanner
        line, label = SCANNER_LINE_CS, 'uri=~`' + SCANNER_RE + '`'
    else:
        # one or more paths/patterns, OR-combined (operator adds them via "+ ИЛИ").
        # multiple values arrive newline-separated (a newline never appears in a URL).
        parts = [p.strip().replace("`", "").replace('"', "")
                 for p in (path or "").split("\n") if p.strip()]
        if match_type == "regex":
            alt = "|".join(parts)                       # raw patterns
        else:                                            # substring → escape each
            alt = "|".join(_re2_escape(p) for p in parts)
        line = "(" + alt + ")"
        label = 'uri=~`(?i).*(' + alt + ').*`'
    # extract remote_addr (ra) AND real_ip_cloudflare (rip) so aggregation can resolve
    # the real client behind Cloudflare in Python (see _autoban_agg / _eff_real)
    return (SEL + ' |~ `' + line + '` |= "remote_addr" ' + _hostf(host) +
            ' | json ra="remote_addr", rip="real_ip_cloudflare", uri="request_uri", '
            'args="args", ref="http_referer", cc="geoip_country_code", st="status" | ' + label)


def _autoban_agg(base, w, k=300):
    """sum by (ra, rip, cc), then fold to the REAL client IP (CF-aware) in Python."""
    q = 'topk(%d, sum by (ra, rip, cc) (count_over_time(%s [%s])))' % (k, base, w)
    out = {}
    for r in _get("/loki/api/v1/query", {"query": q}):
        m = r["metric"]
        ra = m.get("ra")
        if not ra:
            continue
        eff = _eff_real(ra, m.get("rip"))
        cnt = int(float(r["value"][1]))
        pc, pcc = out.get(eff, (0, ""))
        out[eff] = (pc + cnt, pcc or m.get("cc", ""))
    return out


def _autoban_paths(base, w, k=300):
    """sum by (ra, rip, uri), folded to real client IP → {eff_ip: [(uri, count), ...]}."""
    q = 'topk(%d, sum by (ra, rip, uri) (count_over_time(%s [%s])))' % (k, base, w)
    tmp = {}
    for r in _get("/loki/api/v1/query", {"query": q}):
        m = r["metric"]
        ra = m.get("ra")
        if not ra:
            continue
        eff = _eff_real(ra, m.get("rip"))
        uri = m.get("uri", "")
        d = tmp.setdefault(eff, {})
        d[uri] = d.get(uri, 0) + int(float(r["value"][1]))
    return {ip: sorted(d.items(), key=lambda t: -t[1]) for ip, d in tmp.items()}


def autoban_eval(rule, w=None, host="", k=300, ignore_paths=None, with_paths=True):
    """Dry-run: which IPs hit this rule's condition >= threshold over the window.
    ignore_paths: substrings that NEVER count (safety whitelist of legit endpoints).
    with_paths=False: skip the per-path query (the executor doesn't need example paths,
    only IP+count) → HALVES Loki queries per rule. For combine=0 rules the per-path query
    is still required (the threshold is per-path), so it's fetched regardless."""
    mt = (rule.get("match_type") or "substring")
    path = (rule.get("path") or "").strip()
    if mt != "family" and not path:
        return {"window": w or rule.get("window"), "threshold": rule.get("threshold"),
                "matches": [], "total_ips": 0, "error": "пустой путь/паттерн"}
    w = w or rule.get("window") or "10m"
    base = _autoban_base(mt, path, host)
    st = (rule.get("status") or "").strip()
    if st:
        base += ' | st=~`' + st.replace("`", "") + '`'
    # safety whitelist: drop requests to legit paths BEFORE counting (so a whitelisted
    # path can never push an IP over the threshold, no matter the rule)
    ig = [p.strip() for p in (ignore_paths or []) if p and p.strip()]
    if ig:
        alt = "|".join(_re2_escape(p.replace("`", "")) for p in ig)
        base += ' | uri!~`(?i).*(' + alt + ').*`'
    thr = max(1, int(rule.get("threshold") or 1))
    combine = rule.get("combine", 1) in (1, "1", True, "true", None)
    # CF-aware: aggregate by the REAL client IP (resolves Cloudflare edges → real visitor)
    agg = _safe(lambda: _autoban_agg(base, w, k), {})
    # per-path query only when needed: for display (with_paths) or for combine=0 scoring
    per_ip = _safe(lambda: _autoban_paths(base, w), {}) if (with_paths or not combine) else {}
    matches = []
    for ip, (cnt, cc) in agg.items():
        if _skip_ip(ip) or ip in config.TRUSTED_IPS or _is_cf_ip(ip):
            continue
        paths = per_ip.get(ip, [])
        if combine:
            # count = total across all paths (1×/.git + 1×/.env = 2)
            score = cnt
        else:
            # count = the single busiest path; ban only if one path alone reaches N
            score = max((c for _, c in paths), default=0)
        if score < thr:
            continue
        matches.append({"ip": ip, "count": score, "country": cc,
                        "paths": [u for u, _ in paths[:4]]})
    matches.sort(key=lambda x: -x["count"])
    return {"window": w, "threshold": thr, "combine": 1 if combine else 0,
            "matches": matches, "total_ips": len(matches),
            "total_hits": sum(m["count"] for m in matches)}


def ip_rule_paths(ip, rule=None, w="8h", k=8):
    """Top request paths this IP hit that match the rule's condition (or generic
    scanner paths if no rule) — to explain WHY it was banned. Cheap: exact
    remote_addr literal prefilter narrows to this IP before json/label."""
    ipq = ip.replace("`", "").replace('"', "")
    mt = (rule or {}).get("match_type")
    path = (rule or {}).get("path") or ""
    if rule and mt and mt != "family" and path:
        parts = [p.strip().replace("`", "").replace('"', "") for p in path.split("\n") if p.strip()]
        alt = "|".join((p if mt == "regex" else _re2_escape(p)) for p in parts)
        label = 'uri=~`(?i).*(' + alt + ').*`'
    else:
        label = 'uri=~`' + SCANNER_RE + '`'
    # quoted-IP literal matches remote_addr OR real_ip_cloudflare/XFF → works behind CF
    base = (SEL + ' |= `"' + ipq + '"` | json uri="request_uri" | ' + label)
    q = 'topk(%d, sum by (uri) (count_over_time(%s [%s])))' % (k, base, w)
    out = []
    for r in _safe(lambda: _get("/loki/api/v1/query", {"query": q}), []):
        uri = r["metric"].get("uri")
        if uri:
            out.append({"path": uri, "count": int(float(r["value"][1]))})
    out.sort(key=lambda x: -x["count"])
    return out


def _paths_by_ip(base, w, k=200):
    q = 'topk(%d, sum by (ip, uri) (count_over_time(%s [%s])))' % (k, base, w)
    res = _get("/loki/api/v1/query", {"query": q})
    m = {}
    for r in res:
        ip = r["metric"].get("ip")
        uri = r["metric"].get("uri", "")
        if not ip:
            continue
        m.setdefault(ip, []).append((uri, int(float(r["value"][1]))))
    for ip in m:
        m[ip].sort(key=lambda t: -t[1])
    return m


def _topk_match(base, w, k=10):
    q = ('topk(%d, sum by (uri) (count_over_time(%s [%s])))' % (k, base, w))
    res = _get("/loki/api/v1/query", {"query": q})
    out = [{"key": r["metric"].get("uri", ""), "count": int(float(r["value"][1]))} for r in res]
    out.sort(key=lambda x: -x["count"])
    return out


def _topk(field, k=12, parser=None, line="", lbl="", w=W, host=""):
    # |= "remote_addr" restricts to access-log JSON (avoids JSONParserErr on error
    # logs); st extracted only when a status filter (lbl) needs it; selective
    # extraction keeps series under Loki's 500 limit.
    st = ', st="status"' if "st" in lbl else ""
    q = ('topk(%d, sum by (f) (count_over_time(%s |= "remote_addr" %s %s | json f="%s"%s %s [%s])))'
         % (k, SEL, _hostf(host), line, field, st, lbl, w))
    res = _get("/loki/api/v1/query", {"query": q})
    out = []
    for s in res:
        key = s["metric"].get("f", "")
        if parser:
            key = parser(key)
        out.append({"key": key or "—", "count": int(float(s["value"][1]))})
    out.sort(key=lambda x: -x["count"])
    return out


_WIN_ORDER = ["5m", "15m", "1h", "6h", "8h"]


def _chain(w):
    """Windows from w down to 5m — for graceful fallback when a big window
    blows past Loki's max_query_series on high-cardinality topk."""
    w = w if w in _WIN_ORDER else W
    return _WIN_ORDER[_WIN_ORDER.index(w)::-1]


def _topk_fb(field, w, **kw):
    """topk that falls back to a smaller window if the requested one exceeds
    Loki's series limit. Returns (list, effective_window)."""
    for ww in _chain(w):
        try:
            return _topk(field, w=ww, **kw), ww
        except Exception:
            continue
    return [], w


# OWASP CRS rule family -> attack type
_CRS_FAMILY = {
    "911": "Method enforcement", "913": "Scanner detection", "920": "Protocol",
    "921": "Protocol attack", "930": "LFI / file access", "931": "RFI",
    "932": "RCE", "933": "PHP injection", "941": "XSS", "942": "SQLi",
    "943": "Session fixation", "944": "Java", "949": "Anomaly score",
}


def attack_types(w=W):
    """Breakdown of CRS detections by attack family (from rule ids)."""
    q = ('sum by (rid) (count_over_time(' + SEL +
         ' |~ "ModSecurity" | regexp `\\[id \\"(?P<rid>\\d+)\\"\\]` [' + w + ']))')
    res = _get("/loki/api/v1/query", {"query": q})
    agg = {}
    for s in res:
        rid = s["metric"].get("rid", "")
        fam = _CRS_FAMILY.get(rid[:3], "Прочее")
        if rid.startswith("949"):
            continue  # anomaly-score meta rule, not an attack class
        agg[fam] = agg.get(fam, 0) + int(float(s["value"][1]))
    return sorted([{"key": k, "count": v} for k, v in agg.items()], key=lambda x: -x["count"])


# Long-lived/large requests that inflate latency without meaning "slow backend":
# websockets, realtime (soketi /app/), broadcasting auth, file uploads/imports.
LATENCY_EXCLUDE = r'websockets|/app/|/broadcasting|/upload|/import|/files'


def _quantile(q, w=W, host=""):
    # selective extraction (only the field) keeps series cardinality under Loki's limit;
    # exclude long-lived connections so p95/p99 reflect real page/API latency.
    expr = ("quantile_over_time(%s, %s |= \"remote_addr\" %s !~ `%s` | json rt=\"request_time\" "
            "| unwrap rt [%s])" % (q, SEL, _hostf(host), LATENCY_EXCLUDE, w))
    res = _get("/loki/api/v1/query", {"query": expr})
    vals = [float(s["value"][1]) for s in res if s["value"][1] not in ("NaN", "+Inf", "-Inf")]
    return round(sum(vals) / len(vals), 3) if vals else 0.0


def top_ips(country="", k=20, w=W, host=""):
    """Top client IPs, optionally filtered by country code (geo drill-down)."""
    cc = ('| cc=`%s`' % country) if country else ""
    q = ('topk(%d, sum by (ip) (count_over_time(%s |= "remote_addr" %s '
         '| json ip="remote_addr", cc="geoip_country_code" %s [%s])))' % (k, SEL, _hostf(host), cc, w))
    res = _get("/loki/api/v1/query", {"query": q})
    out = [{"ip": s["metric"].get("ip", "?"), "count": int(float(s["value"][1]))} for s in res]
    out.sort(key=lambda x: -x["count"])
    return out


def top_talkers(k=20, w=W, host=""):
    """Most active client IPs overall (not scoped to a country)."""
    return top_ips("", k, w, host)


def geo_breakdown(k=15, w=W, host=""):
    """Per-country requests with how many were blocked (status 403)."""
    total = _topk("geoip_country_code", k=k, w=w, host=host)
    blocked = {x["key"]: x["count"]
               for x in _topk("geoip_country_code", k=40, lbl='| st=`403`', w=w, host=host)}
    for x in total:
        x["blocked"] = blocked.get(x["key"], 0)
    return total


def latency_p95():
    return _quantile(0.95)


def latency_quantiles(w=W, host=""):
    return {"p50": _quantile(0.5, w, host), "p95": _quantile(0.95, w, host), "p99": _quantile(0.99, w, host)}


def total_bytes():
    res = _get("/loki/api/v1/query", {"query":
        'sum(sum_over_time(' + SEL + ' |= "remote_addr" | json b="bytes_sent" | unwrap b [' + W + ']))'})
    return float(res[0]["value"][1]) if res else 0.0


def auth_abuse(w=W, host=""):
    q = ('sum(count_over_time(' + SEL + ' |= "remote_addr" ' + _hostf(host) +
         ' | json uri="request_uri", st="status" '
         '| uri=~`/(auth|login|signin|broadcasting/auth).*` | st=~`40[13]` [' + w + ']))')
    res = _get("/loki/api/v1/query", {"query": q})
    return int(float(res[0]["value"][1])) if res else 0


def crs_samples(family="", limit=30, w="1h"):
    """Sample CRS detections (ModSecurity) with matched data, optionally by family."""
    import time as _t
    end = int(_t.time()); start = end - _window_secs(w)
    res = _get("/loki/api/v1/query_range", {
        "query": SEL + ' |~ "ModSecurity"', "limit": "800", "direction": "backward",
        "start": str(start) + "000000000", "end": str(end) + "000000000"})
    def grab(p, l):
        m = re.search(p, l); return m.group(1) if m else None
    out = []
    for s in res:
        for v in s["values"]:
            l = v[1]
            rid = grab(r'\[id "(\d+)"\]', l)
            if not rid or rid.startswith("949"):
                continue
            fam = _CRS_FAMILY.get(rid[:3], "Прочее")
            if family and fam != family:
                continue
            out.append({
                "ts": int(v[0]) // 1_000_000_000, "rule": rid, "family": fam,
                "msg": grab(r'\[msg "([^"]+)"\]', l),
                "data": (grab(r'\[data "([^"]+)"\]', l) or "")[:120],
                "uri": grab(r'\[uri "([^"]+)"\]', l),
                "client": grab(r'\[client ([\d.]+)\]', l) or grab(r'client: ([\d.]+)', l),
            })
            if len(out) >= limit:
                return out
    return out


def _window_secs(w):
    import re as _re
    m = _re.match(r"(\d+)([mh])", w or "1h")
    if not m:
        return 3600
    n, u = int(m.group(1)), m.group(2)
    return n * 60 if u == "m" else n * 3600


def _strip_q(uri):
    return uri.split("?")[0][:60] if uri else "—"


def unique_visitors(w=W, host=""):
    """Distinct client IPs over the window (rough visitor count)."""
    q = ('count(sum by (ip) (count_over_time(%s |= "remote_addr" %s '
         '| json ip="remote_addr" [%s])))' % (SEL, _hostf(host), w))
    res = _get("/loki/api/v1/query", {"query": q})
    return int(float(res[0]["value"][1])) if res else 0


def crs_by_rule(k=15, w=W):
    """Top CRS rule ids (with family) — finer than attack_types families."""
    q = ('topk(%d, sum by (rid) (count_over_time(%s |~ "ModSecurity" '
         '| regexp `\\[id \\"(?P<rid>\\d+)\\"\\]` [%s])))' % (k, SEL, w))
    res = _get("/loki/api/v1/query", {"query": q})
    out = []
    for s in res:
        rid = s["metric"].get("rid", "")
        if not rid or rid.startswith("949"):
            continue
        out.append({"key": rid + " · " + _CRS_FAMILY.get(rid[:3], "Прочее"),
                    "rid": rid, "count": int(float(s["value"][1]))})
    out.sort(key=lambda x: -x["count"])
    return out


_tor = {"set": set(), "ts": 0}
_tor_lock = threading.Lock()
_tor_refreshing = False


def _tor_fetch():
    """Download the Tor bulk exit-list (~700 KB). Blocking — call off the request path."""
    global _tor_refreshing
    import time as _t
    try:
        with urllib.request.urlopen("https://check.torproject.org/torbulkexitlist", timeout=12) as r:
            ips = set(l.strip() for l in r.read().decode().splitlines() if l.strip() and not l.startswith("#"))
        if ips:
            with _tor_lock:
                _tor["set"] = ips; _tor["ts"] = int(_t.time())
    except Exception as e:
        print("[tor] refresh failed: %s" % e, flush=True)
    finally:
        _tor_refreshing = False


def _tor_set(block=False):
    """Tor exit-node list (cached ~daily). NEVER blocks the request path: returns the
    current (possibly stale/empty) set immediately and kicks a background refresh when
    stale. Pass block=True only from startup/background prewarm to wait for the download."""
    global _tor_refreshing
    if not config.TOR_ENABLED:
        return _tor["set"]          # disabled — always empty, no network at all
    import time as _t
    now = int(_t.time())
    fresh = _tor["set"] and now - _tor["ts"] < 86400
    if not fresh:
        if block:
            _tor_fetch()
        elif not _tor_refreshing:
            with _tor_lock:
                if not _tor_refreshing:        # double-check under lock — no stampede
                    _tor_refreshing = True
                    threading.Thread(target=_tor_fetch, daemon=True).start()
    return _tor["set"]


def reputation(ip, asn):
    """Compose a reputation verdict from ASN flags + Tor membership."""
    tor = ip in _tor_set()
    proxy = bool(asn.get("proxy"))
    hosting = bool(asn.get("hosting"))
    if tor:
        verdict, level = "Tor exit-node", "bad"
    elif proxy and hosting:
        verdict, level = "VPN/датацентр (вероятно бот)", "bad"
    elif hosting:
        verdict, level = "датацентр/хостинг", "warn"
    elif proxy:
        verdict, level = "VPN/proxy", "warn"
    else:
        verdict, level = "обычный провайдер", "ok"
    return {"tor": tor, "proxy": proxy, "hosting": hosting, "verdict": verdict, "level": level}


_asn_cache = {}  # ip -> (ts, data)


def asn_lookup(ip):
    """ASN/org/city/flags via ip-api.com (on-demand, single IP). Cached 1h."""
    if not ip:
        return {}
    import time as _t
    now = int(_t.time())
    hit = _asn_cache.get(ip)
    if hit and now - hit[0] < 3600:
        return hit[1]
    # L2: persistent SQLite cache (survives restarts, 7d)
    from . import db
    cached = db.cache_get("asn:" + ip, 7 * 86400)
    if cached is not None:
        _asn_cache[ip] = (now, cached)
        return cached
    try:
        url = (config.ASN_LOOKUP_URL + urllib.parse.quote(ip) +
               "?fields=status,country,city,regionName,isp,org,as,proxy,hosting,mobile")
        with urllib.request.urlopen(url, timeout=8) as r:
            d = json.load(r)
        if d.get("status") != "success":
            return {}
        out = {"country": d.get("country"), "city": d.get("city"), "region": d.get("regionName"),
               "isp": d.get("isp"), "org": d.get("org"), "asn": d.get("as"),
               "proxy": d.get("proxy"), "hosting": d.get("hosting"), "mobile": d.get("mobile")}
        _asn_cache[ip] = (now, out)
        if len(_asn_cache) > 2000:
            _asn_cache.clear()
        try:
            from . import db
            db.cache_put("asn:" + ip, out)
        except Exception:
            pass
        return out
    except Exception:
        return {}


# Verified good bots — matched by reverse-DNS suffix + forward-confirm (anti-spoof).
GOOD_BOT_DOMAINS = {
    ".googlebot.com": "Googlebot", ".google.com": "Google", ".googleusercontent.com": "Google",
    ".search.msn.com": "Bingbot", ".crawl.yahoo.net": "Yahoo! Slurp",
    ".yandex.com": "YandexBot", ".yandex.net": "Yandex", ".yandex.ru": "Yandex",
    ".baidu.com": "Baiduspider", ".baidu.jp": "Baidu", ".applebot.apple.com": "Applebot",
    ".fbsv.net": "FacebookBot", ".twttr.com": "Twitterbot", ".linkedin.com": "LinkedInBot",
    ".duckduckgo.com": "DuckDuckBot", ".telegram.org": "TelegramBot",
}


def verify_bot(ip):
    """Reverse-DNS + forward-confirm: returns {ptr, bot}. bot set only if the IP's
    PTR matches a known good-bot domain AND forward-resolves back to this IP.
    Cached 7d in SQLite (rDNS rarely changes)."""
    from . import db
    import socket
    cached = db.cache_get("rdns:" + ip, 7 * 86400)
    if cached is not None:
        return cached
    res = {"ptr": None, "bot": None}
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(3)
        host = socket.gethostbyaddr(ip)[0]
        res["ptr"] = host
        h = host.lower()
        name = next((nm for suf, nm in GOOD_BOT_DOMAINS.items() if h.endswith(suf)), None)
        if name:
            try:
                fwd = set(ai[4][0] for ai in socket.getaddrinfo(host, None))
                if ip in fwd:
                    res["bot"] = name
            except Exception:
                pass
    except Exception:
        pass
    finally:
        socket.setdefaulttimeout(old)
    try:
        db.cache_put("rdns:" + ip, res)
    except Exception:
        pass
    return res


def ip_scanner_hits(ip, w="8h", use_cache=False):
    """How many scanner-path requests (.php/.env/wp-…) this IP made — strong
    'this is a scanner, not a legit bot' signal. Quoted-IP literal matches remote_addr
    OR real_ip_cloudflare/XFF (works behind Cloudflare) + a scanner token in the line.
    use_cache=True: 1h SQLite cache (for cheap repeated guards like /api/verdicts)."""
    ipq = ip.replace("`", "").replace('"', "")
    if use_cache:
        from . import db
        c = db.cache_get("scanhits:%s:%s" % (w, ipq), 3600)
        if c is not None:
            return c
    q = ('sum(count_over_time(%s |= `"%s"` |~ `%s` [%s]))'
         % (SEL, ipq, SCANNER_LINE, w))
    try:
        r = _get("/loki/api/v1/query", {"query": q})
        n = int(float(r[0]["value"][1])) if r else 0
    except Exception:
        return 0
    if use_cache:
        try:
            from . import db
            db.cache_put("scanhits:%s:%s" % (w, ipq), n)
        except Exception:
            pass
    return n


def slow_endpoints(k=10, w=W, host=""):
    """Top paths by average request_time (excluding long-lived)."""
    q = ('topk(%d, avg by (p) (avg_over_time(%s |= "remote_addr" %s !~ `%s` '
         '| json p="request_uri", rt="request_time" | unwrap rt [%s])))'
         % (k, SEL, _hostf(host), LATENCY_EXCLUDE, w))
    res = _get("/loki/api/v1/query", {"query": q})
    out = [{"key": _strip_q(s["metric"].get("p", "")), "count": round(float(s["value"][1]), 3)}
           for s in res if s["value"][1] not in ("NaN", "+Inf", "-Inf")]
    out.sort(key=lambda x: -x["count"])
    return out


def bytes_by_domain(k=10, w=W):
    q = ('topk(%d, sum by (h) (sum_over_time(%s |= "remote_addr" '
         '| json h="http_host", b="bytes_sent" | unwrap b [%s])))' % (k, SEL, w))
    res = _get("/loki/api/v1/query", {"query": q})
    out = [{"key": s["metric"].get("h", "—"), "count": round(float(s["value"][1]) / 1048576, 1)}
           for s in res]
    out.sort(key=lambda x: -x["count"])
    return out


def upstream_p95(w=W, host=""):
    expr = ('quantile_over_time(0.95, %s |= "remote_addr" %s !~ `%s` '
            '| json u="upstream_response_time" | unwrap u [%s])' % (SEL, _hostf(host), LATENCY_EXCLUDE, w))
    try:
        res = _get("/loki/api/v1/query", {"query": expr})
        vals = [float(s["value"][1]) for s in res if s["value"][1] not in ("NaN", "+Inf", "-Inf")]
        return round(sum(vals) / len(vals), 3) if vals else 0.0
    except Exception:
        return 0.0


def _window_secs(w):
    """Parse a Loki-style window ('30m','1h','6h','24h','7d') into seconds."""
    try:
        n, unit = int(w[:-1]), w[-1]
        return n * {"m": 60, "h": 3600, "d": 86400}.get(unit, 3600)
    except Exception:
        return 3600


# Cap on raw lines pulled per profile. An IP over this in the window gets an
# approximate (truncated) breakdown — flagged via "total_approx" in the result.
PROFILE_FETCH_LIMIT = 5000


def ip_profile(ip, w="1h"):
    """Full profile of a single IP. ONE raw query_range fetch of this IP's access-log
    lines + in-Python aggregation — replaces 5 concurrent count_over_time scans (which
    each scanned the whole window and contended on Loki, taking ~25s at 6h)."""
    if not ip:
        return {}
    import time as _t
    from collections import Counter
    from concurrent.futures import ThreadPoolExecutor
    ipq = ip.replace("`", "")
    end = int(_t.time())
    start = end - _window_secs(w)
    _t0 = _t.perf_counter()
    _timings = {}

    def fetch_rows():
        s = _t.perf_counter()
        rows = []
        try:
            res = _get("/loki/api/v1/query_range", {
                "query": SEL + ' |= "remote_addr" |= `%s`' % ipq,
                "start": str(start) + "000000000", "end": str(end) + "000000000",
                "limit": str(PROFILE_FETCH_LIMIT), "direction": "backward"})
            for stream in res:
                for v in stream["values"]:
                    try:
                        o = json.loads(v[1])
                    except Exception:
                        continue
                    # match the REAL client (CF-aware): direct → remote_addr==ip;
                    # behind Cloudflare → real_ip_cloudflare==ip. (|= is just a substring
                    # prefilter; this is the exact, anti-spoof check.)
                    if _eff_real(o.get("remote_addr"), o.get("real_ip_cloudflare")) == ip:
                        rows.append(o)
        except Exception as e:
            print("[ip_profile] fetch failed for %s: %s" % (ip, e), flush=True)
        _timings["fetch"] = round((_t.perf_counter() - s) * 1000)
        return rows

    # raw log fetch (Loki) || asn + bot lookups (network, usually cached) — all parallel
    with ThreadPoolExecutor(max_workers=3) as ex:
        f_rows = ex.submit(fetch_rows)
        f_asn = ex.submit(asn_lookup, ip)
        f_bot = ex.submit(verify_bot, ip)
        if config.TOR_ENABLED:
            ex.submit(_tor_set)
        rows = f_rows.result()
        a = f_asn.result()
        vb = f_bot.result()

    def top(counter, k):
        return [{"key": kk, "count": vv} for kk, vv in counter.most_common(k)]
    c_status = Counter(o.get("status") for o in rows if o.get("status"))
    c_cc = Counter(o.get("geoip_country_code") for o in rows if o.get("geoip_country_code"))
    by_status = top(c_status, 10)
    total = len(rows)
    # "blocked" = actual ingress blocks (403) only. 4xx like 422 (validation),
    # 404 (not found), 429 (rate-limit) are errors, NOT blocks — counted separately.
    blocked = sum(v for k, v in c_status.items() if str(k) == "403")
    err_4xx = sum(v for k, v in c_status.items() if str(k).startswith("4") and str(k) != "403")
    err_5xx = sum(v for k, v in c_status.items() if str(k).startswith("5"))

    _wall = round((_t.perf_counter() - _t0) * 1000)
    print("[ip_profile] %s w=%s wall=%dms rows=%d fetch=%dms" % (
        ip, w, _wall, total, _timings.get("fetch", 0)), flush=True)
    return {
        "ip": ip, "window": w,
        "total": total,
        "total_approx": total >= PROFILE_FETCH_LIMIT,   # hit the cap — undercount
        "blocked": blocked,
        "err_4xx": err_4xx,
        "err_5xx": err_5xx,
        "by_status": by_status,
        "top_paths": top(Counter((o.get("request_uri") or "") for o in rows), 10),
        "top_ua": top(Counter((o.get("http_user_agent") or "") for o in rows), 5),
        "country": (top(c_cc, 1) or [{}])[0].get("key", "—"),
        "trusted": config.TRUSTED_IPS.get(ip),
        "asn": a,
        "reputation": reputation(ip, a),
        "ptr": vb.get("ptr"),
        "verified_bot": vb.get("bot"),
    }


def _safe(fn, default):
    try:
        return fn()
    except Exception as e:
        print("[analytics] %s failed: %s" % (getattr(fn, "__name__", "?"), e), flush=True)
        return default


def recent_requests(host="", path="", status="", ip="", ua="", ref="", limit=60, minutes=15):
    """Fetch recent access-log requests matching filters, parsed for the explorer."""
    import time as _t
    filters = ['|= "remote_addr"']
    for term in (host, path, ip, ua, ref):
        if term:
            filters.append('|= `%s`' % term.replace("`", ""))
    if status:
        filters.append('|= `"status":"%s`' % status.replace("`", ""))
    q = SEL + " " + " ".join(filters)
    end = int(_t.time())
    start = end - minutes * 60
    res = _get("/loki/api/v1/query_range", {
        "query": q, "start": str(start) + "000000000", "end": str(end) + "000000000",
        "limit": str(limit), "direction": "backward"})
    rows = []
    for s in res:
        for v in s["values"]:
            try:
                o = json.loads(v[1])
            except Exception:
                continue
            rows.append({
                "ts": int(v[0]) // 1_000_000_000,
                "ip": _eff_ip(o), "method": o.get("request_method"),
                "path": (o.get("request_uri") or "")[:300], "status": o.get("status"),
                "host": o.get("http_host"), "country": o.get("geoip_country_code"),
                "ua": (o.get("http_user_agent") or "")[:200], "rt": o.get("request_time"),
                "ref": (o.get("http_referer") or "")[:300],
                "args": (o.get("args") or "")[:200],
                "bytes": o.get("bytes_sent"),
            })
    rows.sort(key=lambda r: -r["ts"])
    return rows[:limit]


def collect_analytics(w=W, host=""):
    """Heavier breakdowns (slower cadence). Each piece is isolated so one
    failing query (e.g. Loki series limit) doesn't drop the whole set.
    w = window (5m/1h/24h…), host = optional domain filter."""
    # high-cardinality topks: fall back to a smaller window if the requested one
    # exceeds Loki's series limit; record the window actually used.
    paths, wp = _topk_fb("request_uri", w, k=15, parser=_strip_q, line='!~ `' + DENY_ACC + '`', lbl='| st=~`4..` | st!~`429|499`', host=host)
    uas, wu = _topk_fb("http_user_agent", w, k=12, lbl='| st=~`4..` | st!~`429|499`', host=host)
    doms, wd = _topk_fb("http_host", w, k=10, host=host)
    talk = []
    for ww in _chain(w):
        try:
            talk = top_talkers(20, w=ww, host=host); break
        except Exception:
            continue
    return {
        "window": w, "host": host,
        "eff_windows": {"top_paths": wp, "top_user_agents": wu, "top_domains": wd},
        "top_paths": paths,
        "top_user_agents": uas,
        "top_domains": doms,
        "geo": _safe(lambda: geo_breakdown(40, w=w, host=host), []),
        "cache": _safe(lambda: _topk("upstream_cache_status", k=6, w=w, host=host), []),
        "top_talkers": talk,
        "attack_types": _safe(lambda: attack_types(w=w), []),
        "crs_rules": _safe(lambda: crs_by_rule(15, w=w), []),
        "methods": _safe(lambda: _topk("request_method", k=8, w=w, host=host), []),
        "referers": _safe(lambda: _topk("http_referer", k=12, w=w, host=host, lbl='| st=~`4..` | st!~`403|429|499`'), []),
        "tls": _safe(lambda: _topk("ssl_protocol", k=6, w=w, host=host), []),
        "latency": _safe(lambda: latency_quantiles(w=w, host=host), {}),
        "auth_abuse": _safe(lambda: auth_abuse(w=w, host=host), 0),
        "unique_visitors": _safe(lambda: unique_visitors(w=w, host=host), 0),
        "slow_endpoints": _safe(lambda: slow_endpoints(10, w=w, host=host), []),
        "bytes_by_domain": _safe(lambda: bytes_by_domain(10, w=w), []),
        "waf_fp": _safe(lambda: waf_false_positives(w=w), []),
    }


def waf_false_positives(w="1h", limit=200):
    """URIs that trip CRS most — candidates for exclusion before SecRuleEngine On.
    Aggregates CRS sample lines by URI."""
    samples = crs_samples("", limit, w if w in _WIN_ORDER else "1h")
    agg = {}
    for s in samples:
        uri = (s.get("uri") or "—").split("?")[0][:60]
        agg[uri] = agg.get(uri, 0) + 1
    return sorted([{"key": k, "count": v} for k, v in agg.items()], key=lambda x: -x["count"])[:12]
