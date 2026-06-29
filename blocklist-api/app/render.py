"""Render the active denylist into ingress-nginx ConfigMap snippets.

ingress-nginx exposes only ONE `http-snippet` and ONE `server-snippet` key, which
may already hold other config (e.g. anti-range-attack maps). So we MERGE: our
content lives between markers and we splice only that region, leaving the rest
untouched.

  http-snippet   : geo $soc_blocked { default 0; <cidr> 1; ... }   (http context)
  server-snippet : if ($soc_blocked) { return 403; }              (per-server)
"""
import re

from . import config

BEGIN = "# >>> soc blocklist (managed — do not edit between markers) >>>"
END = "# <<< soc blocklist (managed) <<<"

_SECTION = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END) + r"\n?", re.S)


def _wrap(body):
    """body must end with a newline."""
    return BEGIN + "\n" + body + END + "\n"


def geo_body(cidrs):
    """Three blocks (http context):
      1. geo $remote_addr $soc_is_cf  — is the connection from a Cloudflare edge?
      2. map $soc_is_cf $soc_real_ip — real visitor (CF-Connecting-IP behind CF, else remote_addr)
      3. geo $soc_real_ip $soc_blocked — the actual denylist, keyed on the real visitor
    So one list blocks direct hits AND attackers hidden behind Cloudflare."""
    out = []
    # 1) detect Cloudflare edge
    out.append("geo $remote_addr %s {" % config.CF_FLAG_VAR)
    out.append("  default 0;")
    for c in config.CF_RANGES:
        out.append("  %s 1;" % c)
    out.append("}")
    # 2) resolve the real visitor IP
    out.append("map %s %s {" % (config.CF_FLAG_VAR, config.REAL_IP_VAR))
    out.append("  default $remote_addr;")
    out.append("  1 $http_cf_connecting_ip;")
    out.append("}")
    # 3) the denylist (same CIDR list as before), now keyed on the real visitor
    out.append("geo %s %s {" % (config.REAL_IP_VAR, config.GEO_VAR))
    out.append("  default 0;")
    for c in cidrs:
        out.append("  %s 1;" % c)
    out.append("}")
    return "\n".join(out) + "\n"


def path_if_body(patterns, enabled=True):
    """Optional second `if` in the server context: 403 any request URI matching
    one of the enabled path rules (scanner/exploit paths). Returns '' when there
    are no enabled patterns or the master switch is off — we NEVER emit an empty
    `~* "()"`, which would match every URI and 403 the whole site."""
    pats = [p for p in (patterns or []) if p]
    if not enabled or not pats:
        return ""
    joined = "(" + "|".join(pats) + ")"
    return 'if ($request_uri ~* "%s") { return 403; }\n' % joined


def if_body(patterns=None, path_enabled=True):
    """server-snippet managed block: deny by IP (denylist) + deny by path (403 rules)."""
    out = "if (%s) { return 403; }\n" % config.GEO_VAR
    out += path_if_body(patterns, path_enabled)
    return out


def merge(existing, body):
    """Insert/replace our marked section in `existing`, preserving everything else."""
    block = _wrap(body)
    existing = existing or ""
    if _SECTION.search(existing):
        return _SECTION.sub(lambda _: block, existing)
    existing = existing.rstrip("\n")
    return (existing + "\n" + block) if existing.strip() else block


def controller_patch(cidrs, patterns=None, path_enabled=True,
                     existing_http="", existing_server=""):
    """Return the {data: {...}} merge-patch body for the controller ConfigMap."""
    return {"data": {
        "http-snippet": merge(existing_http, geo_body(cidrs)),
        "server-snippet": merge(existing_server, if_body(patterns, path_enabled)),
    }}
