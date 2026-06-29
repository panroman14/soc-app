"""Validation + safety rails for denylist entries.

Everything here is pure (no I/O) so it's trivially unit-testable.
"""
import ipaddress
import re

from . import config


# Benign URIs a path-403 rule must NOT match — guards against a too-broad pattern
# (e.g. `.*\.php` or a stray `.*`) that would 403 legitimate traffic on every host.
_BENIGN_SAMPLES = [
    "/", "/index.html", "/index.php", "/home", "/login", "/account/login",
    "/api/users", "/api/v1/orders", "/dashboard", "/static/app.js",
    "/assets/main.css", "/favicon.ico", "/robots.txt", "/images/logo.png",
    "/.well-known/acme-challenge/x", "/.well-known/security.txt",
]
_MAX_PATTERN_LEN = 8000


def validate_pattern(pattern, force=False):
    """Validate a path-403 regex fragment. Returns the trimmed pattern or raises.

    Rules:
      - must be a non-empty string, not absurdly long
      - no `"` (would terminate the nginx quoted string and break the config)
      - must compile as a regex
      - (unless force) must not match any known-benign path — else it would 403
        real users across every domain on the shared catch-all server
    """
    if not pattern or not isinstance(pattern, str):
        raise BlockError("пустой паттерн")
    pattern = pattern.strip()
    if len(pattern) > _MAX_PATTERN_LEN:
        raise BlockError("паттерн слишком длинный (>%d символов)" % _MAX_PATTERN_LEN)
    if '"' in pattern:
        raise BlockError('кавычка " в паттерне сломает nginx-конфиг — убери её')
    try:
        rx = re.compile(pattern, re.IGNORECASE)  # nginx uses ~* (case-insensitive)
    except re.error as e:
        raise BlockError("некорректная регулярка: %s" % e)
    if not force:
        for sample in _BENIGN_SAMPLES:
            if rx.search(sample):
                raise BlockError(
                    "паттерн ловит легитимный путь '%s' — это зарубит нормальный "
                    "трафик на всех доменах (force=true, чтобы всё равно добавить)" % sample)
    return pattern


class BlockError(ValueError):
    """Raised when a block request is rejected by a safety rule."""


# Cloudflare edge ranges — NEVER bannable (would 403 all CF-fronted traffic).
_CF_CIDRS = ["173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
             "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
             "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
             "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32",
             "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
             "2a06:98c0::/29", "2c0f:f248::/32"]
_CF_NETS = []
for _c in _CF_CIDRS:
    try:
        _CF_NETS.append(ipaddress.ip_network(_c))
    except ValueError:
        pass


def _allowed_nets():
    out = []
    for ip in config.ALLOWLIST:
        try:
            out.append(ipaddress.ip_network(ip, strict=False))
        except ValueError:
            pass
    return out


def normalize_cidr(cidr):
    """Parse + canonicalize a CIDR/IP string. Raises BlockError on garbage.

    A bare IP becomes a /32 (or /128). Returns the canonical string.
    """
    if not cidr or not isinstance(cidr, str):
        raise BlockError("пустой CIDR")
    cidr = cidr.strip()
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        raise BlockError("некорректный CIDR/IP: %s" % e)
    return str(net)


def validate(cidr, force=False):
    """Validate a CIDR against safety rails. Returns canonical CIDR or raises.

    Rules:
      - must parse
      - never 0.0.0.0/0 or ::/0 (even with force)
      - must not contain any allowlisted IP
      - prefix not broader than MIN_PREFIX_* unless force=True
    """
    net = ipaddress.ip_network(normalize_cidr(cidr), strict=False)

    if net.prefixlen == 0:
        raise BlockError("нельзя блокировать весь интернет (/0)")

    for allow in _allowed_nets():
        # overlap in either direction → refuse (would block a trusted IP)
        if net.overlaps(allow):
            raise BlockError("CIDR пересекается с allowlist (%s) — заблокировал бы доверенный IP" % allow)

    for cf in _CF_NETS:
        if net.overlaps(cf):
            raise BlockError("это диапазон Cloudflare (%s) — банить нельзя (заблокирует весь CF-трафик)" % cf)

    if net.is_private or net.is_loopback or net.is_link_local or net.is_reserved:
        raise BlockError("приватный/служебный диапазон (%s) — банить нельзя (внутренняя сеть / LB)" % net)

    floor = config.MIN_PREFIX_V4 if net.version == 4 else config.MIN_PREFIX_V6
    if net.prefixlen < floor and not force:
        raise BlockError("слишком широкая подсеть (/%d < /%d) — нужен force=true" % (net.prefixlen, floor))

    return str(net)


def collapse(cidrs):
    """Merge overlapping/adjacent CIDRs into a minimal set (sorted strings)."""
    nets = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue
    return [str(n) for n in ipaddress.collapse_addresses(nets)]
