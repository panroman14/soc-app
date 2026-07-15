"""Multi-user auth for the dashboard: scrypt password hashes, optional TOTP MFA,
signed session cookies, roles (admin / viewer), and brute-force lockout.

Design notes:
- Passwords are hashed with stdlib `hashlib.scrypt` (no dependency). Stored as
  `scrypt$N$r$p$salt_hex$hash_hex`; verified in constant time.
- Sessions are STATELESS signed cookies: base64(payload).hmac_sha256. The signing key
  is `SECRET_KEY` if set (rotating it logs everyone out) else a random key persisted in
  app_settings. Each user carries an `epoch` int embedded in the cookie — bumping it
  (logout-all / password change) invalidates all of that user's existing cookies.
- TOTP (RFC 6238, stdlib) is optional per user; an admin account can require it.
- Bootstrap: first run with no users seeds an admin from BASIC_AUTH_USER/PASS if set, so
  existing single-cred deploys keep working (their env creds become the first admin).
"""
import base64
import hashlib
import hmac
import json
import os
import struct
import time

from . import config, db

_LOCKOUT_MAX = 6            # failed attempts before lockout (per user+ip)
_LOCKOUT_MAX_USER = 20      # AND a global per-username cap across ALL ips in the window
_LOCKOUT_WINDOW = 900       # ...within this many seconds
_LOCKOUT_FOR = 900          # lock duration
_SESSION_TTL = 12 * 3600
COOKIE = "soc_session"

_fails = {}                 # (user,ip) -> [ts, ...]  (in-memory, single process)
_fails_user = {}            # user -> [ts, ...]  — global cap so a spoofed X-Forwarded-For
                            # can't spread guesses across unlimited (user,ip) buckets (S2)


# ── schema ────────────────────────────────────────────────────────────────────
def init():
    with db._lock, db._conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username    TEXT PRIMARY KEY,
                pw_hash     TEXT NOT NULL,
                role        TEXT NOT NULL DEFAULT 'viewer',
                totp_secret TEXT,
                epoch       INTEGER NOT NULL DEFAULT 0,
                created     INTEGER,
                last_login  INTEGER
            )""")
    _bootstrap()


def _bootstrap():
    if user_count() > 0:
        return
    u, p = config.BASIC_AUTH_USER, config.BASIC_AUTH_PASS
    if u and p:
        create_user(u, p, role="admin")
        print("[auth] seeded first admin '%s' from BASIC_AUTH_USER/PASS" % u, flush=True)


# ── password hashing (scrypt, stdlib) ───────────────────────────────────────────
def hash_pw(pw):
    salt = os.urandom(16)
    dk = hashlib.scrypt(pw.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)
    return "scrypt$16384$8$1$%s$%s" % (salt.hex(), dk.hex())


# A valid throwaway hash used to spend the SAME scrypt time on a non-existent username
# as on a real one, so response timing doesn't reveal which usernames exist (S11).
_DUMMY_HASH = None


def _dummy_hash():
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_pw(os.urandom(16).hex())
    return _DUMMY_HASH


def verify_pw(pw, stored):
    try:
        algo, n, r, p, salt, h = stored.split("$")
        if algo != "scrypt":
            return False
        dk = hashlib.scrypt(pw.encode("utf-8"), salt=bytes.fromhex(salt),
                            n=int(n), r=int(r), p=int(p), dklen=len(bytes.fromhex(h)))
        return hmac.compare_digest(dk, bytes.fromhex(h))
    except Exception:
        return False


# ── TOTP (RFC 6238, stdlib) ─────────────────────────────────────────────────────
def totp_new_secret():
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def _totp_at(secret, t, step=30, digits=6):
    pad = "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(secret.upper() + pad)
    h = hmac.new(key, struct.pack(">Q", int(t // step)), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_verify(secret, code, window=1, now=None):
    code = str(code or "").strip()
    if not (secret and code):
        return False
    now = now if now is not None else time.time()
    return any(hmac.compare_digest(_totp_at(secret, now + w * 30), code)
               for w in range(-window, window + 1))


_totp_used = {}             # (user, code) -> ts — consumed TOTP codes, to block replay


def totp_consume(username, code, now=None):
    """Record a just-verified code as used; return False if it was ALREADY used within
    the validity window (a replay). Bounds the ~90s window in which a phished/observed
    code could be re-submitted."""
    now = now if now is not None else time.time()
    for k, ts in list(_totp_used.items()):        # prune expired
        if now - ts > 90:
            _totp_used.pop(k, None)
    k = (username, str(code))
    if k in _totp_used:
        return False
    _totp_used[k] = now
    return True


def totp_uri(username, secret):
    issuer = "SOC Dashboard"
    return ("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=6&period=30"
            % (issuer.replace(" ", "%20"), username, secret, issuer.replace(" ", "%20")))


# ── session cookie (stateless, signed) ──────────────────────────────────────────
def _session_key():
    if config.SECRET_KEY:
        return config.SECRET_KEY.encode("utf-8")
    k = db.setting_get("auth_session_key", None)
    if not k:
        k = os.urandom(32).hex()
        db.setting_set("auth_session_key", k)
    return k.encode("utf-8")


def _b64u(b):
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))


def make_session(username, role, epoch, ttl=_SESSION_TTL):
    body = _b64u(json.dumps({"u": username, "r": role, "e": epoch,
                             "x": int(time.time()) + ttl}).encode("utf-8"))
    sig = hmac.new(_session_key(), body.encode("ascii"), hashlib.sha256).hexdigest()
    return body + "." + sig


def read_session(tok):
    """Return the payload dict for a valid, unexpired, correctly-signed cookie whose
    embedded epoch still matches the user's current epoch; else None."""
    try:
        body, _, sig = (tok or "").partition(".")
        good = hmac.new(_session_key(), body.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, good):
            return None
        p = json.loads(_b64u_dec(body))
        if p.get("x", 0) < time.time():
            return None
        u = get_user(p.get("u"))
        if not u or u["epoch"] != p.get("e"):
            return None
        p["role"] = u["role"]            # role changes take effect immediately
        return p
    except Exception:
        return None


# ── user store ──────────────────────────────────────────────────────────────────
def user_count():
    with db._conn() as c:
        return c.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def get_user(username):
    if not username:
        return None
    with db._conn() as c:
        r = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    return dict(r) if r else None


def list_users():
    with db._conn() as c:
        rows = c.execute("SELECT username, role, totp_secret, created, last_login "
                         "FROM users ORDER BY username").fetchall()
    return [{"username": r["username"], "role": r["role"],
             "totp": bool(r["totp_secret"]), "created": r["created"],
             "last_login": r["last_login"]} for r in rows]


def create_user(username, password, role="viewer"):
    username = (username or "").strip()
    if not username or "$" in username or len(username) > 64:
        raise ValueError("bad username")
    if not password or len(password) < 8:
        raise ValueError("password too short (min 8)")
    role = role if role in ("admin", "viewer") else "viewer"
    with db._lock, db._conn() as c:
        c.execute("INSERT INTO users (username, pw_hash, role, epoch, created) "
                  "VALUES (?,?,?,0,?)", (username, hash_pw(password), role, int(time.time())))


def set_password(username, password):
    if not password or len(password) < 8:
        raise ValueError("password too short (min 8)")
    with db._lock, db._conn() as c:
        c.execute("UPDATE users SET pw_hash=?, epoch=epoch+1 WHERE username=?",
                  (hash_pw(password), username))          # epoch bump = log out everywhere


def admin_count():
    with db._conn() as c:
        return c.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]


def set_role(username, role):
    if role not in ("admin", "viewer"):
        raise ValueError("bad role")
    # Never let the last admin be demoted — same protection as delete_user has, but on
    # the upsert/set-role path too, so nobody can strand the system with zero admins (S14).
    if role != "admin":
        cur = get_user(username)
        if cur and cur["role"] == "admin" and admin_count() <= 1:
            raise ValueError("can't demote the last admin")
    with db._lock, db._conn() as c:
        c.execute("UPDATE users SET role=? WHERE username=?", (role, username))


def set_totp(username, secret):
    with db._lock, db._conn() as c:
        c.execute("UPDATE users SET totp_secret=? WHERE username=?", (secret, username))


def bump_epoch(username):
    with db._lock, db._conn() as c:
        c.execute("UPDATE users SET epoch=epoch+1 WHERE username=?", (username,))


def touch_login(username):
    with db._lock, db._conn() as c:
        c.execute("UPDATE users SET last_login=? WHERE username=?", (int(time.time()), username))


def delete_user(username):
    with db._lock, db._conn() as c:
        c.execute("DELETE FROM users WHERE username=?", (username,))


# ── lockout ──────────────────────────────────────────────────────────────────────
def _recent(seq, now):
    return [t for t in (seq or []) if now - t < _LOCKOUT_WINDOW]


def locked(username, ip):
    now = time.time()
    hits = _recent(_fails.get((username, ip)), now)
    _fails[(username, ip)] = hits
    ghits = _recent(_fails_user.get(username), now)
    _fails_user[username] = ghits
    # locked if EITHER this ip has too many fails, OR the account has too many total
    # fails across all ips this window (bounds distributed / XFF-spoofed guessing).
    return len(hits) >= _LOCKOUT_MAX or len(ghits) >= _LOCKOUT_MAX_USER


def note_fail(username, ip):
    now = time.time()
    _fails.setdefault((username, ip), []).append(now)
    _fails_user.setdefault(username, []).append(now)


def clear_fails(username, ip):
    _fails.pop((username, ip), None)
    _fails_user.pop(username, None)


# ── the check used by the request middleware ─────────────────────────────────────
def authenticate(username, password, code, ip):
    """Returns (payload_or_None, error_code). error_code ∈
    {ok, bad, locked, totp_required, totp_bad}."""
    if locked(username, ip):
        return None, "locked"
    u = get_user(username)
    # Always run scrypt (against a dummy hash when the user is missing) so the response
    # time is the same whether or not the username exists — no enumeration oracle (S11).
    ok = verify_pw(password, u["pw_hash"] if u else _dummy_hash())
    if not u or not ok:
        note_fail(username, ip)
        return None, "bad"
    if u["totp_secret"]:
        if not code:
            return None, "totp_required"
        if not totp_verify(u["totp_secret"], code) or not totp_consume(username, code):
            note_fail(username, ip)                # wrong OR replayed code
            return None, "totp_bad"
    clear_fails(username, ip)
    touch_login(username)
    return {"u": username, "r": u["role"], "e": u["epoch"]}, "ok"
