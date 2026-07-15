"""Unit tests for multi-user auth (app/auth.py): scrypt, TOTP, sessions, lockout.

Run: backend/.venv/bin/python backend/tests/test_auth.py
"""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import config  # noqa: E402

config.DB_PATH = os.path.join(tempfile.mkdtemp(), "auth-test.db")
config.SECRET_KEY = "test-session-key"
config.BASIC_AUTH_USER = ""
config.BASIC_AUTH_PASS = ""

from app import auth  # noqa: E402  (after DB_PATH is set)

auth.init()


def _fresh():
    # wipe at the storage layer — delete_user now refuses to remove the last admin
    # (production invariant), so tests reset state directly rather than via that guard.
    from app import db
    with db._lock, db._conn() as c:
        c.execute("DELETE FROM users")
    auth._fails.clear()
    auth._fails_user.clear()
    auth._totp_used.clear()


def test_password_hash_roundtrip():
    _fresh()
    auth.create_user("alice", "hunter2secret", role="admin")
    u = auth.get_user("alice")
    assert u["pw_hash"].startswith("scrypt$") and "hunter2secret" not in u["pw_hash"]
    assert auth.verify_pw("hunter2secret", u["pw_hash"])
    assert not auth.verify_pw("wrong", u["pw_hash"])


def test_short_password_rejected():
    _fresh()
    try:
        auth.create_user("bob", "short")
        assert False, "expected rejection"
    except ValueError:
        pass


def test_authenticate_flow():
    _fresh()
    auth.create_user("alice", "hunter2secret", role="admin")
    p, err = auth.authenticate("alice", "hunter2secret", "", "1.2.3.4")
    assert err == "ok" and p["r"] == "admin"
    p, err = auth.authenticate("alice", "nope", "", "1.2.3.4")
    assert p is None and err == "bad"


def test_lockout():
    _fresh()
    auth.create_user("alice", "hunter2secret")
    for _ in range(auth._LOCKOUT_MAX):
        auth.authenticate("alice", "wrong", "", "9.9.9.9")
    p, err = auth.authenticate("alice", "hunter2secret", "", "9.9.9.9")  # correct, but locked
    assert err == "locked"


def test_totp_required_and_verified():
    _fresh()
    auth.create_user("alice", "hunter2secret")
    secret = auth.totp_new_secret()
    auth.set_totp("alice", secret)
    p, err = auth.authenticate("alice", "hunter2secret", "", "1.2.3.4")
    assert err == "totp_required"
    code = auth._totp_at(secret, time.time())
    p, err = auth.authenticate("alice", "hunter2secret", code, "1.2.3.4")
    assert err == "ok"
    p, err = auth.authenticate("alice", "hunter2secret", "000000", "1.2.3.4")
    assert err in ("totp_bad", "locked")


def test_session_roundtrip_and_tamper():
    _fresh()
    auth.create_user("alice", "hunter2secret", role="admin")
    u = auth.get_user("alice")
    tok = auth.make_session("alice", "admin", u["epoch"])
    p = auth.read_session(tok)
    assert p and p["u"] == "alice" and p["role"] == "admin"
    assert auth.read_session(tok[:-3] + "000") is None          # bad signature
    assert auth.read_session("garbage") is None


def test_epoch_bump_invalidates_session():
    _fresh()
    auth.create_user("alice", "hunter2secret")
    u = auth.get_user("alice")
    tok = auth.make_session("alice", "viewer", u["epoch"])
    assert auth.read_session(tok)
    auth.set_password("alice", "newpassword1")                  # bumps epoch
    assert auth.read_session(tok) is None                       # old cookie now invalid


def test_expired_session():
    _fresh()
    auth.create_user("alice", "hunter2secret")
    u = auth.get_user("alice")
    tok = auth.make_session("alice", "viewer", u["epoch"], ttl=-1)
    assert auth.read_session(tok) is None


def test_global_lockout_across_ips():
    # S2 regression: a spoofed X-Forwarded-For rotates the per-(user,ip) bucket, so the
    # GLOBAL per-username cap is what must still trip. 20 fails from 20 distinct ips lock.
    _fresh()
    auth.create_user("alice", "hunter2secret")
    for i in range(auth._LOCKOUT_MAX_USER):
        auth.authenticate("alice", "wrong", "", "10.0.0.%d" % i)   # each ip: 1 fail (< per-ip max)
    p, err = auth.authenticate("alice", "hunter2secret", "", "10.0.0.250")  # fresh ip, correct pw
    assert err == "locked"                                          # global cap held


def test_unknown_user_returns_bad_and_dummy_hash_shape():
    # S11: unknown user must still hit scrypt (via _dummy_hash) — verify the contract and
    # that the dummy hash uses the same scrypt params as a real one (comparable cost).
    _fresh()
    p, err = auth.authenticate("ghost", "whatever", "", "1.2.3.4")
    assert p is None and err == "bad"
    assert auth._dummy_hash().startswith("scrypt$16384$8$1$")


def test_totp_replay_blocked():
    # P2-N7: a valid code works once; an immediate replay is rejected.
    _fresh()
    auth.create_user("alice", "hunter2secret")
    secret = auth.totp_new_secret()
    auth.set_totp("alice", secret)
    code = auth._totp_at(secret, time.time())
    _, err1 = auth.authenticate("alice", "hunter2secret", code, "1.2.3.4")
    _, err2 = auth.authenticate("alice", "hunter2secret", code, "1.2.3.4")   # same code again
    assert err1 == "ok"
    assert err2 in ("totp_bad", "locked")


def test_last_admin_cannot_be_demoted_or_deleted():
    # S14 / P2-N6: the sole admin is protected on BOTH set_role and delete_user.
    _fresh()
    auth.create_user("root", "adminpass12", role="admin")
    for fn in (lambda: auth.set_role("root", "viewer"), lambda: auth.delete_user("root")):
        try:
            fn(); assert False, "expected last-admin guard to raise"
        except ValueError:
            pass
    assert auth.get_user("root")["role"] == "admin"       # unchanged
    # with a second admin, demotion is allowed again
    auth.create_user("root2", "adminpass12", role="admin")
    auth.set_role("root", "viewer")
    assert auth.get_user("root")["role"] == "viewer"


def test_logout_epoch_bump_invalidates_cookie():
    # P2-N5: real server-side revocation — a bumped epoch invalidates issued cookies.
    _fresh()
    auth.create_user("alice", "hunter2secret")
    u = auth.get_user("alice")
    tok = auth.make_session("alice", "viewer", u["epoch"])
    assert auth.read_session(tok)
    auth.bump_epoch("alice")                              # what /api/auth/logout now does
    assert auth.read_session(tok) is None


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print("  ok  %s" % fn.__name__)
        except Exception as e:
            failed += 1; print("  FAIL %s: %r" % (fn.__name__, e))
    print("\n%d/%d passed" % (len(fns) - failed, len(fns)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
