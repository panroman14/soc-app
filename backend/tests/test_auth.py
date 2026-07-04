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
    for u in [x["username"] for x in auth.list_users()]:
        auth.delete_user(u)
    auth._fails.clear()


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
