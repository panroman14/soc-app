#!/usr/bin/env python3
"""HTTP-layer security regression tests (CSRF, rate-limit, role gate, session
revocation). Runnable two ways:
    python backend/tests/test_web_security.py     # no pytest needed (CI uses this)
    pytest backend/tests/test_web_security.py

These pin the behaviour behind the audit fixes so a refactor of the middleware /
endpoints can't silently reopen them — in particular the CSRF netloc check (a first-pass
`startswith` regression), the judge-ip/ip-profile throttle, the admin gate on the node
install command, and real logout revocation.
"""
import os
import sys
import tempfile

# auth ON (no DEV bypass); creds seed the first admin; isolated DB + no external deps.
os.environ["SOC_DEV_NO_AUTH"] = "0"
os.environ["BASIC_AUTH_USER"] = "admin"
os.environ["BASIC_AUTH_PASS"] = "supersecret1"
os.environ["BLOCKLIST_API_URL"] = ""
os.environ["LOKI_URL"] = "http://127.0.0.1:1"
os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "web-sec-test.db")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient           # noqa: E402
from app.main import app                            # noqa: E402
from app import auth, db                            # noqa: E402

db.init()
auth.init()
if not auth.get_user("admin"):
    auth.create_user("admin", "supersecret1", role="admin")
if not auth.get_user("viewer1"):
    auth.create_user("viewer1", "viewerpass1", role="viewer")

_H = {"Origin": "http://testserver", "Host": "testserver"}


def _login(u, p):
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"username": u, "password": p}, headers=_H)
    assert r.status_code == 200, r.text
    return c


def test_login_and_fail_closed():
    c = TestClient(app)
    assert c.get("/api/health").status_code == 200
    assert c.get("/api/summary").status_code == 401         # unauth API fails closed


def test_csrf_netloc_equality_not_prefix():
    c = _login("admin", "supersecret1")
    # legit same-origin (Origin) → allowed
    assert c.post("/api/auth/totp/setup",
                  headers={"Origin": "http://testserver", "Host": "testserver"}).status_code == 200
    # legit via Referer fallback → allowed
    assert c.post("/api/auth/totp/setup",
                  headers={"Referer": "http://testserver/x", "Host": "testserver"}).status_code == 200
    # lookalike suffix must be REJECTED (the startswith-regression case)
    assert c.post("/api/auth/totp/setup",
                  headers={"Origin": "http://testserver.evil.net", "Host": "testserver"}).status_code == 403
    assert c.post("/api/auth/totp/setup",
                  headers={"Referer": "http://testserver.evil.net/x", "Host": "testserver"}).status_code == 403


def test_csrf_headerless_allowed():
    # no Origin/Referer at all → allowed (SameSite=Strict covers cross-site)
    c = _login("admin", "supersecret1")
    assert c.post("/api/auth/totp/setup", headers={"Host": "testserver"}).status_code == 200


def test_rate_limit_kicks_in():
    c = _login("admin", "supersecret1")
    codes = [c.get("/api/ip_profile", params={"ip": "1.2.3.4"}).status_code for _ in range(34)]
    assert 429 in codes, codes                              # throttled after the window limit


def test_nodes_install_admin_only():
    assert _login("viewer1", "viewerpass1").get("/api/nodes/install").status_code == 403
    assert _login("admin", "supersecret1").get("/api/nodes/install").status_code != 403


def test_logout_revokes_session_serverside():
    c = _login("admin", "supersecret1")
    tok = c.cookies.get("soc_session")
    assert c.get("/api/auth/me").status_code == 200
    c.post("/api/auth/logout", headers=_H)
    # replay the captured cookie on a fresh client → must be rejected (epoch bumped)
    raw = TestClient(app)
    raw.cookies.set("soc_session", tok)
    assert raw.get("/api/auth/me").status_code == 401


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print("  ok  %s" % fn.__name__)
        except Exception as e:
            failed += 1
            print("  FAIL %s: %r" % (fn.__name__, e))
    print("\n%d/%d passed" % (len(fns) - failed, len(fns)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run_all())
