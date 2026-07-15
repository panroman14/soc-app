#!/usr/bin/env python3
"""Regression tests for the enrollment trust model + CF-target fail-open enumeration.
Runnable two ways:
    python blocklist-api/tests/test_enroll_enforce.py
    pytest blocklist-api/tests/test_enroll_enforce.py

Pins the audit fixes:
- re-enroll mints a FRESH token (no disclosure) and invalidates the old one (P2 / S4);
- an enrolled node's target_type is forced to nginx-file (S5);
- one undecryptable CF token must NOT drop the whole CF target list — enumeration goes
  through the non-decrypting public_view, decryption is fail-loud only on actual use
  (P2-R2 / S3).
"""
import os
import sys
import tempfile

_d = tempfile.mkdtemp()
os.environ["STORE"] = "file"
os.environ["STORE_DIR"] = _d
os.environ["BLOCKLIST_TOKEN"] = "t"
os.environ["SECRET_KEY"] = "unit-key-1"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import cf_targets, config, crypto, nodes   # noqa: E402


def test_reenroll_rotates_token():
    r1 = nodes.enroll(node_id="web1", hostname="h1")
    t1 = r1["token"]
    r2 = nodes.enroll(node_id="web1", hostname="h1")   # same id again
    t2 = r2["token"]
    assert t1 and t2 and t1 != t2                       # fresh token, not the old one
    assert nodes.token_owner(t2) == "web1"              # new token valid
    assert nodes.token_owner(t1) is None                # old token invalidated


def test_enrolled_target_type_forced_nginx_file():
    r = nodes.enroll(node_id="web2", target_type="ingress-cm")   # tries to self-elevate
    assert r["target_type"] == "nginx-file"
    assert nodes.get("web2")["target_type"] == "nginx-file"


def test_cf_enumeration_survives_one_bad_token():
    # store two CF targets, both sealed under the current key
    cf_targets.upsert("good", {"name": "Good", "token": "cf-token-A", "mode": "ip-list"})
    cf_targets.upsert("bad", {"name": "Bad", "token": "cf-token-B", "mode": "ip-list"})
    # now the 'bad' entry becomes undecryptable: simulate a key rotation that dropped the
    # key 'bad' was sealed under (wrong key now).
    config.SECRET_KEY = "unit-key-2"
    crypto._key_cache.clear()
    cf_targets._cache["d"] = None            # force reload from store

    ids = {t["id"] for t in cf_targets.public_view()}
    assert {"good", "bad"} <= ids            # enumeration does NOT drop targets (no decrypt)
    assert all(t["token_set"] for t in cf_targets.public_view())

    # actual USE is fail-loud, per-target: get() raises for both (wrong key), never
    # silently returns a garbage/empty token.
    for tid in ("good", "bad"):
        try:
            cf_targets.get(tid)
            assert False, "expected fail-loud decryption error for %s" % tid
        except ValueError:
            pass


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
