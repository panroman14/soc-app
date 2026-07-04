"""Unit tests for encryption-at-rest of GUI secrets (app/crypto.py).

Run: blocklist-api/.venv/bin/python blocklist-api/tests/test_crypto.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import config, crypto  # noqa: E402


def _key(k):
    config.SECRET_KEY = k


def test_roundtrip():
    _key("test-key-123")
    tok = "cf_abc123-TOKEN.with/special+chars=="
    ct = crypto.seal(tok)
    assert ct.startswith("enc1:") and tok not in ct      # actually encrypted
    assert crypto.open_(ct) == tok


def test_nonce_differs():
    _key("k")
    a, b = crypto.seal("same"), crypto.seal("same")
    assert a != b                                         # random nonce per seal
    assert crypto.open_(a) == crypto.open_(b) == "same"


def test_plaintext_passthrough():
    _key("k")
    assert crypto.open_("plain-legacy-token") == "plain-legacy-token"   # no prefix → as-is
    assert crypto.seal("") == "" and crypto.seal(None) is None


def test_disabled_no_key_stores_plaintext():
    _key("")
    assert crypto.seal("tok") == "tok"                    # no key → unchanged
    assert not crypto.enabled()


def test_double_seal_is_noop():
    _key("k")
    once = crypto.seal("tok")
    assert crypto.seal(once) == once                      # already-encrypted passes through


def test_wrong_key_fails():
    _key("right")
    ct = crypto.seal("secret")
    _key("wrong")
    try:
        crypto.open_(ct)
        assert False, "expected auth failure with wrong key"
    except ValueError:
        pass


def test_tamper_detected():
    _key("k")
    ct = crypto.seal("secret")
    import base64
    blob = bytearray(base64.b64decode(ct[len("enc1:"):]))
    blob[-1] ^= 0x01                                       # flip a tag bit
    tampered = "enc1:" + base64.b64encode(bytes(blob)).decode()
    try:
        crypto.open_(tampered)
        assert False, "expected auth failure on tamper"
    except ValueError:
        pass


def test_encrypted_but_no_key_raises():
    _key("k")
    ct = crypto.seal("secret")
    _key("")
    try:
        crypto.open_(ct)
        assert False, "expected error decrypting without key"
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
