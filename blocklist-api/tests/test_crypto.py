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
    assert ct.startswith("enc:") and tok not in ct       # actually encrypted (Fernet)
    assert crypto.open_(ct) == tok


def test_nonce_differs():
    _key("k")
    a, b = crypto.seal("same"), crypto.seal("same")
    assert a != b                                         # random nonce per seal
    assert crypto.open_(a) == crypto.open_(b) == "same"


def test_plaintext_passthrough_only_when_disabled():
    _key("")                                                # encryption OFF → legacy passthrough
    assert crypto.open_("plain-legacy-token") == "plain-legacy-token"
    _key("k")
    assert crypto.seal("") == "" and crypto.seal(None) is None
    assert crypto.open_("") == ""                           # empty always ok


def test_plaintext_rejected_when_enabled():
    # once a key is set, a plaintext secret is a legacy-not-resaved OR a tamper/downgrade
    # substitution — open_ must refuse it, not hand it to enforcement.
    _key("k")
    try:
        crypto.open_("plain-or-injected-token")
        assert False, "plaintext secret must be rejected while SECRET_KEY is set"
    except ValueError:
        pass


def test_stretched_key_derivation():
    # new ciphertext must not be decryptable with the pre-stretching (plain sha256) key —
    # proves PBKDF2 stretching is actually in the encrypt path.
    import base64 as _b64, hashlib as _h
    from cryptography.fernet import Fernet as _F, InvalidToken as _IT
    _key("some-passphrase")
    ct = crypto.open_ and crypto.seal("secret")
    legacy = _F(_b64.urlsafe_b64encode(_h.sha256(b"some-passphrase").digest()))
    try:
        legacy.decrypt(ct[len("enc:"):].encode())
        assert False, "new ciphertext should not decrypt under the un-stretched key"
    except _IT:
        pass
    assert crypto.open_(ct) == "secret"                     # but the module reads it fine


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
    body = ct[len("enc:"):]
    tampered = "enc:" + body[:-2] + ("AA" if body[-2:] != "AA" else "BB")  # corrupt token tail
    try:
        crypto.open_(tampered)
        assert False, "expected auth failure on tamper"
    except ValueError:
        pass


def test_key_rotation():
    # new key prepended, old kept → old ciphertext still decrypts; new writes use new key
    _key("old-key")
    old_ct = crypto.seal("secret")
    _key("new-key,old-key")                               # MultiFernet: new encrypts, both decrypt
    assert crypto.open_(old_ct) == "secret"              # old ciphertext still readable
    new_ct = crypto.seal("secret")
    _key("new-key")                                       # drop old key
    assert crypto.open_(new_ct) == "secret"              # re-saved secret readable
    try:
        crypto.open_(old_ct); assert False, "old ct should fail once old key dropped"
    except ValueError:
        pass


def test_legacy_scheme_rejected():
    _key("k")
    try:
        crypto.open_("enc1:whatever")
        assert False, "legacy enc1: must be rejected, not returned as plaintext"
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
