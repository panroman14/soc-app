"""Encryption-at-rest for GUI-entered secrets (the Cloudflare API token).

Secrets typed into the dashboard are persisted in the pluggable STORE (file / sqlite /
configmap). Without this they sit in plaintext — anyone who can read the store file or
the ConfigMap reads the token. Here we encrypt them with a key that lives ONLY in the
environment (`SECRET_KEY`), so the store and the key are separated: a leaked store is
ciphertext, and the key never touches disk.

Stdlib-only (no `cryptography` dependency, keeps the image lean): an authenticated
stream cipher built from HMAC-SHA256 — a CTR keystream for confidentiality plus an
encrypt-then-MAC tag for integrity. `SECRET_KEY` is split into independent enc/mac
subkeys via HMAC (HKDF-style). Ciphertext is tagged `enc1:` so plaintext (pre-upgrade
values, or ENV defaults) is recognised and passed through untouched.

Opt-in + backward compatible: no `SECRET_KEY` → values are stored as-is (a startup
warning is logged elsewhere). Set `SECRET_KEY` and new writes are encrypted; existing
plaintext still reads fine and is re-encrypted on its next save.
"""
import base64
import hashlib
import hmac
import os

from . import config

_PREFIX = "enc1:"
_NONCE = 16
_TAG = 32


def enabled():
    return bool(config.SECRET_KEY)


def _subkeys():
    master = config.SECRET_KEY.encode("utf-8")
    enc = hmac.new(master, b"soc-secret-enc/v1", hashlib.sha256).digest()
    mac = hmac.new(master, b"soc-secret-mac/v1", hashlib.sha256).digest()
    return enc, mac


def _keystream(enc_key, nonce, n):
    out = bytearray()
    ctr = 0
    while len(out) < n:
        out += hmac.new(enc_key, nonce + ctr.to_bytes(8, "big"), hashlib.sha256).digest()
        ctr += 1
    return bytes(out[:n])


def is_encrypted(v):
    return isinstance(v, str) and v.startswith(_PREFIX)


def seal(value):
    """Encrypt a secret string for storage. No key configured → return unchanged.
    Already-encrypted or empty values pass through."""
    if not value or not isinstance(value, str) or is_encrypted(value) or not enabled():
        return value
    enc_key, mac_key = _subkeys()
    nonce = os.urandom(_NONCE)
    pt = value.encode("utf-8")
    ct = bytes(a ^ b for a, b in zip(pt, _keystream(enc_key, nonce, len(pt))))
    tag = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    return _PREFIX + base64.b64encode(nonce + ct + tag).decode("ascii")


def open_(value):
    """Decrypt a stored secret. Plaintext (no prefix) passes through. Raises ValueError
    on a bad key or tampered ciphertext (fail loud, never return garbage)."""
    if not is_encrypted(value):
        return value
    if not enabled():
        raise ValueError("secret is encrypted but SECRET_KEY is not set")
    try:
        blob = base64.b64decode(value[len(_PREFIX):])
    except Exception:
        raise ValueError("secret: malformed ciphertext")
    if len(blob) < _NONCE + _TAG:
        raise ValueError("secret: truncated ciphertext")
    nonce, ct, tag = blob[:_NONCE], blob[_NONCE:-_TAG], blob[-_TAG:]
    enc_key, mac_key = _subkeys()
    if not hmac.compare_digest(tag, hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()):
        raise ValueError("secret: authentication failed (wrong SECRET_KEY or tampered)")
    return bytes(a ^ b for a, b in zip(ct, _keystream(enc_key, nonce, len(ct)))).decode("utf-8")
