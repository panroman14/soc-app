"""Encryption-at-rest for GUI-entered secrets (the Cloudflare API token).

Secrets typed into the dashboard are persisted in the pluggable STORE (file / sqlite /
configmap). Without this they sit in plaintext — anyone who can read the store file or
the ConfigMap reads the token. Here we encrypt them with a key that lives ONLY in the
environment (`SECRET_KEY`), so the store and the key are separated: a leaked store is
ciphertext, and the key never touches disk.

Uses **Fernet** (AES-128-CBC + HMAC-SHA256, authenticated) from the audited
`cryptography` library — not a hand-rolled construction. Ciphertext is tagged `enc:`
so plaintext (pre-upgrade values, or ENV defaults) is recognised and passed through.

Key rotation: `SECRET_KEY` may hold several comma-separated keys — the FIRST encrypts,
ALL decrypt (MultiFernet). To rotate: prepend a new key, keep the old one until every
stored secret has been re-saved (which re-encrypts under the new key), then drop it.

Any string works as a key (it's hashed to a 32-byte Fernet key), but use a long random
value — `openssl rand -hex 32`. There is no password stretching, so a weak/guessable
`SECRET_KEY` is brute-forceable.

Opt-in + backward compatible: no `SECRET_KEY` → values are stored as-is (a startup
warning is logged elsewhere). Set `SECRET_KEY` and new writes are encrypted; existing
plaintext still reads fine and is re-encrypted on its next save.
"""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from . import config

_PREFIX = "enc:"
_LEGACY = "enc1:"     # superseded hand-rolled HMAC-CTR scheme (never released)


def enabled():
    return bool(config.SECRET_KEY)


def _fernet_key(secret):
    # accept any string; derive a stable urlsafe-base64 32-byte Fernet key from it
    return base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())


def _mf():
    keys = [k.strip() for k in config.SECRET_KEY.split(",") if k.strip()]
    return MultiFernet([Fernet(_fernet_key(k)) for k in keys])   # 1st encrypts, all decrypt


def is_encrypted(v):
    return isinstance(v, str) and v.startswith(_PREFIX)


def seal(value):
    """Encrypt a secret string for storage. No key configured → return unchanged.
    Already-encrypted or empty values pass through."""
    if not value or not isinstance(value, str) or is_encrypted(value) or not enabled():
        return value
    return _PREFIX + _mf().encrypt(value.encode("utf-8")).decode("ascii")


def open_(value):
    """Decrypt a stored secret. Plaintext (no prefix) passes through. Raises ValueError
    on a bad key or tampered ciphertext (fail loud, never return garbage)."""
    if isinstance(value, str) and value.startswith(_LEGACY):
        raise ValueError("secret was encrypted with a superseded scheme — re-enter it in the GUI")
    if not is_encrypted(value):
        return value
    if not enabled():
        raise ValueError("secret is encrypted but SECRET_KEY is not set")
    try:
        return _mf().decrypt(value[len(_PREFIX):].encode("ascii")).decode("utf-8")
    except InvalidToken:
        raise ValueError("secret: authentication failed (wrong SECRET_KEY or tampered)")
    except Exception as e:
        raise ValueError("secret: malformed ciphertext (%s)" % e)
