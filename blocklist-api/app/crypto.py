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

Key derivation: the passphrase is stretched with PBKDF2-HMAC-SHA256 (`_KDF_ITERS`
iterations, fixed application salt) into the 32-byte Fernet key. Stretching makes an
offline dictionary attack on a weak/guessable `SECRET_KEY` far costlier — but still use
a long random value (`openssl rand -hex 32`); the salt is application-fixed (the store
holds no per-secret salt, since the Fernet key must be derivable from SECRET_KEY alone).
Ciphertext produced by the pre-stretching scheme (plain SHA-256 key) is still DECRYPTED
transparently — each passphrase contributes both a stretched and a legacy Fernet to the
MultiFernet, so upgrades are seamless and re-saving a secret moves it onto the new key.

Integrity vs a store-tamper attacker: once encryption is enabled every stored secret
MUST be `enc:`-tagged. `open_` REFUSES to read a plaintext secret when a key is set
(instead of trusting it), so an attacker who can write the store cannot downgrade
`enc:<ciphertext>` to an injected plaintext value — the substitution is rejected, and a
valid `enc:` token cannot be forged (Fernet AEAD). Plaintext passthrough survives only
when encryption is DISABLED (no key), for the pre-encryption backward-compatible path.

Opt-in: no `SECRET_KEY` → values are stored as-is (a startup warning is logged
elsewhere). Set `SECRET_KEY` and new writes are encrypted; a legacy plaintext secret
must be re-entered once in the GUI (which seals it).
"""
import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from . import config

_PREFIX = "enc:"
_LEGACY = "enc1:"     # superseded hand-rolled HMAC-CTR scheme (never released)

# PBKDF2 stretch: fixed application salt (the Fernet key must be a pure function of
# SECRET_KEY — no room for a per-secret random salt) + a high iteration count so a weak
# passphrase is expensive to brute-force offline against a leaked ciphertext.
_KDF_SALT = b"soc-blocklist-secretkey-v2"
_KDF_ITERS = 200_000

_key_cache = {}       # config.SECRET_KEY string -> MultiFernet (derivation is expensive)


def enabled():
    return bool(config.SECRET_KEY)


def _stretched_key(secret):
    dk = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), _KDF_SALT, _KDF_ITERS, 32)
    return base64.urlsafe_b64encode(dk)


def _legacy_key(secret):
    # pre-stretching derivation — kept so old ciphertext still decrypts
    return base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())


def _mf():
    """MultiFernet for the current SECRET_KEY. For each comma-separated passphrase we add
    the stretched Fernet (used to ENCRYPT for the first key) then its legacy Fernet — so
    the first key's stretched form encrypts new data, and everything (new + old scheme,
    all keys) decrypts. Cached: PBKDF2 is deliberately slow."""
    sk = config.SECRET_KEY
    mf = _key_cache.get(sk)
    if mf is None:
        fernets = []
        for k in (k.strip() for k in sk.split(",") if k.strip()):
            fernets.append(Fernet(_stretched_key(k)))
            fernets.append(Fernet(_legacy_key(k)))
        mf = MultiFernet(fernets)      # fernets[0] (stretched, first key) encrypts
        _key_cache[sk] = mf
    return mf


def is_encrypted(v):
    return isinstance(v, str) and v.startswith(_PREFIX)


def seal(value):
    """Encrypt a secret string for storage. No key configured → return unchanged.
    Already-encrypted or empty values pass through."""
    if not value or not isinstance(value, str) or is_encrypted(value) or not enabled():
        return value
    return _PREFIX + _mf().encrypt(value.encode("utf-8")).decode("ascii")


def open_(value):
    """Decrypt a stored secret. Raises ValueError on a bad key, tampered ciphertext, or a
    plaintext secret while encryption is enabled (fail loud, never trust unauthenticated
    data). Plaintext passes through ONLY when encryption is disabled (no key)."""
    if isinstance(value, str) and value.startswith(_LEGACY):
        raise ValueError("secret was encrypted with a superseded scheme — re-enter it in the GUI")
    if not is_encrypted(value):
        # Non-encrypted value. When a key IS set, a non-empty plaintext secret is either a
        # legacy value not yet re-saved OR a tamper/downgrade substitution — refuse it
        # rather than hand an unauthenticated value to enforcement (re-enter it in the GUI).
        if value and enabled():
            raise ValueError("secret is stored as plaintext but SECRET_KEY is set — "
                             "re-enter it in the GUI to encrypt it")
        return value
    if not enabled():
        raise ValueError("secret is encrypted but SECRET_KEY is not set")
    try:
        return _mf().decrypt(value[len(_PREFIX):].encode("ascii")).decode("utf-8")
    except InvalidToken:
        raise ValueError("secret: authentication failed (wrong SECRET_KEY or tampered)")
    except Exception as e:
        raise ValueError("secret: malformed ciphertext (%s)" % e)
