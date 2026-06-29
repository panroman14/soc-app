"""Pluggable persistence for the denylist STATE (entries.json / audit.json /
path_rules.json). One interface, three backends, selected by config.STORE — so the
same blocklist-api runs unchanged in Kubernetes (ConfigMap) and on a plain VM
(file or sqlite). Enforcement (where bans are applied) is a SEPARATE concern; see
enforce.py.

Backends are document stores keyed by filename-like keys. `load(keys)` returns
{key: raw_str_or_None} (a missing document is None, not an error); `save(mapping)`
upserts only the given keys (others untouched), mirroring ConfigMap merge-patch.
"""
import json
import os
import sqlite3
import threading

from . import config

# Documents the store holds. ConfigMap is auto-created with these defaults so the
# Helm chart never has to manage (and risk resetting) the data.
DEFAULTS = {"entries.json": "[]", "audit.json": "[]"}


class Storage:
    def load(self, keys):
        raise NotImplementedError

    def save(self, mapping):
        raise NotImplementedError


class ConfigMapStorage(Storage):
    """k8s ConfigMap (in-cluster). The original behavior."""

    def __init__(self):
        from . import k8s
        self._k8s = k8s

    def load(self, keys):
        data = self._k8s.get_or_create_cm_data(config.DENYLIST_NS, config.DENYLIST_CM, DEFAULTS)
        return {k: data.get(k) for k in keys}

    def save(self, mapping):
        self._k8s.patch_cm_data(config.DENYLIST_NS, config.DENYLIST_CM, dict(mapping))


class FileStorage(Storage):
    """One JSON file per key under STORE_DIR. Atomic writes (tmp + os.replace)."""

    def __init__(self, dirpath):
        self._dir = dirpath
        self._lock = threading.Lock()
        os.makedirs(self._dir, exist_ok=True)

    def _path(self, key):
        # keys are fixed filename-like constants; guard against path escapes anyway
        return os.path.join(self._dir, os.path.basename(key))

    def load(self, keys):
        out = {}
        for k in keys:
            try:
                with open(self._path(k), "r", encoding="utf-8") as f:
                    out[k] = f.read()
            except FileNotFoundError:
                out[k] = DEFAULTS.get(k)
        return out

    def save(self, mapping):
        with self._lock:
            for k, v in mapping.items():
                p = self._path(k)
                tmp = p + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    f.write(v)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, p)


class SqliteStorage(Storage):
    """Single SQLite file, one row per key. WAL so reads never block the writer."""

    def __init__(self, path):
        self._path = path
        self._lock = threading.Lock()
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        with self._conn() as c:
            c.execute("CREATE TABLE IF NOT EXISTS docs (k TEXT PRIMARY KEY, v TEXT)")

    def _conn(self):
        c = sqlite3.connect(self._path, timeout=10)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=5000")
        return c

    def load(self, keys):
        with self._lock, self._conn() as c:
            rows = dict(c.execute("SELECT k, v FROM docs").fetchall())
        return {k: (rows.get(k) if rows.get(k) is not None else DEFAULTS.get(k)) for k in keys}

    def save(self, mapping):
        with self._lock, self._conn() as c:
            c.executemany("INSERT OR REPLACE INTO docs (k, v) VALUES (?, ?)",
                          list(mapping.items()))


_backend = None
_factory_lock = threading.Lock()


def get_backend():
    """Singleton store selected by config.STORE."""
    global _backend
    if _backend is None:
        with _factory_lock:
            if _backend is None:
                if config.STORE == "file":
                    _backend = FileStorage(config.STORE_DIR)
                elif config.STORE == "sqlite":
                    _backend = SqliteStorage(config.STORE_SQLITE)
                else:
                    _backend = ConfigMapStorage()
    return _backend
