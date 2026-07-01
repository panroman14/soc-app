"""Structured logging (O2) + request-id propagation (O4).

Replaces scattered print() with level-controlled, greppable logs that carry a
request id. LOG_LEVEL (default INFO) and LOG_FORMAT (logfmt|json, default logfmt)
are env-controlled. The request id lives in a contextvar set by the request-id
middleware; a logging.Filter stamps it onto every record.
"""
import contextvars
import json
import logging
import os
import sys

_rid = contextvars.ContextVar("rid", default="-")


def set_rid(v):
    _rid.set(v or "-")


def get_rid():
    return _rid.get()


class _RidFilter(logging.Filter):
    def filter(self, record):
        record.rid = _rid.get()
        return True


class _JsonFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname, "logger": record.name,
            "rid": getattr(record, "rid", "-"), "msg": record.getMessage(),
        }, ensure_ascii=False)


_configured = False


def setup():
    """Idempotent: configure the root logger once and return the app logger."""
    global _configured
    if not _configured:
        handler = logging.StreamHandler(sys.stdout)
        handler.addFilter(_RidFilter())
        if os.environ.get("LOG_FORMAT", "logfmt").lower() == "json":
            handler.setFormatter(_JsonFormatter())
        else:
            handler.setFormatter(logging.Formatter(
                "%(asctime)s %(levelname)s rid=%(rid)s %(name)s: %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S"))
        root = logging.getLogger()
        root.handlers[:] = [handler]
        root.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())
        _configured = True
    return logging.getLogger("soc")
