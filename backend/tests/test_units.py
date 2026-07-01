#!/usr/bin/env python3
"""Unit tests for the pure fan-out / LogQL / egress logic — the fleet's correctness
core. Runnable two ways:
    python backend/tests/test_units.py     # no pytest needed (CI uses this)
    pytest backend/tests/test_units.py
Covers the invariants behind the P0-P2 fixes and the ROADMAP-2 P0-quick/X3 fixes so
they can't silently regress.
"""
import os
import sys

os.environ.setdefault("DB_PATH", "/tmp/soc_test_units.db")
os.environ.setdefault("BLOCKLIST_API_URL", "")
os.environ.setdefault("LOKI_URL", "http://127.0.0.1:1")
os.environ.setdefault("SOC_DEV_NO_AUTH", "1")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import app.main as m      # noqa: E402
import app.loki as L      # noqa: E402


# ── _parse_omnibar ────────────────────────────────────────────────────────────
def test_omnibar_status_ranges():
    def chip0(q):
        c = m._parse_omnibar(q)["chips"]
        return c[0] if c else None
    assert chip0("status:4xx") == {"field": "status", "op": "class", "value": "4"}
    assert chip0("status:>=400") == {"field": "status", "op": "class", "value": "45"}
    assert chip0("status:>=500") == {"field": "status", "op": "class", "value": "5"}
    assert chip0("status:<400") == {"field": "status", "op": "class", "value": "1234"}
    assert chip0("status:400") == {"field": "status", "op": "eq", "value": "400"}


def test_omnibar_ops_and_freetext():
    p = m._parse_omnibar('method:POST -country:US rt:>1.5 login attacks')
    assert {"field": "method", "op": "eq", "value": "POST"} in p["chips"]
    assert {"field": "country", "op": "neq", "value": "US"} in p["chips"]
    assert {"field": "rt", "op": "gte", "value": "1.5"} in p["chips"]
    assert p["search"] == "login"
    assert p["attacks_only"] is True


def test_omnibar_unbalanced_quotes_dont_raise():
    p = m._parse_omnibar('path:"/a b status:5xx')   # missing closing quote
    assert isinstance(p["chips"], list)             # falls back to .split(), no crash


def test_omnibar_never_reaches_raw():
    # an omnibar body must become escaped chips, never raw LogQL passthrough
    q = m._logql_from_body({"omnibar": "path:/x method:GET"})
    assert "| path=" in q and "| method=" in q


# ── LogQL builder / escaping ──────────────────────────────────────────────────
def test_chip_escaping_blocks_injection():
    c = L._chip_clause("path", "eq", 'a" | line_format "pwned')
    assert c == '| path="a\\" | line_format \\"pwned"'   # quote escaped, not a break-out
    assert L._chip_clause("ua", "re", ".*(x|y)") == '| ua=~"\\.\\*\\(x\\|y\\)"'


def test_status_class_multidigit():
    assert L._chip_clause("status", "class", "4") == '| status=~"4.."'
    assert L._chip_clause("status", "class", "45") == '| status=~"[45].."'


def test_raw_is_gated_passthrough():
    # raw wins verbatim (documented power-user escape hatch) — asserts the branch exists
    assert L.build_logql(raw='{app="x"} |= "y"') == '{app="x"} |= "y"'
    # structured path escapes the search term
    q = L.build_logql(search='he"llo')
    assert '|= "he\\"llo"' in q


def test_raw_requires_stream_selector():
    # X1: raw with no / empty selector is rejected (can't read every stream)
    for bad in ["", "  ", "| json", "{} |= \"x\"", "{ } | json"]:
        try:
            L.build_logql(raw=bad)
            if bad.strip():                 # empty raw is fine (falls through to structured)
                assert False, "expected reject for %r" % bad
        except ValueError:
            pass


# ── _egress_check (SSRF guard) ────────────────────────────────────────────────
def test_egress_blocks_metadata_and_scheme():
    assert m._egress_check("http://169.254.169.254/latest")[0] is False   # link-local
    assert m._egress_check("ftp://example.com")[0] is False               # scheme
    assert m._egress_check("http://127.0.0.1", allow_internal=False)[0] is False
    assert m._egress_check("http://10.0.0.5:8080", allow_internal=True)[0] is True


# ── _route_for (X3 fail-closed) ───────────────────────────────────────────────
def _fleet(ids):
    m._backends = lambda scope=None: [(i, "u", "") for i in ids]


def test_route_for_broadcast_and_resolve():
    _fleet(["a", "b"])
    m._targets_index = lambda scope=None: ({"t1": ["a"]}, {"g1": ["b"]})
    assert set(m._route_for({})) == {"a", "b"}                    # no attachment → all
    assert set(m._route_for({"all": True})) == {"a", "b"}         # all → all
    assert m._route_for({"groups": ["g1"]}) == ["b"]             # resolves to owner
    assert m._route_for({"targets": ["t1"]}) == ["a"]


def test_route_for_fail_closed_on_fleet():
    _fleet(["a", "b"])
    m._targets_index = lambda scope=None: ({}, {})
    assert m._route_for({"groups": ["ghost"]}) == []             # unresolved on fleet → []
    _fleet(["only"])
    assert m._route_for({"groups": ["ghost"]}) == ["only"]       # single backend → broadcast


# ── _write_fanout (aggregation, dedup, max, partial, type-mix) ────────────────
def test_backends_registry_only_ignores_env():
    # the registry is the single source of truth — env BLOCKLIST_API_URL must NOT be
    # injected into the fleet at call time (it is seeded once at startup instead).
    os.environ["BLOCKLIST_API_URL"] = "http://orig:8080"
    os.environ["BLOCKLIST_API_TOKEN"] = "tok"
    m.config.BLOCKLIST_API_URL = "http://c2:8080"
    m._ing_apis = lambda: {"items": {"c2": {"url": "http://c2:8080", "token": "t"}}, "scope": "__all__"}
    urls = {b[1] for b in m._backends("__all__")}
    assert urls == {"http://c2:8080"}                  # only the registry, no env ghost


def test_seed_registry_from_env():
    # first boot with an empty registry + env URL → migrate it in as 'default' once.
    store = {}
    m.db.setting_get = lambda k, d=None: store.get(k, d)
    m.db.setting_set = lambda k, v: store.__setitem__(k, v)
    m._ing_apis = lambda: store.get("ingress_apis", {"items": {}, "active": ""})
    m._ing_apis_save = lambda v: store.__setitem__("ingress_apis", v)
    os.environ["BLOCKLIST_API_URL"] = "http://seed:8080"
    os.environ["BLOCKLIST_API_TOKEN"] = "stok"
    m._seed_registry_from_env()
    d = store["ingress_apis"]
    assert d["items"]["default"] == {"url": "http://seed:8080", "token": "stok"}
    assert d["active"] == "default" and d["seeded"] is True
    # idempotent: a second call (e.g. after the user deleted 'default') re-seeds nothing
    store["ingress_apis"] = {"items": {}, "active": "", "seeded": True}
    m._seed_registry_from_env()
    assert store["ingress_apis"]["items"] == {}        # stays deleted, not resurrected


def _bcall_seq(pairs):
    it = iter(pairs)
    m._bcall_to = lambda url, tok, me, pa, pl=None, timeout=15: next(it)


def test_write_fanout_single_verbatim():
    _fleet(["a"])
    _bcall_seq([(200, {"cidr": "1.1.1.1", "active": 7})])
    st, out = m._write_fanout("POST", "/block", {}, ["a"])
    assert st == 200 and out == {"cidr": "1.1.1.1", "active": 7}   # single → verbatim


def test_write_fanout_union_and_max():
    _fleet(["a", "b"])
    _bcall_seq([(200, {"blocked": ["1.1.1.1"], "active": 50}),
                (200, {"blocked": ["1.1.1.1", "2.2.2.2"], "active": 50})])
    st, out = m._write_fanout("POST", "/block_bulk", {}, ["a", "b"])
    assert st == 200 and out["ok"] is True
    assert out["blocked"] == ["1.1.1.1", "2.2.2.2"]               # union-deduped (Q2)
    assert out["active"] == 50                                    # max, not 100 (Q3)


def test_write_fanout_partial_502():
    _fleet(["a", "b"])
    _bcall_seq([(200, {"blocked": ["1.1.1.1"]}), (502, {"error": "down"})])
    st, out = m._write_fanout("POST", "/block_bulk", {}, ["a", "b"])
    assert st == 502 and out["ok"] is False and out.get("partial") is True


def test_write_fanout_type_mix_no_crash():
    _fleet(["a", "b"])
    _bcall_seq([(200, {"active": 50}), (200, {"active": [1, 2]})])
    st, out = m._write_fanout("POST", "/x", {}, ["a", "b"])       # int then list — no crash (C5)
    assert st == 200


def test_write_fanout_empty_ids_errors():
    _fleet(["a"])
    st, out = m._write_fanout("POST", "/x", {}, [])
    assert out["ok"] is False


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
