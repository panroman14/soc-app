"""Lightweight, deterministic anomaly signals from snapshot history.

Python decides the HARD signal (what changed vs the recent baseline); the LLM
later turns it into a human narrative. Keeping the hard detection in code means
alerts/severity don't depend on the model behaving.
"""
import statistics

# fields to baseline + a floor so tiny absolute numbers don't trigger on ratio
FIELDS = {
    "forbidden_new": 200,
    "crs_detections": 50,
    "status_404": 300,
    "status_4xx": 500,
    "status_5xx": 50,
    "distinct_attacker_ips": 8,
}


def _median(vals):
    vals = [v for v in vals if v is not None]
    return statistics.median(vals) if vals else 0.0


def detect(latest, history):
    """Compare latest snapshot to median of recent history.

    Returns (severity, signals) where signals is a list of human-ish deltas.
    severity: ok | notice | warning | critical
    """
    base = history[:-1] if len(history) > 1 else []
    signals = []
    score = 0

    for field, floor in FIELDS.items():
        cur = float(latest.get(field, 0) or 0)
        med = _median([h.get(field, 0) for h in base]) if base else 0.0
        if cur < floor:
            continue
        # ratio vs baseline (guard divide-by-zero: treat 0 baseline as 1)
        ratio = cur / med if med >= 1 else cur
        if cur >= floor and (med < 1 or ratio >= 3):
            sev = "high" if (ratio >= 6 or cur >= floor * 10) else "med"
            score += 2 if sev == "high" else 1
            signals.append({
                "field": field, "current": cur, "baseline": round(med, 1),
                "ratio": round(ratio, 1) if med >= 1 else None, "level": sev,
            })

    mr = float(latest.get("malicious_ratio", 0) or 0)
    if mr >= 0.35 and float(latest.get("requests_real", 0) or 0) >= 2000:
        score += 2
        signals.append({"field": "malicious_ratio", "current": mr, "level": "high"})

    severity = "ok"
    if score >= 4:
        severity = "critical"
    elif score >= 2:
        severity = "warning"
    elif score >= 1:
        severity = "notice"

    # "forbidden_new" / "status_4xx"(403) / malicious_ratio describe traffic that is
    # being BLOCKED (attack repelled) — not a breach. Reserve CRITICAL for signals
    # that something is getting THROUGH to the app.
    through = {"crs_detections", "status_404", "status_5xx", "distinct_attacker_ips"}
    has_through = any(s["field"] in through for s in signals)
    if severity == "critical" and not has_through:
        severity = "warning"
    return severity, signals
