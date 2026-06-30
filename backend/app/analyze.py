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


def _mad(vals, med):
    """Median Absolute Deviation — a robust (outlier-resistant) spread estimate.
    Used instead of stdev so a single past spike doesn't inflate the band and mask
    a real anomaly (or vice-versa)."""
    vals = [v for v in vals if v is not None]
    if not vals:
        return 0.0
    return statistics.median([abs(v - med) for v in vals])


def detect(latest, history):
    """Compare latest snapshot to a ROBUST rolling baseline of recent history.

    A field flags only when it clears its floor AND is a statistically significant
    outlier — both a ratio jump (≥3× median) AND a modified z-score (≥3.5) vs the
    baseline's own spread (MAD). Requiring significance, not just a ratio over a
    possibly-noisy median, cuts false alarms on naturally bursty metrics.

    Returns (severity, signals). severity: ok | notice | warning | critical
    """
    base = history[:-1] if len(history) > 1 else []
    signals = []
    score = 0

    for field, floor in FIELDS.items():
        cur = float(latest.get(field, 0) or 0)
        vals = [float(h.get(field, 0) or 0) for h in base]
        med = _median(vals) if vals else 0.0
        if cur < floor:
            continue
        ratio = cur / med if med >= 1 else cur
        # modified z-score (Iglewicz–Hoaglin): 0.6745·(x−median)/MAD, robust to spikes.
        # MAD=0 (flat baseline) → fall back to "any ratio≥3 over floor" so a first-ever
        # spike from a quiet baseline still fires.
        mad = _mad(vals, med)
        mz = 0.6745 * (cur - med) / mad if mad >= 1 else None
        cold = med < 1                       # essentially no baseline yet
        significant = cold or (ratio >= 3 and (mz is None or mz >= 3.5))
        if significant:
            sev = "high" if (ratio >= 6 or cur >= floor * 10 or (mz is not None and mz >= 8)) else "med"
            score += 2 if sev == "high" else 1
            signals.append({
                "field": field, "current": cur, "baseline": round(med, 1),
                "ratio": round(ratio, 1) if med >= 1 else None,
                "z": round(mz, 1) if mz is not None else None, "level": sev,
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
