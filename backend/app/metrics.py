"""Render a summary dict as Prometheus exposition text.

Keeps the same metric names the standalone loki-ingress-exporter used, so the
existing Prometheus scrape job and alert rules keep working unchanged.
"""

_SCALARS = [
    ("loki_ingress_requests_5m", "requests_total"),
    ("loki_ingress_requests_real_5m", "requests_real"),
    ("loki_ingress_forbidden_5m", "forbidden_new"),
    ("loki_ingress_blocked_denylisted_5m", "blocked_denylisted"),
    ("loki_ingress_crs_detections_5m", "crs_detections"),
    ("loki_ingress_404_5m", "status_404"),
    ("loki_ingress_4xx_5m", "status_4xx"),
    ("loki_ingress_5xx_5m", "status_5xx"),
    ("loki_ingress_modsec_denied_5m", "modsec_denied"),
    ("loki_ingress_distinct_attacker_ips_5m", "distinct_attacker_ips"),
]


def render(summary, loki_up, path403=None):
    lines = []
    if summary:
        for metric, key in _SCALARS:
            lines.append("# TYPE %s gauge" % metric)
            lines.append("%s %s" % (metric, summary.get(key, 0)))
        lines.append("# TYPE loki_ingress_blocked_by_subnet_5m gauge")
        for s in summary.get("top_subnets", []):
            sub = s["subnet"].replace(".0/24", "")
            lines.append('loki_ingress_blocked_by_subnet_5m{subnet="%s"} %s' % (sub, s["count"]))
    # 403-path rules health (None until the first blocklist-api poll succeeds)
    if path403:
        lines.append("# TYPE loki_ingress_path403_rules gauge")
        lines.append("loki_ingress_path403_rules %d" % int(path403.get("count", 0)))
        lines.append("# TYPE loki_ingress_path403_rules_enabled gauge")
        lines.append("loki_ingress_path403_rules_enabled %d" % int(path403.get("enabled_count", 0)))
        lines.append("# TYPE loki_ingress_path403_master gauge")
        lines.append("loki_ingress_path403_master %d" % (1 if path403.get("enabled") else 0))
        lines.append("# TYPE loki_ingress_path403_rendered_ok gauge")
        lines.append("loki_ingress_path403_rendered_ok %d" % (1 if path403.get("rendered_ok") else 0))
        lines.append("# TYPE loki_ingress_path403_controller_reachable gauge")
        lines.append("loki_ingress_path403_controller_reachable %d" % (1 if path403.get("controller_reachable") else 0))
    lines.append("# TYPE loki_ingress_exporter_loki_up gauge")
    lines.append("loki_ingress_exporter_loki_up %d" % (1 if loki_up else 0))
    return "\n".join(lines) + "\n"
