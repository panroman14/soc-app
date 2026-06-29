"""LLM insight layer — turns an aggregated summary + anomaly signals into a
plain-language verdict via Gemma (Ollama). Robust to non-JSON model output.
"""
import json
import re
import urllib.request

from . import config, db


class LLMDisabled(Exception):
    """Raised when the operator has turned the LLM off via the dashboard toggle."""


def enabled():
    """Master on/off switch (persisted in app_settings). Default ON."""
    return bool(db.setting_get("llm_enabled", True))


def base_url():
    """LLM endpoint — GUI override (app_settings) over the LLM_URL env default."""
    return (db.setting_get("llm_url", "") or config.LLM_URL).rstrip("/")


def model():
    """LLM model — GUI override over the LLM_MODEL env default."""
    return db.setting_get("llm_model", "") or config.LLM_MODEL

SYSTEM = (
    "Ты SOC-аналитик трафика веб-сайта. На вход — агрегаты логов ingress за "
    "окно и сигналы аномалий (уже посчитаны кодом, забаненные подсети исключены). "
    "Дай короткий разбор на русском. Отвечай СТРОГО одним JSON-объектом без markdown:\n"
    '{"severity":"ok|notice|warning|critical","headline":"<кратко>",'
    '"summary":"<2-4 предложения: что происходит>",'
    '"attention":["<на что обратить внимание>"],'
    '"actions":["<что сделать>"]}'
)


def _prompt(summary, severity, signals):
    return (
        "Окно: %s\n"
        "Всего запросов: %s, реальных(без забаненных): %s\n"
        "Заблокировано новых: %s, из уже-забаненных: %s\n"
        "404: %s, 4xx: %s, 5xx: %s\n"
        "CRS payload-срабатываний: %s, ModSecurity denied: %s\n"
        "Разных атакующих IP (новых): %s\n"
        "Доля вредного трафика: %s\n"
        "Топ подсетей: %s\n"
        "Код оценил серьёзность как: %s\n"
        "Сигналы аномалий: %s\n"
    ) % (
        summary.get("window"), summary.get("requests_total"), summary.get("requests_real"),
        summary.get("forbidden_new"), summary.get("blocked_denylisted"),
        summary.get("status_404"), summary.get("status_4xx"), summary.get("status_5xx"),
        summary.get("crs_detections"), summary.get("modsec_denied"),
        summary.get("distinct_attacker_ips"), summary.get("malicious_ratio"),
        json.dumps(summary.get("top_subnets", []), ensure_ascii=False),
        severity, json.dumps(signals, ensure_ascii=False),
    )


def _call(messages, timeout=120, num_predict=400):
    if not enabled():
        raise LLMDisabled("LLM отключён оператором")
    body = json.dumps({
        "model": model(),
        "messages": messages,
        "stream": False,
        # cap output length (faster, fewer timeouts) + keep model warm between calls
        "options": {"temperature": 0.2, "num_predict": num_predict},
        "keep_alive": "30m",
    }).encode()
    req = urllib.request.Request(
        base_url() + "/api/chat", data=body,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)["message"]["content"]


def _parse(text, fallback_severity):
    m = re.search(r"\{.*\}", text, re.S)
    if m:
        try:
            obj = json.loads(m.group(0), strict=False)  # tolerate control chars in strings
            obj.setdefault("severity", fallback_severity)
            return obj
        except Exception:
            pass
    return {"severity": fallback_severity, "headline": "Разбор трафика",
            "summary": text.strip()[:600], "attention": [], "actions": []}


def analyze(summary, severity, signals):
    """Return an insight dict. Falls back gracefully if the LLM is unreachable.

    Sets insight["llm_ok"] (+ "llm_error") so the API/dashboard can flag LLM health.
    """
    try:
        raw = _call([{"role": "system", "content": SYSTEM},
                     {"role": "user", "content": _prompt(summary, severity, signals)}])
        insight = _parse(raw, severity)
        insight["llm_ok"] = True
        insight["llm_error"] = None
    except LLMDisabled:
        # not an error — the operator turned the LLM off; keep code-side severity
        insight = {"severity": severity, "headline": "AI-разбор выключен",
                   "summary": "LLM отключён оператором — показываются только метрики (без разбора модели).",
                   "attention": [], "actions": [],
                   "llm_ok": None, "llm_error": None, "llm_disabled": True}
    except Exception as e:
        insight = {"severity": severity, "headline": "LLM недоступен",
                   "summary": "Не удалось получить разбор от модели: %s" % e,
                   "attention": [], "actions": [],
                   "llm_ok": False, "llm_error": str(e)}
    insight["signals"] = signals
    insight["llm_severity"] = insight.get("severity")
    # final severity = max(code, llm) — code is the safety net
    insight["severity"] = _max_sev(severity, insight.get("severity", severity))
    return insight


def digest(daily_stats):
    """Structured period digest. Returns {overview, attacks[], recommendations[]}."""
    sys_p = ("Ты SOC-аналитик веб-сайта. По агрегатам за период дай сводку на русском. "
             "Ответь СТРОГО одним JSON-объектом без markdown:\n"
             '{"overview":"<2-3 предложения: общая картина трафика и тренд>",'
             '"attacks":["<кратко про замеченную атаку/скан/аномалию>"],'
             '"recommendations":["<конкретное действие>"]}\n'
             "Не выдумывай числа — бери из данных. Если атак нет — пустой список attacks.")
    try:
        raw = _call([{"role": "system", "content": sys_p},
                     {"role": "user", "content": "Агрегаты за период:\n" + json.dumps(daily_stats, ensure_ascii=False)}],
                    timeout=240)
        m = re.search(r"\{.*\}", raw, re.S)
        obj = json.loads(m.group(0), strict=False) if m else {}
        if not isinstance(obj, dict):
            obj = {}
        obj.setdefault("overview", raw.strip()[:600] if not m else "")
        obj.setdefault("attacks", [])
        obj.setdefault("recommendations", [])
        if not isinstance(obj.get("attacks"), list):
            obj["attacks"] = []
        if not isinstance(obj.get("recommendations"), list):
            obj["recommendations"] = []
        return obj
    except Exception as e:
        return {"overview": "Не удалось сгенерировать дайджест: %s" % e,
                "attacks": [], "recommendations": []}


def suggest_rules(summary, analytics):
    """Suggest concrete deny / WAF rules from current attack data. Returns JSON-ish text."""
    sys_p = ("Ты инженер по безопасности ingress-nginx + ModSecurity. По данным об атаке "
             "предложи КОНКРЕТНЫЕ правила защиты. Ответь JSON без markdown: "
             '{"deny":["<CIDR для denylist-source-range>"],'
             '"waf":["<строки ModSecurity SecRule или ctl>"],'
             '"rationale":"<кратко почему>"}. Если данных мало — пустые списки.')
    ctx = {
        "top_subnets": summary.get("top_subnets", []),
        "attack_types": analytics.get("attack_types", []),
        "top_paths": analytics.get("top_paths", [])[:8],
        "top_user_agents": analytics.get("top_user_agents", [])[:6],
        "forbidden_new": summary.get("forbidden_new"),
        "crs_detections": summary.get("crs_detections"),
    }
    try:
        raw = _call([{"role": "system", "content": sys_p},
                     {"role": "user", "content": json.dumps(ctx, ensure_ascii=False)}])
        m = re.search(r"\{.*\}", raw, re.S)
        obj = json.loads(m.group(0), strict=False) if m else {}
        if not isinstance(obj, dict):
            obj = {}
        obj.setdefault("deny", [])
        obj.setdefault("waf", [])
        obj.setdefault("rationale", raw.strip()[:400] if not m else "Модель не дала пояснения.")
        return obj
    except Exception as e:
        return {"deny": [], "waf": [], "rationale": "Ошибка генерации: %s" % e}


def judge_suspects(items, num_predict=900, timeout=180):
    """Per-IP verdict for suspicious IPs. items: [{ip,count,country,paths,isp,asn,hosting,proxy,reputation}].
    Returns list of {ip, kind, ban, confidence, reason}."""
    sys_p = ("Ты SOC-аналитик веб-сайта. Дан список IP с подозрительной "
             "активностью (много ошибок 4xx). Для КАЖДОГО реши, кто это и надо ли банить. "
             "Учитывай: число ошибок, какие пути, страна, ISP/ASN, флаги hosting/proxy, репутация. "
             "Легит: реальные люди, Googlebot/Bing/FB/боты соцсетей. Вредонос: датацентр/VPN, перебор "
             "путей, явный скан. Поле ptr — это reverse-DNS хоста: если он из домена поисковика/соцсети "
             "(googlebot.com, msn, yandex и т.п.) — это легит-бот. SEO-краулеры (ahrefs, semrush, mj12) — "
             "не вредонос, но можно банить как назойливых. Ответь СТРОГО JSON без markdown:\n"
             '{"verdicts":[{"ip":"<ip>","kind":"user|legit-bot|scanner|malicious",'
             '"ban":true|false,"confidence":"low|med|high","reason":"<кратко по-русски>"}]}')
    try:
        raw = _call([{"role": "system", "content": sys_p},
                     {"role": "user", "content": json.dumps(items, ensure_ascii=False)}],
                    timeout=timeout, num_predict=num_predict)
        m = re.search(r"\{.*\}", raw, re.S)
        obj = json.loads(m.group(0), strict=False) if m else {}
        v = obj.get("verdicts") if isinstance(obj, dict) else None
        return v if isinstance(v, list) else []
    except Exception:
        return []


def nl_to_filters(question):
    """Natural-language query -> safe explorer filters (no raw LogQL from the model)."""
    sys_p = ("Преобразуй вопрос о логах ingress в JSON-фильтры. Только эти поля: "
             '{"host":"","path":"","status":"","ip":"","minutes":60}. '
             "status — код или префикс (4,5,404). minutes — окно в минутах (по умолчанию 60). "
             "Пустые поля опускай. Ответь ТОЛЬКО JSON, без пояснений.")
    try:
        raw = _call([{"role": "system", "content": sys_p},
                     {"role": "user", "content": question}], timeout=60)
        m = re.search(r"\{.*\}", raw, re.S)
        obj = json.loads(m.group(0), strict=False) if m else {}
        out = {}
        for k in ("host", "path", "status", "ip"):
            if obj.get(k):
                out[k] = str(obj[k])[:80]
        try:
            out["minutes"] = max(1, min(1440, int(obj.get("minutes", 60))))
        except Exception:
            out["minutes"] = 60
        return out
    except Exception as e:
        return {"error": str(e), "minutes": 60}


_ORDER = {"ok": 0, "notice": 1, "warning": 2, "critical": 3}


def _max_sev(a, b):
    a = a if a in _ORDER else "ok"
    b = b if b in _ORDER else "ok"
    return a if _ORDER[a] >= _ORDER[b] else b
