# SOC-app — Роадмапа v2 (после P0–P2)

> Составлено 2026-07-01 по итогам второго аудита в 3 потока (security re-audit · баги нового кода · архитектура/forward).
> Предыдущий роадмап ([ROADMAP.md](ROADMAP.md)) — P0/P1/P2 закрыты. Это следующая волна.
> Документ, кода не меняли. Ссылки `файл:строка` — на момент аудита, перед правкой сверять.

> **Прогресс (2026-07-01):** ✅ **вся in-repo часть ROADMAP-2 закрыта и запушена.**
> **P0-quick** Q1–Q5 (`e7cf19b`) · **X3**+**O1** (`ae7af70`) · **C1** (`eafda34`) · **X1/X2** (`2a4cd2e`) ·
> **Pf2/Pf3** (`a2aa2d3`) · **C2/C3/Pf1** (`214b27c`) · **O3/D3** (`4f384aa`) · **O2/O4** structured-logging+request-id (`594518d`) ·
> **Pf4/C4** audit-limit+ns-cursor (`abe9f69`). **C5** в Q-batch.
> Осталось (крупное / вне репо): **D1/D2** lockfiles+digest-pin (нужен реестр/сеть), **F1–F6** фичи
> (WS live-tail, absolute time-range, fleet-alerting rules, RBAC+audit действий, notifications-completeness, backup/restore) —
> требуют живой инфры / продуктовых решений.

## 0. Что уже крепко (не переделывать)
Аудит **подтвердил**, что все фиксы сессии держатся: fail-closed auth (оба сервиса + чарт), `_egress_check` (wired во все URL-входы), CSRF/CSP/заголовки, middleware-порядок (auth→security→no-cache), LogQL-escaping в структурном пути, `escJs()` (единственное косметическое исключение — ниже), Logs v2 auth, `_write_fanout` partial→502, CIDR-dedup в `/api/blocklist`. Плюс **обнаружено**: в репо уже есть CI (`.github/workflows/ci.yml`) + e2e smoke-тест (`tests/smoke.sh`, покрывает blocklist-api).

### Матрица приоритетов v2
| P | Тема | Пункты |
|---|------|--------|
| **P0-quick** | Регрессии моей же сессии — быстрые, подтверждённые | Q1 `status:>=400` кнопка мертва · Q2 `blocked` двойной счёт · Q3 `active` бессмысленная сумма · Q4 quoted-facet ломается · Q5 escJs@2517 |
| **P1** | Безопасность | X1 `raw` LogQL (обход scope/cost) · X2 egress TOCTOU+redirect · X3 `_route_for` веер на неразрешённом attachment |
| **P2** | Корректность/консистентность | C1 config-writes single-active под merged-UI · C2 zoom не тянет `end_ns` в hist/facets · C3 tail race/timer-leak · C4 cursor boundary-ms дедуп · C5 type-mix в `_write_fanout` |
| **P3** | Перф/масштаб | Pf1 facets N×7 · Pf2 health/targets cache · Pf3 read-timeouts · Pf4 audit/log server-side cursor |
| **P4** | Observability/тесты | O1 unit-тесты fan-out/LogQL · O2 structured logging · O3 per-backend метрики · O4 request-id |
| **P5** | Фичи | F1 WS live-tail · F2 absolute time-range · F3 fleet alerting/SLO · F4 RBAC + audit действий · F5 notifications/threat-feeds UI · F6 backup + schema-normalize |
| **P6** | Deps/build | D1 lockfiles+hashes · D2 digest-pin + CI publish · D3 blocking security-gates |

---

## P0-quick — быстрые регрессии этой сессии (чинить первыми)

### Q1 — `status:>=400` quick-кнопка «errors» не находит ничего · CONFIRMED
`frontend/index.html:946` шлёт `status:>=400` → `_parse_omnibar` (`backend/app/main.py:326-331`) спец-кейсит status только по `^[2345]xx$`; `>=400` падает в generic → `| status=">=400"` (точное совпадение с несуществующим литералом) → **0 строк**. Самая заметная кнопка Logs мертва.
**Фикс:** либо кнопку на `status:4xx`+`5xx`, либо научить `_parse_omnibar`/`_chip_clause` диапазону status (`>=400`→`status=~"[45].."`). **S.**

### Q2 — Мульти-бэкенд `blocked` двойной счёт · CONFIRMED
`backend/app/main.py:832-834` — `_write_fanout` конкатит list-ключи; blocklist-api отдаёт `blocked`/`skipped` списками CIDR. При бане одного IP на N бэкендах (broadcast/`all`/`/unblock`/feeds/autoban-`all`) список содержит CIDR N раз → UI «Забанено: 2», `autoban_last_run.banned` и feed-счётчики завышены на replication factor.
**Фикс:** для set-подобных ключей (`blocked`,`skipped`,`removed`-list) — union, не concat; или `len(set(...))` в потребителях. **S.**

### Q3 — Суммирование `active` по флоту бессмысленно · CONFIRMED
`backend/app/main.py:830-831` + фронт `2143/2376/2382/2447/2610`. `active`=«число активных правил на ЭТОМ бэкенде»; сумма по флоту → «активно правил: 150» при 3×50. `removed` (сумма) ок, `active` — нет.
**Фикс:** не суммировать backend-local gauge — убрать из агрегата (показывать per-backend в `results[]`) или `max` с релейблом. **S.**

### Q4 — `lgQuick`/`lgFacetPick` ломают значения с пробелами · CONFIRMED
`frontend/index.html:1545-1548` — `lgQuick` делает `.split(/\s+/)`; `lgFacetPick("path","/a b")`→`path:"/a b"`→split→`['path:"/a','b"']`. Любой path/UA с пробелом ломает омнибар.
**Фикс:** quote-aware split в `lgQuick` (не резать внутри кавычек), либо не пере-сплитить существующее. **S.**

### Q5 — `frontend/index.html:2517` использует `esc()`+ручной replace вместо `escJs()` · LOW
Читается через `this.dataset.p` (не в JS-контексте) → на практике безопасно, но единственное место мимо стандарта `escJs()`. **Фикс:** заменить на `escJs(r.path)`. **XS.**

---

## P1 — Безопасность

### X1 — `raw` LogQL полностью операторо-контролируемый, обходит scope и веерит на весь флот · HIGH
`backend/app/loki.py:234-235` (`if raw: return raw.strip()`) + `main.py` `/api/logs/query`. `raw` минует всё escaping И `_sel_with_sources` → теряется `INGRESS_SELECTOR` (можно читать любые стримы каждого Loki, не только nginx), `_apply_env` не скоупит запрос без селектора, нет cap на стоимость → regex-бомба/огромный `count_over_time` идёт параллельно по всему флоту (до 8 воркеров). Аутентифицировано (не эскалация прав), но глушит guardrails структурного пути.
**Фикс:** решить судьбу `raw`: (a) всё равно навешивать/требовать `INGRESS_SELECTOR`, отклонять пустой селектор; (b) max time-range, отклонять длинные `[Nd]`; (c) вынести за отдельный capability-флаг; или удалить поле. **M.**

### X2 — `_egress_check` уязвим к DNS-rebinding (TOCTOU) и не проверяет redirects · MEDIUM
`backend/app/main.py:643-673`. Резолвит и валидирует IP, но реальный запрос (`urlopen`) резолвит заново → между check и use DNS может перекинуться на `169.254.169.254`/`127.0.0.1`. Плюс `urlopen` по умолчанию **следует за редиректами**, а redirect-таргет не проверяется. Для `_fetch_feed` (`allow_internal=False`) — реальная экспозиция (публичный A-рекорд → rebinding/302 на метаданные). Кодировки (octal/decimal/IPv4-mapped) — **проверено, безопасно** (getaddrinfo нормализует).
**Фикс:** для `_fetch_feed` — запретить redirects (или re-check на каждом хопе), резолвить один раз и коннектиться на валидированный IP с пиннингом Host. **M.**

### X3 — `_route_for` веерит на весь флот при неразрешённом attachment · MEDIUM
`backend/app/main.py:777-797` — `return sorted(picked) if picked else all_ids`. Если названная группа/таргет не резолвится (опечатка/переименование/стейл), запись уходит **на все** бэкенды вместо no-op/ошибки → непреднамеренный fleet-wide бан (особенно опасно с `/block_bulk`).
**Фикс:** различать «явно all/пусто → broadcast намеренно» и «названо-но-не-резолвится → `[]`, запись падает». **S.**

---

## P2 — Корректность / консистентность

### C1 — Config-writes идут в один бэкенд под merged-read UI · MEDIUM (латентный баг)
`/api/environments` GET/POST/delete (`main.py:944/967/974/981`, через `_blocklist_call` — **игнорируют даже scope-пикер**), `/api/settings` (`925`), `/api/notify_config` (`1041`), path-rule read/write (`api_path_rules 1888`, `api_path_rule 1927/2275`, `path_seed*` `2294/2303`, `path_type 2267`), `enroll_info 1118`, `/targets` seeding `1285`. Reads смёржены по флоту, а эти пишут в active → оператор правит на A, B молча расходится, merged-view показывает смесь. `path_status`/`path_master` уже сделали fleet-aware — остальное нет.
**Фикс:** по каждому эндпоинту решить fleet-write (settings/notify/path-rules → `_write_fanout` на `__all__`) vs owner-routed; environments — минимум через `_scoped_backend()`, не `config.*`. **M.**

### C2 — Zoom тянет `end_ns` только в query, не в histogram/facets · MEDIUM
`main.py:449-500` — hist/facets не читают `body["end_ns"]`; `loki.py` обе берут `_t.time()` как end. После `lgZoom` таблица показывает зум-окно, а гистограмма/фасеты — трейлинг `now-minutes`. **Фикс:** прокинуть `end_ns` в `log_histogram(_by_class)`/`log_facets` и прочитать в эндпоинтах. **S.**

### C3 — Tail: timer не гасится при уходе с Logs + гонка stale-фильтра · MEDIUM
`frontend/index.html:showView` (нет `clearTimeout(_lgTimer)`) → один лишний fan-out после ухода, `_lg.tail` остаётся true (авто-резюм при возврате). Плюс: in-flight `lgTail` со старым омнибаром может дописать строки старого фильтра поверх нового `_lg.rows` (нет generation-токена в `_post`). **Фикс:** `clearTimeout` в showView при уходе; инкрементный run-token, дропать устаревшие tail-ответы. **S.**

### C4 — Cursor/tail дедуп теряет/дублит строки на границе миллисекунды · LOW
`main.py:444` cursor=`rows[-1].ts*1e6-1`, а `ts` усечён до мс (`loki.py:255`) → строки в ту же мс пропадают между страницами; `lgTail` `r.ts>maxTs` дропает строки той же мс; `lgLoadOlder` конкатит без дедупа. Под высоким RPS — реальный риск. **Фикс:** пагинация/дедуп по композитному ключу (ns + hash строки), не по усечённому ms. **S/M.**

### C5 — `_write_fanout` крашится при type-mix ключа между бэкендами · MEDIUM (suspected)
`main.py:825-836` — ветвление по типу первого значения, потом слепо применяет к остальным: A `active=50` (int), B `active=[…]` (list) → `int+list` → 500. Кусает только при смешанных версиях бэкендов (rolling upgrade). **Фикс:** guard на каждый arithmetic/concat, фолбэк на `results[]`-only при mismatch. **S.**

---

## P3 — Перф / масштаб (20 VM + 2 кластера)

### Pf1 — Facets = N×7 Loki-запросов; каждый клик фильтра ≈ 9×N запросов · HIGH-perf
`loki.py:344-350` (1 `query_range` на поле, 7 полей) + `_loki_fanout` по источникам + `_lgFetch` = query(1)+hist(1)+facets(7). На 5 источниках любой клик/тоггл ≈ 45 `query_range` по всему окну. Самый тяжёлый перф-хотспот сессии.
**Фикс:** (a) debounce + грузить фасеты только когда панель видима и не на каждый run; (b) батчить в меньшее число `sum by()`; (c) кэш по (query,window) на секунды; (d) сократить `_FACET_FIELDS`. **M.**

### Pf2 — Кэшировать `/api/backends/health` + `_targets_index` · S/M (высокий ROI)
`api_backends_health` (`main.py:2067`) — 2 блокирующих вызова на бэкенд **на каждый UI-poll, без кэша** (22 бэкенда = 44 round-trip/poll). `_targets_index` (`761`) ре-фанится на каждую routed-запись. Паттерн кэша уже есть (`_env_url_cache`, `_an_cache`, `_bc_cache`). **Фикс:** TTL-кэш (~10-15s) + фоновый refresher; прокинуть уже полученный флот в `_write_fanout`. **S/M.**

### Pf3 — Раздельные read/write таймауты; деградация медленного источника · S
Плоские 15s (`main.py:677/723`) → один медленный кластер стопорит весь merged-read на 15s. **Фикс:** короткий read-timeout (~4-5s) + уже готовый partial-контракт; показывать per-source latency (health уже считает). **S.**

### Pf4 — Server-side merge+cursor для audit/log · M
`/api/blocklist_audit` и `/api/autoban/log` фанят и мёржат **полный** audit с N бэкендов каждый вызов. **Фикс:** server-side merge-limit + cursor (паттерн уже в log-query). **M.**

---

## P4 — Observability / тесты

### O1 — Unit-тесты чистых fan-out/LogQL функций · S (делать первым)
Ноль покрытия на ядре корректности флота (`smoke.sh` трогает только blocklist-api). Покрыть: `_route_for` (resolve/all/empty-fallback/scope/коллизии), `_write_fanout` (verbatim/aggregate/partial-502/empty), `_fanout_list` (тегирование ошибок), `_parse_omnibar` (facet/neg/class/gte/unknown/free-text + **никогда не в `raw`**), `build_logql`/`_chip_clause` (escaping, `raw` gated), `_egress_check` (метаданные/RFC1918/схема/DNS-fail). Новые `backend/tests/test_{fanout,logql,egress}.py` + pytest-шаг в `ci.yml`. **S.**

### O2 — Structured logging вместо `print()` · S/M
~19 `print(...,flush=True)` (`main.py` + `loki.py`) → `logging` с JSON/logfmt, уровнями, request/backend-id. Связано с error-hygiene (детали хостов/URL — только на сервер). **S/M.**

### O3 — Per-backend latency/error метрики в `/metrics` · M
Сейчас `/metrics` — только Loki-ingress трафик + path403 health, **нет fleet-health метрики** (упавший бэкенд виден только в UI-поле, не скрейпится). Добавить `soc_backend_up{backend}`, `soc_backend_latency_ms`, `soc_fanout_errors_total{backend,path}`, `soc_write_partial_total`. **M.**

### O4 — Request-id / correlation · S
Middleware штампует `X-Request-Id`, прокидывает в structured logs + fan-out sub-calls (сейчас корреляция UI-действия по N вызовам невозможна). **S.**

---

## P5 — Фичи

- **F1 — настоящий live-tail (WebSocket/SSE)** через Loki `/loki/api/v1/tail`, append+dedup, сохранение скролла (`websockets` уже в зависимостях). Сейчас polling `query_range` каждые 5s. **M.**
- **F2 — absolute time-range** (`from`/`to` epoch через query/histogram/facets + календарь); сейчас только `minutes`, ретеншн >24ч недоступен для incident-review. **S backend / M frontend.**
- **F3 — fleet alerting/SLO**: из O3-метрик → Prometheus alert rules (backend down, partial-write rate, Loki-source unreachable) + **health-view для `_loki_targets`** (сейчас у Loki-источников нет health-поверхности). **M.**
- **F4 — RBAC / multi-operator + audit действий дашборда**: сейчас один Basic-cred, все действия анонимны; добавить идентичность оператора + audit кто банил/репойнтил/правил (отдельно от audit блоклиста). **L.**
- **F5 — notifications completeness + threat-feed UI**: `notify.py` (Slack/Telegram) — хорошая база; нет delivery-status/retry, `_matches` простой, `notify_config` single-active (C1). Threat-feeds без management/health UI. **M.**
- **F6 — backup/restore настроек + schema-normalize + scoped views**: экспорт/импорт `soc.db`+сторов; per-source field-map для гетерогенных Loki (k8s ingress-nginx JSON ≠ nginx-VM → `method/path/status` пустые для кластеров, `loki.py:247`); saved views всё ещё один глобальный blob. **M.**

---

## P6 — Deps / build

- **D1 — lockfiles + hash-pinning**: оба `requirements.txt` — плавающие minor (`fastapi==0.115.*`) без транзитивного лока и хешей. `pip-compile --generate-hashes` + `--require-hashes`. **S.**
- **D2 — digest-pin базовых образов + CI publish**: оба Dockerfile `FROM python:3.12-slim` (плавающий тег) → `@sha256:`. CI-job build+push обоих образов (и baked blocklist-api) на тег — закрывает единственный «вне репо» пункт S7. **S/M.**
- **D3 — блокирующие security-gates**: `pip-audit` сейчас non-blocking (`ci.yml:44-48`); сделать блокирующим (или fail на HIGH), добавить `helm lint`/`helm template` + Bandit. **S.**

---

## Рекомендованная последовательность
1. **P0-quick** (Q1–Q5) — 5 быстрых подтверждённых регрессий, мелкие правки, высокая заметность.
2. **X3 + C1 + C5** — латентные баги корректности (веер на неразрешённом attachment; config-writes расходятся; type-mix краш).
3. **O1 + D1/D2** — тесты + lock/pin: дешёвая страховочная сетка перед дальнейшей работой по флоту.
4. **X1 + X2** — решить судьбу `raw`, закрыть egress TOCTOU/redirect.
5. **Pf1/Pf2/Pf3** — перф хотспоты (facets, health-cache, read-timeouts).
6. **O2/O3/O4 + F3** — сделать флот наблюдаемым/алертящим.
7. **C2/C3/C4 + F1/F2 + F6-normalize** — добить Logs v2 (zoom-консистентность, tail-гонки, WS, absolute, гетерогенные схемы).
8. **H2(index.html decomposition) + F4(RBAC/audit)** — две крупные структурные инвестиции.

> Два пункта — **латентные баги, не фичи**, и их стоит поднять вперёд независимо от темы: **C1** (config-writes расходятся по флоту под merged-read) и **X3/H4** (`_route_for` веерит таргетированный бан при неудачном резолве).

*Аудит read-only. `raw` LogQL (X1) — единственное «решить продуктово»; остальное — конкретные фиксы. P0-quick Q1–Q4 — регрессии, внесённые в эту же сессию (Logs v2 / fan-out), ловятся юнит-тестами из O1.*
