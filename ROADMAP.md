# SOC-app — Аудит и роадмапа

> Статус: **документ, кода не меняли.** Составлено 2026-07-01 по итогам аудита в 4 потока
> (безопасность soc-app backend · безопасность blocklist-api + Helm · баги/качество · раздел Logs).
> Ссылки вида `файл:строка` — на момент аудита; перед правкой сверяться.

Скоуп: `backend/app/*.py` (дашборд, FastAPI), `blocklist-api/app/*.py` (сервис банов),
`blocklist-api/templates/*` + `values*.yaml` (Helm), `frontend/index.html` (весь UI).

---

## 0. Executive summary

Ядро логики (баны, safety-rails, RBAC) — крепкое. Проблемы сконцентрированы в трёх местах:

1. **Аутентификация fail-open.** И дашборд, и blocklist-api при незаданных кредах пускают всех без проверки. На security-appliance это fail-open контроль.
2. **SSRF + утечки секретов.** Дашборд ходит по URL, которые задаёт пользователь, без egress-валидации; enroll-секрет и (на k8s) CF-токены лежат/отдаются в открытом виде.
3. **Fan-out незакончен.** Reads смёржены по флоту, но часть write/read путей всё ещё бьёт только в активный бэкенд → оператор видит неверные цифры и «0 забанено», частичные сбои маскируются под успех.

Плюс раздел **Logs** — однобэкендный, live-tail не тейлит, обрезка на 400 строк, схема ломается на k8s-логах; предложен полноценный редизайн в стиле Datadog.

### Матрица приоритетов

> **Прогресс:** ✅ **P0 закрыт** (S1 `c64c4c3`, S2 `2806d92`, S3 `a23acd7`, S6 `e59ff04`).
> ✅ **P1 закрыт** (B1/B2 `0675b2e`, B3/B4/B5 `a10d7c1`, B6 `34db720`, S7 `84bd51c`). Дальше — P2.

| P | Тема | Пункты |
|---|------|--------|
| **P0** ✅ DONE | Auth fail-closed (оба сервиса) · SSRF egress-allowlist · enroll-секрет не отдавать · CF-токены не в ConfigMap | S1, S2, S3, S6 |
| **P1** ✅ DONE | Fan-out корректность (ложные «0 забанено», частичный сбой=успех, why/log/executor/feeds однобэкендные) · JS-инъекция в onclick · supply-chain образа | B1–B6, S7 |
| **P2** | Logs Explorer v2 (Datadog-style) · CORS/CSRF/заголовки · инъекция в nginx snippet · pod hardening | LOGS, S5, S8, S9 |
| **P3** | Оптимизации (кэш targets-index, пагинация, таймауты), тесты fan-out, UX-мелочи | OPT, полировка |

---

## 1. Безопасность (P0/P1)

### S1 — CRITICAL · Аутентификация fail-open на ОБОИХ сервисах
- **Дашборд:** `backend/config.py:19-20`, `backend/app/main.py:55-71`. Basic-auth middleware — **no-op, если `BASIC_AUTH_USER/PASS` не заданы** (`deploy/soc.env.example:10-11` пустые), контейнер слушает `0.0.0.0:8077`. Нет `Depends`, сессий, токенов — `/api/*` открыт всем, кто дотянулся до порта: банить IP, армить автобан, регистрировать/активировать backend (увести весь трафик), менять LLM-endpoint, тянуть enroll-one-liner.
- **blocklist-api:** `blocklist-api/app/main.py:43-44` — `if not config.TOKEN: return await call_next(request)` пускает всех. `values.yaml:8` шлёт `token: ""` по умолчанию; защита — один `print()`-варнинг (`main.py:512-515`).
- **Фикс:** fail **closed** — не стартовать (или 503 на все не-exempt пути) при пустых кредах вне явного dev-режима (`SOC_DEV_NO_AUTH=1`). В чарте — `fail` при рендере, если не задан `token`/`existingSecret`. Забиндить дашборд на `127.0.0.1` за реверс-прокси.

### S2 — CRITICAL · SSRF: сервер ходит по URL от пользователя без egress-валидации
- `backend/app/main.py:1799-1829` (`/api/ingress_apis/test` — вообще без проверки схемы), `:1684-1699` (`/api/blocklist_config`), `:1832-1864` (save/activate → `_set_active_backend`), `:435-461` (`_bcall_to`), `:1474-1494` (threat feeds).
- Валидация — максимум `startswith("http://"/"https://")`. Нет блок-листа `169.254.169.254`, `127.0.0.0/8`, RFC1918, `[::1]`.
- **Сценарии:** зонд облачных метаданных (reachability/latency/ошибка отражаются обратно → оракул); после save+activate злого URL **весь** последующий `_blocklist_call`/`_fanout` уходит на хост атакующего (internal port-scan, blind SSRF); фиды тянутся по таймеру.
- **Фикс:** централизованный egress-guard — резолвить хост, отклонять loopback/link-local/private/reserved, пинить резолвнутый IP (анти-rebinding), только https/известные порты; применить в `_bcall_to`, `/test`, `_fetch_feed`.

### S3 — CRITICAL · Enroll-секрет отдаётся по API
- blocklist-api `blocklist-api/app/main.py:328-334` — `GET /enroll_info` возвращает `enroll_secret` открытым текстом.
- Дашборд `backend/app/main.py:831-851` — `/api/nodes/install` проксирует его в готовый `curl … ENROLL_SECRET=<секрет> bash`. При S1 (без auth) любой читатель получает секрет → регистрирует rogue-ноду, тянет `/nginx_snippet` любого таргета.
- **Фикс:** не эхоить `enroll_secret` в ответах; рендерить one-liner на сервере или выдавать одноразовый short-TTL enroll-токен; никогда не логировать.

### S6 — CRITICAL · CF-токены пишутся в plaintext ConfigMap (k8s-дефолт)
- `blocklist-api/app/cf_targets.py:59-60,152-158` и `environments.py:51-53,84-87` пишут CF-токен в pluggable store; при `STORE=configmap` (дефолт, `config.py:52`) это **ConfigMap** `soc-denylist` — токен в открытом виде, читаем любым с `get configmaps`, в etcd/бэкапах/GitOps.
- `settings.py:120-125` **правильно** отказывается писать `CF_API_TOKEN` в ConfigMap — но `cf_targets/environments.upsert` такого гарда не имеют.
- **Фикс:** тот же отказ для `cf_targets`/`environments`, либо роутить CF-токены в Secret независимо от store; минимум — блокировать создание CF-таргета при `STORE=configmap`.

### S4 — HIGH · CORS/CSRF/заголовки отсутствуют
- `backend/app/main.py` — нет `CORSMiddleware`/`TrustedHostMiddleware`, нет CSP/`X-Frame-Options`/`X-Content-Type-Options`/HSTS. Все мутации — plain `POST` c `request.json()`, без CSRF-токена и проверки `Origin`.
- При S1 злая веб-страница у оператора в той же сети делает cross-origin POST (ban / repoint backend). Даже с Basic-auth браузер реиграет креды → CSRF остаётся.
- **Фикс:** CSP + `X-Frame-Options: DENY` + `nosniff`; проверка `Origin` на мутациях; CORS не расширять.

### S5 — HIGH · LogQL-инъекция / ReDoS в запросах к Loki
- `backend/app/loki.py:194-234` (`_chip_clause`, `build_logql` — `raw` проходит насквозь), `:1335-1344`, `:122-128`, `:713/717`.
- Значения инлайнятся в LogQL с ad-hoc «санитайзом» (`v.replace('"','.')`); `raw` и regex-чипы принимают произвольный RE2 → дорогие/greedy запросы (DoS общего Loki), обход `env`-лейбла. SQL при этом полностью параметризован — SQLi нет (хорошо).
- **Фикс:** единый `_re2_escape` на chip/search-путях (функция есть, но не используется), `raw` — только под auth + cost-guard, whitelist имён лейблов.

### S7 — HIGH · Supply-chain: runtime `pip install` без хешей + floating image tag
- `blocklist-api/templates/deployment.yaml:23-28` — initContainer на каждом старте тянет пакеты с PyPI; версии пиннуты, но **не по хешу** (`--require-hashes` нет), база `python:3.11-slim` — **плавающий тег** (`values.yaml:3-4`). Компрометация зеркала/тега → код атакующего в поде, у которого RBAC на патч ingress-контроллера.
- Плюс расхождение: `values.yaml` (fastapi 0.111) ≠ корневой `requirements.txt` (fastapi 0.115.*).
- **Фикс:** собрать реальный образ (Dockerfile уже есть), пиннить `image:` по `@sha256:`; если оставлять initContainer — `--require-hashes` + lock-файл + база по digest. Свести версии.

### S8 — HIGH · Инъекция в nginx `server-snippet` / чрезмерно широкий паттерн
- RBAC `rbac.yaml:39-62` (патч CM контроллера = управление nginx всего кластера — least-privilege, это ок). Рендер `render.py:53-69`, валидация `safety.py:22-49`.
- `validate_pattern` блокирует только: пусто, `>8000` символов, литерал `"`, некомпилящийся regex. **Не** отклоняет `\n`/`\r`/`\0` и nginx-метасимволы; `force=true` пропускает и benign-check. Паттерн с переводом строки/`.*` → DoS/403 на весь кластер (**инъекция — suspected**, over-broad — confirmed).
- CF-аналог `cloudflare.py:227-233` санитайзит иначе (`.replace('"','')`) — рассинхрон.
- **Фикс:** отклонять control-chars и опасные последовательности; отдельное подтверждение для `force`; валидировать паттерн один раз под строжайший таргет.

### S9 — MEDIUM · Прочее (сводно)
- **Секреты at-rest:** токены в plaintext SQLite (`db.py:148-152`, `blocklist_api_override`, `ingress_apis`). Read-эндпоинты **правильно** редактят до `token_set`/`token_valid` (`main.py:1679,1740`), Basic-auth — `compare_digest`. Компрометация тома БД = компрометация токенов. Задокументировать/шифровать.
- **SSRF/DoS `/api/webcheck` + `asn_lookup`** (`main.py:413-426`, `loki.py:1085-1103`): job/url санитайзятся (ок), но `.read()` без лимита — раздувание памяти. Кап на `.read(N)`.
- **Утечка внутренних деталей в ошибках** (`str(e)` повсюду): хосты/порты/URL в `error`-полях; при S1 — разведка. Логировать детально на сервере, клиенту — generic.
- **`/install/*` открыт** (`main.py:39`): раскрывает логику агента; `curl|bash` по не-https `PUBLIC_URL` → MITM=root RCE. Форсить https в prod, подписывать артефакт.
- **`/metrics` в `AUTH_EXEMPT`** (`config.py:22`): сводка трафика/атак без auth при открытом порте.
- **node-token compare O(n)** (`nodes.py:120-128`): constant-time на сравнение, но линейный скан. Low.
- **ingress по умолчанию публичен** (`ingress.yaml`, `values.yaml:24-32`): защита — только `whitelist-source-range` с placeholder-диапазонами; при S1-пустом токене API в интернете. Дефолт `ingress.enabled:false` / требовать реальный whitelist.
- **pod securityContext** (`deployment.yaml:58-62`): есть `runAsNonRoot`/`drop:[ALL]`/limits; **нет** `readOnlyRootFilesystem`, `seccompProfile: RuntimeDefault`, `fsGroup`.
- **`code-configmap.yaml`**: код как ConfigMap, без подписи/пиннинга, лимит 1 MiB; `update configmaps` = подмена кода. Предпочесть digest-pinned образ.
- **Чарт может отрендерить Deployment со ссылкой на несозданный Secret** (`deployment.yaml:37-41` vs `secret.yaml:1`) → `CreateContainerConfigError`; оператор «чинит» пустым токеном → S1. `fail` при рендере.

### Что реально крепко (сохранить)
SQL параметризован (нет SQLi) · `compare_digest` для admin/enroll · read-эндпоинты редактят токены · RBAC least-privilege (namespaced Role, `resourceNames`, без wildcards) · IP safety-rails (`safety.validate`: `/0`, allowlist, CF-диапазоны, private/loopback, min-prefix; `collapse_addresses` → нет инъекции через CIDR) · node-token least-privilege (id из токена, не из тела) · branding-upload по типу/размеру.

---

## 2. Баги и корректность (P1)

Главный корень — **fan-out доделан наполовину**: reads смёржены, но часть путей всё ещё однобэкендная, а write-ответ на мульти-флоте меняет форму, которую фронт не понимает.

### B1 — HIGH · Мульти-бэкенд write рапортует ложные «0 забанено / 0 снято»
- `frontend/index.html:2350` (`unbanAll`), `:2358` (`banAllCandidates`), `:2415`, `:2578`, `:2344` (`resyncNow`), `:2111/:2122` (`blockIP/blockManual`).
- На флоте ≥2 `_write_fanout` возвращает `{ok,multi:true,results:[…]}` (`main.py:576`) **без** ключей `blocked/removed/cidr/active/skipped`, а фронт читает `res.blocked.length` и т.п. → «Забанено: 0». `unblock_all`/`resync`/`unblock`/`path_master`/`path_type` **всегда** веерят → **всегда** ловят это на мульти-флоте.
- **Фикс:** в `_write_fanout` при `multi` сворачивать агрегаты (сумма `blocked/removed`, union `skipped`, first `active`) в топ-уровень; и/или научить фронт читать `res.multi` и суммировать `results[].resp.*`.

### B2 — HIGH · Частичный сбой записи выдаётся за успех
- `backend/app/main.py:574-576` — `ok_any = ok_any or ok`, HTTP 200 если хоть один бэкенд ответил.
- Бан прошёл на A, на B — 500/timeout → UI показывает успех, на B атакующий всё ещё проходит.
- **Фикс:** `ok = all(...)` или явный `partial:true` с per-backend ошибками; фронт показывает `results[].ok===false`.

### B3 — HIGH · `why` / autoban-log читают только активный бэкенд
- `main.py:1048,1060` (`/api/autoban/why`), `:1100-1101` (`/api/autoban/log`).
- Таблица банов смёржена, но «почему забанен» (с активного A) для бана на B рапортует **«не в денлисте»**; флаг `active` в логе неверен.
- **Фикс:** фанить `/list` и `/audit` здесь тоже (`_fanout_list`).

### B4 — HIGH · `_blocked_nets()` дедуп по активному бэкенду → ре-баны/дубли в превью
- `main.py:2165-2174`, потребители `/api/autoban/preview` (`:1539`), `_drop_already_blocked` (`:2177`).
- IP, забаненный на B (не A), считается незаблокированным → превью «забанит», executor ре-банит, дедуп кандидатов неполный.
- **Фикс:** строить `nets` из `_fanout_list("/list","blocks")`.

### B5 — HIGH · Executor автобана и импорт threat-feeds пишут только в активный бэкенд
- `main.py:1332` (executor `block_bulk`), `:1436` (feeds).
- Правило на группу, живущую на B, при активном A → бан уходит на A (не тот ingress) или в дефолт-группу A.
- **Фикс:** executor через `_route_for(it)`/`_write_fanout`; фиды через `_route_for({"group":group})`/`_backends()`.

### B6 — MEDIUM · JS-инъекция в inline `onclick`: `esc()` не экранирует кавычки
- `frontend/index.html:1070` (`esc` экранирует лишь `< > &`), используется в одинарных кавычках onclick: `:2169` `openProfile('${esc(cidr)}')`, `:2174` `unblockCIDR`, `:3362` `deleteNode`, `:1639` `lgBanIP('${ip}')` (вообще без replace) и др.
- Значение с `'` или `\` вырывается из строки → выполнение произвольного handler-кода. Атакер-контролируемые данные (reason, лог-поля, UA, path) в onclick. Местами уже костыль `.replace(/'/g,"\\'")` (`:1640,:1563`) — доказывает, что базовый helper небезопасен.
- **Фикс:** отдельный `escJs()` **везде**, где значение идёт в inline-handler; лучше — `data-*` + делегирование через `addEventListener`.

### B7 — MEDIUM · Живой RU→EN транслятор портит динамический контент
- `frontend/index.html:1465` (`_trText` — слепой substring-replace по любому тексту с кириллицей), `:1483-1488` (MutationObserver по всему `body`).
- В EN любой text-node с кириллической подстрокой из `RU2EN` переписывается: reason/лог-строки/JSON-детали/UA могут молча искажаться; плюс перф — TreeWalker на каждую мутацию при автo-refresh.
- **Фикс:** переводить только узлы, помеченные как UI-chrome (класс/`data-i18n`), пропускать `.mono`/лог/детали.

### B8 — MEDIUM · Смёрженный blocklist молча теряет баны упавшего бэкенда
- `frontend/index.html:2144-2150` (`renderBlocklist`) и `:2563-2565` игнорят `d.backend_errors` (его отдаёт `main.py:878`). Единственный сигнал — глобальный health-бейдж, не привязан к таблице; счётчик «N активных» врёт.
- **Фикс:** при непустом `backend_errors` — inline-варнинг в карточке.

### B9 — MEDIUM · `ex.map` в fan-out ре-райзит: один краш валит весь read
- `main.py:498-499`, `:1795-1796`. `list(ex.map(...))` пробрасывает первое исключение воркера → 500 вместо partial, вопреки контракту в докстринге (`:483`).
- **Фикс:** `as_completed` + per-future try/except, либо catch-all в теле `one()`.

### Suspected / ниже уверенность
- **MEDIUM (by-design, рискованно)** — коллизия имён групп веерит бан на все бэкенды с этим именем (`main.py:530-531,550-551`): ban на группу «prod» → на каждый кластер с группой «prod». Рассмотреть backend-квалификатор группы или показывать в attach-UI, во что резолвится.
- **LOW** — `_route_for` при пустом резолве **молча веерит на весь флот** (`main.py:555`): опечатка/временно упавший владелец → таргетированный бан становится fleet-wide. Различать «резолв пустой» и «нет attachment».
- **LOW** — `ban_targets/check`, `_ban_groups`, seeding, «добавить в основное 403» (`main.py:614,1013,1964,1972,2120-2133`) — активный бэкенд, хотя вокруг всё смёржено.
- **LOW** — `_env_loki_url` кэш по активному бэкенду (`main.py:667-683`).

---

## 3. Раздел Logs → Logs Explorer v2 (Datadog-style) (P2)

### 3A. Аудит текущего состояния (почему «скудно и неудобно»)
Фронт `frontend/index.html`: view `view-logs` L923-990, логика `_lg` L1530-1687. Бэк `backend/app/loki.py` L122-291; эндпоинты `main.py` L228-312.

1. **Однобэкендность (главный пробел)** — все logs-эндпоинты бьют в один `loki.scope(env,…)` (`main.py:235,248,256,277,293`), один base URL (`loki.py:96,158`). В отличие от банов (`_fanout`), логи **не фанятся**. 20 VM + 2 кластера вместе не посмотреть.
2. **Env на фронте заглушён** — `const _env="";` и `_withEnv(url){return url}` (`index.html:1072-1073`) — no-op. В Logs-view нет селектора env/источника вообще; единственный скоуп — дерево Sources, и то в пределах одного Loki.
3. **Live-tail не тейлит** — `lgTailToggle`+`lgRun` каждые 5с перезапрашивают всё окно `limit:400` и заменяют `innerHTML` (`:1611,1658,1614-1631`) → теряется скролл/раскрытые строки. `end_ns` для forward-пагинации есть в бэке (`loki.py:257`), но фронт его не шлёт.
4. **Нет пагинации, потолок 400-1000 строк** (`:1601`, `main.py:279`) — на реальном трафике 15 мин > 400 строк, старое молча обрезается без индикации.
5. **LogQL-инъекция/ReDoS через `raw`** (`loki.py:220`) и слабый санитайз чипов (`:210-213`) — см. S5.
6. **Хрупкая форма запроса** — хардкод `|= "remote_addr"` перед `| json` (`loki.py:224`) + один `| json a="b"` под nginx-VM: **ingress-nginx k8s-логи имеют другую JSON-схему** → `method/path/status` пустые для кластерных логов (корректность на гетерогенных источниках).
7. **Гистограмма не кликабельна** — `title="drag to zoom (coming)"` (`index.html:981`), но `lgRenderHist` рисует статичные бары.
8. **Время — фикс. дропдаун 15m/1h/6h/24h** (`:944`), нет абсолютного диапазона/7d/календаря; ретеншн >24ч недоступен.
9. **Чипы молча дропаются** — `_chip_clause` возвращает `""` для неизвестного поля/битого float (`loki.py:198,207`) без фидбэка; `real_ip` есть в `_LOG_FIELDS`, но нет в UI-чипах.
10. **Saved views — один глобальный blob** (`main.py:302`), без scope по env/оператору; применение вида каждый раз перегружает дерево.
11. **Тонкие error-состояния** — исключения → `{error:str(e)}` (`main.py:282,296`), фронт всё равно рендерит `q.rows`; таймаут (частый на широком запросе) — как сырой текст.
12. **Parsed-таблица фикс. 7 колонок** (`index.html:1618`, CSS L169) — нет кастомизации, UA/country/host/referer парсятся, но не показываются как колонки; raw-режим — просто дамп строки; нет структурного JSON-дерева, click-to-filter, подсветки совпадения.
13. **Перф** — каждый `lgRun` = 2 синхронных `query_range` (rows + histogram c `count_over_time` по всему окну), при tail — пара полных сканов каждые 5с без кэша, без debounce на переключение источников.
14. **Мелочи:** `recent_logs`/`/api/logs` — легаси, не используются explorer'ом; `_fmt_ns` — только `%H:%M:%S`, на 24ч времена без даты.

### 3B. Редизайн — спецификация
**Раскладка:** три панели — слева **фасеты**, в центре **омнибар + гистограмма + поток**, справа **детальный drawer**.

1. **Омнибар с синтаксисом** вместо chip-builder+raw: `facet:value`, диапазоны (`status:>=400`, `rt:>1.5`), globs (`path:/wp-*`), негация (`-status:200`), `AND/OR`/скобки, свободный текст → `|= "…"`. **Парсинг на бэке**, никогда не прокидывать текст в `raw`. Power-user LogQL — под фичефлагом + cost-limit. Автокомплит фасетов/значений.
2. **Панель фасетов (авто, со счётчиками):** `status`, `status_class` (2xx/3xx/4xx/5xx), `method`, `path`, `host`, `ip`, `country`, `env`, `project`, `cluster/source`, `ua`. Чек = добавить `facet:value`. Числовые — слайдеры. Счётчики через `topk(N, sum by(<label>)(count_over_time(<base>[range])))` (паттерн уже есть — `top_subnets`/`distinct_ips`, `loki.py:300,306`). **Новый** `POST /api/logs/facets`.
3. **Пикер времени + гистограмма объёма:** пресеты + **абсолютный from/to** (календарь); стек-бары **по status_class** (зелёный/синий/жёлтый/красный) — спайки ошибок видны; клик по бару = зум, drag-select = диапазон (дорисовать уже присутствующий `#lg-hist`). **Расширить** `/api/logs/histogram` до серий по классам.
4. **Поток результатов:** бесконечный скролл с **курсор-пагинацией** через существующий `end_ns` (`loki.py:257`) → `{rows, next_cursor}`, «load older». Цвет по статусу (`_lgStatusColor`), относительное+абсолютное время (починить `_fmt_ns` c датой). Тоггл raw / **структурный JSON-tree** с **click-a-field-to-filter**. **Кастомизация колонок** из каталога фасетов (UA/country/host/referer уже парсятся `_parse_line`, `loki.py:245`), сохраняется в view. Подсветка совпадения.
5. **Настоящий live-tail:** WebSocket/SSE на Loki `/loki/api/v1/tail`, либо polling с `start=<last_ts>` + **append+dedup**, сохраняя скролл («follow» автоскроллит, скролл вверх — пауза). Выкинуть текущий full-refresh цикл (`:1611,1658`).
6. **Мульти-источник (fan-out) — критично:** селектор источников с группировкой 20 VM по `env`/`project` + 2 кластера («all / by env / by cluster»). Бэк **фанит логи** как баны: зеркалить `_fanout`/`_backends`, резолвить набор `(env, loki_url)` из реестра окружений (`_env_loki_url`, `main.py:670`), параллельные `query_range`, **merge-sort по времени**, тег `source/env/cluster` в строке. Фасеты/гистограмма суммируются. **Per-source статус** `{rows, sources:[{id,ok,count,error}]}` — один медленный кластер деградирует gracefully. Нормализация схем (nginx-VM vs ingress-nginx) серверным field-map — чинит баг #6.
7. **Quick-filters / views / export:** кнопки Errors(≥400)/5xx/4xx/**Attacks**(`_ATTACK_RE`, `loki.py:152`)/Slow(rt>1s). Views — namespace по env/оператору. Server-side export полного результата (CSV/NDJSON курсором), т.к. клиент держит одну страницу.

**Форма API (что бэк должен вернуть):**
- `POST /api/logs/query` → `{rows:[{ts,time,status,method,path,ip,ua,country,host,rt,line,source,env}], next_cursor, sources:[{id,ok,count,error}], query}` — **изменить**.
- `POST /api/logs/facets` → `{total, facets:{<facet>:[{value,count}]}}` — **новый**.
- `POST /api/logs/histogram` → `{step, series:{<status_class>:[{t,v}]}}` — **расширить**.
- `GET /api/logs/autocomplete?facet=&prefix=` — **новый**.
- Все три — **фанятся по флоту Loki и мёржатся** (общий новый helper).

**Есть/переиспользовать:** каталог `_LOG_FIELDS`; chip→LogQL (`build_logql`,`_chip_clause`); `_parse_line` уже тянет UA/country/host/rt; одно-серийная гистограмма (`log_histogram`); `end_ns`-курсор; `log_labels`/`log_label_values`; статус-цвет; хранилище views; blueprint `_fanout`/`_backends`.
**Строить:** logs-fan-out+merge+нормализация+per-source статус; facets-API; кликабельная стек-гистограмма; курсорный бесконечный скролл; настоящий live-tail; парсер омнибара+автокомплит; абсолютное время; кастомизация колонок; селектор env/источника (снять заглушки `_env`/`_withEnv`); харднинг инъекций/cost-guard.

---

## 4. Общие улучшения / оптимизации (P3)

- **Единый контракт `_write_fanout`** — всегда `ok`, `partial`, агрегаты `blocked/removed/skipped/active` + `results`; обновить все success-хендлеры фронта. Убивает весь класс «ложный 0/успех» разом (B1, B2).
- **Consistency-pass:** grep оставшихся `_blocklist_call(` в read/merge-контексте (why, log, `_blocked_nets`, `_ban_groups`, seeding, executor, feeds) — по каждому решить fan-out-read vs owner-routed-write. Однобэкендные reads под смёрженным UI — повторяющийся корень.
- **Кэш:** short-TTL для `_targets_index` и `/api/backends/health` (health = 2 вызова/бэкенд, поллится из UI); передавать уже полученный флот в `_write_fanout` (сейчас ban с attachment = ≥2 фан-аута `/targets` + write).
- **Таймауты/observability:** flat 15с/бэкенд — медленный стопорит весь read; короче read-timeout, логировать per-backend latency (уже считается в health), вынести счётчики `backend_errors` в `/metrics`.
- **Пагинация:** `/api/blocklist_audit?limit=500` и `/api/autoban/log` фанят и мёржат полный audit по N бэкендам каждый раз — серверный merge+limit + курсор.
- **Frontend safety:** `escJs()` / делегирование (B6); скоуп транслятора только на UI-текст (B7).
- **Тесты:** юнит на `_route_for` (коллизии, пустой-резолв фолбэк, упавший бэкенд), `_write_fanout` (single/multi/partial), `_fanout_list` (тегирование ошибок) — самые хрупкие инварианты fan-out.
- **UX:** inline-индикация частичного флота в каждой fan-out вьюхе (не только глобальный бейдж); в `_ing_apis()` дефолт явно с ключом `scope`.

---

## 5. Рекомендуемый порядок работ

1. **P0 безопасность (быстро, наибольший blast-radius):** S1 (fail-closed auth, оба сервиса + `fail` в чарте) → S2 (SSRF egress-allowlist) → S3 (enroll-секрет не отдавать) → S6 (CF-токены не в ConfigMap).
2. **P1 корректность fan-out:** B1+B2 (контракт `_write_fanout`: агрегаты + `partial`) → B3/B4/B5 (why/log/`_blocked_nets`/executor/feeds на fan-out/route) → B6 (`escJs`) → S7 (digest-образ, убрать runtime pip).
3. **P2:** Logs Explorer v2 (раздел 3B, фазами: fan-out+омнибар+фасеты → гистограмма+курсор → live-tail) → S4 (CORS/CSRF/заголовки) → S8 (харднинг паттернов) → pod hardening (`readOnlyRootFilesystem`/seccomp), ingress-дефолты.
4. **P3:** кэш/таймауты/пагинация, тесты fan-out, UX-мелочи, B7 (скоуп транслятора), B8/B9 (inline backend_errors, `as_completed`).

---

*Аудит read-only, правок кода не вносилось. Незакоммиченная Фаза-3 fan-out (health/dedup) в рабочем дереве — на неё findings не распространяются как на «баги незавершённости».*
