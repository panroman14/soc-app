const SEV = {
  ok:{label:"спокойно",cls:"bg-emerald-500/10 text-emerald-300 border-emerald-500/30",dot:"#73bf69"},
  notice:{label:"внимание",cls:"bg-sky-500/10 text-sky-300 border-sky-500/30",dot:"#38bdf8"},
  warning:{label:"тревога",cls:"bg-amber-500/10 text-amber-300 border-amber-500/30",dot:"#ff9830"},
  critical:{label:"критично",cls:"bg-red-500/10 text-red-300 border-red-500/40",dot:"#f2495c"},
};
const fmt=n=>n==null?"—":(n>=1000?(n/1000).toFixed(n>=10000?0:1)+"k":Math.round(n));

// ── in-app dialogs (replace native alert/confirm/prompt) ──────────────────────
function _showModal({title,body,buttons}){
  return new Promise(resolve=>{
    const root=document.getElementById("modal-root");
    const close=v=>{ root.classList.add("hidden"); root.innerHTML=""; document.removeEventListener("keydown",onkey); resolve(v); };
    const pick=b=>close(b.value==="__input__"?(root.querySelector("#_mi")?root.querySelector("#_mi").value:null):b.value);
    function onkey(e){ if(e.key==="Escape"){const b=buttons.find(x=>x.esc); if(b){e.preventDefault();pick(b);}} else if(e.key==="Enter"){const b=buttons.find(x=>x.enter); if(b){e.preventDefault();pick(b);}} }
    root.innerHTML=`<div class="modal-bg"><div class="modal-box card" role="dialog" aria-modal="true">${title?`<div class="modal-h">${esc(title)}</div>`:""}<div>${body}</div><div class="modal-f"></div></div></div>`;
    const f=root.querySelector(".modal-f");
    buttons.forEach(b=>{ const btn=document.createElement("button"); btn.type="button";
      btn.className="btn"+(b.kind==="primary"?" btn-primary":"")+(b.kind==="danger"?" btn-danger":""); btn.textContent=b.label;
      btn.onclick=()=>pick(b); f.appendChild(btn); });
    root.classList.remove("hidden");
    root.querySelector(".modal-bg").addEventListener("click",e=>{ if(e.target.classList.contains("modal-bg")){const b=buttons.find(x=>x.esc); if(b)pick(b);} });
    document.addEventListener("keydown",onkey);
    const inp=root.querySelector("#_mi");
    if(inp){ inp.focus(); inp.select&&inp.select(); } else (root.querySelector(".btn-primary")||f.lastChild)?.focus();
  });
}
const _CANCEL=()=>_lang==="ru"?"Отмена":"Cancel";
function uiAlert(msg,title){ return _showModal({title:title||"",body:`<div class="modal-msg">${esc(msg)}</div>`,buttons:[{label:"OK",kind:"primary",value:true,enter:true,esc:true}]}); }
function uiConfirm(msg,title){ return _showModal({title:title||"",body:`<div class="modal-msg">${esc(msg)}</div>`,buttons:[{label:_CANCEL(),value:false,esc:true},{label:"OK",kind:"primary",value:true,enter:true}]}); }
function uiPrompt(msg,ph,val){ return _showModal({title:"",body:`<div class="modal-msg">${esc(msg)}</div><input id="_mi" class="input" style="margin-top:10px" placeholder="${esc(ph||"")}" value="${esc(val||"")}">`,buttons:[{label:_CANCEL(),value:null,esc:true},{label:"OK",kind:"primary",value:"__input__",enter:true}]}); }
const pct=n=>n==null?"—":(n*100).toFixed(1)+"%";
const ago=ts=>{if(!ts)return"—";const s=Math.floor(Date.now()/1000-ts);return s<60?s+"с":Math.floor(s/60)+"м";};
const dt=ts=>{if(!ts)return"—";const d=new Date(ts*1000);const p=n=>String(n).padStart(2,"0");return `${p(d.getDate())}.${p(d.getMonth()+1)} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;};
const esc=s=>String(s==null?"":s).replace(/[<>&]/g,c=>({"<":"&lt;",">":"&gt;","&":"&amp;"}[c]));
// esc() is for HTML-text context only. For a value interpolated into a
// single-quoted JS string inside an inline handler (onclick="f('${…}')"), esc() is
// UNSAFE — a ' or \ breaks out into arbitrary code. escJs() JS-escapes \ ' and
// newlines, then HTML-encodes the attribute-significant chars so " can't close the
// attribute either. Use escJs() wherever a value goes into an inline handler arg.
const escJs=s=>String(s==null?"":s)
  .replace(/\\/g,"\\\\").replace(/'/g,"\\'").replace(/\r?\n/g,"\\n")
  .replace(/&/g,"&amp;").replace(/"/g,"&quot;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
// escAttr: value for a double-quoted HTML attribute (esc handles &<>, then " → &quot;).
// NB: NOT escJs — an attribute read via dataset must keep a literal ', not \'.
const escAttr=s=>esc(s).replace(/"/g,"&quot;");
// окружения убраны из UI — env-скоупинг логов оставлен инертным (всегда пустой env).
const _env="";
function _withEnv(url){ return url; }

// ── i18n (en default, ru toggle) ──────────────────────────────────────────────
const I18N={en:{
  "title":"SOC Dashboard","subtitle":"traffic & attack monitoring · all domains","tagline":"traffic & attack monitor",
  "nav.dash":"Overview","nav.autoban":"Auto-ban","nav.p403":"403 rules","nav.nodes":"Nodes","nav.targets":"Resources","nav.dashboards":"Dashboards","db.new":"dashboard","db.panel":"panel","db.edit":"edit","db.preset":"+ preset…","db.export":"export","db.import":"import","tg.groups":"Groups","ing.h":"Ingress","ing.sub":"Registered ingress-nginx (k8s) backends — each is its own entity you can name, edit and remove. Its in-cluster ingress-cm targets are listed under it.","нет ingress-таргетов":"no ingress targets",
  "ing.setup":"Setup cluster","ing.setup.h":"Connect a cluster","ing.setup.sub":"Three steps: deploy blocklist-api into the cluster, wire logs into Loki, and make sure the values target points at your ingress-nginx.",
  "ing.s1":"Install blocklist-api (Helm)","ing.s1.sub":"The chart carries the RBAC to patch the ingress-nginx ConfigMap — a web form can't, Helm can. Run it with cluster-admin.","ing.s1.after":"After install, point the dashboard at the API: BLOCKLIST_API_URL=https://<hostname>",
  "ing.connect":"After install — verify the dashboard can reach this API:","ing.connect.hint":"Host and token are taken from the fields above. Save adds this ingress as an entity above — its ingress-cm targets become available for 403 / auto-ban.",
  "ing.test":"Test connection","ing.backends":"Registered connections","сохраняю…":"saving…","ошибка":"error",
  "укажи hostname выше":"enter a hostname above","проверяю":"checking","доступен, токен принят":"reachable, token accepted","нет связи":"no connection","токен не принят":"token rejected",
  "сохранено и активно":"saved and active","активно":"active","сделать активным":"make active","пока нет — проверь соединение и нажми Save":"none yet — test the connection and click Save","Удалить это подключение?":"Delete this connection?",
  "ing.f.ns":"Install namespace","ing.f.host":"block-api hostname","ing.f.cns":"Controller namespace","ing.f.ccm":"Controller ConfigMap","ing.f.ip":"Dashboard IP (whitelist)","ing.f.token":"Token","ing.gen":"generate","ing.f.loki":"Dashboard Loki push URL",
  "ing.s2":"Logs into Loki","ing.s2.sub":"The dashboard reads traffic/attacks from Loki. You need one of:","ing.s2.a":"Loki + Promtail already in the cluster","ing.s2.a2":"— then just give the dashboard access to that Loki (set its URL in the dashboard config/deploy).","ing.s2.b":"Loki only on the dashboard","ing.s2.b2":"— then install Promtail in the cluster so it ships ingress-nginx logs to the dashboard's Loki. URL below:",
  "ing.s3":"values.yaml — where the target is set","ing.s3.sub":"The ingress target IS the controller's namespace + ConfigMap pair. Same values as the command above:",
  "nav.system":"System","sys.h":"System","sys.sub":"Host running the SOC dashboard (soc-app) — its own load, memory and uptime.","нет данных о хосте":"no host data","tg.sub":"A group bundles several targets (nginx nodes + Cloudflare). 403 & auto-ban rules attach to a group and apply to all its targets at once.","tg.newname":"New group:","tg.create":"Create","tg.add":"Add","таргет":"target","нет токена":"no token","токен задан":"token set","nav.journal":"Journal","nav.logs":"Logs","nav.settings":"Settings",
  "grp.monitor":"Monitor","grp.defend":"Defend","grp.infra":"Infra","ban.quick":"Ban IP","search.ph":"Search IP → profile","window":"window","set.env":"Environments","set.cf":"CF targets","set.notify":"Notifications","set.autoban":"Auto-ban","set.global":"Global","set.account":"Account","set.users":"Users",
  "login.sub":"Sign in to continue","login.setup":"No users yet — set BASIC_AUTH_USER/PASS to seed the first admin.","login.user":"Username","login.pass":"Password","login.totp":"2FA code","login.go":"Sign in",
  "acc.h":"Your account","acc.pw":"Change password","acc.pw.cur":"Current","acc.pw.new":"New (min 8)","acc.2fa":"Two-factor (TOTP)","acc.2fa.enable":"Enable","acc.2fa.disable":"Disable","acc.2fa.scan":"Add this secret to your authenticator app, then confirm a code:","acc.2fa.code":"6-digit code","acc.2fa.confirm":"Confirm",
  "usr.h":"Users","usr.add":"Add user","usr.name":"Username","usr.pass":"Password","usr.role":"Role","usr.create":"Create","usr.reset":"reset pw",
  "cft.h":"Cloudflare targets","cft.sub":"A named Cloudflare account/zone you attach to ban groups & 403 rules like any target. Token is write-only (stored server-side, shown only as «set»).","cft.new":"New CF target",
  "env.h":"Environments","env.new":"New environment","env.sub":"Each environment is one bundle — its nodes, its Cloudflare token, its Loki, its rules and alert channels. Nodes join one at install (--env).",
  "set.global.sub":"LLM endpoint, default Cloudflare / ingress (fallback when an environment has none of its own), and the default group. ENV values are defaults; overridden here.",
  "save":"Save","delete":"Delete","edit":"Edit","env.name":"Name","env.loki":"Loki URL","env.loki.hint":"(blank = shared Loki + env label)","env.cf":"Cloudflare for this environment","env.ing":"ingress-nginx (k8s) for this environment",
  "env.ing.hint":"No cluster endpoint here: blocklist-api runs inside the cluster and patches this ConfigMap via its ServiceAccount. The dashboard only talks to blocklist-api (set by BLOCKLIST_API_URL at deploy).",
  "env":"Environment","env.all":"all","connecting":"connecting…","refresh":"refresh",
  "logs.title":"Live logs","logs.sub":"Raw nginx lines from Loki, filtered by the current environment.","logs.access":"access","logs.error":"error","logs.follow":"tail","logs.empty":"no log lines for this filter","logs.off":"log viewer needs Loki (LOKI_URL) configured",
  "logs.sources":"Sources","logs.views":"Saved views","logs.parsed":"parsed","logs.export":"export","logs.filter":"filter","logs.attacks":"attacks",
  "logs.src":"source","logs.bars":"bars","logs.lines":"lines","logs.area":"area","logs.toppaths":"top paths","logs.topips":"top IPs","logs.clickf":"· click = filter","logs.stream":"rows under filter","logs.older":"older",
  "ai.title":"AI analyst","ai.feed":"AI insights feed","llm.on":"🤖 LLM: on","llm.off":"🤖 LLM: off","llm.label":"LLM analysis","llm.hint":"When off, all AI mentions disappear from the dashboard.",
  "nf.h":"Notifications — Slack / Telegram","nf.sub":"First define channels (where to send), then rules (what & when — event × env × severity → channel).","nf.channels":"Channels","nf.rules":"Rules","nf.addrule":"＋ Rule",
  "p403.where":"Available targets:","p403.addrule":"Add rule",
  "tf.h":"Threat feeds","tf.sub":"Import external block lists (Spamhaus, Tor, custom IP/CIDR) and ban them into a group. Self-syncing: entries that leave a feed expire on their own.","tf.every":"Refresh every (h)","tf.now":"Refresh now","tf.add":"＋ feed","tf.presets":"presets:",
  "crs.h":"WAF / CRS triggers","crs.sub":"/ OWASP ModSecurity — anomaly score exceeded",
  "esc.h":"Escalation ladder","esc.sub":"Repeat offenders (re-banned after a prior ban expired) get a longer ban each time. Off = every rule uses its own fixed TTL.","esc.ladder":"TTL ladder (1st, 2nd, 3rd… offense)","esc.memory":"Forgive after (days)",
},ru:{
  "title":"SOC Дашборд","subtitle":"мониторинг трафика и атак · все домены","tagline":"монитор трафика и атак",
  "nav.dash":"Обзор","nav.autoban":"Автобан","nav.p403":"Правила 403","nav.nodes":"Ноды","nav.targets":"Ресурсы","nav.dashboards":"Дашборды","db.new":"дашборд","db.panel":"панель","db.edit":"править","db.preset":"+ пресет…","db.export":"экспорт","db.import":"импорт","tg.groups":"Группы","ing.h":"Ingress","ing.sub":"Зарегистрированные ingress-nginx (k8s) бэкенды — каждый отдельная сущность: имя, правка, удаление. Его ingress-cm таргеты показаны под ним.",
  "ing.setup":"Подключить кластер","ing.setup.h":"Подключить кластер","ing.setup.sub":"Три шага: поднять blocklist-api в кластере, наладить логи в Loki, и убедиться, что таргет в values указывает на твой ingress-nginx.",
  "ing.s1":"Установить blocklist-api (Helm)","ing.s1.sub":"Чарт несёт RBAC на патч ConfigMap'а ingress-nginx — веб-форма так не может, а helm может. Запускать с правами cluster-admin.","ing.s1.after":"После установки укажи дашборду адрес API: BLOCKLIST_API_URL=https://<хостнейм>",
  "ing.connect":"После установки — проверь, что дашборд достучится до этого API:","ing.connect.hint":"Хост и токен берутся из полей выше. Save добавляет ingress как сущность выше — его ingress-cm таргеты станут доступны для 403/автобана.",
  "ing.test":"Проверить соединение","ing.backends":"Зарегистрированные подключения",
  "ing.f.ns":"Namespace установки","ing.f.host":"Хостнейм block-api","ing.f.cns":"Namespace контроллера","ing.f.ccm":"ConfigMap контроллера","ing.f.ip":"IP дашборда (whitelist)","ing.f.token":"Token","ing.gen":"сгенерить","ing.f.loki":"Loki push URL дашборда",
  "ing.s2":"Логи в Loki","ing.s2.sub":"Дашборд читает трафик/атаки из Loki. Нужен один из вариантов:","ing.s2.a":"Loki + Promtail уже в кластере","ing.s2.a2":"— тогда просто дай дашборду доступ к этому Loki (укажи его URL в настройках/при деплое дашборда).","ing.s2.b":"Loki только на дашборде","ing.s2.b2":"— тогда поставь Promtail в кластер, чтобы он слал логи ingress-nginx в Loki дашборда. URL ниже:",
  "ing.s3":"values.yaml — где указывается таргет","ing.s3.sub":"Таргет ingress — это и есть пара «namespace + ConfigMap контроллера». Те же значения, что в команде выше:",
  "nav.system":"Система","sys.h":"Система","sys.sub":"Хост, на котором крутится SOC-дашборд (soc-app) — его нагрузка, память и аптайм.","tg.sub":"Группа — набор таргетов (nginx-ноды + Cloudflare). Правила 403 и автобан привязываются к группе и применяются сразу ко всем её таргетам.","tg.newname":"Новая группа:","tg.create":"Создать","tg.add":"Добавить","nav.journal":"Журнал","nav.logs":"Логи","nav.settings":"Настройки",
  "grp.monitor":"Мониторинг","grp.defend":"Защита","grp.infra":"Инфра","ban.quick":"Бан IP","search.ph":"Поиск IP → профиль","window":"окно","set.env":"Окружения","set.cf":"CF-таргеты","set.notify":"Уведомления","set.autoban":"Автобан","set.global":"Глобальные","set.account":"Аккаунт","set.users":"Пользователи",
  "login.sub":"Войдите, чтобы продолжить","login.setup":"Пользователей нет — задай BASIC_AUTH_USER/PASS для первого админа.","login.user":"Логин","login.pass":"Пароль","login.totp":"Код 2FA","login.go":"Войти",
  "acc.h":"Ваш аккаунт","acc.pw":"Смена пароля","acc.pw.cur":"Текущий","acc.pw.new":"Новый (мин 8)","acc.2fa":"Двухфакторка (TOTP)","acc.2fa.enable":"Включить","acc.2fa.disable":"Выключить","acc.2fa.scan":"Добавь этот секрет в приложение-аутентификатор и подтверди кодом:","acc.2fa.code":"6-значный код","acc.2fa.confirm":"Подтвердить",
  "usr.h":"Пользователи","usr.add":"Добавить","usr.name":"Логин","usr.pass":"Пароль","usr.role":"Роль","usr.create":"Создать","usr.reset":"сброс пароля",
  "cft.h":"Cloudflare-таргеты","cft.sub":"Именованный аккаунт/зона Cloudflare, который привязывается к группам и 403-правилам как любой таргет. Токен write-only (хранится на сервере, показывается только как «задан»).","cft.new":"Новый CF-таргет",
  "env.h":"Окружения","env.new":"Новое окружение","edit":"Изменить","env.sub":"Каждое окружение — связка: свои ноды, свой Cloudflare-токен, свой Loki, свои правила и каналы уведомлений. Ноды вступают при установке (--env).",
  "env.ing.hint":"Эндпоинт кластера тут не нужен: blocklist-api работает внутри кластера и патчит этот ConfigMap через свой ServiceAccount. Дашборд общается только с blocklist-api (адрес задаётся в BLOCKLIST_API_URL при деплое).",
  "set.global.sub":"LLM-эндпоинт, дефолтный Cloudflare/ingress (фолбэк, если у env нет своего), и группа по умолчанию. ENV — дефолты, тут переопределяются.",
  "save":"Сохранить","delete":"Удалить","env.name":"Название","env.loki":"Loki URL","env.loki.hint":"(пусто = общий Loki + метка env)","env.cf":"Cloudflare для этого окружения","env.ing":"ingress-nginx (k8s) для этого окружения",
  "env":"Окружение","env.all":"все","connecting":"подключение…","refresh":"обновить",
  "logs.title":"Логи в реальном времени","logs.sub":"Сырые строки nginx из Loki, фильтр по текущему окружению.","logs.access":"доступ","logs.error":"ошибки","logs.follow":"хвост","logs.empty":"нет строк под фильтр","logs.off":"для просмотра логов нужен настроенный Loki (LOKI_URL)",
  "logs.sources":"Источники","logs.views":"Сохранённые виды","logs.parsed":"таблица","logs.export":"экспорт","logs.filter":"фильтр","logs.attacks":"атаки",
  "logs.src":"источник","logs.bars":"бары","logs.lines":"линии","logs.area":"площадь","logs.toppaths":"топ путей","logs.topips":"топ IP","logs.clickf":"· клик = фильтр","logs.stream":"строки под фильтром","logs.older":"старше",
  "ai.title":"AI-аналитик","ai.feed":"Лента AI-инсайтов","llm.on":"🤖 LLM: вкл","llm.off":"🤖 LLM: выкл","llm.label":"AI-разбор (LLM)","llm.hint":"Когда выключен, все упоминания AI исчезают с дашборда.",
  "nf.h":"Уведомления — Slack / Telegram","nf.sub":"Сначала задай каналы (куда слать), затем правила (что и при каких условиях — событие × env × важность → канал).","nf.channels":"Каналы","nf.rules":"Правила","nf.addrule":"＋ Правило",
  "p403.where":"Доступные таргеты:","p403.addrule":"Добавить правило",
  "tf.h":"Threat-фиды","tf.sub":"Импорт внешних блок-листов (Spamhaus, Tor, свои IP/CIDR) и бан в группу. Самосинхронизация: ушедшие из фида записи истекают сами.","tf.every":"Обновлять каждые (ч)","tf.now":"Обновить сейчас","tf.add":"＋ фид","tf.presets":"пресеты:",
  "crs.h":"WAF / CRS срабатывания","crs.sub":"/ OWASP ModSecurity — превышен anomaly score",
  "esc.h":"Лестница эскалации","esc.sub":"Повторные нарушители (забанены снова после истечения прошлого бана) получают всё более длинный бан. Выкл = у каждого правила свой фиксированный TTL.","esc.ladder":"Лестница TTL (1-е, 2-е, 3-е… нарушение)","esc.memory":"Прощать через (дней)",
}};
let _lang="en"; try{localStorage.removeItem("soc_lang");}catch(e){}  /* English-only: RU removed */
function t(k){ return (I18N[_lang]&&I18N[_lang][k])||I18N.en[k]||k; }
function applyI18n(){
  document.querySelectorAll("[data-i18n]").forEach(el=>{ el.textContent=t(el.getAttribute("data-i18n")); });
  document.querySelectorAll("[data-i18n-ph]").forEach(el=>{ el.placeholder=t(el.getAttribute("data-i18n-ph")); });
  const lb=document.getElementById("lang-btn"); if(lb)lb.textContent=_lang.toUpperCase();
  document.documentElement.lang=_lang;
}
function toggleLang(){ _lang=_lang==="en"?"ru":"en"; localStorage.setItem("soc_lang",_lang); location.reload(); }

// ── backend fan-out scope (whole fleet vs one blocklist-api) ──────────────────
let _scope="__all__", _backends=[];
// No backend picker in the GUI: reads always fan out across ALL blocklist-api
// instances and their targets appear as one flat set of entities (nginx / CF /
// ingress), exactly like any other target. This only loads the fleet list for the
// passive health indicator + internal routing — it never lets you "switch backend".
async function loadScope(){
  try{
    const d=await fetch("/api/backend_scope").then(r=>r.json());
    _scope="__all__"; _backends=d.backends||[];
    loadBackendHealth();
  }catch(e){}
}
// small per-row badge naming the backend(s) a row came from (only when fleet>1).
// accepts a string or an array (a CIDR deduped across several backends).
function _beBadge(b){
  if(!b||_backends.length<2)return "";
  const arr=(Array.isArray(b)?b:[b]).filter(Boolean);
  return arr.map(x=>`<span class="text-[9px] px-1 py-0.5 rounded bg-slate-800 text-slate-400 mono ml-1" title="backend">${esc(_beName(x))}</span>`).join("");
}
// human-readable backend name. The implicit HOME backend (id "__home__") owns the
// local nginx nodes / CF — show it as the "worker" (lives in the System section),
// not the reserved id / raw URL. Registry backends prefer their friendly name.
function _beName(id){ if(id==="__home__")return _trText("worker"); const b=(_backends||[]).find(x=>x.id===id); return (b&&b.name)||id; }
// fleet health indicator + "data may be incomplete" warning when a backend is down
async function loadBackendHealth(){
  const el=document.getElementById("be-health"); if(!el)return;
  if(_backends.length<2){ el.classList.add("hidden"); return; }
  try{
    const d=await fetch("/api/backends/health").then(r=>r.json());
    const bes=d.backends||[]; const bad=bes.filter(b=>!b.reachable||b.token_ok===false);
    if(!bad.length){
      el.className="text-[11px] px-1.5 py-0.5 rounded bg-emerald-900/40 text-emerald-400";
      el.textContent="● "+bes.length; el.title=bes.map(b=>`${_beName(b.id)}: ${b.latency_ms}ms`).join("\n");
    }else{
      el.className="text-[11px] px-1.5 py-0.5 rounded bg-rose-900/50 text-rose-300";
      el.textContent="⚠ "+bad.length+"/"+bes.length;
      el.title=bad.map(b=>`${_beName(b.id)}: ${b.error||(b.token_ok===false?"токен не принят":"недоступен")}`).join("\n")
        +"\n— данные ниже могут быть неполными";
    }
    el.classList.remove("hidden");
  }catch(e){ el.classList.add("hidden"); }
}

// ── live RU→EN translation (en default; ru shows source). Covers dynamically
// rendered content via a MutationObserver, so no need to refactor every string. ──
const RU2EN={
  "нет лейблов":"no labels","строк":"rows","забанить IP":"ban IP","путь в 403":"path → 403","открой 403 и добавь путь":"open 403 and add the path","следим…":"following…","Название вида:":"View name:",
  "нет дашбордов":"no dashboards","пусто — добавь панель":"empty — add a panel","мало точек":"not enough points","Поиск в логах":"Logs search","Имя дашборда:":"Dashboard name:","Удалить дашборд?":"Delete dashboard?","Новая панель":"New panel","Панель":"Panel","Заголовок":"Title","Тип":"Type","Метрика":"Metric","Метрики":"Metrics","Источник (топ)":"Source (top-list)","Ширина":"Width","Высота":"Height","Заливка area":"Area fill","Цвета серий":"Series colors","Пороговые линии":"Thresholds","порог":"threshold","выберите метрики":"pick metrics","Полоса аномалий":"Anomaly band","прочее":"other","нет строк под фильтр":"no rows match","не удалось сохранить: ":"save failed: ","не похоже на дашборд":"not a dashboard file","не удалось импортировать: ":"import failed: ",
  // _trText-consumed strings mistakenly added only to I18N (leaked Russian in EN) — now in RU2EN
  "Удалить это подключение?":"Delete this connection?","доступен, токен принят":"reachable, token accepted","нет ingress-таргетов":"no ingress targets","нет данных о хосте":"no host data","нет связи":"no connection","нет токена":"no token","пока нет — проверь соединение и нажми Save":"none yet — test the connection and click Save","проверяю":"checking","сделать активным":"make active","сохранено и активно":"saved and active","таргет":"target","токен задан":"token set","токен не принят":"token rejected","укажи hostname выше":"enter a hostname above",
  "нет связи: ":"no connection: ","пустой URL":"empty URL","токен не принят (HTTP ":"token rejected (HTTP ","не удалось определить id из URL":"couldn't determine id from the URL","подключение не найдено":"connection not found","ошибка запроса /targets: ":"/targets request error: ",
  "окно:":"window:","🔍 поиск IP → профиль":"🔍 search IP → profile","загрузка…":"loading…","загрузка":"loading",
  "ошибка:":"error:","ошибка":"error","ошибка проверки:":"check error:","не удалось:":"failed:","сохраняю…":"saving…",
  "сохранено":"saved","сохранить":"save","Сохранить":"Save","удалить":"delete","удалён":"deleted","отмена":"cancel",
  "обновить":"refresh","проверяю…":"checking…","Проверить подключение":"Check connection","тест":"test","вкл":"on","выкл":"off",
  "включить":"enable","выключить":"disable","включено":"enabled","включена":"enabled","выключена":"disabled","активно":"active","пауза":"pause","нет данных":"no data",
  "никогда":"never","назад":"ago","всего":"total","Всего:":"Total:","Заблок.:":"Blocked:","причина":"reason","группы:":"groups:",
  "дефолтная группа:":"default group:","группа по умолч.":"default group","по умолчанию":"default","все":"all","все домены":"all domains",
  "мониторинг трафика и атак":"traffic & attack monitoring","подключение…":"connecting…","онлайн":"online","офлайн":"offline",
  "Проблемы в обработке":"Processing problems","недоступен":"unreachable","не готов":"not ready","запрос не прошёл":"query failed",
  "обновлены":"updated","Данные":"Data","Правила 403":"403 rules","рендер":"render","дрейф!":"drift!","акт.":"act.",
  "AI-аналитик":"AI analyst","AI-разбор":"AI insight","Лента AI-инсайтов":"AI insights feed","AI-разбор выключен":"AI insight off",
  "Кандидаты в бан":"Ban candidates","Подозрительные IP":"Suspicious IPs","Активные блокировки":"Active blocks","Кто и что":"Who & what",
  "Заблокировать":"Block","разблокировать":"unblock","забанить":"ban","забанен":"banned","разбанен":"unbanned","бан":"ban","разбан":"unban",
  "истёк TTL":"TTL expired","причина бана":"ban reason","навсегда":"forever","профиль":"profile","оператор":"operator",
  "автобан":"auto-ban","Автобан":"Auto-ban","система":"system","Создать новое правило":"Create a rule","Редактировать правило":"Edit rule",
  "укажи путь":"set a path","нужно имя":"name required","укажи путь/паттерн":"set a path/pattern","превью":"preview",
  "считаю (Loki)…":"computing (Loki)…","основное":"primary","сделать основным":"make primary","ред.":"edit","Правил пока нет.":"No rules yet.",
  "Создай первое слева.":"Create your first on the left.","семейство:":"family:","путь":"path","код":"code","бан ":"ban ",
  "Включить автобан":"Enable auto-ban","Автобан включён":"Auto-ban on","Выключен":"Off","Исполнитель не подключён":"Executor not wired",
  "Ноды":"Nodes","Подключённые ноды":"Connected nodes","Добавить ноду":"Add node","отозвать":"revoke","баны на ноде":"bans on node",
  "пока нет подключённых нод.":"no connected nodes yet.","Установка агента на nginx-VM":"Agent install on the nginx VM",
  "nginx-VM с агентом soc-nginx-agent — откуда собираем трафик и куда применяем bans.":"nginx VMs running soc-nginx-agent — where traffic is read and bans are applied. The dashboard host itself is shown first.",
  "пока нет подключённых нод. Нажми «+ Добавить ноду».":"no connected nodes yet. Click “+ Add node”.","нет нод в этом env.":"no nodes in this env.",
  "дашборд":"dashboard","роль":"role","важность ≥":"severity ≥","(любой)":"(any)",
  "Пока нет каналов — добавь Slack или Telegram выше.":"No channels yet — add Slack or Telegram above.",
  "Пока нет правил — добавь правило, чтобы события попадали в канал.":"No rules yet — add one so events reach a channel.","blocklist-api не настроен.":"blocklist-api not configured.",
  "IP + 403-пути":"IP + 403 paths","только IP":"IP only","нода":"node",
  "нет nginx/ingress таргетов — добавь ноду или включи ingress у env.":"no nginx/ingress targets — add a node or enable ingress for the env.",
  "Cloudflare не применяет 403 по пути (только IP):":"Cloudflare doesn't apply path-403 (IP only):",
  "Список строится автоматически: nginx-file — это подключённые ноды, cloudflare и ingress-cm — из настроек окружения.":"The list is built automatically: nginx-file = connected nodes, cloudflare and ingress-cm = from environment settings.",
  "настраивается:":"managed in:","В правило":"Into rule","В какое правило дописать паттерн (одно правило = группа путей)":"Which rule to append the pattern to (one rule = a group of paths)",
  "все таргеты":"all targets","Таргет-группа":"Target group","к какой таргет-группе применяется это правило":"which target group this rule applies to","Куда применять (таргет-группа). Только для нового правила.":"Where to apply (target group). New rule only.",
  "Таргет-группы":"Target groups","удалить группу":"delete group","+ таргет…":"+ target…","пусто":"empty",
  "пока нет своих групп. Создай группу и добавь в неё таргеты.":"no custom groups yet. Create one and add targets.",
  "Группа — это набор таргетов. Правила 403 и автобан применяются к выбранной группе. (Окружения уже сами по себе группы; тут — свои произвольные.)":"A group is a set of targets. 403 rules & auto-ban apply to the chosen group. (Environments are already groups; these are your own arbitrary ones.)",
  "имя группы, напр. nginx1":"group name, e.g. nginx1","＋ группа":"＋ group",
  // ── 403 view static strings ──
  "Правила 403 — блокировка по пути":"403 rules — block by path","блокировка по пути":"block by path",
  "Пути, которые сразу отдают ":"Paths that immediately return ","Это ":"This is ","не бан IP":"not an IP ban",
  "(сканеры/эксплойты:":"(scanners/exploits:"," — режется сам путь, на всех доменах окружения.":" — the path itself is cut, on all domains of the environment."," — режется сам путь, на всех привязанных таргетах.":" — the path itself is cut, on all attached targets.",
  "содержит":"contains","секция:":"section:","поиск по имени / паттерну…":"search by name / pattern…",
  "сгенерится regex:":"generated regex:","проверь на примере — забанит или нет:":"test on an example — blocked or not:",
  "засеять из правил автобана":"seed from auto-ban rules","базовый набор сканеров":"basic scanner set","автобана":"auto-ban","Автобане":"Auto-ban","(подстрока)":"(substring)",
  "напр. env-файлы":"e.g. env files","новое":"new","＋ новое правило":"＋ new rule","— меняются в ":"— managed in ",
  "пусто — добавь правило, засей из автобана или базовый набор.":"empty — add a rule, seed from auto-ban, or use the basic set.",
  "🛡️ защищённые (в 403 добавить нельзя, общий список с автобаном): ":"🛡️ protected (can't add to 403, shared list with auto-ban): ",
  // ── auto-ban view static strings ──
  "Механизм автобана":"Auto-ban engine","ручной бан в группу:":"manual ban to group:","Защищённые пути":"Protected paths",
  "— автобан их НИКОГДА не банит, и в 403 их добавить НЕЛЬЗЯ (общий предохранитель)":"— auto-ban NEVER bans these, and they CAN'T be added to 403 (shared safety net)",
  "+ добавить":"+ add","/новый/путь":"/new/path","Готовые пути":"Preset paths",
  "— клик добавит путь в условие правила (ИЛИ)":"— click adds the path to the rule condition (OR)",
  "кого бы забанило · реального бана нет":"who would be banned · no real ban","кого бы забанило":"who would be banned",
  "Секреты / dotfiles":"Secrets / dotfiles","Админки / БД":"Admin panels / DB","Конфиги / бэкапы":"Configs / backups","CVE / роутеры / RCE":"CVE / routers / RCE",
  "blocklist-api не настроен — баны отключены.":"blocklist-api not configured — bans disabled.",
  "таргеты не заданы — забань ноду в окружение или включи Cloudflare у env.":"no targets — assign a node to an environment or enable Cloudflare for the env.",
  "дефолтная группа:":"default group:","Превью":"Preview",
  "частота: любой путь":"rate: any path","нет фидов — добавь свой или возьми из пресетов ниже.":"no feeds — add your own or pick a preset below.",
  "страны (опц.)":"countries (opt.)","CN, RU — пусто = любая":"CN, RU — empty = any",
  "сработок WAF":"WAF triggers","за CF":"behind CF","бан":"ban","чисто — срабатываний WAF нет за окно":"clean — no WAF triggers in window",
  "применяется к":"applies to","все таргеты":"all targets","группа":"group","нет таргетов":"no targets","нет nginx/ingress таргетов":"no nginx/ingress targets",
  "не привязано — правило не действует":"not attached — rule does nothing","привязка":"attach","+ привязать…":"+ attach…","убрать":"remove","группы":"groups","таргеты":"targets","паттерн":"pattern",
  "подключённая нода":"connected node","Cloudflare окружения":"environment Cloudflare","ingress окружения":"environment ingress",
  "Cloudflare-таргет":"Cloudflare target","Настройки → CF-таргеты":"Settings → CF targets","ingress-cm таргет":"ingress-cm target",
  "Настройки → Окружения":"Settings → Environments","Настройки → Глобальные":"Settings → Global","задан в BAN_TARGETS":"defined in BAN_TARGETS",
  "открыть во вкладке Ноды":"open in the Nodes tab","источник":"source","подключённая нода — открыть во вкладке Ноды":"connected node — open in the Nodes tab",
  "нет бэкендов":"no backends","таргетов":"targets","нечего привязать":"nothing to attach","привязать":"attach","Cloudflare WAF — 403 по пути на edge":"Cloudflare WAF — path-403 at the edge","через какие бэкенды эта группа применяет баны/403":"which backends this group enforces bans/403 through",
  "повторные нарушители":"repeat offenders","повторных нарушителей пока нет":"no repeat offenders yet",
  "осталось до авто-разбана":"time left until auto-unban","истекает…":"expiring…",
  "обновляю…":"refreshing…","забанено: ":"banned: ",
  "волна":"wave","показать строки":"show rows","забанить все":"ban all","в основном":"mostly","Итог окна":"Window summary","всплеск(ов) 5xx":"5xx spike(s)","последний":"last","без всплесков":"no spikes","уник. IP":"uniq IP","не удалось":"failed","трафик":"traffic","Запись":"Record","этот IP за 24ч":"this IP over 24h","ошибок":"errors","все ноды":"all nodes","все кластеры":"all clusters","запросов":"requests","запр/мин":"req/min","используется LOKI_URL по умолчанию — можно добавить ещё Loki":"using default LOKI_URL — you can add more Loki sources","путь":"path","страна":"country",
  "Банит IP по числу запросов за окно — без привязки к пути (флуд / перебор / скрейпинг). Код ответа ниже можно оставить пустым или сузить, напр. 404.":"Bans an IP by request count over the window — no path needed (flood / brute-force / scraping). The status code below can stay empty or be narrowed, e.g. 404.",
  "Выключен — ни одно правило не банит (правила можно настраивать, превью работает).":"Off — no rule bans (rules are editable, preview works).",
  "Исполнитель не подключён — реального бана нет.":"Executor not wired — no real ban.","Заполни условие и нажми «Превью».":"Fill the condition and hit “Preview”.",
  "Журнал действий":"Action journal","все действия":"all actions","баны":"bans","разбаны":"unbans","истёкшие (TTL)":"expired (TTL)",
  "только с ошибкой":"errors only","применено":"applied","нет записей под фильтр.":"no records for this filter.",
  "Настройки":"Settings","Окружения":"Environments","Уведомления":"Notifications","Глобальные":"Global","Глобальные настройки":"Global settings",
  "Окружение":"Environment","Название":"Name","Каналы":"Channels","Правила":"Rules","канал":"channel","правило":"rule","метка":"label",
  "важность":"severity","событие":"event","нет каналов":"no channels","нет правил":"no rules","задан":"set","не задан":"not set",
  "только через ENV":"ENV only","Куда применяются баны":"Where bans apply","таргеты":"targets","окружение":"environment",
  "не задан в blocklist-api":"not set in blocklist-api","команда недоступна":"command unavailable","не настроен":"not configured",
  "Скопировать":"Copy","дней":"days","день":"day","с назад":"s ago","м назад":"m ago","ч назад":"h ago","д назад":"d ago",
  // ── batch 2: dashboard labels ──
  "Дашборд":"Dashboard","Журнал":"Journal","Логи":"Logs","Все":"All","Найти":"Find","Добавить":"Add","Добавить правило":"Add rule",
  "Имя":"Name","Имя правила":"Rule name","Тип":"Type","Путь":"Path","Условие":"Condition","Форма":"Form","Что сделать":"What to do",
  "На что смотреть":"What to watch","Почему сработало":"Why it fired","Денлист":"Denylist","Динамика":"Trend","География":"Geography",
  "Доступность":"Availability","Запросы":"Requests","Статусы":"Statuses","Статусы ответов":"Response statuses","Карта угроз":"Threat map",
  "Сигнатуры атак":"Attack signatures","Типы атак":"Attack types","Топ IP":"Top IPs","Топ путей":"Top paths","Топ доменов":"Top domains",
  "Топ User-Agent":"Top User-Agents","Топ talkers":"Top talkers","Топ атакуемых путей":"Top attacked paths","Медленные эндпоинты":"Slow endpoints",
  "Производительность и нагрузка":"Performance & load","Обзор запросов":"Requests overview","Разбор трафика":"Traffic breakdown",
  "Трафик по доменам":"Traffic by domain","Подозрительная активность":"Suspicious activity","Предложения по защите":"Defense suggestions",
  "Механизм автобана":"Auto-ban engine","Правила автобана":"Auto-ban rules","Активные правила":"Active rules","Готовые пути":"Preset paths",
  "Логи автобана":"Auto-ban log","Просятся в бан":"Want banning","Список пуст.":"List is empty.","Список пуст — банить некого.":"List empty — nobody to ban.",
  "Забанить":"Ban","Забанить ВСЕХ":"Ban ALL","Разбанить":"Unblock","Проверить":"Check","Проверить IP":"Check IP","Снять блок с":"Unblock",
  "Сохранить правило":"Save rule","Сохранить из JSON":"Save from JSON","Редактировать правило #":"Edit rule #","Удалить правило #":"Delete rule #",
  "Удалить правило 403?":"Delete the 403 rule?","Удалить окружение «":"Delete environment «","Отозвать токен ноды «":"Revoke node token «",
  "Группа (куда банить)":"Group (where to ban)","Куда применяются баны (таргеты)":"Where bans apply (targets)","Атакующих IP":"Attacker IPs",
  "Атак. IP":"Attacker IPs","Уник. IP":"Unique IPs","Реальных":"Real","Вредного":"Malicious","Доля вредного трафика":"Malicious traffic share",
  "Заблокировано новых":"Newly blocked","Заблокировано:":"Blocked:","Забанено:":"Banned:","Забанило бы":"Would ban","Запросов ≥":"Requests ≥",
  "Запросов/5м":"Requests/5m","Трафик / 5м":"Traffic / 5m","Трафик, МБ":"Traffic, MB","Латентность p95, c":"Latency p95, s","Латентность p95":"Latency p95",
  "Ошибки 4xx":"4xx errors","Время ответа":"Response time","за окно":"over window","за CF":"behind CF","всего/1ч":"total/1h",
  "Ждём первый разбор от LLM…":"Waiting for the first LLM verdict…","генерирую… (LLM ~30с)":"generating… (LLM ~30s)",
  "Конкретных правил не предложено.":"No specific rules suggested.","заблокировано (403)":"blocked (403)","заблокировано":"blocked",
  "ingress вернул 403":"ingress returned 403","ingress на":"ingress on","на ingress":"on ingress","активных блокировок нет":"no active blocks",
  "Активные блокировки":"Active blocks","Новые блоки":"New blocks","Снято блокировок:":"Blocks removed:","Ресинк выполнен. Активных правил:":"Resync done. Active rules:",
  "введи IP":"enter IP","введи IP/CIDR":"enter IP/CIDR","введи путь":"enter path","нет":"no","внимание":"attention","вредонос":"malware","время":"time",
  "Создать новое правило":"Create a rule","Превью (dry-run)":"Preview (dry-run)","Заполни условие и нажми «Превью».":"Fill the condition and hit «Preview».",
  "нет связи с Loki":"no connection to Loki","нет строк под фильтр":"no lines for this filter","нет таргетов.":"no targets.","нет нод в этом env.":"no nodes in this env.",
  "нет запросов за окно":"no requests in window","нет примеров за окно":"no samples in window","ничего не найдено":"nothing found","Нет IP в результате":"No IPs in the result",
  "критично":"critical","легит-бот":"legit bot","геолокация":"geolocation","детали недоступны":"details unavailable","дайджест недоступен":"digest unavailable",
  "история (audit):":"history (audit):","каналы":"channels","имя:":"name:","истекает":"expires","код (404)":"code (404)","код (опц.)":"code (opt.)",
  "Подсеть ·":"Subnet ·","Топ IP ·":"Top IPs ·","Путь ·":"Path ·","Профиль ·":"Profile ·","Поиск ·":"Search ·","Домен ·":"Domain ·",
  // time windows
  "15 мин":"15 min","30 мин":"30 min","1 час":"1 hour","3 часа":"3 hours","6 часов":"6 hours","8 часов":"8 hours","24 часа":"24 hours","7 дней":"7 days","30 дней":"30 days",
  // countries
  "Австралия":"Australia","Австрия":"Austria","Азербайджан":"Azerbaijan","Армения":"Armenia","Беларусь":"Belarus","Бельгия":"Belgium","Болгария":"Bulgaria",
  "Бразилия":"Brazil","Великобритания":"United Kingdom","Венгрия":"Hungary","Вьетнам":"Vietnam","Германия":"Germany","Гонконг":"Hong Kong","Греция":"Greece",
  "Грузия":"Georgia","Дания":"Denmark","Израиль":"Israel","Индия":"India","Индонезия":"Indonesia","Ирландия":"Ireland","Испания":"Spain","Италия":"Italy",
  "Казахстан":"Kazakhstan","Канада":"Canada","Китай":"China","Корея":"Korea","Латвия":"Latvia","Литва":"Lithuania","Мексика":"Mexico","Молдова":"Moldova",
  "Нидерланды":"Netherlands","Норвегия":"Norway","Польша":"Poland","Португалия":"Portugal","Россия":"Russia","Румыния":"Romania","Сингапур":"Singapore",
  "Турция":"Turkey","Украина":"Ukraine","Финляндия":"Finland","Франция":"France","Чехия":"Czechia","Швейцария":"Switzerland","Швеция":"Sweden","Эстония":"Estonia","Япония":"Japan",
  "США":"USA","ОАЭ":"UAE","ЮАР":"South Africa",
  // status badge (uppercased) + chart legends + misc
  "СПОКОЙНО":"CALM","ВНИМАНИЕ":"NOTICE","ТРЕВОГА":"ALERT","КРИТИЧНО":"CRITICAL",
  "статусы:":"statuses:","всего":"total","реальный":"real","новые блоки":"new blocks","денлист":"denylist",
  // ── batch 3: audit sweep — dynamic strings that were leaking Russian in EN ──
  // §0: ingress-API registry (were misplaced in I18N, consumed via _trText→RU2EN)
  "нет ingress-таргетов":"no ingress targets","укажи hostname выше":"enter a hostname above","проверяю":"checking",
  "доступен, токен принят":"reachable, token accepted","нет связи":"no connection","токен не принят":"token rejected",
  "сохранено и активно":"saved and active","сделать активным":"make active","Удалить это подключение?":"Delete this connection?",
  "пока нет — проверь соединение и нажми Save":"none yet — test the connection and click Save",
  "нет данных о хосте":"no host data","нет токена":"no token","токен задан":"token set","таргет":"target",
  // §5: dashboard / search / forms
  "Изменить название и иконку":"Edit name and icon","Спросить словами: «404 на /admin за 30 минут»":"Ask in words: “404 on /admin in 30 minutes”",
  "хост (example.com)":"host (example.com)","за какое время":"over what period","IP или CIDR (напр. 203.0.113.0/24)":"IP or CIDR (e.g. 203.0.113.0/24)",
  "перечитать денлист в ingress (после kubectl apply)":"re-read the denylist in ingress (after kubectl apply)","поиск по IP/причине…":"search by IP/reason…",
  "окно анализа":"analysis window","форс-перепроверка ИИ (игнор кэша)":"force AI re-check (ignore cache)","окно":"window",
  "выгрузить текущую форму как JSON":"export the current form as JSON","напр. WP-login brute":"e.g. WP-login brute",
  "кого бы забанило (dry-run, без бана)":"who would be banned (dry-run, no ban)","IP (напр. 203.0.113.45)":"IP (e.g. 203.0.113.45)",
  "Куда применять: к какой группе таргетов (нод/ingress). Пусто = все.":"Where to apply: which target group (nodes/ingress). Empty = all.",
  "добавить, даже если апка считает паттерн слишком широким":"add even if the app thinks the pattern is too broad",
  "Вместо создания нового правила дописать паттерн в существующее (одно правило = пачка путей)":"Append the pattern to an existing rule instead of creating a new one (one rule = a batch of paths)",
  "🔎 поиск в строках…":"🔎 search in lines…","монитор трафика и атак":"traffic & attack monitor","спокойно":"calm","тревога":"alert","Отмена":"Cancel",
  "скрытые карточки:":"hidden cards:","— не определено":"— undefined","⚠ атака":"⚠ attack","карта не загрузилась (CDN недоступен)":"map failed to load (CDN unavailable)",
  "ошибка карты:":"map error:","✓ доверенный:":"✓ trusted:","☁ Это адрес":"☁ This is the address of",
  ", а не реального посетителя. Бан бесполезен — реальный клиент скрыт за фларой (в":", not the real visitor. Banning is useless — the real client is hidden behind Cloudflare (in",
  "). Смотри реальный IP в запросах ниже.":"). See the real IP in the requests below.",
  "4xx кроме 403 — 404/422/429 и т.п. (не блок, ошибки запроса)":"4xx except 403 — 404/422/429 etc. (not a block, request errors)","сеть:":"network:",
  "⛔ бан бесполезен (Cloudflare)":"⛔ ban useless (Cloudflare)","⛔ заблокировать на ingress":"⛔ block on ingress",
  "Будет возвращаться 403 для этого источника.":"It will return 403 for this source.","(активно правил:":"(active rules:","Не удалось:":"Failed:",
  "IP или CIDR для бана:":"IP or CIDR to ban:","только автобан":"auto-ban only",
  "blocklist-api не настроен (BLOCKLIST_API_URL пуст) — кнопки блокировки отключены.":"blocklist-api not configured (BLOCKLIST_API_URL empty) — block buttons disabled.",
  "ошибка загрузки денлиста":"denylist load error","✓ просмотрено":"✓ reviewed","пометить":"mark","снять отметку «просмотрено»":"unmark “reviewed”",
  "пометить просмотренным":"mark as reviewed","сканер":"scanner","юзер":"user","подозрит.":"susp.","профиль / вся инфа":"profile / all info",
  "хитов 4xx":"4xx hits","хитов":"hits","подозрительно:":"suspicious:","подозрительная активность":"suspicious activity","считаю…":"computing…",
  "чисто — реальных сканеров нет за окно (":"clean — no real scanners in window (","за Cloudflare (реальный IP скрыт)":"behind Cloudflare (real IP hidden)",
  "ошибка загрузки":"load error","Снять ВСЕ блокировки с ingress?":"Remove ALL blocks from ingress?",
  "(статический deny-список приложения не затрагивается)":"(the app's static deny-list is untouched)","Каждый будет получать 403.":"Each will get 403.",
  "Активных правил:":"Active rules:","ошибок 4xx":"4xx errors","чисто — аномальных 4xx нет за окно (":"clean — no anomalous 4xx in window (",
  "Все уже оценены — жми «Переоценить» для форс-перепроверки.":"All already assessed — hit “Re-assess” to force a recheck.","подозрительных IP на ingress?":"suspicious IPs on ingress?",
  "… (несколько секунд)":"… (a few seconds)","Полный отчёт: проверки SSL, заголовков, безопасности, DNS, портов, стека.":"Full report: SSL, headers, security, DNS, ports, stack checks.",
  "Атака":"Attack","Ошибка:":"Error:","⤓ экспорт всех IP":"⤓ export all IPs","ошибка запроса":"request error","отдано:":"served:",
  "забанить IP из результата на ingress (403)":"ban result IPs on ingress (403)","поиск…":"search…","все коды (":"all codes (",
  "уже забанен на ingress (правило":"already banned on ingress (rule","из «показать запросы»":"from “show requests”","IP уже забанены на ingress.":"IPs already banned on ingress.",
  "новых IP на ingress?":"new IPs on ingress?","уже забанены — пропущу)":"already banned — will skip)",
  "пропущено (доверенные/приватные):":"skipped (trusted/private):","уже было:":"already present:","Сначала «Найти» — нет результатов для экспорта":"Hit “Find” first — no results to export",
  "🤖 разбираю запрос… (LLM)":"🤖 parsing the query… (LLM)","LLM понял так:":"LLM understood it as:","404 (перебор путей)":"404 (path brute-force)",
  "5xx (сервер)":"5xx (server)","CRS-пейлоады (SQLi/XSS)":"CRS payloads (SQLi/XSS)","— было ~":"— was ~",", рост ×":", growth ×","(раньше почти не было)":"(almost none before)",
  "⚠️ Часть трафика доходит до приложения — стоит разобраться (детали ниже).":"⚠️ Some traffic reaches the app — worth investigating (details below).",
  "✅ Атака отбита: всплеск — это заблокированный трафик (deny/403), до сайта он не дошёл. Срочных действий не требуется.":"✅ Attack repelled: the spike is blocked traffic (deny/403), it never reached the site. No urgent action needed.",
  "проходит":"passes","блокируется":"blocked","Лента AI-разборов":"AI insights feed","— клик, чтобы развернуть «почему»":"— click to expand “why”","мс":"ms",
  "(топы за":"(tops over","— больше окно упирается в лимит Loki)":"— a larger window hits the Loki limit)","Дашборд не получает данные от backend (":"Dashboard isn't receiving data from the backend (",
  "⚠ Замечено":"⚠ Noticed","✅ Рекомендации":"✅ Recommendations","ошибка генерации":"generation error","возобновить":"resume","пауза авто-обновления":"pause auto-refresh",
  "свернуть/развернуть":"collapse/expand","удалено правило 403":"403 rule deleted","переключатель 403":"403 toggle","— нет данных о применении":"— no enforcement data",
  "пока нет CF-таргетов. Нажми «+ CF target».":"no CF targets yet. Click “+ CF target”.","(задан — введи для замены)":"(set — enter to replace)","(обязательно)":"(required)",
  "ID CF-таргета (напр. nginx-aaa-cloudflare):":"CF target ID (e.g. nginx-aaa-cloudflare):","не сохранилось:":"not saved:","Удалить CF-таргет «":"Delete CF target “",
  "»? Он отвяжется от групп/правил. Список/правило в самом Cloudflare не удаляются автоматически.":"”? It will detach from groups/rules. The list/rule in Cloudflare itself is not deleted automatically.",
  "нет ответа.":"no response.","сначала задай id канала и сохрани":"set the channel id first and save","✓ отправлено":"✓ sent",
  "только через ENV (STORE=configmap — ConfigMap хранит открытым текстом)":"ENV only (STORE=configmap — ConfigMap stores plaintext)","нет Cloudflare-таргетов в targets.":"no Cloudflare targets in targets.",
  "ошибка загрузки:":"load error:","blocklist-api не настроен (BLOCKLIST_API_URL пуст) — ноды недоступны.":"blocklist-api not configured (BLOCKLIST_API_URL empty) — nodes unavailable.",
  "# ENROLL_SECRET не задан в blocklist-api — задай его, чтобы агенты могли регистрироваться.":"# ENROLL_SECRET not set in blocklist-api — set it so agents can register.",
  "⚠ Задай PUBLIC_URL в blocklist-api (адрес, по которому VM достучатся до API) — без него команда неполная.":"⚠ Set PUBLIC_URL in blocklist-api (the address VMs reach the API at) — without it the command is incomplete.",
  "»? Агент перестанет получать баны, пока не перерегистрируется.":"”? The agent will stop receiving bans until it re-registers.","уже есть":"already present",
  "Добавлено частично:":"Partially added:","Отметь основные правила звёздочкой ★ во вкладках 403 и Автобан.":"Mark primary rules with a ★ in the 403 and Auto-ban tabs.",
  "не удалось загрузить:":"failed to load:","🛡️ защищённые (в 403 добавить нельзя, общий список с автобаном):":"🛡️ protected (can't add to 403, shared list with auto-ban):","— меняются в":"— managed in",
  ": 403 выключен — включить":": 403 off — enable",": нет связи с бэкендом":": no connection to the backend","дрейф":"drift",
  ": дрейф рендера — нажми ↻ ресинк в Денлисте":": render drift — hit ↻ resync in Denylist",": 403 активен — выключить":": 403 active — disable",
  "· найдено":"· found","ничего не найдено по «":"nothing found for “","chars":"chars","(без имени)":"(no name)",
  "добавить путь (как «Путь содержит», напр. /.env)":"add a path (like “Path contains”, e.g. /.env)","» уже есть — пропущено":"” already exists — skipped",
  "в правиле не осталось ни одного пути — тогда удали правило целиком.":"no paths left in the rule — then delete the rule entirely.","Точный URI":"Exact URI",
  "Wildcard (* = что угодно)":"Wildcard (* = anything)","/admin/*  или  *.sql":"/admin/*  or  *.sql","Regex (как nginx ~*)":"Regex (like nginx ~*)",
  "✗ некорректный regex:":"✗ invalid regex:","✗ кавычка \" запрещена — сломает nginx":"✗ the \" quote is forbidden — it breaks nginx",
  "⚠ поймает обычный путь «":"⚠ will catch a normal path “","» — отклонится (или включи force)":"” — will be rejected (or enable force)","🚫 забанит":"🚫 will ban","✓ пропустит":"✓ will pass",
  "— (имя только для нового)":"— (name only for a new one)","не удалось сменить группу:":"failed to change group:","правило не найдено":"rule not found",
  "• уже есть в «":"• already in “","✓ в «":"✓ in “","• такое правило уже есть — не дублирую":"• such a rule already exists — not duplicating","✓ создано":"✓ created",
  "Выключить ВСЮ секцию 403?":"Disable the WHOLE 403 section?","Все правила по путям перестанут блокировать — сканеры снова будут проходить.":"All path rules will stop blocking — scanners will get through again.",
  "Добавить базовый набор правил сканеров одним правилом «base-scanners»?":"Add the basic scanner rule set as one “base-scanners” rule?",
  "(повторный засев обновит его, не создаст дубль)":"(re-seeding updates it, won't create a duplicate)","✓ базовый набор добавлен/обновлён.":"✓ basic set added/updated.",
  "Если у тебя был свой ручной if в ингрессе — убери его, чтобы не дублировать.":"If you had your own manual if in the ingress — remove it to avoid duplication.",
  "не удалось получить правила автобана":"failed to fetch auto-ban rules","выбери правило автобана → станет правилом 403":"pick an auto-ban rule → it becomes a 403 rule",
  ") — кроме семейств":") — except families","— семейство, нельзя":"— a family, not allowed","пут.":"paths","✓ создано/обновлено:":"✓ created/updated:","пропущено:":"skipped:",
  "» уже ловится правилом «":"” is already caught by rule “","Всё равно добавить отдельным правилом?":"Add as a separate rule anyway?","уже ловится":"already caught",
  "не удалось добавить в 403:":"failed to add to 403:","список пуст — автобан считает все пути":"list empty — auto-ban counts all paths","не забудь «Сохранить»":"don't forget “Save”",
  "забанено:":"banned:","(но это приватный/уже-denied статический диапазон)":"(but this is a private/already-denied static range)","и ещё":"and",
  "сошлось по путям (24ч):":"matched by paths (24h):","примеры путей не найдены (активность старше 24ч)":"no path examples found (activity older than 24h)","⌛ истёк":"⌛ expired",
  "· ≥N/окно":"· ≥N/window","ошибка загрузки логов:":"log load error:","событий автобана (последние сверху)":"auto-ban events (latest on top)","событий автобана пока нет":"no auto-ban events yet",
  "Автобан ещё никого не банил (или kill-switch был выключен).":"Auto-ban hasn't banned anyone yet (or the kill-switch was off).","пути не сохранены":"paths not saved","снят":"removed","сошлось по путям":"matched by paths",
  "➕ в основные (403 + автобан)":"➕ to primary (403 + auto-ban)","🚫 добавить в правило 403:":"🚫 add to a 403 rule:","⛔ в автобан (бан IP по порогу):":"⛔ to auto-ban (ban IP by threshold):",
  "нет автобан-правил с путями.":"no auto-ban rules with paths.","создать правило →":"create a rule →","нет правила":"no rule","✓ уже есть":"✓ already there","✓ добавлено":"✓ added",
  "не JSON:":"not JSON:","массив: загрузил первое, для пачки жми «Сохранить из JSON»":"array: loaded the first, for a batch hit “Save from JSON”","✓ загружено в форму":"✓ loaded into the form",
  "такая группа уже есть":"such a group already exists","· прогон":"· run","назад: включено правил":"ago: rules enabled",", новых забанено":", newly banned",", уже в бане":", already banned",
  ", отложено по лимиту":", deferred by limit","ВКЛЮЧЁН":"ON","— включённые правила банят на ingress каждые":"— enabled rules ban on ingress every","новых/проход).":"new/pass).",
  "Включённые правила начнут РЕАЛЬНО банить IP на ingress каждые":"Enabled rules will REALLY start banning IPs on ingress every","новых за проход).":"new per pass).",
  "Исключаются: доверенные, приватные, Cloudflare, уже забаненные.":"Excluded: trusted, private, Cloudflare, already banned.","Выключить можно этим же тумблером в любой момент.":"You can turn it off with the same toggle anytime.",
  "уже в денлисте (пропущено)":"already in denylist (skipped)","0 новых IP под условие (≥":"0 new IPs match the condition (≥","Никого нового бы не забанило.":"Nobody new would be banned.",
  "новых IP (≥":"new IPs (≥"," за ":" over ","с (≤":"s (≤","с (до":"s (up to","ИЛИ":"OR","(по 1 пути)":"(per 1 path)","(∑ путей)":"(∑ paths)","лого":"logo",
  "файл больше 180KB — выбери поменьше":"file larger than 180KB — pick a smaller one","ошибка сохранения":"save error","не удалось сохранить":"failed to save",
  // ── batch 4: leaks from the Live Logs / Dashboards rewrites + inflection guards ──
  // inflection guards: short stems (все/таргет/бан/сканер/дашборд/код) were corrupting
  // longer inflected forms (всех→allх, таргетах→targetах, бана→banа, сканеры→scannerы).
  // Longest-first matching means these win over the stems.
  "всех":"all","всем":"all","таргетах":"targets","таргет(ов)":"target(s)","таргетов":"targets",
  "сканеры":"scanners","сканеров":"scanners","бана":"ban","банил":"banned","банился":"was banned","банов":"bans",
  "автобаном":"by auto-ban","блоклистом":"by blocklist","денлисте":"denylist","дашборда":"dashboard","дашборде":"dashboard",
  "коды":"codes","путей":"paths","хост":"host",
  // new UI strings
  "сгенерировать":"generate","Спросить":"Ask","🤖 Спросить":"🤖 Ask",
  "Нажми «сгенерировать» — LLM предложит deny/WAF-правила по текущей атаке.":"Click “generate” — the LLM will suggest deny/WAF rules for the current attack.",
  "Дайджест за период":"Digest for the period","— тяни за правый-нижний угол карточки, чтобы менять размер":"— drag the card's bottom-right corner to resize",
  "новые подсети":"new subnets","клик → payload":"click → payload","клик → профиль IP":"click → IP profile",
  "CRS-правила":"CRS rules","HTTP-методы":"HTTP methods","TLS-протоколы":"TLS protocols","URI, триггерящие CRS":"URIs triggering CRS",
  "WAF: кандидаты в ложные":"WAF: false-positive candidates","avg сек":"avg s","МБ":"MB",
  "— клик по путям/IP/UA выше тоже открывает запросы":"— clicking paths/IP/UA above also opens requests",
  "клик по путям/IP/UA выше тоже открывает запросы":"clicking paths/IP/UA above also opens requests",
  "до 80 строк":"up to 80 rows","пресеты:":"presets:","пресеты":"presets",
  "Задай фильтр и нажми «Найти» — увидишь сырые запросы.":"Set a filter and hit “Find” — you'll see raw requests.",
  "блокировки на ingress":"blocks on ingress",
  "1ч":"1h","2ч":"2h","3ч":"3h","6ч":"6h","8ч":"8h","12ч":"12h","24ч":"24h","15м":"15m","30м":"30m","1д":"1d","3д":"3d","7д":"7d","30д":"30d",
  "↩ Разбанить всех":"↩ Unblock all","Разбанить всех":"Unblock all","Ресинк":"Resync","⛔ Забанить всех":"⛔ Ban all","Забанить всех":"Ban all",
  "аномально много 4xx (перебор эндпоинтов)":"abnormally many 4xx (endpoint brute-force)","Оценить ИИ":"Assess with AI","Переоценить":"Re-assess",
  "Список строится автоматически: nginx — это подключённые ноды, Cloudflare — из реестра CF-таргетов.":"The list is built automatically: nginx = connected nodes, Cloudflare = from the CF-targets registry.",
  "Вставь готовое правило (или несколько — массивом) в JSON и нажми «Загрузить в форму» либо «Сохранить из JSON».":"Paste a ready rule (or several — as an array) into JSON and hit “Load into form” or “Save from JSON”.",
  "Загрузить в форму":"Load into form","форма → JSON":"form → JSON","путь по regex":"path by regex","семейство сигнатур":"signature family","ещё путь":"another path",
  "вкл: 1×/.git + 1×/.env = 2 → сработает · выкл: порог должен набрать один путь":"on: 1×/.git + 1×/.env = 2 → fires · off: the threshold must be met by a single path",
  "складывать запросы по всем путям":"sum requests across all paths","TTL бана":"ban TTL","Стартовая привязка (можно менять потом у правила)":"Initial attachment (changeable later on the rule)",
  "— забанен ли и за что":"— whether it's banned and why","забанен ли и за что":"whether it's banned and why",
  "— кого и по какому правилу забанил":"— who was banned and by which rule","кого и по какому правилу забанил":"who was banned and by which rule",
  "Пути, которые сразу отдают":"Paths that immediately return","Regex (вручную)":"Regex (manual)","🎯 Группа таргетов":"🎯 Target group","Группа таргетов":"Target group",
  "⚙ дополнительно ▾":"⚙ advanced ▾","дополнительно":"advanced","дописать в правило:":"append to rule:","дописать в правило":"append to rule",
  "nginx-VM с агентом soc-nginx-agent — откуда собираем трафик и куда применяем баны.":"nginx VMs running soc-nginx-agent — where traffic is read and bans are applied.",
  "Выполни на виртуалке (Linux, root). Нода появится в списке после первого heartbeat:":"Run on the VM (Linux, root). The node appears in the list after its first heartbeat:",
  "Что приложение пыталось сделать (бан / разбан / истёк TTL / правила 403) и чем закончилось применение на таргетах.":"What the app tried to do (ban / unban / TTL expired / 403 rules) and how enforcement on the targets ended.",
  "правила 403":"403 rules",
  "🔒 CONFIG_LOCK=env — конфиг только из переменных окружения, редактирование через GUI отключено.":"🔒 CONFIG_LOCK=env — config comes only from environment variables; GUI editing is disabled.",
  "Название и иконка":"Name and icon","Иконка":"Icon","Подпись":"Subtitle","Иконка (PNG/SVG, <190KB)":"Icon (PNG/SVG, <190KB)","убрать иконку":"remove icon",
  "ошибки 4xx":"4xx errors","· «+автобан» добавит путь в правило":"· “+auto-ban” adds the path to a rule","показать запросы":"show requests",
  "Это IP Cloudflare, не реальный посетитель — бан бесполезен. Реальный клиент скрыт за фларой.":"This is a Cloudflare IP, not a real visitor — banning is useless. The real client is hidden behind Cloudflare.",
  "стр.":"pg.","активных":"active","за Cloudflare (IP скрыт)":"behind Cloudflare (IP hidden)","хост:":"host:","страна:":"country:","время ответа:":"response time:",
  "все коды":"all codes","Отозвать токен и удалить ноду":"Revoke token and delete node","(ⓡ = регэксп, наведи — увидишь точный паттерн)":"(ⓡ = regex, hover to see the exact pattern)",
  "× чтобы убрать":"× to remove",
  "Если у него есть 403 — он от nginx-правила (сканер-блок) или приложения, не от нашего бана.":"If it has a 403 — it's from an nginx rule (scanner block) or the app, not from our ban.",
  "НЕ в денлисте — автобаном/блоклистом не банился.":"NOT in the denylist — wasn't banned by auto-ban/blocklist.",
  "Применяет и баны IP, и правила 403 по пути":"Applies both IP bans and path-based 403 rules","Применяет только баны IP — 403-пути Cloudflare не умеет":"Applies IP bans only — Cloudflare can't do path-403",
  "(или имя ниже)":"(or a name below)","Режим":"Mode","(опц.)":"(opt.)","задан (введите, чтобы заменить)":"set (enter to replace)",
  "# promtail → Loki дашборда":"# promtail → dashboard's Loki","# blocklist-api/values.yaml — таргет ingress = ns + CM контроллера":"# blocklist-api/values.yaml — ingress target = ns + controller CM",
  "# (собирает поды":"# (collects pods","; в Loki прилетят как job=ingress-nginx)":"; they arrive in Loki as job=ingress-nginx)",
  "режется сам путь, на всех привязанных таргетах.":"the path itself is cut, on all attached targets.","режется сам путь, на всех доменах окружения.":"the path itself is cut, on all domains of the environment.",
  "все бэкенды":"all backends","данные ниже могут быть неполными":"data below may be incomplete","недоступен":"unreachable","локальный":"local",
  "править":"edit","имя":"name","не удалось: ":"failed: ","оставь пустым — не менять":"leave blank to keep","локальный blocklist-api":"local blocklist-api",
  "нет подключённых ingress — нажми «Setup cluster», чтобы добавить":"no ingress connected — click «Setup cluster» to add one",
  "добавлено":"added","Удалить этот ingress?":"Delete this ingress?","переименовать":"rename","Имя ноды (пусто — вернуть исходное):":"Node name (blank = restore original):","ничего":"none",
  "IP в бане":"IP banned","баны идут":"bans active","готов · банов нет":"ready · no bans","простаивает":"idle",
  "активность банов · 24ч":"ban activity · 24h","активности нет":"no activity","приатаченные 403-правила":"attached 403 rules",
  "403-правил нет":"no 403 rules","автобан выкл":"auto-ban off","автобан":"auto-ban","способ применения":"enforcement",
  "включён · банит по IP":"on · bans by IP","выключен · баны не добавляются":"off · no new bans","последние баны":"recent bans",
  "ничего не приатачено":"nothing attached","активны":"active","в бане":"banned","готов":"ready","таргетов пока нет — подключи ноду, CF-таргет или ingress.":"no targets yet — connect a node, CF target or ingress.",
  "нет токена — не банит":"no token — not enforcing",
};
let _ruKeys=null, _trMO=null, _trBusy=false;
function _ruSorted(){ if(!_ruKeys)_ruKeys=Object.keys(RU2EN).sort((a,b)=>b.length-a.length); return _ruKeys; }
function _trText(v){ if(!/[А-Яа-яЁё]/.test(v))return v; for(const k of _ruSorted())if(v.indexOf(k)>=0)v=v.split(k).join(RU2EN[k]); return v; }
function translateDOM(root){
  if(_lang!=="en")return;
  root=root||document.body;
  const w=document.createTreeWalker(root,NodeFilter.SHOW_TEXT),nodes=[]; let n;
  while(n=w.nextNode())nodes.push(n);
  nodes.forEach(t=>{ const v=_trText(t.nodeValue); if(v!==t.nodeValue)t.nodeValue=v; });
  (root.querySelectorAll?root.querySelectorAll("[placeholder],[title]"):[]).forEach(e=>{
    if(e.placeholder){const v=_trText(e.placeholder); if(v!==e.placeholder)e.placeholder=v;}
    if(e.title){const v=_trText(e.title); if(v!==e.title)e.title=v;}
  });
}
function startTranslator(){
  if(_lang!=="en"||_trMO)return;
  translateDOM(document.body);
  // translateDOM only edits text/attributes (never adds nodes), so it can't
  // self-trigger this childList observer — no busy-guard needed (the guard was
  // skipping rapid successive renders, leaving Russian on screen).
  _trMO=new MutationObserver(ms=>{
    ms.forEach(m=>m.addedNodes&&m.addedNodes.forEach(nd=>{
      if(nd.nodeType===1)translateDOM(nd); else if(nd.nodeType===3){const v=_trText(nd.nodeValue); if(v!==nd.nodeValue)nd.nodeValue=v;}
    }));
  });
  _trMO.observe(document.body,{childList:true,subtree:true});
}

// ── card manager (hide / restore dashboard sections) ──────────────────────────
let _hiddenCards=JSON.parse(localStorage.getItem("soc_hidden_cards")||"[]");
function _cardKey(h){ return h.getAttribute("data-i18n")||h.dataset.card||h.textContent.replace(/[×▾▸]/g,"").replace(/\s+/g," ").trim().slice(0,40); }
function _saveCards(){ localStorage.setItem("soc_hidden_cards",JSON.stringify(_hiddenCards)); }
function _applyCard(h,key){
  const hidden=_hiddenCards.includes(key);
  h.style.display=hidden?"none":"";
  const body=h.nextElementSibling;
  if(body&&body.tagName!=="H2")body.style.display=hidden?"none":"";
}
function initCards(){
  const dash=document.getElementById("view-dash"); if(!dash)return;
  dash.querySelectorAll("h2.sec").forEach(h=>{
    let key=h.dataset.card; if(!key){ key=_cardKey(h); h.dataset.card=key; }
    if(!h.querySelector(".card-hide")){
      const b=document.createElement("button"); b.className="card-hide"; b.textContent="×"; b.title="hide";
      b.onclick=e=>{ e.stopPropagation(); hideCard(key); };
      h.appendChild(b);
    }
    _applyCard(h,key);
  });
  renderTray();
}
function hideCard(k){ if(!_hiddenCards.includes(k))_hiddenCards.push(k); _saveCards(); initCards(); }
function showCard(k){ _hiddenCards=_hiddenCards.filter(x=>x!==k); _saveCards(); initCards(); }
function renderTray(){
  const tray=document.getElementById("card-tray"); if(!tray)return;
  if(!_hiddenCards.length){ tray.classList.add("hidden"); return; }
  tray.classList.remove("hidden");
  const lbl=_lang==="ru"?"скрытые карточки:":"hidden cards:";
  tray.innerHTML=`<span style="color:var(--faint)">${lbl}</span>`+_hiddenCards.map(k=>{
    const title=(I18N[_lang]&&I18N[_lang][k])||I18N.en[k]||k;
    // короткий ярлык: до тире/двоеточия (отбрасываем длинные подсказки) + лимит
    const short=title.split(/—|–|:|·|\//)[0].trim().slice(0,24);
    return `<span class="tray-chip" data-k="${esc(k)}" onclick="showCard(this.dataset.k)" title="${esc(title)}">+ ${esc(short)}</span>`;
  }).join("");
}

// ── Logs v4: simple explorer (source tabs → chart → click-filters → tops → stream) ──
const _lg={cls:"",pathQ:"",chips:[],tail:false,rawMode:false,sources:[],rows:[],cursor:null,endNs:null,winMin:null,
  style:localStorage.getItem("soc_lg_style")||"bars"};
let _lgTimer=null,_lgSrcAll=[],_lgSrcCounts=[],_lgWin=+(localStorage.getItem("soc_lg_win")||60);
const _LG_CLS=["2xx","3xx","4xx","5xx"];
const _LG_COL={"2xx":"#6fcf97","3xx":"#6fcf97","4xx":"#d9a441","5xx":"#e07070"};
const _LG_WINS=[[15,"15m"],[60,"1h"],[360,"6h"],[1440,"24h"],[10080,"7d"]];
function loadLogs(){ lgRenderWinTabs(); lgStyleApply(); lgClsApply(); lgRenderChips(); lgLoadPrefs(); lgLoadSources(); lgRun(); }
function _lgMins(){ return _lg.winMin||_lgWin; }
// filters are plain chips — no query language. cls pill + path substring + click chips.
function _lgChips(){
  const out=[];
  if(_lg.cls)out.push({field:"status",op:"class",value:_lg.cls});
  if(_lg.pathQ)out.push({field:"path",op:"re",value:_lg.pathQ});
  // group chips by field: same field + multiple values => OR (regex alternation),
  // different fields stay separate (AND). Prevents "path=A AND path=B" => 0 rows.
  const byF={}; _lg.chips.forEach(c=>{ (byF[c.field]=byF[c.field]||[]).push(c.value); });
  Object.keys(byF).forEach(f=>{ const vs=byF[f];
    if(vs.length===1) out.push({field:f,op:"eq",value:vs[0]});
    else out.push({field:f,op:"re",value:vs.map(v=>String(v).replace(/[.*+?^${}()|[\]\\]/g,"\\$&")).join("|")}); });
  return out;
}
function _lgBody(extra){
  const b={chips:_lgChips(), minutes:_lgMins()};
  if(_lg.sources.length)b.log_sources=_lg.sources;
  if(_lg.sel)b.sources=_lg.sel;                    // stream-label selector (target tabs)
  if(_lg.endNs)b.end_ns=_lg.endNs;
  return Object.assign(b, extra||{});
}
function lgClsSet(c){ _lg.cls=(_lg.cls===c?"":c); lgClsApply(); lgRun(); }
function lgClsApply(){ document.querySelectorAll(".lg-pill[data-c]").forEach(p=>p.classList.toggle("on",p.dataset.c===_lg.cls)); }
function lgPathQ(v){ _lg.pathQ=(v||"").trim(); lgRun(); }
function lgChipAdd(field,value){
  value=String(value);
  const i=_lg.chips.findIndex(c=>c.field===field&&c.value===value);
  if(i>=0)_lg.chips.splice(i,1); else _lg.chips.push({field,value});   // click again = remove
  lgRenderChips(); lgRun();
}
function lgChipDel(i){ _lg.chips.splice(i,1); lgRenderChips(); lgRun(); }
const _LG_FLD_RU={path:"путь",ip:"IP",host:"host",country:"страна",method:"method",status:"status",ua:"UA"};
function lgRenderChips(){
  const el=document.getElementById("lg-chips"); if(!el)return;
  el.innerHTML=_lg.chips.map((c,i)=>
    `<span class="mono" style="font-size:10.5px;padding:2px 8px;border-radius:6px;background:#5794f214;border:1px solid #5794f22e;color:#84aef0">${esc(_LG_FLD_RU[c.field]||c.field)}: ${esc(c.value.length>34?c.value.slice(0,34)+"…":c.value)} <button onclick="lgChipDel(${i})" style="color:#7c6fb0">✕</button></span>`).join("");
}
// window + chart-style tabs
function lgRenderWinTabs(){
  const el=document.getElementById("lg-win-tabs"); if(!el)return;
  el.innerHTML=_LG_WINS.map(([m,l])=>`<span class="lg-pill${_lgWin===m&&!_lg.winMin?" on":""}" onclick="lgWinSet(${m})">${l}</span>`).join("");
}
function lgWinSet(m){ _lgWin=m; localStorage.setItem("soc_lg_win",m); lgRun(); }
// chart style: the picked style becomes the DEFAULT — stored server-side
// (ui_prefs) so it survives other browsers/devices; localStorage is a fast cache
function lgStyleSet(s){
  _lg.style=s; localStorage.setItem("soc_lg_style",s); lgStyleApply();
  if(_lgHistData)lgRenderHist(_lgHistData);
  _post("/api/ui_prefs",{logs_chart_style:s}).catch(()=>{});
}
function lgStyleApply(){ document.querySelectorAll("#lg-style-seg span[data-s]").forEach(x=>x.classList.toggle("on",x.dataset.s===_lg.style)); }
async function lgLoadPrefs(){
  try{
    const d=await fetch("/api/ui_prefs").then(r=>r.json());
    const s=(d.prefs||{}).logs_chart_style;
    if(s&&["bars","lines","area"].includes(s)&&s!==_lg.style){
      _lg.style=s; localStorage.setItem("soc_lg_style",s); lgStyleApply();
      if(_lgHistData)lgRenderHist(_lgHistData);
    }
  }catch(e){}
}
// ── query + render ──
async function lgRun(){ _lg.endNs=null; _lg.winMin=null; lgRenderWinTabs(); return _lgFetch(); }
let _lgGen=0, _lgFacetDeb=null, _lgHistData=null;
async function _lgFetch(){
  const tbl=document.getElementById("lg-table"); if(!tbl)return;
  const gen=++_lgGen;                              // run-token (C3): drop stale async results
  try{
    const [q,h]=await Promise.all([
      _post("/api/logs/query", _lgBody({limit:200})),
      _post("/api/logs/histogram", _lgBody({by_class:true}))
    ]);
    if(gen!==_lgGen)return;                         // a newer run superseded this one
    if(q.enabled===false){ tbl.innerHTML='<div class="text-slate-600 text-xs p-2">Loki '+_trText("не настроен")+' (LOKI_URL).</div>'; document.getElementById("lg-hist").innerHTML=""; return; }
    _lg.rows=q.rows||[]; _lg.cursor=q.next_cursor||null; _lgSrcCounts=q.sources||[];
    _lgHistData=h;
    lgRenderRows(); lgRenderHist(h); lgRenderSrcStatus(q.sources||[]); lgStats(q); lgWinLabel();
    document.getElementById("lg-more").classList.toggle("hidden", !_lg.cursor);
    clearTimeout(_lgFacetDeb);
    _lgFacetDeb=setTimeout(()=>lgLoadTops(gen),400);   // Pf1: debounce topk queries
  }catch(e){ if(gen===_lgGen)tbl.innerHTML='<div class="text-red-400 text-xs p-2">error: '+esc(e.message)+'</div>'; }
  clearTimeout(_lgTimer);
  if(_lg.tail&&_view==="logs")_lgTimer=setTimeout(lgTail,5000);
}
const _lgKey=r=>(r.ts_ns||r.ts)+"|"+(r.line||"");   // ns+line identity (C4)
async function lgTail(){
  const gen=_lgGen, maxNs=_lg.rows.length?(_lg.rows[0].ts_ns||_lg.rows[0].ts*1e6):0;
  try{
    const q=await _post("/api/logs/query", _lgBody({limit:100}));
    if(gen!==_lgGen)return;                         // filter changed mid-flight → drop (C3)
    const seen=new Set(_lg.rows.map(_lgKey));
    const fresh=(q.rows||[]).filter(r=>(r.ts_ns||r.ts*1e6)>maxNs && !seen.has(_lgKey(r)));
    if(fresh.length){ _lg.rows=fresh.concat(_lg.rows).slice(0,1000); lgRenderRows(); lgStats(q); }
  }catch(e){}
  clearTimeout(_lgTimer);
  if(_lg.tail&&_view==="logs")_lgTimer=setTimeout(lgTail,5000);
}
async function lgLoadOlder(){
  if(!_lg.cursor)return;
  try{
    const q=await _post("/api/logs/query", _lgBody({limit:200, end_ns:_lg.cursor}));
    const seen=new Set(_lg.rows.map(_lgKey));       // dedup across the page boundary (C4)
    _lg.rows=_lg.rows.concat((q.rows||[]).filter(r=>!seen.has(_lgKey(r)))); _lg.cursor=q.next_cursor||null;
    lgRenderRows(); document.getElementById("lg-more").classList.toggle("hidden", !_lg.cursor);
  }catch(e){}
}
function lgZoom(t,step){ _lg.endNs=(t+(step||60))*1e9; _lg.winMin=Math.max(1,Math.round((step||60)*30/60)); _lgFetch(); }
function lgTailToggle(){ _lg.tail=!_lg.tail; const b=document.getElementById("lg-tail-btn"); b.classList.toggle("btn-primary",_lg.tail); b.querySelector("span").textContent=_lg.tail?_trText("следим…"):_trText("tail"); if(_lg.tail)lgTail(); else clearTimeout(_lgTimer); }
function _lgStatusColor(s){const n=+s||0;return n>=500?"#e07070":n>=400?"#d9a441":n>=200?"#6fcf97":"#9aa4b6";}
function lgStats(q){
  const el=document.getElementById("lg-stats"); if(!el)return;
  el.textContent=_lg.rows.length+(_lg.cursor?"+":"");
}
function lgRenderRows(){
  const tbl=document.getElementById("lg-table"); if(!tbl)return;
  if(!_lg.rows.length){ tbl.innerHTML=`<div class="text-slate-600 text-xs p-2">${_trText("нет строк под фильтр")}</div>`; return; }
  if(_lg.rawMode){ tbl.innerHTML=_lg.rows.map(r=>`<div class="lg-raw-line"><span style="color:#5b6577">${esc(r.time)}</span> <span style="color:${_lgStatusColor(r.status)}">${esc(r.line)}</span></div>`).join(""); return; }
  const multi=_lgSrcAll.length>1;
  const head=`<div class="lg-row head"><span>time</span><span>IP</span><span>method</span><span>st</span><span>path</span><span>ms</span><span></span></div>`;
  tbl.innerHTML=head+_lg.rows.map((r,i)=>{
    const ms=r.rt?Math.round(parseFloat(r.rt)*1000):"";
    return `<div class="lg-row" onclick="lgRowExpand(${i},this)">
      <span class="mono" style="color:#5b6577">${esc(r.time)}${multi&&r.source?` · <span style="color:#475569">${esc(r.source)}</span>`:""}</span>
      <span class="mono">${r.country?flag(r.country)+" ":""}${esc(r.ip||"")}</span>
      <span class="mono text-slate-400">${esc(r.method||"")}</span>
      <span class="mono" style="color:${_lgStatusColor(r.status)}">${esc(r.status||"")}</span>
      <span class="mono text-slate-300" title="${esc(r.path||"")}">${esc(r.path||"")}</span>
      <span class="mono text-slate-500">${ms}</span>
      <span class="text-slate-600">▸</span>
    </div>`;
  }).join("");
}
// ── inspector: right-hand record panel (mockup A) with 24h IP context ──
let _lgSelIdx=null;
function lgRowExpand(i,el){
  const r=_lg.rows[i]; if(!r)return;
  const panel=document.getElementById("lg-insp");
  if(_lgSelIdx===i&&!panel.classList.contains("hidden")){ lgInspClose(); return; }
  _lgSelIdx=i;
  document.querySelectorAll("#lg-table .lg-row.lg-sel").forEach(x=>x.classList.remove("lg-sel"));
  if(el)el.classList.add("lg-sel");
  const ip=r.ip||"";
  const kv=(k,v,color)=>v?`<span class="k">${k}</span><span class="v"${color?` style="color:${color}"`:""} title="${escAttr(String(v))}">${esc(String(v))}</span>`:"";
  const chip=(f,v)=>v?`<button onclick="lgFacetPick('${escJs(f)}','${escJs(String(v))}')" class="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 hover:bg-slate-700" title="filter">${esc(f)}:${esc(String(v).slice(0,24))}</button>`:"";
  const ms=r.rt?Math.round(parseFloat(r.rt)*1000)+" ms":"";
  panel.classList.remove("hidden");
  panel.innerHTML=`<div class="flex items-center justify-between mb-2">
      <span class="text-[12px] font-medium text-slate-200">${_trText("Запись")}</span>
      <button onclick="lgInspClose()" class="text-slate-500 hover:text-slate-300">✕</button></div>
    <div class="lg-kv">
      ${kv("time",r.time)}${kv("ip",(r.country?flag(r.country)+" ":"")+ip)}${kv("status",r.status,_lgStatusColor(r.status))}
      ${kv("method",r.method)}${kv("path",r.path)}${kv("host",r.host)}${kv("rt",ms)}${kv("source",r.source)}${kv("ua",r.ua)}
    </div>
    ${ip?`<div id="lg-insp-ip24" class="mt-2 p-2 rounded-lg" style="border:1px solid var(--border);background:#0a0e14">
      <div class="text-[9px] uppercase tracking-wide" style="color:var(--faint)">${_trText("этот IP за 24ч")}</div>
      <div class="text-slate-600 text-[11px]">…</div></div>`:""}
    <div class="flex flex-col gap-1.5 mt-2">
      ${ip?`<button onclick="lgBanIP('${escJs(ip)}')" class="text-[11px] px-2 py-1 rounded bg-rose-600/25 text-rose-200 hover:bg-rose-600/40">⛔ ${_trText("забанить IP")}</button>`:""}
      ${r.path?`<button onclick="lgPathTo403('${escJs(r.path)}')" class="text-[11px] px-2 py-1 rounded bg-indigo-600/25 text-indigo-200 hover:bg-indigo-600/40">🛂 ${_trText("путь в 403")}</button>`:""}
      ${ip?`<button onclick="quickSearch('${escJs(ip)}')" class="text-[11px] px-2 py-1 rounded bg-slate-700/60 text-slate-200 hover:bg-slate-600">👤 ${_trText("профиль")}</button>`:""}
    </div>
    <div class="flex gap-1 mt-2 flex-wrap">${chip("status",r.status)}${chip("method",r.method)}${chip("ip",r.ip)}${chip("country",r.country)}${chip("host",r.host)}</div>
    <div class="text-[9px] uppercase tracking-wide mt-2" style="color:var(--faint)">raw</div>
    <pre class="mono text-[10px] text-slate-400 whitespace-pre-wrap break-all mt-1 p-2 rounded-lg" style="border:1px solid var(--border);background:#0a0e14;max-height:180px;overflow:auto">${esc((()=>{try{return JSON.stringify(JSON.parse(r.line),null,2);}catch(e){return r.line;}})())}</pre>`;
  if(ip)_lgIp24(ip);
}
function lgInspClose(){
  _lgSelIdx=null;
  document.getElementById("lg-insp").classList.add("hidden");
  document.querySelectorAll("#lg-table .lg-row.lg-sel").forEach(x=>x.classList.remove("lg-sel"));
}
async function _lgIp24(ip){
  const el=document.getElementById("lg-insp-ip24"); if(!el)return;
  try{
    const body={chips:[{field:"ip",op:"eq",value:ip}],minutes:1440,by_class:true};
    if(_lg.sources.length)body.log_sources=_lg.sources;
    const d=await _post("/api/logs/histogram",body);
    const cur=document.getElementById("lg-insp-ip24"); if(!cur)return;   // inspector re-rendered
    const series=(d&&d.series)||{};
    const buckets={}; let tot=0,err=0;
    Object.keys(series).forEach(c=>(series[c]||[]).forEach(p=>{ buckets[p.t]=(buckets[p.t]||0)+p.v; tot+=p.v; if(c==="4xx"||c==="5xx")err+=p.v; }));
    const ts=Object.keys(buckets).map(Number).sort((a,b)=>a-b);
    if(!tot){ cur.querySelector("div:last-child").innerHTML=`<span class="text-slate-600 text-[11px]">${_trText("нет данных")}</span>`; return; }
    const max=Math.max(...ts.map(t=>buckets[t]),1);
    const pts=ts.map((t,i)=>`${(i/(ts.length-1||1)*200).toFixed(1)},${(18-buckets[t]/max*16).toFixed(1)}`).join(" ");
    const ep=Math.round(err/tot*100);
    cur.querySelector("div:last-child").innerHTML=
      `<div class="mono text-[11px]" style="color:${ep>50?"#fbbf24":"#c4cdda"}">${_dbNum(tot)} hits · ${ep}% ${_trText("ошибок")}</div>
       <svg viewBox="0 0 200 20" width="100%" height="20"><polyline points="${pts}" fill="none" stroke="${ep>50?"#fbbf24":"#5794f2"}" stroke-width="1.3"/></svg>`;
  }catch(e){}
}
async function lgBanIP(ip){
  if(!await uiConfirm(_trText("забанить IP")+" "+ip+"?"))return;
  const r=await _post("/api/block",{cidr:ip,reason:"from live logs",ttl:2592000});
  uiAlert(r&&r.ok?("✓ "+_trText("забанен")+": "+ip):("не удалось: "+((r&&r.error)||"?")));
}
function lgPathTo403(path){ showView('p403'); uiAlert(_trText("открой 403 и добавь путь")+": "+path); }
function lgFacetPick(field,value){ lgChipAdd(field,String(value)); }
// ── chart: bars / lines / area, Y axis in req/min, click = zoom ──
function _lgFmtT(t,winMin){ const d=new Date(t*1000); const hm=("0"+d.getHours()).slice(-2)+":"+("0"+d.getMinutes()).slice(-2);
  return winMin>1440?(d.getMonth()+1)+"/"+d.getDate()+" "+hm:hm; }
function _lgNiceMax(v){ const p=Math.pow(10,Math.floor(Math.log10(Math.max(1,v)))); const n=v/p;
  return (n<=1?1:n<=2?2:n<=5?5:10)*p; }
function lgRenderHist(h){
  const el=document.getElementById("lg-hist"); if(!el)return;
  const series=(h&&h.series)||{}; const step=(h&&h.step)||60, k=60/step;  // → req/min
  const buckets={}; Object.keys(series).forEach(c=>(series[c]||[]).forEach(p=>{ (buckets[p.t]=buckets[p.t]||{})[c]=p.v; }));
  const seen=Object.keys(buckets).map(Number).sort((a,b)=>a-b);
  // header numbers: totals over the window
  let sumT=0,sum4=0,sum5=0;
  seen.forEach(t=>{ _LG_CLS.forEach(c=>{ const v=buckets[t][c]||0; sumT+=v; if(c==="4xx")sum4+=v; if(c==="5xx")sum5+=v; }); });
  document.getElementById("lg-num-req").textContent=_dbNum(sumT)+" "+_trText("запросов");
  document.getElementById("lg-num-4xx").textContent=sum4?_dbNum(sum4)+" 4xx":"";
  document.getElementById("lg-num-5xx").textContent=sum5?_dbNum(sum5)+" 5xx":"";
  if(!seen.length){ el.innerHTML='<div class="text-slate-600 text-xs">'+_trText("нет строк под фильтр")+'</div>'; return; }
  // fill missing buckets across the WHOLE window (not just the seen range) —
  // otherwise a single non-empty bucket renders as one page-wide bar
  let ts=[];
  const endS=Math.floor((_lg.endNs?_lg.endNs/1e9:Date.now()/1000)/step)*step;
  const startS=endS-_lgMins()*60;
  if(step>0&&(endS-startS)/step<=400){
    // anchor the grid to a REAL bucket so filled slots align with Loki's timestamps
    const first=seen[0]-Math.ceil(Math.max(0,seen[0]-startS)/step)*step;
    for(let t=first;t<=Math.max(endS,seen[seen.length-1]);t+=step){ ts.push(t); buckets[t]=buckets[t]||{}; }
    if(!ts.length)ts=seen;
  } else ts=seen;
  const W=800,H=138,L=48,B=16,T=16,plotW=W-L-8,plotH=H-B-T;
  const winMin=_lgMins(), rpm=(t,cs)=>cs.reduce((a,c)=>a+(buckets[t][c]||0),0)*k;
  let rawMax=1; ts.forEach(t=>{ const v=rpm(t,_LG_CLS); if(v>rawMax)rawMax=v; });
  const max=_lgNiceMax(rawMax);
  const colW=plotW/ts.length, bw=Math.max(1.5,colW-1.5);
  const _ti={}; ts.forEach((t,i)=>_ti[t]=i);
  const x=t=>L+(_ti[t]!==undefined?_ti[t]:0)*colW;
  const y=v=>T+plotH-(v/max)*plotH;
  const fmt=v=>v>=1000?_dbNum(v):(Math.round(v*10)/10);
  // axes: Y with unit, X with time
  let g=`<line x1="${L}" y1="${T}" x2="${L}" y2="${T+plotH}" stroke="var(--border)"/>`+
        `<line x1="${L}" y1="${T+plotH}" x2="${W-4}" y2="${T+plotH}" stroke="var(--border)"/>`+
        `<line x1="${L}" y1="${T+plotH/2}" x2="${W-4}" y2="${T+plotH/2}" stroke="#161d29"/>`+
        `<text x="${L-5}" y="${T+plotH+3}" text-anchor="end" font-size="9" fill="#5b6675">0</text>`+
        `<text x="${L-5}" y="${T+plotH/2+3}" text-anchor="end" font-size="9" fill="#5b6675">${fmt(max/2)}</text>`+
        `<text x="${L-5}" y="${T+3}" text-anchor="end" font-size="9" fill="#5b6675">${fmt(max)}</text>`+
        `<text x="${L-5}" y="${T-8}" text-anchor="end" font-size="8" fill="#5b6675">${_trText("запр/мин")}</text>`;
  const tip=t=>`${_lgFmtT(t,winMin)} · ${fmt(rpm(t,_LG_CLS))} ${_trText("запр/мин")}`+(rpm(t,["4xx"])?` · 4xx ${fmt(rpm(t,["4xx"]))}`:"")+(rpm(t,["5xx"])?` · 5xx ${fmt(rpm(t,["5xx"]))}`:"");
  if(_lg.style==="bars"){
    g+=ts.map(t=>{
      let yy=T+plotH, segs="";
      [["2xx","3xx"],["4xx"],["5xx"]].forEach((cs,ci)=>{ const v=rpm(t,cs); if(!v)return;
        const hh=v/max*plotH; yy-=hh;
        segs+=`<rect x="${x(t).toFixed(1)}" y="${yy.toFixed(1)}" width="${bw.toFixed(1)}" height="${hh.toFixed(1)}" fill="${ci===0?"#6fcf97":ci===1?"#d9a441":"#e07070"}" opacity="${ci===0?".3":".85"}"/>`; });
      return `<g class="hbar" onclick="lgZoom(${t},${step})"><title>${tip(t)}</title><rect x="${x(t).toFixed(1)}" y="${T}" width="${bw.toFixed(1)}" height="${plotH}" fill="transparent"/>${segs}</g>`;
    }).join("");
  } else if(_lg.style==="lines"){
    const line=(cs,col,op)=>`<polyline points="${ts.map(t=>(x(t)+bw/2).toFixed(1)+","+y(rpm(t,cs)).toFixed(1)).join(" ")}" fill="none" stroke="${col}" stroke-width="1.4" opacity="${op}"/>`;
    g+=line(_LG_CLS,"#6fcf97",".8")+line(["4xx"],"#d9a441",".8")+line(["5xx"],"#e07070",".9");
    g+=ts.map(t=>`<g class="hbar" onclick="lgZoom(${t},${step})"><title>${tip(t)}</title><rect x="${x(t).toFixed(1)}" y="${T}" width="${colW.toFixed(1)}" height="${plotH}" fill="transparent"/></g>`).join("");
  } else {                                       // area: total fill + errors fill on top
    const poly=(cs,fill,stroke)=>{ const pts=ts.map(t=>(x(t)+bw/2).toFixed(1)+","+y(rpm(t,cs)).toFixed(1)).join(" ");
      return `<polygon points="${(x(ts[0])+bw/2).toFixed(1)},${(T+plotH).toFixed(1)} ${pts} ${(x(ts[ts.length-1])+bw/2).toFixed(1)},${(T+plotH).toFixed(1)}" fill="${fill}" stroke="${stroke}" stroke-width="1.2"/>`; };
    g+=poly(_LG_CLS,"#6fcf9722","#6fcf97")+poly(["4xx","5xx"],"#e0707033","#e07070");
    g+=ts.map(t=>`<g class="hbar" onclick="lgZoom(${t},${step})"><title>${tip(t)}</title><rect x="${x(t).toFixed(1)}" y="${T}" width="${colW.toFixed(1)}" height="${plotH}" fill="transparent"/></g>`).join("");
  }
  // spike value labels: peak of each series in a dark pill above the peak, so the
  // number reads over both the plot and a same-coloured line/bar
  const peak=cs=>{ let bt=null,bv=0; ts.forEach(t=>{ const v=rpm(t,cs); if(v>bv){bv=v;bt=t;} }); return {t:bt,v:bv}; };
  const cand=[{p:peak(["5xx"]),col:"#e07070"},{p:peak(["4xx"]),col:"#d9a441"},{p:peak(_LG_CLS),col:"#a8b3c4"}];
  const used=[];
  cand.forEach(c=>{
    if(!c.p.t||c.p.v<=0)return;
    let px=Math.min(W-18,Math.max(L+12,x(c.p.t)+bw/2));
    if(used.some(u=>Math.abs(u-px)<34))return;      // stronger (error) label wins the spot
    used.push(px);
    const txt=fmt(c.p.v), wpx=String(txt).length*5.6+8;
    let cy=y(c.p.v)-9; if(cy<T+7)cy=y(c.p.v)+11;     // no room above → put just below apex
    g+=`<rect x="${(px-wpx/2).toFixed(1)}" y="${(cy-7).toFixed(1)}" width="${wpx.toFixed(1)}" height="13" rx="3" fill="#0b0e14" stroke="${c.col}" stroke-opacity=".4"/>`+
       `<text x="${px.toFixed(1)}" y="${(cy+3).toFixed(1)}" text-anchor="middle" font-size="9.5" font-weight="500" fill="${c.col}">${txt}</text>`;
  });
  // X ticks: 4, deduped
  const nx=Math.min(4,ts.length), seenLbl=new Set();
  for(let i=0;i<nx;i++){ const t=ts[Math.floor(i*(ts.length-1)/Math.max(1,nx-1))];
    const lbl=_lgFmtT(t,winMin); if(seenLbl.has(lbl))continue; seenLbl.add(lbl);
    g+=`<text x="${(x(t)+bw/2).toFixed(1)}" y="${H-4}" text-anchor="middle" font-size="9" fill="#5b6675">${lbl}</text>`; }
  // legend
  const leg=_lg.style==="area"
    ?`<rect x="${W-150}" y="${T}" width="8" height="6" fill="#6fcf9744"/><text x="${W-139}" y="${T+6}" font-size="9" fill="#8c98ab">${_trText("всего")}</text><rect x="${W-92}" y="${T}" width="8" height="6" fill="#e0707066"/><text x="${W-81}" y="${T+6}" font-size="9" fill="#8c98ab">4xx+5xx</text>`
    :`<rect x="${W-190}" y="${T}" width="8" height="6" fill="#6fcf9755"/><text x="${W-179}" y="${T+6}" font-size="9" fill="#8c98ab">${_lg.style==="lines"?_trText("всего"):"ok"}</text><rect x="${W-128}" y="${T}" width="8" height="6" fill="#d9a441"/><text x="${W-117}" y="${T+6}" font-size="9" fill="#8c98ab">4xx</text><rect x="${W-84}" y="${T}" width="8" height="6" fill="#e07070"/><text x="${W-73}" y="${T+6}" font-size="9" fill="#8c98ab">5xx</text>`;
  g+=`<g>${leg}</g>`;
  el.innerHTML=`<svg viewBox="0 0 ${W} ${H}" width="100%" style="display:block">${g}</svg>`;
}
// ── tops: top paths + top IPs. Counts are computed WITHOUT the click-filter on the
//    same field (so picking a path keeps the whole list); the picked value is
//    highlighted and clicking it again removes the filter. ──
const _lgTopN={path:10,ip:10};
function _lgChipsWithout(field){
  const out=[];
  if(_lg.cls)out.push({field:"status",op:"class",value:_lg.cls});
  if(_lg.pathQ)out.push({field:"path",op:"re",value:_lg.pathQ});   // substring search stays — tops follow it
  _lg.chips.forEach(c=>{ if(c.field!==field)out.push({field:c.field,op:"eq",value:c.value}); });
  return out;
}
function _lgTopRows(items,field){
  if(!items||!items.length)return `<div class="text-slate-600 text-xs">${_trText("нет данных")}</div>`;
  const act=new Set(_lg.chips.filter(c=>c.field===field).map(c=>c.value));
  const max=Math.max(...items.map(i=>i.count),1);
  const sorted=items.slice().sort((a,b)=>(act.has(String(b.value))?1:0)-(act.has(String(a.value))?1:0));
  return sorted.map((it,idx)=>{
    const v=String(it.value), on=act.has(v);
    const ban=field==="ip"&&idx<5?`<button onclick="event.stopPropagation();lgBanIP('${escJs(v)}')" class="mono" style="font-size:9.5px;color:#d98f8f;border:1px solid #3a2a2a;border-radius:4px;padding:0 4px" title="ban">⛔</button>`:"";
    return `<div class="lg-brow${on?" lg-on":""}" onclick="lgChipAdd('${escJs(field)}','${escJs(v)}')" title="${on?"remove filter":"filter"}">
      <span class="bnm" style="max-width:46%">${field==="ip"&&it.country?flag(String(it.country))+" ":""}${esc(v)}</span>
      <span class="btrk"><span style="display:block;width:${Math.round(it.count/max*100)}%;height:100%;background:#5794f255"></span></span>
      <span class="bct">${on?"✕":_dbNum(it.count)}</span>${ban}</div>`;
  }).join("");
}
const _LG_RAIL_FIELDS=["country","host","method"];
function _lgRailRows(items,field){
  if(!items||!items.length)return "";
  const act=new Set(_lg.chips.filter(c=>c.field===field).map(c=>c.value));
  const max=Math.max(...items.map(i=>i.count),1);
  const sorted=items.slice(0,7).sort((a,b)=>(act.has(String(b.value))?1:0)-(act.has(String(a.value))?1:0));
  return sorted.map(it=>{
    const v=String(it.value), on=act.has(v), col=field==="status"?_lgStatusColor(v):"#5794f2";
    return `<div class="lg-brow${on?" lg-on":""}" onclick="lgChipAdd('${escJs(field)}','${escJs(v)}')" title="${on?"remove filter":"filter"}">
      <span class="bnm" style="color:${field==="status"?col:"#c4cdda"}">${field==='country'?flag(v)+' ':''}${esc(v)}</span>
      <span class="btrk"><span style="display:block;width:${Math.round(it.count/max*100)}%;height:100%;background:${col}77"></span></span>
      <span class="bct">${on?"✕":_dbNum(it.count)}</span></div>`;
  }).join("");
}
async function lgLoadTops(gen){
  const els={path:document.getElementById("lg-top-path"),ip:document.getElementById("lg-top-ip")};
  const rail=document.getElementById("lg-facets");
  if(!els.path)return;
  try{
    const flds=["path","ip","status"].concat(_LG_RAIL_FIELDS);
    const res=await Promise.all(flds.map(f=>
      _post("/api/logs/facets",Object.assign(_lgBody({fields:[f],topn:f==="path"||f==="ip"?_lgTopN[f]:7}),{chips:_lgChipsWithout(f)})).catch(()=>null)));
    if(gen!==undefined&&gen!==_lgGen)return;
    ["path","ip"].forEach((f,i)=>{
      const d=res[i];
      if(d&&d.enabled===false){ els[f].innerHTML='<div class="text-slate-600 text-xs">Loki '+_trText("не настроен")+'.</div>'; return; }
      els[f].innerHTML=_lgTopRows((d&&d.facets&&d.facets[f])||[],f);
      const btn=document.getElementById("lg-more-"+f);
      if(btn)btn.textContent=_lgTopN[f]<=10?"25 ▾":"10 ▴";
    });
    const stEl=document.getElementById("lg-top-status");
    if(stEl)stEl.innerHTML=_lgRailRows((res[2]&&res[2].facets&&res[2].facets.status)||[],"status")
      ||`<div class="text-slate-600 text-xs">${_trText("нет данных")}</div>`;
    if(rail){
      const sec=(f,i)=>{ const html=_lgRailRows((res[i]&&res[i].facets&&res[i].facets[f])||[],f);
        return html?`<div><div class="text-[10px] uppercase tracking-wide text-slate-500 mb-0.5">${f}</div>${html}</div>`:""; };
      rail.innerHTML=_LG_RAIL_FIELDS.map((f,j)=>sec(f,j+3)).filter(Boolean).join("")
        ||`<div class="text-slate-600 text-xs">${_trText("нет данных")}</div>`;
    }
  }catch(e){}
}
function lgTopMore(f){ _lgTopN[f]=_lgTopN[f]<=10?25:10; lgLoadTops(); }
function lgWinLabel(){
  const el=document.getElementById("lg-win-label"); if(!el)return;
  if(_lg.endNs&&_lg.winMin){
    const end=_lg.endNs/1e9, start=end-_lg.winMin*60;
    el.classList.remove("hidden");
    el.innerHTML=`${_lgFmtT(start,1440)}–${_lgFmtT(end,1440)} <button onclick="lgRun()" title="reset" style="color:var(--faint)">✕</button>`;
    lgRenderWinTabs();
  } else el.classList.add("hidden");
}
// ── source tabs by TARGET (nginx VMs via the `vm` stream label, Ingress = no vm),
//    plus extra registered Loki backends. ⚙ panel manages the Loki registry. ──
let _lgVms=[];
async function lgLoadSources(){
  try{ const d=await fetch("/api/log_sources").then(r=>r.json()); _lgSrcAll=d.items||[]; }catch(e){ _lgSrcAll=[]; }
  try{ const d=await fetch("/api/log_label_values?name=vm").then(r=>r.json()); _lgVms=(d.values||[]).filter(Boolean); }catch(e){ _lgVms=[]; }
  lgRenderSrcTabs();
}
const _LG_IC_NGINX='<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#6fcf97" stroke-width="2" style="display:inline-block;vertical-align:-2px"><rect x="2" y="3" width="20" height="7" rx="2"/><rect x="2" y="14" width="20" height="7" rx="2"/><line x1="6" y1="6.5" x2="6" y2="6.51"/><line x1="6" y1="17.5" x2="6" y2="17.51"/></svg>';
const _LG_IC_ING='<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#60a5fa" stroke-width="2" style="display:inline-block;vertical-align:-2px"><path d="M12 2l8 4.5v9L12 20l-8-4.5v-9z"/><path d="M12 11v9M12 11l8-4.5M12 11L4 6.5"/></svg>';
// multi-select: any mix of nginx nodes + ingress + clusters; menus stay open
const _lgPick={vms:[],ing:false,lokis:[]};
function _lgPickApply(){
  const vmList=_lgPick.vms.slice();
  if(_lgPick.ing)vmList.push("");                  // "" = streams without a vm label (k8s)
  _lg.sel=vmList.length?{vm:vmList}:null;
  _lg.sources=_lgPick.lokis.slice();
}
function lgRenderSrcTabs(){
  const el=document.getElementById("lg-src-tabs"); if(!el)return;
  const open=[...el.querySelectorAll(".lg-dd[open]")].map((d,i)=>d.dataset.dd);
  const chk=on=>`<span class="lg-dd-chk${on?" on":""}"></span>`;
  const it=(kind,val,on,label)=>`<div class="lg-dd-it${on?" on":""}" onclick="event.stopPropagation();lgSrcToggle('${kind}','${escJs(val)}')">${chk(on)}${label}</div>`;
  const none=!_lgPick.vms.length&&!_lgPick.ing&&!_lgPick.lokis.length;
  const nSel=_lgPick.vms.length, iSel=(_lgPick.ing?1:0)+_lgPick.lokis.length;
  const nLbl=nSel===0?null:nSel===1?_lgPick.vms[0]:nSel+"/"+_lgVms.length;
  const iLbl=iSel===0?null:(_lgPick.ing&&!_lgPick.lokis.length)?_trText("все кластеры"):(iSel===1?((_lgSrcAll.find(s=>s.id===_lgPick.lokis[0])||{}).label||_lgPick.lokis[0]):String(iSel));
  const dd=(key,icon,title,selLabel,items)=>`<details class="lg-dd" name="lg-src-dd" data-dd="${key}"${open.includes(key)?" open":""}>
      <summary class="lg-pill${selLabel!==null?" on":""}">${icon} ${title}${selLabel!==null?`: <span class="mono">${esc(selLabel)}</span>`:""} ▾</summary>
      <div class="lg-dd-menu">${items}</div></details>`;
  const allOn=_lgVms.length&&_lgPick.vms.length===_lgVms.length;
  const nginxItems=(_lgVms.length>1?it("vm-all","",allOn,_trText("все ноды")):"")+_lgVms.map(v=>it("vm",v,_lgPick.vms.includes(v),esc(v))).join("");
  const ingItems=it("ing","",_lgPick.ing,_trText("все кластеры"))+_lgSrcAll.map(s=>it("loki",s.id,_lgPick.lokis.includes(s.id),esc(s.label||s.id))).join("");
  el.innerHTML=`<span class="lg-pill${none?" on":""}" onclick="lgSrcToggle('all','')">${_trText("Все")}</span>`
    +(_lgVms.length?dd("n",_LG_IC_NGINX,"nginx",nLbl,nginxItems):"")
    +dd("i",_LG_IC_ING,"Ingress",iLbl,ingItems);
}
function lgSrcToggle(kind,val){
  if(kind==="all"){ _lgPick.vms=[]; _lgPick.ing=false; _lgPick.lokis=[];
    document.querySelectorAll(".lg-dd[open]").forEach(d=>d.removeAttribute("open")); }
  else if(kind==="vm")_lgPick.vms=_lgPick.vms.includes(val)?_lgPick.vms.filter(x=>x!==val):_lgPick.vms.concat(val);
  else if(kind==="vm-all")_lgPick.vms=_lgPick.vms.length===_lgVms.length?[]:_lgVms.slice();
  else if(kind==="ing")_lgPick.ing=!_lgPick.ing;
  else if(kind==="loki")_lgPick.lokis=_lgPick.lokis.includes(val)?_lgPick.lokis.filter(x=>x!==val):_lgPick.lokis.concat(val);
  _lgPickApply(); lgRenderSrcTabs(); lgRun();
}
function lgSourcesOpen(){
  const p=document.getElementById("lg-src-panel"); const wasHidden=p.classList.contains("hidden");
  p.classList.toggle("hidden"); if(!wasHidden)return;
  const rows=_lgSrcAll.map(s=>`<span class="inline-flex items-center gap-1"><span class="tray-chip" style="cursor:default">${esc(s.label||s.id)}</span><button onclick="lgSrcDel('${escJs(s.id)}')" class="text-[11px] text-rose-400/70 hover:text-rose-300">✕</button></span>`).join("");
  p.innerHTML=`<div class="flex items-center gap-1.5 flex-wrap">${rows||`<span class="text-slate-600 text-xs">${_trText("используется LOKI_URL по умолчанию — можно добавить ещё Loki")}</span>`}
    <span class="lg-sep"></span>
    <input id="lg-src-url" class="input mono" style="width:210px" placeholder="https://loki.cluster:3100">
    <input id="lg-src-label" class="input" style="width:120px" placeholder="label (env/cluster)">
    <button onclick="lgSrcAdd()" class="btn btn-ghost btn-xs">+ add</button></div>`;
}
async function lgSrcAdd(){
  const url=(document.getElementById("lg-src-url").value||"").trim(), label=(document.getElementById("lg-src-label").value||"").trim();
  if(!url)return; const r=await _post("/api/log_sources",{url,label});
  if(r.ok){ await lgLoadSources(); document.getElementById("lg-src-panel").classList.add("hidden"); lgSourcesOpen(); }
  else uiAlert("не удалось: "+(r.error||"?"));
}
async function lgSrcDel(id){ if(!await uiConfirm(_trText("Удалить это подключение?")))return; await _post("/api/log_sources/delete",{id}); _lg.sources=_lg.sources.filter(x=>x!==id); await lgLoadSources(); document.getElementById("lg-src-panel").classList.add("hidden"); lgSourcesOpen(); lgRun(); }
function lgRenderSrcStatus(sources){
  const el=document.getElementById("lg-src-status"); if(!el)return;
  const bad=(sources||[]).filter(s=>!s.ok);
  if(!bad.length){ el.textContent=""; return; }
  el.className="text-[11px] text-rose-300"; el.textContent="⚠ "+bad.length+"/"+sources.length+" down";
  el.title=bad.map(s=>s.id+": "+(s.error||"?")).join("\n");
}
function lgExport(){
  const blob=new Blob([JSON.stringify(_lg.rows,null,2)],{type:"text/plain"}); const a=document.createElement("a");
  a.href=URL.createObjectURL(blob); a.download="soc-logs.json"; a.click();
}

// ── Custom dashboards (Grafana-style) ─────────────────────────────────────────
const _db={list:[],def:"",curId:"",editing:false};
let _dbData=null,_dbTimer=null,_dbEdit=null;
const _DB_METRICS={
  requests_total:{l:"Requests",f:v=>_dbNum(v)}, requests_real:{l:"Real requests",f:v=>_dbNum(v)},
  forbidden_new:{l:"New blocks",f:v=>_dbNum(v)}, crs_detections:{l:"CRS payloads",f:v=>_dbNum(v)},
  distinct_attacker_ips:{l:"Attacker IPs",f:v=>_dbNum(v)}, unique_visitors:{l:"Unique IPs",f:v=>_dbNum(v)},
  latency_p95:{l:"Latency p95",f:v=>v==null?"—":(+v).toFixed(2)+"s"},
  availability:{l:"Availability",f:v=>v==null?"—":(v*100).toFixed(2)+"%"},
  bytes_mb:{l:"Traffic MB",f:v=>v==null?"—":Math.round(v)}, malicious_ratio:{l:"Malicious %",f:v=>v==null?"—":(v*100).toFixed(1)+"%"}};
const _DB_ANALYTICS={top_paths:"Top paths",top_talkers:"Top talkers (IPs)",top_user_agents:"Top UA",
  top_domains:"Top domains",attack_types:"Attack types",methods:"Methods",crs_rules:"CRS rules",
  geo:"Countries",slow_endpoints:"Slow endpoints"};
// drilldown: which analytics keys route a row-click to an existing view/handler
const _DB_DRILL={top_talkers:1,geo:1,top_paths:1,slow_endpoints:1};
function _dbDrillable(k){ return !!_DB_DRILL[k]; }
function _dbDrillGo(key,value){
  if(!value)return;
  if(key==="top_talkers"){ if(typeof openProfile==="function")openProfile(value); return; }
  if(key==="geo"){ if(typeof openIps==="function")openIps(value); return; }
  if(key==="top_paths"||key==="slow_endpoints"){
    if(typeof showView==="function")showView("dash");
    ["ex_host","ex_status","ex_ip"].forEach(id=>{const e=document.getElementById(id); if(e)e.value="";});
    const p=document.getElementById("ex_path"); if(p)p.value=value;
    if(typeof runExplorer==="function")runExplorer();
    const out=document.getElementById("ex_out"); if(out)setTimeout(()=>out.scrollIntoView({behavior:"smooth",block:"center"}),120);
  }
}
// panel-type taxonomy: which input(s) each type consumes
const _DB_TYPES=[["stat","Stat"],["multistat","Multi-stat"],["timeseries","Time series"],["stacked","Stacked area"],
  ["sparkgrid","Sparkline grid"],["heatmap","Heatmap"],["gauge","Gauge"],["waffle","Waffle %"],["bar","Bar"],["hbar","Bar %"],
  ["table","Table"],["pie","Pie"],["donut","Donut"],["treemap","Treemap"],["geo","Countries"],["logs","Logs"]];
const _DB_T_METRIC=["stat","gauge","waffle"];                              // one summary metric
const _DB_T_METRICS=["multistat","timeseries","stacked","heatmap","sparkgrid"]; // many metrics / history series
const _DB_T_ANALYTICS=["bar","hbar","table","pie","donut","treemap"];      // one analytics top-list
const _DB_PALETTE=["#73bf69","#fade2a","#5794f2","#ff9830","#f2495c","#b877d9","#37a2ea","#96d98d"];
const _DB_ROWH=40,_DB_GAP=12,_DB_COLS=12;                           // grid geometry (matches CSS)
function _dbNum(v){ v=+v||0; return v>=1e6?(v/1e6).toFixed(1)+"M":v>=1e3?(v/1e3).toFixed(1)+"k":String(v); }
function _dbDefH(t){ return t==="logs"?6:(t==="stat"||t==="gauge"||t==="multistat"||t==="waffle")?3:(t==="heatmap"||t==="sparkgrid")?4:5; }
function _dbHHMM(ts){ const d=new Date((+ts||0)*1000); return String(d.getHours()).padStart(2,"0")+":"+String(d.getMinutes()).padStart(2,"0"); }
function dbCur(){ return _db.list.find(d=>d.id===_db.curId)||_db.list[0]; }

async function loadDashboards(){
  try{
    const d=await fetch("/api/dashboards").then(r=>r.json());
    _db.list=d.list||[]; _db.def=d.default||""; if(!_db.curId)_db.curId=_db.def||(_db.list[0]||{}).id;
    dbFillPicker(); dbSyncVars(); dbLoadEnvOpts(); dbLoad(true);
  }catch(e){ document.getElementById("db-grid").innerHTML=`<div class="text-red-400 text-xs">ошибка: ${esc(e.message)}</div>`; }
}
function dbFillPicker(){ const sel=document.getElementById("db-pick"); if(!sel)return;
  sel.innerHTML=_db.list.map(d=>`<option value="${esc(d.id)}" ${d.id===_db.curId?"selected":""}>${esc(d.name)}</option>`).join(""); }
function dbSelect(id){ _db.curId=id; dbSyncVars(); dbLoad(true); }
function dbSyncVars(){ const d=dbCur()||{},v=d.vars||{};
  const e=document.getElementById("db-var-env"),w=document.getElementById("db-var-win");
  if(e)e.value=v.env||""; if(w)w.value=v.window||""; }
function dbVarChange(){ const d=dbCur(); if(!d)return;
  d.vars=Object.assign({},d.vars,{env:document.getElementById("db-var-env").value,window:document.getElementById("db-var-win").value});
  dbPersist(); dbLoad(true); }
async function dbLoadEnvOpts(){
  try{ const d=await fetch("/api/log_label_values?name=env").then(r=>r.json());
    const sel=document.getElementById("db-var-env"); if(!sel)return; const cur=sel.value;
    sel.innerHTML='<option value="">all</option>'+(d.values||[]).map(v=>`<option value="${esc(v)}">${esc(v)}</option>`).join(""); sel.value=cur;
  }catch(e){}
}
async function dbLoad(refetch){
  const grid=document.getElementById("db-grid"); if(!grid)return;
  if(!dbCur()){ grid.innerHTML=`<div class="text-slate-600 text-xs">${_trText("нет дашбордов")}</div>`; return; }
  if(refetch||!_dbData){
    const v=dbCur().vars||{}, qp=new URLSearchParams();
    if(v.env)qp.set("env",v.env); if(v.window)qp.set("window",v.window);
    const sfx=qp.toString()?("?"+qp.toString()):"";
    try{
      const [s,h,a]=await Promise.all([
        fetch("/api/summary"+(v.env?"?env="+encodeURIComponent(v.env):"")).then(r=>r.json()).catch(()=>({})),
        fetch("/api/history?limit=240").then(r=>r.json()).catch(()=>({snapshots:[]})),
        fetch("/api/analytics"+sfx).then(r=>r.json()).catch(()=>({}))]);
      _dbData={summary:s.summary||s||{}, history:h.snapshots||[], analytics:(a.analytics||a||{})};
    }catch(e){ _dbData={summary:{},history:[],analytics:{}}; }
  }
  dbRender();
  clearTimeout(_dbTimer); if(_view==="dashboards"&&!_db.editing)_dbTimer=setTimeout(()=>dbLoad(true),30000);
}

// ── grid layout: normalize {gx,gy,w,h}, flow-pack legacy panels, compact ───────
function _dbNormalize(dash){
  let need=false;
  dash.panels.forEach(p=>{
    if(p.w==null)p.w=Math.min(12,Math.max(2,p.span||4));
    if(p.h==null){p.h=_dbDefH(p.type);need=true;}
    if(p.gx==null||p.gy==null)need=true;
  });
  if(need)_dbFlow(dash.panels);
  return need;
}
function _dbFlow(panels){                   // greedy top-left packer into a 12-col grid
  const bottom=new Array(_DB_COLS).fill(0);
  panels.forEach(p=>{
    const w=Math.min(_DB_COLS,Math.max(2,p.w||4)),h=Math.max(2,p.h||4);
    let bx=0,by=Infinity;
    for(let x=0;x+w<=_DB_COLS;x++){ let y=0; for(let i=x;i<x+w;i++)y=Math.max(y,bottom[i]); if(y<by){by=y;bx=x;} }
    p.gx=bx;p.gy=by;p.w=w;p.h=h;
    for(let i=bx;i<bx+w;i++)bottom[i]=by+h;
  });
}
function _dbCollide(a,b){ return a.gx<b.gx+b.w && a.gx+a.w>b.gx && a.gy<b.gy+b.h && a.gy+a.h>b.gy; }
function _dbCompact(panels){                // gravity-up compaction preserving order
  const sorted=panels.slice().sort((a,b)=>(a.gy-b.gy)||(a.gx-b.gx));
  const placed=[];
  sorted.forEach(p=>{ let y=p.gy; while(y>0&&!placed.some(q=>_dbCollide({...p,gy:y-1},q)))y--; p.gy=y; placed.push(p); });
}
function _dbResolve(panels,active){         // push panels the active one overlaps downward, then compact
  let guard=0,moved=true;
  while(moved&&guard++<300){
    moved=false;
    for(const p of panels){
      if(p===active)continue;
      if(_dbCollide(p,active)){ p.gy=active.gy+active.h; moved=true; }
    }
    // cascade: anything now overlapping a pushed panel also drops
    for(const p of panels)for(const q of panels){ if(p!==q&&_dbCollide(p,q)&&p.gy<q.gy){ /* keep order */ } }
  }
  _dbCompact(panels.filter(p=>p!==active).concat([active]).sort((a,b)=>a.gy-b.gy||a.gx-b.gx));
}

function dbRender(){
  const grid=document.getElementById("db-grid"),dash=dbCur(); if(!grid||!dash)return;
  grid.classList.toggle("db-editing",_db.editing);
  if(_dbNormalize(dash))dbPersist();
  if(!dash.panels.length){ grid.innerHTML=`<div class="text-slate-600 text-xs" style="grid-column:1 / span 12">${_trText("пусто — добавь панель")}</div>`; return; }
  const maxRow=Math.max(6,...dash.panels.map(p=>p.gy+p.h));
  grid.style.gridTemplateRows=`repeat(${maxRow},${_DB_ROWH}px)`;
  grid.innerHTML=`<div class="db-ghost" id="db-ghost"></div>`+dash.panels.map(p=>`<div class="db-panel" data-pid="${esc(p.id)}"
    style="grid-column:${(p.gx|0)+1} / span ${Math.max(2,Math.min(12,p.w||4))};grid-row:${(p.gy|0)+1} / span ${Math.max(2,p.h||4)}">
    <div class="db-head" onpointerdown="dbDragStart(event,'${escJs(p.id)}')"><span class="db-title">${esc(p.title||p.type)}</span>
      <span class="db-tools">
        <button onpointerdown="event.stopPropagation()" onclick="dbDupPanel('${escJs(p.id)}')" class="text-[11px] text-slate-300" title="duplicate">⧉</button>
        <button onpointerdown="event.stopPropagation()" onclick="dbEditPanel('${escJs(p.id)}')" class="text-[11px]" style="color:var(--accent2)" title="edit">✎</button>
        <button onpointerdown="event.stopPropagation()" onclick="dbDelPanel('${escJs(p.id)}')" class="text-[11px] text-rose-300" title="remove">✕</button></span></div>
    <div class="db-body" id="dbp-${esc(p.id)}"></div>
    <div class="db-resize" onpointerdown="dbResizeStart(event,'${escJs(p.id)}')"></div></div>`).join("");
  dash.panels.forEach(dbFillPanel);
}
function dbFillPanel(p){
  const el=document.getElementById("dbp-"+p.id); if(!el)return;
  try{
    if(p.type==="stat")el.innerHTML=_dbStat(p);
    else if(p.type==="multistat")el.innerHTML=_dbMulti(p);
    else if(p.type==="timeseries")el.innerHTML=_dbTimeseries(p,false);
    else if(p.type==="stacked")el.innerHTML=_dbTimeseries(p,true);
    else if(p.type==="heatmap")el.innerHTML=_dbHeatmap(p);
    else if(p.type==="bar")el.innerHTML=_dbBar(p,false);
    else if(p.type==="hbar")el.innerHTML=_dbBar(p,true);
    else if(p.type==="table")el.innerHTML=_dbTable(p);
    else if(p.type==="pie")el.innerHTML=_dbPie(p,false);
    else if(p.type==="donut")el.innerHTML=_dbPie(p,true);
    else if(p.type==="gauge")el.innerHTML=_dbGauge(p);
    else if(p.type==="geo")el.innerHTML=_dbGeo(p);
    else if(p.type==="sparkgrid")el.innerHTML=_dbSparkGrid(p);
    else if(p.type==="treemap")el.innerHTML=_dbTreemap(p);
    else if(p.type==="waffle")el.innerHTML=_dbWaffle(p);
    else if(p.type==="logs"){ el.innerHTML=`<span class="text-slate-600 text-xs">…</span>`; _dbLogsPanel(p,el); }
    else el.innerHTML=`<span class="text-slate-600 text-xs">${esc(p.type)}?</span>`;
  }catch(e){ el.innerHTML=`<span class="text-rose-400 text-xs">${esc(e.message)}</span>`; }
}

// ── SVG helpers ────────────────────────────────────────────────────────────────
function _smooth(pts){                       // Catmull-Rom → cubic Bézier path 'd'
  if(pts.length<2)return pts.length?`M${pts[0][0]},${pts[0][1]}`:"";
  let d=`M${pts[0][0].toFixed(1)},${pts[0][1].toFixed(1)}`;
  for(let i=0;i<pts.length-1;i++){
    const p0=pts[i-1]||pts[i],p1=pts[i],p2=pts[i+1],p3=pts[i+2]||p2;
    const c1x=p1[0]+(p2[0]-p0[0])/6,c1y=p1[1]+(p2[1]-p0[1])/6;
    const c2x=p2[0]-(p3[0]-p1[0])/6,c2y=p2[1]-(p3[1]-p1[1])/6;
    d+=` C${c1x.toFixed(1)},${c1y.toFixed(1)} ${c2x.toFixed(1)},${c2y.toFixed(1)} ${p2[0].toFixed(1)},${p2[1].toFixed(1)}`;
  }
  return d;
}
function _niceMax(v){ if(v<=0)return 1; const p=Math.pow(10,Math.floor(Math.log10(v))); const n=v/p;
  const s=n<=1?1:n<=2?2:n<=5?5:10; return s*p; }
function _median(a){ if(!a.length)return 0; const s=a.slice().sort((x,y)=>x-y),m=s.length>>1; return s.length%2?s[m]:(s[m-1]+s[m])/2; }
// anomaly band: trailing rolling median ± 3·(1.4826·MAD); returns band-fill + breach-dot SVG for one series
function _dbAnomaly(series,xs,Y,max){
  const n=series.length; if(n<3)return {band:"",breach:""};
  const WIN=8,up=[],lo=[],br=[];
  for(let i=0;i<n;i++){ const a=Math.max(0,i-WIN+1),win=series.slice(a,i+1);
    const med=_median(win),mad=_median(win.map(x=>Math.abs(x-med))),sd=mad*1.4826;
    const b=Math.max(sd*3, med*0.2, 1);
    up.push(Math.min(med+b,max)); lo.push(Math.max(0,med-b));
    if(i>=2 && Math.abs(series[i]-med)>b) br.push(i); }
  const upPts=up.map((v,i)=>[xs[i],Y(v)]), loPts=lo.map((v,i)=>[xs[i],Y(v)]);
  const dUp=_smooth(upPts), dLo=loPts.slice().reverse().map(p=>`L${p[0].toFixed(1)},${p[1].toFixed(1)}`).join("");
  return { band:`<path d="${dUp} ${dLo} Z" fill="var(--accent)" fill-opacity=".12"/>`,
           breach:br.map(i=>`<circle cx="${xs[i].toFixed(1)}" cy="${Y(series[i]).toFixed(1)}" r="3" fill="var(--crit)" stroke="var(--surface)" stroke-width="1.2"/>`).join("") }; }

const _dbHov={};   // panel-id → {W,H,pl,pr,pt,pb,plotW,plotH,n,xs,series:[{color,pts,name}],fmt,tf}
function _dbTimeseries(p,stacked){
  const snaps=_dbData.history||[],metrics=(p.metrics&&p.metrics.length?p.metrics:[p.metric]).filter(Boolean);
  if(snaps.length<2||!metrics.length)return `<div class="db-empty text-slate-600 text-xs">${_trText("мало точек")}</div>`;
  const W=600,H=200,pl=42,pr=10,pt=10,pb=20,plotW=W-pl-pr,plotH=H-pt-pb;
  const n=snaps.length, xs=snaps.map((s,i)=>pl+(n===1?0:i/(n-1)*plotW));
  // series values
  const vals=metrics.map(m=>snaps.map(s=>+s[m]||0));
  let max=1;
  if(stacked){ for(let i=0;i<n;i++){ let sum=0; vals.forEach(v=>sum+=v[i]); if(sum>max)max=sum; } }
  else { vals.forEach(v=>v.forEach(x=>{ if(x>max)max=x; })); }
  const thr=(p.thresholds||[]).filter(t=>t&&isFinite(+t.v)); thr.forEach(t=>{ if(+t.v>max)max=+t.v; });  // keep thresholds on-chart
  max=_niceMax(max);
  const Y=v=>pt+plotH-(v/max)*plotH;
  const _ano=(p.anomaly&&!stacked&&vals.length)?_dbAnomaly(vals[0],xs,Y,max):{band:"",breach:""};
  const defs=[],paths=[],dots=[];
  const stackTop=new Array(n).fill(0); // running total for stacked
  const seriesMeta=[];
  metrics.forEach((m,mi)=>{
    const col=(p.colors&&p.colors[m])||_DB_PALETTE[mi%_DB_PALETTE.length];
    let linePts,areaPts;
    if(stacked){
      const topY=[],botY=[];
      for(let i=0;i<n;i++){ const base=stackTop[i]; stackTop[i]=base+vals[mi][i]; topY.push([xs[i],Y(stackTop[i])]); botY.push([xs[i],Y(base)]); }
      linePts=topY;
      const dTop=_smooth(topY), dBot=botY.slice().reverse().map(pt2=>`L${pt2[0].toFixed(1)},${pt2[1].toFixed(1)}`).join("");
      paths.push(`<path d="${dTop} ${dBot} Z" fill="${col}" fill-opacity=".28"/>`);
      paths.push(`<path d="${dTop}" fill="none" stroke="${col}" stroke-width="1.6"/>`);
    } else {
      linePts=vals[mi].map((v,i)=>[xs[i],Y(v)]);
      const gid=`g-${p.id}-${mi}`;
      defs.push(`<linearGradient id="${gid}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${col}" stop-opacity="${metrics.length>1?.18:.34}"/><stop offset="1" stop-color="${col}" stop-opacity="0"/></linearGradient>`);
      const dLine=_smooth(linePts);
      paths.push(`<path d="${dLine} L${xs[n-1].toFixed(1)},${(pt+plotH).toFixed(1)} L${xs[0].toFixed(1)},${(pt+plotH).toFixed(1)} Z" fill="url(#${gid})"/>`);
      paths.push(`<path d="${dLine}" fill="none" stroke="${col}" stroke-width="1.8"/>`);
    }
    dots.push(`<circle cx="${linePts[n-1][0].toFixed(1)}" cy="${linePts[n-1][1].toFixed(1)}" r="2.6" fill="${col}"/>`);
    seriesMeta.push({color:col,pts:linePts,name:(_DB_METRICS[m]||{l:m}).l,vals:vals[mi]});
  });
  // axes: y gridlines/labels + x time labels
  let ax="";
  for(let g=0;g<=2;g++){ const v=max*g/2,y=Y(v);
    ax+=`<line x1="${pl}" y1="${y.toFixed(1)}" x2="${W-pr}" y2="${y.toFixed(1)}" stroke="var(--border)" stroke-width="1"/>`+
        `<text class="db-ax" x="${pl-5}" y="${(y+3).toFixed(1)}" text-anchor="end">${esc(_dbNum(v))}</text>`; }
  const xticks=Math.min(4,n-1);
  for(let t=0;t<=xticks;t++){ const i=Math.round(t/xticks*(n-1));
    ax+=`<text class="db-ax" x="${xs[i].toFixed(1)}" y="${(H-6)}" text-anchor="middle">${esc(_dbHHMM(snaps[i].ts))}</text>`; }
  // threshold lines (dashed, labelled at the right edge)
  const thrSvg=thr.map(t=>{ const y=Y(+t.v),c=t.c||"var(--crit)";
    return `<line x1="${pl}" y1="${y.toFixed(1)}" x2="${W-pr}" y2="${y.toFixed(1)}" stroke="${c}" stroke-width="1.2" stroke-dasharray="5 3" opacity=".85"/>`+
      `<text class="db-ax" x="${W-pr-2}" y="${(y-3).toFixed(1)}" text-anchor="end" style="fill:${c}">${esc(_dbNum(+t.v))}</text>`; }).join("");
  _dbHov[p.id]={W,H,pl,plotW,n,xs,pt,plotH,series:seriesMeta,fmt:v=>_dbNum(v),snaps};
  const legend=seriesMeta.map(s=>`<span style="color:${s.color}">● <span style="color:var(--muted)">${esc(s.name)}</span></span>`).join(" &nbsp; ");
  // hover dots pre-created inside the SVG string (parsed in SVG namespace by the HTML parser)
  const hdots=seriesMeta.map((s,k)=>`<circle class="db-hd" data-k="${k}" r="3.4" fill="${s.color}" stroke="var(--surface)" stroke-width="1.6" style="display:none"/>`).join("");
  return `<div class="text-[10px] mb-1" style="color:var(--faint)">${legend}</div>
    <svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="width:100%;height:calc(100% - 16px)" onmousemove="dbTsMove(event,'${escJs(p.id)}')" onmouseleave="dbTsLeave('${escJs(p.id)}')">
    <defs>${defs.join("")}</defs>${ax}${thrSvg}${_ano.band}${paths.join("")}${dots.join("")}${_ano.breach}
    <line id="cx-${esc(p.id)}" class="db-crosshair" y1="${pt}" y2="${pt+plotH}" style="display:none"/>${hdots}</svg>
    <div class="db-tsi" id="tip-${esc(p.id)}" style="display:none"></div>`;
}
function dbTsMove(ev,id){
  const H=_dbHov[id]; if(!H)return; const svg=ev.currentTarget,r=svg.getBoundingClientRect();
  if(!r.width)return;
  const vx=(ev.clientX-r.left)/r.width*H.W;
  let i=Math.round((vx-H.pl)/H.plotW*(H.n-1)); i=Math.max(0,Math.min(H.n-1,i));
  const ln=document.getElementById("cx-"+id); if(!ln)return;
  const x=H.xs[i]; ln.style.display=""; ln.setAttribute("x1",x); ln.setAttribute("x2",x);
  const dots=svg.querySelectorAll(".db-hd");
  H.series.forEach((s,k)=>{ const c=dots[k]; if(c){ c.setAttribute("cx",x.toFixed(1)); c.setAttribute("cy",s.pts[i][1].toFixed(1)); c.style.display=""; } });
  const tip=document.getElementById("tip-"+id); if(!tip)return;
  tip.innerHTML=`<div class="db-tsi-t">${esc(_dbHHMM(H.snaps[i].ts))}</div>`+
    H.series.map(s=>`<div><span style="color:${s.color}">●</span> ${esc(s.name)}: <b>${esc(String(H.fmt(s.vals[i])))}</b></div>`).join("");
  tip.style.display="block";
  const frac=(x-H.pl)/H.plotW, right=frac>0.6;                 // flip side near the right edge
  tip.style.left=right?"auto":(frac*100+2)+"%"; tip.style.right=right?((1-frac)*100+2)+"%":"auto"; tip.style.top="4px";
}
function dbTsLeave(id){ const ln=document.getElementById("cx-"+id),tip=document.getElementById("tip-"+id),b=ln&&ln.closest(".db-body");
  if(ln)ln.style.display="none"; if(tip)tip.style.display="none";
  if(b)b.querySelectorAll(".db-hd").forEach(c=>c.style.display="none"); }

function _dbStat(p){
  const m=p.metric,meta=_DB_METRICS[m]||{l:m,f:v=>v},v=(_dbData.summary||{})[m];
  const spark=(_dbData.history||[]).map(s=>+s[m]||0);
  let delta="";
  if(spark.length>1){ const a=spark[0],b=spark[spark.length-1],d=b-a;
    const cls=Math.abs(d)<1e-9?"flat":d>0?"up":"dn",arr=cls==="flat"?"→":d>0?"▲":"▼";
    const pctd=a?Math.abs(d/a*100):0; delta=`<span class="db-delta ${cls}">${arr} ${pctd>=1?Math.round(pctd)+"%":_dbNum(Math.abs(d))}</span>`; }
  return `<div class="db-stat-wrap"><div><span class="db-stat-val">${v==null?"—":esc(String(meta.f(v)))}</span>${delta}</div>
    <div class="db-stat-sub">${esc(meta.l)}</div>${spark.length>1?_dbSpark(spark,p.id):""}</div>`;
}
function _dbSpark(vals,id){
  const w=200,h=34,max=Math.max(...vals,1),min=Math.min(...vals,0),rng=(max-min)||1;
  const pts=vals.map((v,i)=>[i/(vals.length-1)*w,h-((v-min)/rng)*h]);
  const gid="sp-"+id;
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" style="width:100%;height:34px;margin-top:8px">
    <defs><linearGradient id="${gid}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="var(--accent)" stop-opacity=".34"/><stop offset="1" stop-color="var(--accent)" stop-opacity="0"/></linearGradient></defs>
    <path d="${_smooth(pts)} L${w},${h} L0,${h} Z" fill="url(#${gid})"/>
    <path d="${_smooth(pts)}" fill="none" stroke="var(--accent)" stroke-width="1.6"/>
    <circle cx="${pts[pts.length-1][0].toFixed(1)}" cy="${pts[pts.length-1][1].toFixed(1)}" r="2.4" fill="var(--accent2)"/></svg>`;
}
function _dbMulti(p){
  const ms=(p.metrics&&p.metrics.length?p.metrics:[p.metric||"requests_total"]).filter(Boolean);
  const sum=_dbData.summary||{};
  return `<div class="db-multi">`+ms.map(m=>{ const meta=_DB_METRICS[m]||{l:m,f:v=>v},v=sum[m];
    const c=(p.colors&&p.colors[m])?` style="color:${p.colors[m]}"`:"";
    return `<div class="m"><div class="mv"${c}>${v==null?"—":esc(String(meta.f(v)))}</div><div class="ml">${esc(meta.l)}</div></div>`;
  }).join("")+`</div>`;
}
function _dbList(key){ let v=(_dbData.analytics||{})[key]; if(!Array.isArray(v))v=[];
  return v.map(it=>({k:it.key!=null?it.key:(it.name||it.label||it.uri||it.cc||"—"),n:+it.count||+it.n||+it.hits||0})); }
function _dbBar(p,pct){
  const rows=_dbList(p.key).slice(0,8); if(!rows.length)return `<span class="text-slate-600 text-xs">${_trText("нет данных")}</span>`;
  const total=rows.reduce((s,r)=>s+r.n,0)||1,max=Math.max(...rows.map(r=>r.n),1),dr=_dbDrillable(p.key);
  return rows.map(r=>{ const w=pct?Math.round(r.n/total*100):Math.round(r.n/max*100);
    const rt=pct?Math.round(r.n/total*100)+"%":_dbNum(r.n);
    return `<div class="db-bar-row${dr?' db-drill':''}" data-dk="${esc(String(r.k))}"><span class="db-bar-k" title="${esc(String(r.k))}">${esc(String(r.k))}</span><span class="db-bar-track"><span class="db-bar-fill" style="width:${w}%"></span></span><span class="db-bar-n">${rt}</span></div>`; }).join("");
}
function _dbTable(p){
  const rows=_dbList(p.key).slice(0,20); if(!rows.length)return `<span class="text-slate-600 text-xs">${_trText("нет данных")}</span>`;
  const dr=_dbDrillable(p.key);
  return `<div style="overflow:auto;height:100%"><table class="db-tbl"><thead><tr><th>${esc(_DB_ANALYTICS[p.key]||p.key)}</th><th style="text-align:right">#</th></tr></thead><tbody>${rows.map(r=>`<tr${dr?' class="db-drill"':''} data-dk="${esc(String(r.k))}"><td class="mono" style="max-width:0;overflow:hidden;text-overflow:ellipsis">${esc(String(r.k))}</td><td style="text-align:right">${_dbNum(r.n)}</td></tr>`).join("")}</tbody></table></div>`;
}
function _dbPie(p,donut){
  const rows=_dbList(p.key).slice(0,7); if(!rows.length)return `<span class="text-slate-600 text-xs">${_trText("нет данных")}</span>`;
  const total=rows.reduce((s,r)=>s+r.n,0)||1; const R=donut?50:30,sw=donut?16:60,C=2*Math.PI*R; let off=0;
  const ring=rows.map((r,i)=>{const frac=r.n/total,len=frac*C,seg=`<circle cx="60" cy="60" r="${R}" fill="none" stroke="${_DB_PALETTE[i%_DB_PALETTE.length]}" stroke-width="${sw}" stroke-dasharray="${len.toFixed(2)} ${(C-len).toFixed(2)}" stroke-dashoffset="${(-off).toFixed(2)}" transform="rotate(-90 60 60)"><title>${esc(String(r.k))}: ${_dbNum(r.n)} (${Math.round(frac*100)}%)</title></circle>`;off+=len;return seg;}).join("");
  const center=donut?`<text x="60" y="56" text-anchor="middle" font-size="18" font-weight="700" fill="var(--text)">${_dbNum(total)}</text><text x="60" y="72" text-anchor="middle" font-size="9" fill="var(--faint)">total</text>`:"";
  const legend=rows.map((r,i)=>`<div class="flex items-center gap-1.5 text-[11px]"><span style="color:${_DB_PALETTE[i%_DB_PALETTE.length]}">●</span><span class="truncate flex-1" style="color:var(--muted)">${esc(String(r.k))}</span><span style="color:var(--text)">${Math.round(r.n/total*100)}%</span></div>`).join("");
  return `<div class="flex items-center gap-3 h-full"><svg viewBox="0 0 120 120" style="width:112px;height:112px;flex-shrink:0">${ring}${center}</svg><div class="flex-1 min-w-0 space-y-0.5" style="overflow:auto;max-height:100%">${legend}</div></div>`;
}
function _dbGauge(p){
  const m=p.metric,meta=_DB_METRICS[m]||{l:m},raw=(_dbData.summary||{})[m];
  let frac=+raw||0; if(frac>1)frac=Math.min(1,frac/100);
  const pct=Math.round(frac*100),R=46,C=Math.PI*R,len=frac*C;
  const col=frac>=0.66?"var(--ok)":frac>=0.33?"var(--warn)":"var(--crit)";
  return `<div class="flex flex-col items-center justify-center h-full"><svg viewBox="0 0 120 70" style="width:150px;height:84px">
    <path d="M14 60 A46 46 0 0 1 106 60" fill="none" stroke="var(--border)" stroke-width="12" stroke-linecap="round"/>
    <path d="M14 60 A46 46 0 0 1 106 60" fill="none" stroke="${col}" stroke-width="12" stroke-linecap="round" stroke-dasharray="${len.toFixed(1)} ${C.toFixed(1)}"/></svg>
    <div class="db-stat-val" style="font-size:24px;margin-top:-10px">${pct}%</div><div class="db-stat-sub">${esc(meta.l)}</div></div>`;
}
function _dbHeatmap(p){
  const snaps=_dbData.history||[],metrics=(p.metrics&&p.metrics.length?p.metrics:[p.metric]).filter(Boolean);
  if(snaps.length<2||!metrics.length)return `<div class="text-slate-600 text-xs">${_trText("мало точек")}</div>`;
  const N=Math.min(snaps.length,60),step=Math.ceil(snaps.length/N);
  const idx=[]; for(let i=0;i<snaps.length;i+=step)idx.push(i);
  const rows=metrics.map(m=>{
    const cells=idx.map(i=>+snaps[i][m]||0),mx=Math.max(...cells,1);
    const html=idx.map((i,k)=>{ const v=cells[k],t=Math.log10(v+1)/Math.log10(mx+1);
      return `<div class="db-hm-cell" style="background:${_hmColor(t)}" title="${esc(_dbHHMM(snaps[i].ts))} · ${esc((_DB_METRICS[m]||{l:m}).l)}: ${_dbNum(v)}"></div>`; }).join("");
    return `<div class="db-hm-row"><span class="db-hm-lbl">${esc((_DB_METRICS[m]||{l:m}).l)}</span><span class="db-hm-cells">${html}</span></div>`;
  }).join("");
  const t0=_dbHHMM(snaps[idx[0]].ts),t1=_dbHHMM(snaps[idx[idx.length-1]].ts);
  return rows+`<div class="flex justify-between mt-1" style="font-size:9px;color:var(--faint);padding-left:94px"><span>${esc(t0)}</span><span>${esc(t1)}</span></div>`;
}
function _hmColor(t){ // 0..1 → dark → accent ramp
  t=Math.max(0,Math.min(1,t));
  const a=[40,39,56],b=[139,124,246]; // --border-ish → --accent
  const c=a.map((x,i)=>Math.round(x+(b[i]-x)*t));
  return `rgb(${c[0]},${c[1]},${c[2]})`;
}
function _dbGeo(p){
  const rows=_dbList("geo").slice(0,10); if(!rows.length)return `<span class="text-slate-600 text-xs">${_trText("нет данных")}</span>`;
  const max=Math.max(...rows.map(r=>r.n),1);
  return rows.map(r=>`<div class="db-bar-row db-drill" data-dk="${esc(String(r.k))}"><span class="db-bar-k">${flag(String(r.k))} ${esc(String(r.k))}</span><span class="db-bar-track"><span class="db-bar-fill" style="width:${Math.round(r.n/max*100)}%"></span></span><span class="db-bar-n">${_dbNum(r.n)}</span></div>`).join("");
}
function _dbSparkGrid(p){                     // small multiples: one mini-trend per metric
  const snaps=_dbData.history||[], sum=_dbData.summary||{};
  const ms=(p.metrics&&p.metrics.length?p.metrics:[p.metric]).filter(Boolean);
  if(!ms.length)return `<span class="text-slate-600 text-xs">${_trText("выберите метрики")}</span>`;
  return `<div class="db-sg">`+ms.map((m,mi)=>{
    const meta=_DB_METRICS[m]||{l:m,f:v=>v}, series=snaps.map(s=>+s[m]||0);
    const cur=sum[m]!=null?sum[m]:(series.length?series[series.length-1]:null);
    const col=(p.colors&&p.colors[m])||_DB_PALETTE[mi%_DB_PALETTE.length];
    let delta="";
    if(series.length>1){ const a=series[0],b=series[series.length-1],dd=b-a;
      const cls=Math.abs(dd)<1e-9?"flat":dd>0?"up":"dn",arr=cls==="flat"?"→":dd>0?"▲":"▼",pd=a?Math.abs(dd/a*100):0;
      delta=`<span class="db-delta ${cls}" style="font-size:10px;margin:0">${arr}${pd>=1?Math.round(pd)+"%":""}</span>`; }
    let svg="";
    if(series.length>1){ const w=120,h=26,mx=Math.max(...series,1),mn=Math.min(...series,0),rng=(mx-mn)||1;
      const pts=series.map((v,i)=>[i/(series.length-1)*w, h-((v-mn)/rng)*h]);
      svg=`<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" style="width:100%;height:26px;margin-top:4px"><path d="${_smooth(pts)}" fill="none" stroke="${col}" stroke-width="1.6"/><circle cx="${pts[pts.length-1][0].toFixed(1)}" cy="${pts[pts.length-1][1].toFixed(1)}" r="2" fill="${col}"/></svg>`; }
    return `<div class="db-sg-cell"><div class="db-sg-h"><span class="db-sg-l">${esc(meta.l)}</span>${delta}</div><div class="db-sg-v">${cur==null?"—":esc(String(meta.f(cur)))}</div>${svg}</div>`;
  }).join("")+`</div>`;
}
function _dbWaffle(p){                        // one ratio metric → 10×10 unit grid
  const m=p.metric,meta=_DB_METRICS[m]||{l:m,f:v=>v},raw=(_dbData.summary||{})[m];
  if(raw==null)return `<span class="text-slate-600 text-xs">${_trText("нет данных")}</span>`;
  let frac=+raw||0; if(frac>1)frac=Math.min(1,frac/100);
  const filled=Math.round(frac*100);
  const hot=(m==="malicious_ratio"||m==="forbidden_new"||m==="crs_detections")?"var(--crit)":(m==="availability")?"var(--ok)":"var(--accent)";
  let cells=""; for(let i=0;i<100;i++)cells+=`<span class="db-wf-c" style="background:${i<filled?hot:'#ffffff10'}"></span>`;
  const pv=frac*100, pct=((pv>0&&pv<10)||pv>90)?pv.toFixed(1):String(Math.round(pv));
  return `<div class="db-wf-wrap"><div class="db-wf">${cells}</div><div class="db-wf-meta"><div class="db-wf-pct" style="color:${hot}">${pct}%</div><div class="db-stat-sub">${esc(meta.l)}</div></div></div>`;
}
function _squarify(children,x,y,w,h){         // Bruls et al. squarified treemap layout
  const out=[], nodes=children.map(c=>({item:c, area:Math.max(c.area,1e-6)}));
  const total=nodes.reduce((s,n)=>s+n.area,0)||1, k=(w*h)/total; nodes.forEach(n=>n.area*=k);
  const worst=(row,side)=>{ const sum=row.reduce((s,r)=>s+r.area,0),mx=Math.max(...row.map(r=>r.area)),mn=Math.min(...row.map(r=>r.area));
    return Math.max((side*side*mx)/(sum*sum),(sum*sum)/(side*side*mn)); };
  let rx=x,ry=y,rw=w,rh=h,i=0;
  while(i<nodes.length){
    const vertical=rw<rh, side=vertical?rw:rh; let row=[nodes[i]],j=i+1;
    while(j<nodes.length){ const test=row.concat([nodes[j]]); if(worst(test,side)<=worst(row,side)){ row.push(nodes[j]); j++; } else break; }
    const rowSum=row.reduce((s,r)=>s+r.area,0), thick=rowSum/side; let off=vertical?rx:ry;
    row.forEach(n=>{ const len=n.area/thick;
      if(vertical){ out.push({item:n.item,x:off,y:ry,w:len,h:thick}); off+=len; }
      else { out.push({item:n.item,x:rx,y:off,w:thick,h:len}); off+=len; } });
    if(vertical){ ry+=thick; rh-=thick; } else { rx+=thick; rw-=thick; }
    i=j;
  }
  return out;
}
function _dbTreemap(p){                       // analytics top-list → treemap (area ∝ count)
  let rows=_dbList(p.key).filter(r=>r.n>0).sort((a,b)=>b.n-a.n);
  if(!rows.length)return `<span class="text-slate-600 text-xs">${_trText("нет данных")}</span>`;
  const top=rows.slice(0,14), restN=rows.slice(14).reduce((s,r)=>s+r.n,0);
  if(restN>0)top.push({k:_trText("прочее"),n:restN,_o:1});
  const total=top.reduce((s,r)=>s+r.n,0)||1;
  const tiles=_squarify(top.map((r,i)=>({r,i,area:r.n})),0,0,100,100);
  return `<div class="db-tm">`+tiles.map(t=>{
    const r=t.item.r, col=r._o?"var(--faint)":_DB_PALETTE[t.item.i%_DB_PALETTE.length], pct=Math.round(r.n/total*100), lbl=t.w>16&&t.h>12, dr=_dbDrillable(p.key)&&!r._o;
    return `<div class="db-tm-c${dr?' db-drill':''}"${dr?` data-dk="${esc(String(r.k))}"`:''} style="left:${t.x.toFixed(2)}%;top:${t.y.toFixed(2)}%;width:${t.w.toFixed(2)}%;height:${t.h.toFixed(2)}%;background:${col};color:${r._o?'#ECEAF6':'#0d0c14'}" title="${esc(String(r.k))}: ${_dbNum(r.n)} (${pct}%)">${lbl?`<span class="db-tm-k">${esc(String(r.k))}</span><span class="db-tm-n">${_dbNum(r.n)}</span>`:""}</div>`;
  }).join("")+`</div>`;
}
async function _dbLogsPanel(p,el){
  try{
    const body={search:p.search||"",chips:[],sources:{},minutes:p.minutes||15,limit:20,env:(dbCur().vars||{}).env||_env||""};
    const d=await fetch("/api/logs/query",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)}).then(r=>r.json());
    const rows=d.rows||[];
    el.innerHTML=rows.length?`<div style="overflow:auto;height:100%"><table class="db-tbl"><tbody>${rows.map(r=>`<tr><td class="mono" style="color:var(--faint);width:54px">${esc(r.time)}</td><td class="mono" style="color:${_lgStatusColor(r.status)};width:30px">${esc(r.status||"")}</td><td class="mono" style="max-width:0;overflow:hidden;text-overflow:ellipsis">${esc(r.path||r.line||"")}</td></tr>`).join("")}</tbody></table></div>`
      :`<span class="text-slate-600 text-xs">${_trText("нет строк под фильтр")}</span>`;
  }catch(e){ el.innerHTML=`<span class="text-rose-400 text-xs">${esc(e.message)}</span>`; }
}

// ── edit-mode: toggle, drag-move, resize ───────────────────────────────────────
function dbToggleEdit(){ _db.editing=!_db.editing; document.getElementById("db-editmode").classList.toggle("btn-primary",_db.editing); dbRender(); }
function dbDelPanel(id){ const d=dbCur(); d.panels=d.panels.filter(p=>p.id!==id); _dbCompact(d.panels); dbPersist(); dbRender(); }
function dbDupPanel(id){ const d=dbCur(),p=d.panels.find(x=>x.id===id); if(!p)return;
  const c=JSON.parse(JSON.stringify(p)); c.id="p"+Date.now(); c.title=(p.title||"")+" copy"; c.gy=p.gy+p.h; c.gx=p.gx;
  d.panels.push(c); _dbResolve(d.panels,c); dbPersist(); dbRender(); }
function dbAddPanel(){ dbEditPanel(null); }

let _dbDrag=null;
function _dbGridMetrics(){ const g=document.getElementById("db-grid"),r=g.getBoundingClientRect();
  const colW=(r.width-_DB_GAP*(_DB_COLS-1))/_DB_COLS; return {g,r,colW}; }
function dbDragStart(ev,id){
  if(!_db.editing)return; if(ev.target.closest(".db-tools"))return;
  ev.preventDefault(); const d=dbCur(),p=d.panels.find(x=>x.id===id); if(!p)return;
  const {colW}=_dbGridMetrics(); if(colW<=0)return; const el=ev.currentTarget.closest(".db-panel");
  _dbDrag={id,p,mode:"move",colW,sx:ev.clientX,sy:ev.clientY,gx0:p.gx,gy0:p.gy,el};
  el.classList.add("db-dragging"); el.setPointerCapture&&el.setPointerCapture(ev.pointerId);
  _dbShowGhost(p); window.addEventListener("pointermove",_dbDragMove); window.addEventListener("pointerup",_dbDragEnd);
}
function dbResizeStart(ev,id){
  if(!_db.editing)return; ev.preventDefault(); ev.stopPropagation();
  const d=dbCur(),p=d.panels.find(x=>x.id===id); if(!p)return;
  const {colW}=_dbGridMetrics(); if(colW<=0)return; const el=document.querySelector(`.db-panel[data-pid="${CSS.escape(id)}"]`);
  _dbDrag={id,p,mode:"resize",colW,sx:ev.clientX,sy:ev.clientY,w0:p.w,h0:p.h,el};
  _dbShowGhost(p); window.addEventListener("pointermove",_dbDragMove); window.addEventListener("pointerup",_dbDragEnd);
}
function _dbGhostPx(gx,gy,w,h){ const cw=_dbDrag.colW;
  return {left:gx*(cw+_DB_GAP),top:gy*(_DB_ROWH+_DB_GAP),width:w*cw+(w-1)*_DB_GAP,height:h*_DB_ROWH+(h-1)*_DB_GAP}; }
function _dbShowGhost(p){ const gh=document.getElementById("db-ghost"); if(!gh)return;
  const b=_dbGhostPx(p.gx,p.gy,p.w,p.h); gh.style.display="block";
  gh.style.left=b.left+"px"; gh.style.top=b.top+"px"; gh.style.width=b.width+"px"; gh.style.height=b.height+"px"; }
function _dbDragMove(ev){
  if(!_dbDrag)return; const p=_dbDrag.p,cw=_dbDrag.colW;
  if(_dbDrag.mode==="move"){
    const dcol=Math.round((ev.clientX-_dbDrag.sx)/(cw+_DB_GAP)),drow=Math.round((ev.clientY-_dbDrag.sy)/(_DB_ROWH+_DB_GAP));
    p.gx=Math.max(0,Math.min(_DB_COLS-p.w,_dbDrag.gx0+dcol)); p.gy=Math.max(0,_dbDrag.gy0+drow);
  } else {
    const dcol=Math.round((ev.clientX-_dbDrag.sx)/(cw+_DB_GAP)),drow=Math.round((ev.clientY-_dbDrag.sy)/(_DB_ROWH+_DB_GAP));
    p.w=Math.max(2,Math.min(_DB_COLS-p.gx,_dbDrag.w0+dcol)); p.h=Math.max(2,_dbDrag.h0+drow);
    if(_dbDrag.el){ _dbDrag.el.style.gridColumn=`${p.gx+1} / span ${p.w}`; _dbDrag.el.style.gridRow=`${p.gy+1} / span ${p.h}`; }
  }
  _dbShowGhost(p);
}
function _dbDragEnd(){
  window.removeEventListener("pointermove",_dbDragMove); window.removeEventListener("pointerup",_dbDragEnd);
  const gh=document.getElementById("db-ghost"); if(gh)gh.style.display="none";
  if(!_dbDrag)return; const d=dbCur();
  _dbResolve(d.panels,_dbDrag.p);
  _dbDrag=null; dbPersist(); dbRender();
}

// ── panel editor ───────────────────────────────────────────────────────────────
async function dbEditPanel(id){
  const d=dbCur(),src=id?d.panels.find(x=>x.id===id):null;
  _dbEdit=src?JSON.parse(JSON.stringify(src)):{id:"p"+Date.now(),type:"stat",w:4,h:_dbDefH("stat")};
  if(!_dbEdit.metric)_dbEdit.metric="requests_total"; if(!_dbEdit.key)_dbEdit.key="top_paths";
  if(!_dbEdit.metrics)_dbEdit.metrics=[_dbEdit.metric];
  if(!_dbEdit.colors)_dbEdit.colors={}; if(!_dbEdit.thresholds)_dbEdit.thresholds=[];
  const mo=Object.keys(_DB_METRICS).map(k=>`<option value="${k}" ${_dbEdit.metric===k?"selected":""}>${esc(_DB_METRICS[k].l)}</option>`).join("");
  const ao=Object.keys(_DB_ANALYTICS).map(k=>`<option value="${k}" ${_dbEdit.key===k?"selected":""}>${esc(_DB_ANALYTICS[k])}</option>`).join("");
  const to=_DB_TYPES.map(([t,l])=>`<option value="${t}" ${_dbEdit.type===t?"selected":""}>${esc(l)}</option>`).join("");
  const mp=Object.keys(_DB_METRICS).map(k=>`<label><input type="checkbox" value="${k}" ${(_dbEdit.metrics||[]).includes(k)?"checked":""} onchange="dbeMetricsToggle(this)"> ${esc(_DB_METRICS[k].l)}</label>`).join("");
  const body=`<div class="space-y-2 text-[12px]" style="color:var(--muted)">
    <label class="block">${_trText("Заголовок")}<input class="input mt-1" oninput="_dbEdit.title=this.value" value="${esc(_dbEdit.title||"")}"></label>
    <label class="block">${_trText("Тип")}<select class="input mt-1" onchange="_dbEdit.type=this.value;dbeTypeChange()">${to}</select></label>
    <label class="block" id="dbe-metric-wrap">${_trText("Метрика")}<select class="input mt-1" onchange="_dbEdit.metric=this.value">${mo}</select></label>
    <div class="block" id="dbe-metrics-wrap">${_trText("Метрики")}<div class="db-mp mt-1">${mp}</div></div>
    <label class="block" id="dbe-ana-wrap">${_trText("Источник (топ)")}<select class="input mt-1" onchange="_dbEdit.key=this.value">${ao}</select></label>
    <label class="block hidden" id="dbe-logs-wrap">${_trText("Поиск в логах")}<input class="input mono mt-1" oninput="_dbEdit.search=this.value" value="${esc(_dbEdit.search||"")}" placeholder="/wp-login"></label>
    <label class="flex items-center gap-2 hidden" id="dbe-area-wrap"><input type="checkbox" ${_dbEdit.area!==false?"checked":""} onchange="_dbEdit.area=this.checked"> ${_trText("Заливка area")}</label>
    <label class="flex items-center gap-2 hidden" id="dbe-anomaly-wrap"><input type="checkbox" ${_dbEdit.anomaly?"checked":""} onchange="_dbEdit.anomaly=this.checked"> ${_trText("Полоса аномалий")}</label>
    <div class="block hidden" id="dbe-colors-wrap">${_trText("Цвета серий")}<div class="mt-1 space-y-1" id="dbe-colors"></div></div>
    <div class="block hidden" id="dbe-thr-wrap">${_trText("Пороговые линии")}<div class="mt-1 space-y-1" id="dbe-thr"></div>
      <button type="button" class="btn btn-ghost btn-xs mt-1" onclick="dbeThrAdd()">＋ ${_trText("порог")}</button></div>
    <div class="flex gap-2"><label class="flex-1">${_trText("Ширина")} (2–12)<input type="number" min="2" max="12" class="input mt-1" oninput="_dbEdit.w=+this.value" value="${_dbEdit.w||4}"></label>
    <label class="flex-1">${_trText("Высота")} (2–12)<input type="number" min="2" max="12" class="input mt-1" oninput="_dbEdit.h=+this.value" value="${_dbEdit.h||_dbDefH(_dbEdit.type)}"></label></div></div>`;
  setTimeout(dbeTypeChange,0);
  const r=await _showModal({title:_trText(id?"Панель":"Новая панель"),body,
    buttons:[{label:_CANCEL(),value:null,esc:true},{label:_trText("Сохранить"),kind:"primary",value:"save",enter:true}]});
  if(r==="save")dbSavePanel(id);
}
function dbeMetricsToggle(cb){ const s=new Set(_dbEdit.metrics||[]); cb.checked?s.add(cb.value):s.delete(cb.value); _dbEdit.metrics=[...s]; dbeRenderColors(); }
const _DB_T_COLORS=["timeseries","stacked","multistat"], _DB_T_THR=["timeseries","stacked"];
function dbeTypeChange(){
  const t=_dbEdit.type;
  const show=(elid,on)=>{const e=document.getElementById(elid);if(e)e.classList.toggle("hidden",!on);};
  show("dbe-metric-wrap",_DB_T_METRIC.includes(t));
  show("dbe-metrics-wrap",_DB_T_METRICS.includes(t));
  show("dbe-ana-wrap",_DB_T_ANALYTICS.includes(t));
  show("dbe-logs-wrap",t==="logs");
  show("dbe-area-wrap",t==="timeseries");
  show("dbe-anomaly-wrap",t==="timeseries");
  show("dbe-colors-wrap",_DB_T_COLORS.includes(t));
  show("dbe-thr-wrap",_DB_T_THR.includes(t));
  dbeRenderColors(); dbeRenderThr();
}
function dbeRenderColors(){
  const wrap=document.getElementById("dbe-colors"); if(!wrap)return; _dbEdit.colors=_dbEdit.colors||{};
  const ms=_dbEdit.metrics||[];
  wrap.innerHTML=ms.map((m,i)=>{ const c=_dbEdit.colors[m]||_DB_PALETTE[i%_DB_PALETTE.length];
    return `<div class="flex items-center gap-2"><input type="color" value="${esc(c)}" oninput="dbeColor('${escJs(m)}',this.value)" style="width:30px;height:22px;padding:0;border:none;background:none;cursor:pointer">
      <span style="font-size:11px;color:var(--muted)">${esc((_DB_METRICS[m]||{l:m}).l)}</span></div>`; }).join("")
    ||`<span style="font-size:11px;color:var(--faint)">${_trText("выберите метрики")}</span>`;
}
function dbeColor(m,v){ _dbEdit.colors=_dbEdit.colors||{}; _dbEdit.colors[m]=v; }
function dbeRenderThr(){
  const wrap=document.getElementById("dbe-thr"); if(!wrap)return; _dbEdit.thresholds=_dbEdit.thresholds||[];
  wrap.innerHTML=_dbEdit.thresholds.map((t,i)=>`<div class="flex items-center gap-2">
    <input type="number" class="input" style="width:96px" value="${t.v!=null?esc(String(t.v)):""}" oninput="_dbEdit.thresholds[${i}].v=this.value" placeholder="value">
    <input type="color" value="${esc(t.c||'#f2495c')}" oninput="_dbEdit.thresholds[${i}].c=this.value" style="width:30px;height:22px;padding:0;border:none;background:none;cursor:pointer">
    <button type="button" class="text-rose-300 text-[11px]" onclick="dbeThrDel(${i})">✕</button></div>`).join("");
}
function dbeThrAdd(){ _dbEdit.thresholds=_dbEdit.thresholds||[]; _dbEdit.thresholds.push({v:"",c:"#f2495c"}); dbeRenderThr(); }
function dbeThrDel(i){ _dbEdit.thresholds.splice(i,1); dbeRenderThr(); }
function dbSavePanel(id){
  const d=dbCur(),e=_dbEdit,t=e.type;
  const p={id:e.id,type:t,title:(e.title||"").trim(),w:Math.max(2,Math.min(12,+e.w||4)),h:Math.max(2,Math.min(12,+e.h||_dbDefH(t))),gx:e.gx,gy:e.gy};
  p.span=p.w;
  if(_DB_T_METRIC.includes(t)){p.source="summary";p.metric=e.metric;}
  else if(_DB_T_METRICS.includes(t)){p.source=(t==="multistat")?"summary":"history";p.metrics=(e.metrics&&e.metrics.length?e.metrics:[e.metric]); if(t==="timeseries"){p.area=e.area!==false;p.anomaly=!!e.anomaly;}
    if(_DB_T_COLORS.includes(t)){ const cs={}; (p.metrics||[]).forEach(m=>{ if(e.colors&&e.colors[m])cs[m]=e.colors[m]; }); if(Object.keys(cs).length)p.colors=cs; }
    if(_DB_T_THR.includes(t)){ const th=(e.thresholds||[]).map(x=>({v:+x.v,c:x.c||"#f2495c"})).filter(x=>isFinite(x.v)); if(th.length)p.thresholds=th; }}
  else if(_DB_T_ANALYTICS.includes(t)){p.source="analytics";p.key=e.key;}
  else if(t==="geo"){p.source="analytics";p.key="geo";}
  else if(t==="logs"){p.source="logs";p.search=e.search||"";p.minutes=15;}
  if(!p.title){
    if(_DB_T_ANALYTICS.includes(t))p.title=_DB_ANALYTICS[p.key]||p.key;
    else if(t==="geo")p.title="Countries";
    else if(t==="logs")p.title="Logs";
    else if(_DB_T_METRICS.includes(t))p.title=(p.metrics||[]).map(m=>(_DB_METRICS[m]||{l:m}).l).join(" · ")||t;
    else p.title=(_DB_METRICS[p.metric]||{l:p.metric}).l;
  }
  const ix=id?d.panels.findIndex(x=>x.id===id):-1;
  if(ix>=0){ d.panels[ix]=p; }
  else { p.gx=0;p.gy=Math.max(0,...d.panels.map(x=>x.gy+x.h),0); d.panels.push(p); }
  _dbNormalize(d); if(ix>=0)_dbResolve(d.panels,p); dbPersist(); dbRender();
}
const _DB_PRESETS={
  attacks:{name:"Attacks",panels:[
    {type:"multistat",metrics:["crs_detections","distinct_attacker_ips","forbidden_new"],w:6,h:3,title:"Threat overview"},
    {type:"gauge",metric:"malicious_ratio",w:3,h:3,title:"Malicious %"},
    {type:"stat",metric:"forbidden_new",w:3,h:3,title:"New blocks"},
    {type:"timeseries",metrics:["forbidden_new","crs_detections"],w:8,h:5,title:"Blocks over time"},
    {type:"donut",key:"attack_types",w:4,h:5,title:"Attack types"},
    {type:"table",key:"top_talkers",w:6,h:5,title:"Top talkers (IPs)"},
    {type:"geo",key:"geo",w:6,h:5,title:"Countries"}]},
  performance:{name:"Performance",panels:[
    {type:"multistat",metrics:["requests_total","latency_p95","bytes_mb"],w:6,h:3,title:"Traffic overview"},
    {type:"gauge",metric:"availability",w:3,h:3,title:"Availability"},
    {type:"stat",metric:"unique_visitors",w:3,h:3,title:"Unique IPs"},
    {type:"stacked",metrics:["requests_real","forbidden_new"],w:8,h:5,title:"Traffic (stacked)"},
    {type:"hbar",key:"methods",w:4,h:5,title:"Methods"},
    {type:"table",key:"top_paths",w:6,h:5,title:"Top paths"},
    {type:"bar",key:"slow_endpoints",w:6,h:5,title:"Slow endpoints"}]}};
async function dbNewFromPreset(key){
  const pre=_DB_PRESETS[key]; if(!pre)return;
  const id="d"+Date.now();
  const panels=pre.panels.map((p,i)=>Object.assign({id:"p"+Date.now()+i},p));
  const dash={id,name:pre.name,panels,vars:{},range:""}; _dbFlow(dash.panels);
  _db.list.push(dash); _db.curId=id;
  await dbPersist(); dbFillPicker(); dbSyncVars(); dbLoad(true);
}
async function dbNewDash(){
  const name=await uiPrompt(_trText("Имя дашборда:")); if(!name)return;
  const id="d"+Date.now(); _db.list.push({id,name:name.trim(),panels:[],vars:{},range:""}); _db.curId=id;
  await dbPersist(); dbFillPicker(); _db.editing=true; document.getElementById("db-editmode").classList.add("btn-primary"); dbLoad(false);
}
async function dbRenameDash(){ const d=dbCur(); if(!d)return; const n=await uiPrompt(_trText("Имя дашборда:"),"",d.name); if(!n)return; d.name=n.trim(); await dbPersist(); dbFillPicker(); }
async function dbDeleteDash(){ const d=dbCur(); if(!d)return; if(!await uiConfirm(_trText("Удалить дашборд?")+" «"+d.name+"»"))return;
  _db.list=_db.list.filter(x=>x.id!==d.id); _db.curId=(_db.list[0]||{}).id||""; await dbPersist(); dbFillPicker(); dbLoad(false); }
async function dbPersist(){ try{ await fetch("/api/dashboards",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({list:_db.list,default:_db.def||_db.curId})}); }catch(e){ uiAlert("не удалось сохранить: "+(e.message||e)); } }
// ── export / import a dashboard as JSON ────────────────────────────────────────
function dbExport(){
  const d=dbCur(); if(!d)return;
  const doc={soc_dashboard:1,exported:new Date().toISOString(),name:d.name,panels:d.panels,vars:d.vars||{}};
  const blob=new Blob([JSON.stringify(doc,null,2)],{type:"application/json"});
  const a=document.createElement("a"); a.href=URL.createObjectURL(blob);
  a.download=(d.name||"dashboard").replace(/[^\w.-]+/g,"_")+".json";
  document.body.appendChild(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(a.href),1000);
}
async function dbImport(input){
  const f=input.files&&input.files[0]; input.value=""; if(!f)return;
  try{
    const doc=JSON.parse(await f.text());
    if(!doc||!Array.isArray(doc.panels))throw new Error(_trText("не похоже на дашборд"));
    const id="d"+Date.now();
    const panels=doc.panels.map((p,i)=>Object.assign({},p,{id:"p"+Date.now()+i}));
    const dash={id,name:(doc.name||"imported").toString().slice(0,60),panels,vars:doc.vars||{},range:""};
    _dbNormalize(dash);
    _db.list.push(dash); _db.curId=id;
    await dbPersist(); dbFillPicker(); dbSyncVars(); dbLoad(true);
  }catch(e){ uiAlert(_trText("не удалось импортировать: ")+(e.message||e)); }
}

const CNAMES={US:"США",UA:"Украина",RU:"Россия",GB:"Великобритания",DE:"Германия",FR:"Франция",NL:"Нидерланды",IE:"Ирландия",PL:"Польша",CA:"Канада",IN:"Индия",CN:"Китай",SG:"Сингапур",IT:"Италия",ES:"Испания",SE:"Швеция",FI:"Финляндия",CZ:"Чехия",RO:"Румыния",LV:"Латвия",LT:"Литва",EE:"Эстония",BY:"Беларусь",KZ:"Казахстан",TR:"Турция",BR:"Бразилия",JP:"Япония",KR:"Корея",AU:"Австралия",CH:"Швейцария",AT:"Австрия",BE:"Бельгия",DK:"Дания",NO:"Норвегия",PT:"Португалия",MD:"Молдова",GE:"Грузия",AM:"Армения",AZ:"Азербайджан",IL:"Израиль",AE:"ОАЭ",HK:"Гонконг",VN:"Вьетнам",ID:"Индонезия",MX:"Мексика",ZA:"ЮАР",BG:"Болгария",HU:"Венгрия",GR:"Греция"};
function flag(cc){if(!cc||cc.length!==2||!/^[A-Za-z]{2}$/.test(cc))return"🏳️";return cc.toUpperCase().replace(/./g,c=>String.fromCodePoint(127397+c.charCodeAt(0)));}
function countryLabel(cc){if(!cc)return"— не определено";return flag(cc)+" "+(CNAMES[cc.toUpperCase()]||cc.toUpperCase());}

const STATS=[
  {k:"requests_total",l:"Запросов/5м",c:"text-slate-100"},
  {k:"requests_real",l:"Реальных",c:"text-slate-100"},
  {k:"forbidden_new",l:"Новые блоки",c:"text-amber-300",hot:1,bad:"up"},
  {k:"crs_detections",l:"CRS payload",c:"text-red-300",hot:1,bad:"up"},
  {k:"distinct_attacker_ips",l:"Атак. IP",c:"text-orange-300",hot:1,bad:"up"},
  {k:"unique_visitors",l:"Уник. IP",c:"text-slate-100"},
  {k:"latency_p95",l:"p95, c",c:"text-slate-100",fmt:v=>v==null?"—":v.toFixed(2),bad:"up"},
  {k:"availability",l:"Доступность",c:"text-emerald-300",fmt:v=>v==null?"—":(v*100).toFixed(2)+"%",bad:"dn"},
  {k:"bytes_mb",l:"Трафик, МБ",c:"text-slate-100",fmt:v=>v==null?"—":Math.round(v)},
  {k:"malicious_ratio",l:"Вредного",c:"text-slate-100",fmt:pct,hotr:1,bad:"up"},
];
let uniqueVisitors=null;
const WINS=["5m","15m","1h","6h","8h"];
const WIN_HIST={"5m":12,"15m":34,"1h":130,"6h":740,"8h":960};
let WIN="5m", HOST="";
let lastAn={analytics:{}}, lastAnKey="", lastAnAt=0;
let lastHist={snapshots:[]}, lastIns={current:null,history:[]}, lastHistKey="", lastHistAt=0;
function renderWinSel(){
  document.getElementById("winsel").innerHTML=`<div class="seg">`+WINS.map(w=>
    `<button onclick="setWin('${w}')" class="${w===WIN?"on":""}">${w}</button>`).join("")+`</div>`;
}
function setWin(w){WIN=w;renderWinSel();updateHash();refresh();}
function setHost(v){HOST=(v||"").trim();updateHash();refresh();}
function updateHash(){location.hash=`win=${WIN}&host=${encodeURIComponent(HOST)}`;}
function parseHash(){const h=new URLSearchParams(location.hash.slice(1));if(WINS.includes(h.get("win")))WIN=h.get("win");if(h.get("host")){HOST=h.get("host");const el=document.getElementById("hostsel");if(el)el.value=HOST;}}
function renderStatusPct(s){
  const el=document.getElementById("status_pct");const lg=document.getElementById("status_pct_legend");if(!el)return;
  if(!s){el.innerHTML="";lg.textContent="";return;}
  const parts=[["2xx",s.status_2xx||0,"#73bf69"],["3xx",s.status_3xx||0,"#38bdf8"],["4xx",s.status_4xx||0,"#ff9830"],["5xx",s.status_5xx||0,"#f2495c"]];
  const tot=parts.reduce((a,p)=>a+p[1],0)||1;
  el.innerHTML=parts.map(p=>`<div title="${p[0]}: ${fmt(p[1])} (${(p[1]/tot*100).toFixed(1)}%)" style="width:${(p[1]/tot*100).toFixed(1)}%;background:${p[2]}"></div>`).join("");
  lg.innerHTML=parts.map(p=>`<span style="color:${p[2]}">${p[0]} ${(p[1]/tot*100).toFixed(0)}%</span>`).join(" · ");
}
function _ovStatSpark(series,hot){
  const mn=Math.min.apply(0,series),mx=Math.max.apply(0,series),rng=(mx-mn)||1;
  const pts=series.map((v,i)=>[i/(series.length-1)*100, 20-((v-mn)/rng)*20]);
  return `<svg viewBox="0 0 100 20" preserveAspectRatio="none" class="ov-stat-spark"><path d="${_smooth(pts)}" fill="none" stroke="${hot?'var(--crit)':'var(--accent)'}" stroke-width="1.6"/></svg>`;
}
function renderStats(s){
  const snaps=(lastHist&&lastHist.snapshots)||[];
  document.getElementById("stats").innerHTML=STATS.map(d=>{
    let v=s?s[d.k]:null; const hot=(d.hot&&v>0)||(d.hotr&&v>=0.35);
    const disp=d.fmt?d.fmt(v):fmt(v);
    // trend from history: sparkline + delta vs window start (availability derived from status mix)
    let series=snaps.map(x=>+x[d.k]||0);
    if(d.k==="availability")series=snaps.map(x=>{const t=(x.status_2xx||0)+(x.status_3xx||0)+(x.status_4xx||0)+(x.status_5xx||0);return t?((x.status_2xx||0)+(x.status_3xx||0))/t:0;});
    const vary=series.length>1 && Math.max.apply(0,series)>Math.min.apply(0,series);
    let delta="",spark="";
    if(vary){
      const a=series[0],b=series[series.length-1],dd=b-a,dir=dd>0?"up":dd<0?"dn":"flat";
      const cls=dir==="flat"?"flat":(!d.bad?"neutral":(dir===d.bad?"bad":"good"));
      const arr=dir==="up"?"▲":dir==="dn"?"▼":"→",pd=a?Math.abs(dd/a*100):0;
      delta=`<span class="ov-delta ${cls}">${arr}${pd>=1?Math.round(pd)+"%":""}</span>`;
      spark=_ovStatSpark(series,hot);
    }
    let _vc=d.c; if(d.k==='availability'&&v!=null){_vc=v>=0.995?'text-emerald-300':v>=0.97?'text-amber-300':'text-red-300';}
    return `<div class="card ov-stat ${hot?'ov-stat-hot':''}"><div class="ov-stat-h"><span class="ov-stat-l">${d.l}</span>${delta}</div><div class="ov-stat-v mono ${hot?'text-amber-300':_vc}">${disp}</div>${spark}</div>`;
  }).join("");
}

// Overview charts — pure SVG (no chart CDN); same signatures as before so callers are unchanged.
let charts={};
const _ovHov={};
const ds=(l,c,fill)=>({label:(typeof _trText==="function"?_trText(l):l),color:c,fill:!!fill});
function mkChart(id,datasets,stacked){ return {id,series:datasets,stacked:!!stacked}; }
function setChart(cfg,snaps,arrs){ cfg.series.forEach((s,i)=>s.acc=arrs[i]); _ovRender(cfg,snaps); }
function _ovRender(cfg,snaps){
  const el=document.getElementById(cfg.id); if(!el)return;
  const series=cfg.series.filter(s=>s.acc);
  if(!snaps||snaps.length<2||!series.length){ el.innerHTML=`<div class="text-slate-600 text-xs" style="padding:16px 0">${_trText("мало точек")}</div>`; return; }
  const W=600,H=150,pl=38,pr=10,pt=8,pb=18,plotW=W-pl-pr,plotH=H-pt-pb;
  const n=snaps.length, xs=snaps.map((s,i)=>pl+(n===1?0:i/(n-1)*plotW));
  const vals=series.map(s=>snaps.map(sn=>+s.acc(sn)||0));
  let max=1;
  if(cfg.stacked){ for(let i=0;i<n;i++){let sum=0;vals.forEach(v=>sum+=v[i]); if(sum>max)max=sum;} }
  else vals.forEach(v=>v.forEach(x=>{if(x>max)max=x;}));
  max=_niceMax(max);
  const Y=v=>pt+plotH-(v/max)*plotH;
  const defs=[],paths=[],dots=[],meta=[]; const stackTop=new Array(n).fill(0);
  series.forEach((s,si)=>{ const col=s.color; let pts;
    if(cfg.stacked){ const top=[],bot=[];
      for(let i=0;i<n;i++){const base=stackTop[i];stackTop[i]=base+vals[si][i];top.push([xs[i],Y(stackTop[i])]);bot.push([xs[i],Y(base)]);}
      pts=top; const dTop=_smooth(top),dBot=bot.slice().reverse().map(p=>`L${p[0].toFixed(1)},${p[1].toFixed(1)}`).join("");
      paths.push(`<path d="${dTop} ${dBot} Z" fill="${col}" fill-opacity=".26"/>`);
      paths.push(`<path d="${dTop}" fill="none" stroke="${col}" stroke-width="1.6"/>`);
    } else { pts=vals[si].map((v,i)=>[xs[i],Y(v)]); const gid=`ov-${cfg.id}-${si}`;
      defs.push(`<linearGradient id="${gid}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${col}" stop-opacity="${series.length>1?.16:.30}"/><stop offset="1" stop-color="${col}" stop-opacity="0"/></linearGradient>`);
      const dLine=_smooth(pts);
      paths.push(`<path d="${dLine} L${xs[n-1].toFixed(1)},${(pt+plotH).toFixed(1)} L${xs[0].toFixed(1)},${(pt+plotH).toFixed(1)} Z" fill="url(#${gid})"/>`);
      paths.push(`<path d="${dLine}" fill="none" stroke="${col}" stroke-width="1.8"/>`); }
    dots.push(`<circle cx="${pts[n-1][0].toFixed(1)}" cy="${pts[n-1][1].toFixed(1)}" r="2.4" fill="${col}"/>`);
    meta.push({color:col,pts,name:s.label,vals:vals[si]}); });
  let ax="";
  for(let g=0;g<=2;g++){const v=max*g/2,y=Y(v);
    ax+=`<line x1="${pl}" y1="${y.toFixed(1)}" x2="${W-pr}" y2="${y.toFixed(1)}" stroke="var(--border)" stroke-width="1"/>`+
        `<text class="db-ax" x="${pl-5}" y="${(y+3).toFixed(1)}" text-anchor="end">${esc(_dbNum(v))}</text>`;}
  const xt=Math.min(5,n-1);
  for(let t=0;t<=xt;t++){const i=Math.round(t/xt*(n-1));
    ax+=`<text class="db-ax" x="${xs[i].toFixed(1)}" y="${H-5}" text-anchor="middle">${esc(_dbHHMM(snaps[i].ts))}</text>`;}
  _ovHov[cfg.id]={W,pl,plotW,n,xs,pt,plotH,series:meta,snaps};
  const _ovStat=a=>{if(!a||!a.length)return{last:0,max:0,mean:0};let mx=-Infinity,sm=0;for(const x of a){if(x>mx)mx=x;sm+=x;}return{last:a[a.length-1],max:mx,mean:sm/a.length};};
  const _ovFmt=v=>{const n=Math.abs(v);if(n>=1000)return _dbNum(Math.round(v));if(Number.isInteger(v))return String(v);if(n>=10)return String(Math.round(v));if(n>=1)return v.toFixed(1);return v.toFixed(2);};
  const legend=`<table class="ov-leg"><thead><tr><th></th><th>Last</th><th>Max</th><th>Mean</th></tr></thead><tbody>`+
    meta.map(s=>{const t=_ovStat(s.vals);return `<tr><td class="ovl-n"><span class="ovl-sw" style="background:${s.color}"></span>${esc(s.name)}</td><td>${esc(_ovFmt(t.last))}</td><td>${esc(_ovFmt(t.max))}</td><td>${esc(_ovFmt(t.mean))}</td></tr>`;}).join("")+
    `</tbody></table>`;
  const hd=meta.map((s,k)=>`<circle class="ov-hd" data-k="${k}" r="3.2" fill="${s.color}" stroke="var(--surface)" stroke-width="1.5" style="display:none"/>`).join("");
  el.innerHTML=`<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" style="width:100%;height:140px" onmousemove="ovMove(event,'${escJs(cfg.id)}')" onmouseleave="ovLeave('${escJs(cfg.id)}')">`+
    `<defs>${defs.join("")}</defs>${ax}${paths.join("")}${dots.join("")}`+
    `<line id="ovcx-${esc(cfg.id)}" class="db-crosshair" y1="${pt}" y2="${pt+plotH}" style="display:none"/>${hd}</svg>`+
    `<div class="db-tsi" id="ovtip-${esc(cfg.id)}" style="display:none"></div>`+
    legend;
}
function ovMove(ev,id){ const H=_ovHov[id]; if(!H)return; const svg=ev.currentTarget,r=svg.getBoundingClientRect(); if(!r.width)return;
  const vx=(ev.clientX-r.left)/r.width*H.W; let i=Math.round((vx-H.pl)/H.plotW*(H.n-1)); i=Math.max(0,Math.min(H.n-1,i));
  const ln=document.getElementById("ovcx-"+id); if(!ln)return; const x=H.xs[i]; ln.style.display="";ln.setAttribute("x1",x);ln.setAttribute("x2",x);
  const dots=svg.querySelectorAll(".ov-hd");
  H.series.forEach((s,k)=>{const c=dots[k]; if(c){c.setAttribute("cx",x.toFixed(1));c.setAttribute("cy",s.pts[i][1].toFixed(1));c.style.display="";}});
  const tip=document.getElementById("ovtip-"+id); if(!tip)return;
  tip.innerHTML=`<div class="db-tsi-t">${esc(_dbHHMM(H.snaps[i].ts))}</div>`+H.series.map(s=>`<div><span style="color:${s.color}">●</span> ${esc(s.name)}: <b>${esc(_dbNum(s.vals[i]))}</b></div>`).join("");
  tip.style.display="block"; const frac=(x-H.pl)/H.plotW,right=frac>0.6;
  tip.style.left=right?"auto":(frac*100+2)+"%"; tip.style.right=right?((1-frac)*100+2)+"%":"auto"; tip.style.top="20px";
}
function ovLeave(id){ const ln=document.getElementById("ovcx-"+id),tip=document.getElementById("ovtip-"+id),svg=ln&&ln.closest("svg");
  if(ln)ln.style.display="none"; if(tip)tip.style.display="none"; if(svg)svg.querySelectorAll(".ov-hd").forEach(c=>c.style.display="none"); }

const ATTACK_RE=/(\bunion\b.{0,20}\bselect\b|\bselect\b.{0,30}\bfrom\b|sleep\(\d|benchmark\(|waitfor\s+delay|\bor\s+\d+\s*[-*=]|information_schema|\/\*!|0x[0-9a-f]{8}|<script|onerror\s*=|javascript:|\.\.\/\.\.|etc\/passwd|\$\{(jndi|@?print)|\bmd5\(|;\s*print|\bxor\b)/i;
function looksMalicious(s){return ATTACK_RE.test(String(s||""));}
function bars(id,list,color,drill){
  const el=document.getElementById(id);
  if(!list||!list.length){el.innerHTML=`<div class="text-slate-600 text-xs">нет данных</div>`;return;}
  const max=Math.max(...list.map(x=>x.count||x.peak||0));
  el.innerHTML=list.map(x=>{const v=x.count||x.peak||0;const value=x.key||x.subnet||x.country||"—";const label=x.display||value;
    const mal=looksMalicious(label);
    const click=drill?`onclick="drillRow('${drill}', this.dataset.v)" data-v="${esc(String(value))}" class="cursor-pointer hover:bg-slate-800/40 -mx-1 px-1 rounded"`:"";
    const sub=(x.sub!=null&&x.sub>0)?` <span class="text-red-400" title="заблокировано">/ ${fmt(x.sub)}</span>`:"";
    const badge=mal?`<span class="px-1 rounded bg-red-500/20 text-red-300 text-[9px] mr-1 shrink-0" title="похоже на атаку (SQLi/XSS/RCE)">⚠ атака</span>`:"";
    const lblCls=mal?"text-red-300":"text-slate-300";
    const valCls=mal?"text-red-300":color;
    const barClr=mal?"#f2495c":(color==='text-amber-300'?'#ff9830':color==='text-red-300'?'#f2495c':'#5794f2');
    return `<div ${click}><div class="flex justify-between text-xs mb-0.5 gap-2"><span class="${lblCls} truncate" title="${esc(String(label))}">${badge}${esc(String(label).slice(0,46))}${drill?' <span class=\"text-slate-600\">↗</span>':''}</span><span class="mono ${valCls} shrink-0">${fmt(v)}${sub}</span></div><div class="bar-bg"><div class="h-full rounded" style="width:${(v/max*100).toFixed(0)}%;background:${barClr}99"></div></div></div>`;
  }).join("");
}
let _map=null,_mapMode="count",_mapGeo=[];
// jsVectorMap 1.5.3 поддерживает только OrdinalScale (значение→цвет по ключу),
// поэтому раскладываем трафик по дискретным бакетам 1..6 (0 нельзя — setValues его пропускает).
const _MAPCOLORS=["#38bdf8","#22d3ee","#a3e635","#fbbf24","#f97316","#f2495c"];
const _MAPSCALE=Object.fromEntries(_MAPCOLORS.map((c,i)=>[i+1,c]));
function _mapBuckets(geo,mode){
  const lv={};let max=0,out={};
  (geo||[]).forEach(x=>{const cc=(x.key||"").toUpperCase();if(/^[A-Z]{2}$/.test(cc)){const n=mode==="blocked"?(x.blocked||0):(x.count||0);if(n>0){const l=Math.log10(n+1);lv[cc]=l;if(l>max)max=l;}}});
  Object.keys(lv).forEach(cc=>{const t=max>0?lv[cc]/max:0;out[cc]=1+Math.min(_MAPCOLORS.length-1,Math.floor(t*_MAPCOLORS.length));});
  return out;
}
function _mapTip(code){const x=_mapGeo.find(g=>(g.key||"").toUpperCase()===code);const name=CNAMES[code]||code;if(!x)return `${flag(code)} ${name}`;return `${flag(code)} ${name}<br>Всего: ${fmt(x.count||0)} · Заблок.: ${fmt(x.blocked||0)}`;}
function renderMap(geo){
  _mapGeo=geo||[];
  const empty=document.getElementById("map-empty"),cont=document.getElementById("worldmap");
  if(!cont)return;   // карта удалена из UI
  if(typeof jsVectorMap==="undefined"){cont.classList.add("hidden");empty.classList.remove("hidden");empty.textContent="карта не загрузилась (CDN недоступен)";return;}
  const values=_mapBuckets(_mapGeo,_mapMode);
  if(!Object.keys(values).length&&!_map){empty.classList.remove("hidden");cont.classList.add("hidden");return;}
  empty.classList.add("hidden");cont.classList.remove("hidden");
  if(_map){try{_map.series.regions[0].clear();_map.series.regions[0].setValues(values);}catch(e){}return;}
  try{_map=new jsVectorMap({
    selector:"#worldmap",map:"world",backgroundColor:"transparent",zoomButtons:true,zoomOnScroll:false,
    regionStyle:{initial:{fill:"#171c25",stroke:"#0a0c10","stroke-width":0.4},hover:{fillOpacity:0.7}},
    series:{regions:[{attribute:"fill",scale:_MAPSCALE,values}]},
    onRegionTooltipShow(e,tip,code){tip.text(_mapTip(code),true);},
    onRegionClick(e,code){if(_mapGeo.find(g=>(g.key||"").toUpperCase()===code))openIps(code);}
  });}catch(e){cont.classList.add("hidden");empty.classList.remove("hidden");empty.textContent="ошибка карты: "+e;}
}
function setMapMode(m){
  _mapMode=m;
  const t=document.getElementById("map-mode-total");if(!t)return;
  t.className="px-2 py-1 rounded border "+(m==="count"?"border-slate-600/50 bg-slate-700/30 text-slate-200":"border-slate-700/40 text-slate-400");
  document.getElementById("map-mode-blocked").className="px-2 py-1 rounded border "+(m==="blocked"?"border-red-500/40 bg-red-500/15 text-red-300":"border-slate-700/40 text-slate-400");
  renderMap(_mapGeo);
}
function showModal(title){const m=document.getElementById("modal");document.getElementById("modal-title").textContent=title;document.getElementById("modal-body").innerHTML=`<div class="text-slate-500 text-sm">загрузка…</div>`;m.classList.remove("hidden");return document.getElementById("modal-body");}

function drillRow(type,label){
  if(type==="country") return openIps(label);
  if(type==="ip")      return openProfile(label);
  if(type==="path")   return openRequests({path:label.split("?")[0]}, "Путь · "+label);
  if(type==="ua")     return openRequests({ua:label}, "User-Agent");
  if(type==="subnet") return openRequests({ip:label.replace(".0/24",".")}, "Подсеть · "+label);
  if(type==="host")   return openRequests({host:label}, "Домен · "+label);
  if(type==="ref")    return openRequests({ref:label}, "Referer · "+label.slice(0,40));
  if(type==="crs")    return openCrs(label);
}
async function openCrs(label){
  const fam=(label.split("·")[1]||"").trim();
  const body=showModal("CRS payload · "+label);
  try{const d=await fetch("/api/crs_samples?family="+encodeURIComponent(fam)+"&limit=30").then(r=>r.json());
    if(!d.samples||!d.samples.length){body.innerHTML=`<div class="text-slate-500 text-sm">нет примеров за окно</div>`;return;}
    body.innerHTML=d.samples.map(x=>`<div class="border-b border-slate-800/50 py-2 text-xs">
      <div class="flex justify-between"><span class="mono text-red-300">${esc(x.rule)} ${esc(x.family)}</span><span class="text-slate-600 mono">${esc(x.client||"")}</span></div>
      <div class="text-slate-400">${esc(x.msg||"")}</div>
      ${x.uri?`<div class="mono text-slate-500">${esc(x.uri)}</div>`:""}
      ${x.data?`<div class="mono text-amber-300 break-all">${esc(x.data)}</div>`:""}</div>`).join("");
  }catch(e){body.innerHTML=`<div class="text-red-300 text-sm">ошибка</div>`;}
}
let lastIPs=[];
function globalSearch(v){
  v=(v||"").trim(); if(!v)return;
  if(/^\d{1,3}(\.\d{1,3}){3}$/.test(v)||v.includes(":")) return openProfile(v);   // IP → профиль
  return openRequests({path:v}, "Поиск · "+v);                                    // иначе — путь
}
async function openProfile(ip){
  const body=showModal("Профиль · "+ip);
  try{const p=await fetch("/api/ip_profile?ip="+encodeURIComponent(ip)+"&window=1h").then(r=>r.json());
    if(p.error){body.innerHTML=`<div class="text-red-300 text-sm">${esc(p.error)}</div>`;return;}
    const list=(arr,c)=>(arr||[]).map(x=>`<div class="flex justify-between text-xs"><span class="mono text-slate-300 truncate">${esc(String(x.key).slice(0,40))}</span><span class="mono ${c}">${fmt(x.count)}</span></div>`).join("")||'<span class="text-slate-600 text-xs">—</span>';
    const a=p.asn||{};
    const flags=[a.proxy?'<span class="px-1.5 py-0.5 rounded bg-red-500/15 text-red-300 text-[10px]">VPN/proxy</span>':'',
                 a.hosting?'<span class="px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300 text-[10px]">datacenter</span>':'',
                 a.mobile?'<span class="px-1.5 py-0.5 rounded bg-sky-500/15 text-sky-300 text-[10px]">mobile</span>':''].join(" ");
    const trusted=p.trusted?`<span class="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 text-xs border border-emerald-500/30">✓ доверенный: ${esc(p.trusted)}</span>`:"";
    const rep=p.reputation||{};
    const repCls={bad:"bg-red-500/15 text-red-300 border-red-500/30",warn:"bg-amber-500/15 text-amber-300 border-amber-500/30",ok:"bg-emerald-500/15 text-emerald-300 border-emerald-500/30"}[rep.level]||"bg-slate-700/30 text-slate-300";
    const repBadge=rep.verdict?`<span class="px-2 py-0.5 rounded text-xs border ${repCls}">${rep.tor?"🧅 ":""}${esc(rep.verdict)}</span>`:"";
    const botBadge=p.verified_bot?`<span class="px-2 py-0.5 rounded bg-sky-500/15 text-sky-300 text-xs border border-sky-500/30" title="reverse-DNS подтверждён">🤖 ${esc(p.verified_bot)} · rDNS ✓</span>`:"";
    body.innerHTML=`
      <div class="mb-2 flex gap-2 flex-wrap">${trusted}${cfBadge(ip)}${botBadge}${repBadge}</div>
      ${isCfIp(ip)?`<div class="mb-2 text-[12px] text-orange-300 bg-orange-500/10 border border-orange-500/25 rounded px-2 py-1.5">☁ Это адрес <b>Cloudflare</b>, а не реального посетителя. Бан бесполезен — реальный клиент скрыт за фларой (в <span class="mono">CF-Connecting-IP</span>). Смотри реальный IP в запросах ниже.</div>`:""}
      ${p.ptr?`<div class="mb-2 text-[11px] text-slate-500">rDNS: <span class="mono text-slate-400">${esc(p.ptr)}</span></div>`:""}
      <div class="flex gap-4 mb-2 text-sm flex-wrap">
        <div><div class="text-[11px] text-slate-500">всего/1ч</div><div class="mono text-slate-100 text-lg">${fmt(p.total)}${p.total_approx?"+":""}</div></div>
        <div><div class="text-[11px] text-slate-500" title="ingress вернул 403">заблокировано (403)</div><div class="mono text-red-300 text-lg">${fmt(p.blocked)}</div></div>
        <div><div class="text-[11px] text-slate-500" title="4xx кроме 403 — 404/422/429 и т.п. (не блок, ошибки запроса)">ошибки 4xx</div><div class="mono text-amber-300 text-lg">${fmt(p.err_4xx||0)}</div></div>
        ${(p.err_5xx||0)?`<div><div class="text-[11px] text-slate-500" title="ошибки сервера">5xx</div><div class="mono text-orange-300 text-lg">${fmt(p.err_5xx)}</div></div>`:""}
        <div><div class="text-[11px] text-slate-500">геолокация</div><div class="text-slate-200">${a.city?esc(a.city)+", ":""}${esc(a.country||countryLabel(p.country))}</div></div>
      </div>
      ${(a.isp||a.asn)?`<div class="mb-3 text-xs text-slate-400"><span class="text-slate-500">сеть:</span> ${esc(a.isp||a.org||"")} <span class="text-slate-600">${esc(a.asn||"")}</span> ${flags}</div>`:""}
      <div class="grid grid-cols-2 gap-3">
        <div><div class="text-[11px] text-slate-500 mb-1">Статусы</div>${list(p.by_status,"text-slate-300")}</div>
        <div><div class="text-[11px] text-slate-500 mb-1">UA</div>${list(p.top_ua,"text-slate-400")}</div>
        <div class="col-span-2"><div class="text-[11px] text-slate-500 mb-1">Топ путей <span class="text-slate-600">· «+автобан» добавит путь в правило</span></div>${abPathRows(p.top_paths)}</div>
      </div>
      <div class="mt-3 flex gap-2">
        <button onclick="openRequests({ip:'${escJs(ip)}'},'Запросы · ${esc(ip)}')" class="text-xs px-2 py-1 rounded bg-slate-700/40 text-slate-300 hover:bg-slate-700/60">показать запросы</button>
        ${p.trusted?"":(isCfIp(ip)?`<button onclick="uiAlert('Это IP Cloudflare, не реальный посетитель — бан бесполезен. Реальный клиент скрыт за фларой.')" class="text-xs px-2 py-1 rounded bg-slate-700/50 text-orange-300 border border-orange-500/30">⛔ бан бесполезен (Cloudflare)</button>`:`<button onclick="blockIP('${escJs(ip)}','профиль IP')" class="text-xs px-2 py-1 rounded bg-red-600/80 text-white hover:bg-red-600">⛔ заблокировать на ingress</button>`)}
      </div>`;
  }catch(e){body.innerHTML=`<div class="text-red-300 text-sm">ошибка</div>`;}
}
function exportList(items,filename){
  const blob=new Blob([items.join("\n")+"\n"],{type:"text/plain"});
  const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=filename||"export.txt";a.click();
}

// --- блокировка на ingress (через blocklist-api) ---
async function _post(path,payload){
  const r=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
  return r.json();
}
async function blockIP(cidr,reason,ttl){
  if(!await uiConfirm("Заблокировать "+cidr+" на ingress?\nБудет возвращаться 403 для этого источника."))return;
  const res=await _post("/api/block",{cidr:cidr,reason:reason||"",ttl:(ttl==null?2592000:ttl),group:_banGroup||undefined});
  if(res.ok){uiAlert("Заблокировано: "+(res.cidr||cidr)+" (активно правил: "+(res.active??"?")+")");renderBlocklist();}
  else uiAlert("Не удалось: "+(res.error||"ошибка"));
}
async function blockManual(){
  const cidr=document.getElementById("bl_cidr").value.trim();
  const reason=document.getElementById("bl_reason").value.trim();
  const ttl=parseInt(document.getElementById("bl_ttl").value||"0",10);
  const msg=document.getElementById("bl_msg");
  if(!cidr){msg.textContent="введи IP/CIDR";msg.className="text-xs text-amber-300";return;}
  msg.textContent="…";msg.className="text-xs text-slate-400";
  const res=await _post("/api/block",{cidr:cidr,reason:reason,ttl:ttl,group:_banGroup||undefined});
  if(res.ok){msg.textContent="✓ "+(res.cidr||cidr);msg.className="text-xs text-emerald-300";document.getElementById("bl_cidr").value="";document.getElementById("bl_reason").value="";renderBlocklist();}
  else{msg.textContent="✗ "+(res.error||"ошибка");msg.className="text-xs text-red-300";}
}
async function quickBan(){
  const ip=await uiPrompt(_lang==="ru"?"IP или CIDR для бана:":"IP or CIDR to ban:");
  if(ip&&ip.trim())blockIP(ip.trim(),"manual (topbar)",2592000);
}
function quickSearch(v){ v=(v||"").trim(); if(v)openProfile(v); }
async function unblockCIDR(cidr){
  if(!await uiConfirm("Снять блок с "+cidr+"?"))return;
  const res=await _post("/api/unblock",{cidr:cidr});
  if(res.ok)renderBlocklist(); else uiAlert("Не удалось: "+(res.error||"ошибка"));
}
let _blAll=null, _blPage=0, _blEnabled=true, _blMode="all";
const _BL_PER=12;
const _blIsAutoban=e=>(e.added_by||"").toLowerCase().includes("autoban")||/автобан/i.test(e.reason||"");
function renderBlMode(){
  const el=document.getElementById("bl_mode");if(!el)return;
  const mk=(m,l)=>`<button onclick="setBlMode('${m}')" class="text-[11px] px-2 py-1 rounded ${_blMode===m?'bg-indigo-500/25 text-indigo-200 border border-indigo-500/40':'bg-slate-800 text-slate-400 hover:bg-slate-700'}">${l}</button>`;
  el.innerHTML=mk("all","все")+mk("autoban","только автобан");
}
function setBlMode(m){_blMode=m;_blPage=0;renderBlMode();_renderBlPage();}
async function renderBlocklist(){
  const el=document.getElementById("blocklist");if(!el)return;
  try{
    const d=await fetch("/api/blocklist").then(r=>r.json());
    _blEnabled=!!d.enabled;
    if(!d.enabled){el.innerHTML=`<div class="text-slate-600 text-xs">blocklist-api не настроен (BLOCKLIST_API_URL пуст) — кнопки блокировки отключены.</div>`;return;}
    _blAll=(d.blocks||[]).slice().sort((a,b)=>(b.ts||0)-(a.ts||0)); // свежие сверху
    renderBlMode();_renderBlPage();
  }catch(e){el.innerHTML=`<div class="text-red-300 text-xs">ошибка загрузки денлиста</div>`;}
}
function _renderBlPage(){
  const el=document.getElementById("blocklist");if(!el||_blAll==null)return;
  const q=((document.getElementById("bl_search")||{}).value||"").toLowerCase().trim();
  let base=_blMode==="autoban"?_blAll.filter(_blIsAutoban):_blAll;
  const list=q?base.filter(e=>(e.cidr||"").toLowerCase().includes(q)||(e.reason||"").toLowerCase().includes(q)||(e.added_by||"").toLowerCase().includes(q)):base;
  if(!list.length){el.innerHTML=`<div class="text-slate-600 text-xs">${q?"ничего не найдено":(_blMode==="autoban"?"автобаном пока ничего не заблокировано (исполнитель не подключён)":"активных блокировок нет")}</div>`;return;}
  const pages=Math.ceil(list.length/_BL_PER);
  if(_blPage>=pages)_blPage=pages-1; if(_blPage<0)_blPage=0;
  const page=list.slice(_blPage*_BL_PER,_blPage*_BL_PER+_BL_PER);
  const rows=page.map(e=>{
   const abRule=_blIsAutoban(e)?abRuleFromReason(e.reason):null;
   const abChip=abRule?`<span class="px-1.5 py-0.5 rounded bg-indigo-500/15 text-indigo-300 text-[10px] border border-indigo-500/30 shrink-0" title="забанено автобаном по правилу">🤖 ${esc(abRule)}</span>`:"";
   const ttl=e.ttl?`<span class="bl-ttl mono text-[11px] shrink-0" data-exp="${e.ts+e.ttl}" title="${_trText('осталось до авто-разбана')}">…</span>`
                  :`<span class="text-[11px] shrink-0" style="color:var(--faint)">∞ ${_trText('навсегда')}</span>`;
   return `<div class="flex items-center gap-2 py-0.5 border-b border-slate-800/40 last:border-0">
      <span class="mono text-slate-200 w-40 shrink-0 truncate cursor-pointer hover:text-indigo-300" onclick="openProfile('${escJs((e.cidr||'').split('/')[0])}')">${esc(e.cidr)}</span>
      ${cfBadge((e.cidr||'').split('/')[0])}${abChip}${_beBadge(e.backends||e.backend)}
      <span class="text-xs text-slate-400 flex-1 min-w-0 truncate" title="${esc(e.reason||"")}">${esc(e.reason||"")}</span>
      <span class="text-[11px] text-slate-500 shrink-0">${esc(e.added_by||"")} · ${dt(e.ts)}</span>
      ${ttl}
      <button onclick="unblockCIDR('${escJs(e.cidr)}')" class="text-[11px] px-2 py-0.5 rounded bg-slate-700/50 text-slate-300 hover:bg-slate-700 shrink-0">разбан</button>
    </div>`;}).join("");
  const pager=pages>1?`<div class="flex items-center justify-between mt-2 text-[11px] text-slate-500">
      <button onclick="_blPage--;_renderBlPage()" ${_blPage<=0?"disabled":""} class="px-2 py-0.5 rounded bg-slate-800 ${_blPage<=0?"opacity-40":"hover:bg-slate-700"}">←</button>
      <span>стр. ${_blPage+1}/${pages} · ${list.length} всего</span>
      <button onclick="_blPage++;_renderBlPage()" ${_blPage>=pages-1?"disabled":""} class="px-2 py-0.5 rounded bg-slate-800 ${_blPage>=pages-1?"opacity-40":"hover:bg-slate-700"}">→</button>
    </div>`:`<div class="text-[11px] text-slate-500 mt-2">${list.length} активных</div>`;
  el.innerHTML=rows+pager;
  _blTick(); _blStartCountdown();
}
// live TTL countdown (#10): tick every second, no re-fetch
let _blTimer=null;
function _fmtCountdown(left){
  if(left<=0)return _trText("истекает…");
  const d=Math.floor(left/86400),h=Math.floor(left%86400/3600),m=Math.floor(left%3600/60),s=left%60;
  if(d>0)return d+"d "+h+"h"; if(h>0)return h+"h "+String(m).padStart(2,"0")+"m";
  if(m>0)return m+"m "+String(s).padStart(2,"0")+"s"; return s+"s";
}
function _blTick(){
  const now=Math.floor(Date.now()/1000); let anyLive=false;
  document.querySelectorAll(".bl-ttl[data-exp]").forEach(el=>{
    const left=(+el.dataset.exp||0)-now; anyLive=true;
    el.textContent="⏳ "+_fmtCountdown(left);
    el.style.color=left<=0?"var(--crit)":left<60?"var(--crit)":left<600?"var(--warn)":"var(--faint)";
  });
  return anyLive;
}
function _blStartCountdown(){
  if(_blTimer)return;
  _blTimer=setInterval(()=>{
    if(_view!=="dash"||!document.querySelector(".bl-ttl[data-exp]")){ clearInterval(_blTimer); _blTimer=null; return; }
    _blTick();
  },1000);
}

// --- escalation ladder (#9) ---
function _secToTtl(s){ s=+s||0; if(!s)return "forever"; if(s%86400===0)return (s/86400)+"d"; if(s%3600===0)return (s/3600)+"h"; if(s%60===0)return (s/60)+"m"; return s+"s"; }
function _ttlToSec(t){ t=String(t).trim().toLowerCase(); if(!t||t==="forever"||t==="0"||t==="навсегда")return 0;
  const m=t.match(/^(\d+)\s*([smhd]?)$/); if(!m)return null; const n=+m[1];
  return n*({s:1,m:60,h:3600,d:86400,"":1}[m[2]]); }
function escUiToggle(btn){ btn.classList.toggle("on"); const b=document.getElementById("esc-body"); if(b)b.classList.toggle("hidden",!btn.classList.contains("on")); }
function abProtToggle(){ const b=document.getElementById("ab-protected-body"),c=document.getElementById("ab-prot-chev"); if(!b)return; const open=b.classList.toggle("hidden")===false; if(c)c.textContent=open?"▾":"▸"; }
async function loadEscalation(){
  const en=document.getElementById("esc-enabled"); if(!en)return;   // section lives in Settings now
  let d; try{ d=await (await fetch("/api/autoban/escalation")).json(); }catch(e){ return; }
  en.classList.toggle("on",!!d.enabled);
  const eb=document.getElementById("esc-body"); if(eb)eb.classList.toggle("hidden",!d.enabled);
  const lad=document.getElementById("esc-ladder"); if(lad&&document.activeElement!==lad)lad.value=(d.ladder||[]).map(_secToTtl).join(", ");
  const mem=document.getElementById("esc-memory"); if(mem&&document.activeElement!==mem)mem.value=d.memory_days||30;
  const off=d.offenders||[];
  document.getElementById("esc-offenders").innerHTML=off.length
    ? `<div class="text-slate-500 mb-1">${_trText("повторные нарушители")}:</div>`+off.slice(0,12).map(o=>
        `<span class="inline-flex items-center gap-1 mr-1.5 mb-1 px-1.5 py-0.5 rounded bg-slate-800 mono cursor-pointer hover:text-indigo-300" onclick="openProfile('${escJs(o.ip)}')">${esc(o.ip)} <span class="text-amber-300">×${o.count}</span></span>`).join("")
    : `<span style="color:var(--faint)">${_trText("повторных нарушителей пока нет")}</span>`;
}
async function escSave(){
  const msg=document.getElementById("esc-msg"); msg.textContent=_trText("сохраняю…");
  const ladder=document.getElementById("esc-ladder").value.split(",").map(x=>_ttlToSec(x)).filter(x=>x!==null);
  const body={enabled:document.getElementById("esc-enabled").classList.contains("on"),
    memory_days:document.getElementById("esc-memory").value};
  if(ladder.length)body.ladder=ladder;
  try{ const d=await (await fetch("/api/autoban/escalation",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})).json();
    msg.textContent=d.ok?"✓":(_trText("ошибка")); loadEscalation();
  }catch(e){ msg.textContent="✗ "+e.message; }
}

// --- WAF / CRS triggers (#6) ---
async function renderCrs(){
  const el=document.getElementById("crs_list"); if(!el)return;
  const w=(document.getElementById("crs_win")||{}).value||"1h";
  try{
    const d=await fetch(_withEnv("/api/crs_offenders?window="+encodeURIComponent(w))).then(r=>r.json());
    if(d.error){ el.innerHTML=`<div class="text-red-300 text-xs">${esc(d.error)}</div>`; return; }
    const list=d.offenders||[];
    document.getElementById("crs_summary").innerHTML=list.length
      ? `<span class="text-slate-200 font-medium">${list.length}</span> IP · ${_trText("сработок WAF")}`
      : "";
    el.innerHTML=list.length?list.map(x=>`
      <div class="flex items-center gap-2 py-1.5 border-b border-slate-800/60 last:border-0">
        <span class="mono text-slate-200 w-32 shrink-0 truncate cursor-pointer hover:text-indigo-300" onclick="openProfile('${escJs(x.ip)}')" title="профиль">${esc(x.ip)} ↗</span>
        <span class="mono text-amber-300 shrink-0 w-12 text-right" title="CRS hits">${fmt(x.count)}</span>
        <span class="flex-1 min-w-0 flex flex-wrap gap-1">${(x.families||[]).map(f=>`<span class="px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-300 text-[10px]">${esc(f)}</span>`).join("")}</span>
        ${x.cf?`<span class="text-[10px] px-2 py-0.5 rounded bg-sky-500/15 text-sky-300 border border-sky-500/30 shrink-0">${_trText("за CF")}</span>`
             :`<button onclick="crsBan('${escJs(x.ip)}',${x.count})" class="text-[11px] px-2 py-0.5 rounded bg-red-600/70 text-white hover:bg-red-600 shrink-0">${_trText("бан")}</button>`}
      </div>`).join("")
      : `<div class="text-slate-600 text-xs">${_trText("чисто — срабатываний WAF нет за окно")} (${esc(d.window||w)})</div>`;
  }catch(e){ el.innerHTML=`<div class="text-red-300 text-xs">${_trText("ошибка загрузки")}</div>`; }
}
async function crsBan(ip,count){ await blockIP(ip,"WAF/CRS · "+(count||0)+" hits"); renderCrs(); }

// --- просятся в бан (сканеры) ---
let _banCandObjs=[], _cfCandObjs=[], _showCf=false;
let _suspectObjs=[], _showCfS=false, _verdictMap={};
let _reviewedSet=new Set();
async function loadReviewed(){try{const d=await fetch("/api/reviewed").then(r=>r.json());_reviewedSet=new Set(d.ips||[]);}catch(e){}}
async function toggleReviewed(ip,btn){
  const now=!_reviewedSet.has(ip);
  if(now)_reviewedSet.add(ip);else _reviewedSet.delete(ip);
  const row=btn.closest('[data-ip]'); if(row)['grayscale','opacity-60'].forEach(c=>row.classList.toggle(c,now));
  btn.textContent=now?'✓ просмотрено':'пометить';
  btn.title=now?'снять отметку «просмотрено»':'пометить просмотренным';
  btn.className=`text-[11px] px-1.5 py-0.5 rounded shrink-0 ${now?'bg-emerald-600/70 text-white hover:bg-emerald-600':'bg-slate-700/50 text-slate-300 hover:bg-slate-700'}`;
  try{await _post("/api/review",{ip,reviewed:now});}catch(e){}
}
function toggleCf(){_showCf=!_showCf;renderBanCandidates();}
function toggleCfS(){_showCfS=!_showCfS;renderSuspects();}
function _verdictBadge(ip){
  const v=_verdictMap[ip]; if(!v) return "";
  const m={malicious:["bg-red-500/20 text-red-300 border-red-500/40","вредонос"],scanner:["bg-red-500/15 text-red-300 border-red-500/30","сканер"],"legit-bot":["bg-sky-500/15 text-sky-300 border-sky-500/30","легит-бот"],user:["bg-emerald-500/15 text-emerald-300 border-emerald-500/30","юзер"],"подозрит.":["bg-amber-500/15 text-amber-300 border-amber-500/30","подозрит."]};
  const k=m[v.kind]||["bg-slate-700/40 text-slate-300 border-slate-600/40",esc(v.kind||"?")];
  return `<span class="px-1.5 py-0.5 rounded text-[10px] border ${k[0]} shrink-0" title="${esc(v.reason||"")} · уверенность: ${esc(v.confidence||"")}">🤖 ${k[1]}${v.ban?" · бан":""}</span>`;
}
function _bcRow(x,i,isCf,fn){
  const rv=_reviewedSet.has(x.ip);
  const rvBtn=`<button onclick="toggleReviewed('${escJs(x.ip)}',this)" title="${rv?'снять отметку «просмотрено»':'пометить просмотренным'}" class="text-[11px] px-1.5 py-0.5 rounded shrink-0 ${rv?'bg-emerald-600/70 text-white hover:bg-emerald-600':'bg-slate-700/50 text-slate-300 hover:bg-slate-700'}">${rv?'✓ просмотрено':'пометить'}</button>`;
  return `<div data-ip="${esc(x.ip)}" class="flex items-center gap-x-2 gap-y-1 py-1.5 border-b border-slate-800/60 last:border-0 flex-wrap${rv?' grayscale opacity-60':''}">
    <span class="mono text-[13px] text-slate-200 shrink-0 cursor-pointer hover:text-indigo-300" onclick="openProfile('${escJs(x.ip)}')" title="профиль / вся инфа">${esc(x.ip)} ↗</span>
    <span class="text-xs text-slate-500 shrink-0 truncate max-w-[120px]" title="${esc(countryLabel(x.country))}">${countryLabel(x.country)}</span>
    <span class="mono text-amber-300 shrink-0 tabular-nums" title="хитов 4xx">${fmt(x.count)}</span>
    <span class="shrink-0 flex gap-1">${_sigBadges(x)}${_verdictBadge(x.ip)}</span>
    <span class="text-[11px] text-slate-500 flex-1 basis-32 min-w-0 truncate" title="${esc((x.paths||[]).join(', '))}">${esc((x.paths||[]).slice(0,2).join(", "))}${(x.paths||[]).length>2?` +${(x.paths||[]).length-2}`:""}</span>
    <span class="flex items-center gap-1 shrink-0 ml-auto">${rvBtn}
    ${isCf
      ?`<span class="text-[10px] px-2 py-0.5 rounded bg-sky-500/15 text-sky-300 border border-sky-500/30">за CF</span>`
      :`<button onclick="${fn}(${i})" class="text-[11px] px-2 py-0.5 rounded bg-red-600/70 text-white hover:bg-red-600">бан</button>`}</span>
  </div>`;
}
function _banReason(x){
  const sig=x.signals||[],parts=[];
  if(sig.includes("scanner"))parts.push("сканер"+((x.paths&&x.paths.length)?": "+x.paths.join(", "):""));
  if(sig.includes("payload"))parts.push("payload (SQLi/XSS)");
  if(sig.includes("4xx"))parts.push("подозрительно: "+(x.count||"?")+"× 4xx");
  return parts.join("; ")||"подозрительная активность";
}
function _sigBadges(x){return (x.signals||[]).map(s=>
  s==="payload"?`<span class="px-1.5 py-0.5 rounded text-[10px] bg-red-500/15 text-red-300 border border-red-500/30">SQLi/XSS</span>`
  :s==="4xx"?`<span class="px-1.5 py-0.5 rounded text-[10px] bg-orange-500/15 text-orange-300 border border-orange-500/30">4xx</span>`
  :`<span class="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/15 text-amber-300 border border-amber-500/30">scanner</span>`).join(" ");}
function banCand(i){const x=_banCandObjs[i];if(!x)return;blockIP(x.ip,_banReason(x));}
function banSuspect(i){const x=_suspectObjs[i];if(!x)return;blockIP(x.ip,_banReason(x));}
async function renderBanCandidates(_try){
  _try=_try||0;
  const el=document.getElementById("ban_candidates");if(!el)return;
  try{
    const bw=(document.getElementById("bc_win")||{}).value||"1h";
    await loadReviewed();
    const d=await fetch(_withEnv("/api/ban_candidates?window="+encodeURIComponent(bw))).then(r=>r.json());
    if(d.error){el.innerHTML=`<div class="text-red-300 text-xs">ошибка: ${esc(d.error)}</div>`;return;}
    // расчёт ещё идёт (лок занят, кэша нет) → подождём и перезапросим, не мигая пустотой
    if(d.stale&&!(d.candidates||[]).length&&_try<4){
      if(!el.innerHTML.trim()||_try===0)el.innerHTML='<div class="text-slate-600 text-xs">считаю…</div>';
      return void setTimeout(()=>renderBanCandidates(_try+1),3500);
    }
    const c=d.candidates||[];
    const real=c.filter(x=>!x.cf), cf=c.filter(x=>x.cf);
    _banCandObjs=real; _cfCandObjs=cf;
    const realHits=real.reduce((a,x)=>a+(x.count||0),0);
    const tp=(d.top_paths||[]).slice(0,5).map(p=>`${esc(p.key)} (${fmt(p.count)})`).join(" · ");
    document.getElementById("bc_summary").innerHTML=`<span class="text-slate-200 font-medium">${real.length}</span> IP · <span class="text-slate-200">${fmt(realHits)}</span> хитов${cf.length?` · <span class="text-slate-500">+${cf.length} за Cloudflare (IP скрыт)</span>`:""}`;
    let html = real.length
      ? real.map((x,i)=>_bcRow(x,i,false,'banCand')).join("")
      : `<div class="text-slate-600 text-xs">чисто — реальных сканеров нет за окно (${esc(d.window||"")})</div>`;
    if(cf.length){
      html+=`<div class="mt-2"><button onclick="toggleCf()" class="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 hover:bg-slate-700">${_showCf?"▾ скрыть":"▸ показать"} ${cf.length} за Cloudflare (реальный IP скрыт)</button></div>`;
      if(_showCf) html+=`<div class="mt-1">`+cf.map((x,i)=>_bcRow(x,i,true,'banCand')).join("")+`</div>`;
    }
    el.innerHTML=html;
  }catch(e){el.innerHTML=`<div class="text-red-300 text-xs">ошибка загрузки</div>`;}
}
async function resyncNow(){
  const res=await _post("/api/resync",{});
  if(res.ok){uiAlert("Ресинк выполнен. Активных правил: "+(res.active??"?"));renderBlocklist();}
  else uiAlert("Не удалось: "+(res.error||"ошибка"));
}
async function unbanAll(){
  if(!await uiConfirm("Снять ВСЕ блокировки с ingress?\n(статический deny-список приложения не затрагивается)"))return;
  const res=await _post("/api/unblock_all",{});
  if(res.ok){uiAlert("Снято блокировок: "+(res.removed??0));renderBlocklist();renderBanCandidates();}
  else uiAlert("Не удалось: "+(res.error||"ошибка"));
}
async function banAllCandidates(){
  if(!_banCandObjs.length){uiAlert("Список пуст — банить некого.");return;}
  if(!await uiConfirm("Забанить ВСЕХ "+_banCandObjs.length+" IP на ingress?\nКаждый будет получать 403."))return;
  const items=_banCandObjs.map(x=>({cidr:x.ip,reason:_banReason(x)}));
  const res=await _post("/api/block_bulk",{items,ttl:2592000,group:_banGroup||undefined});
  if(res.ok){uiAlert("Забанено: "+(res.blocked?res.blocked.length:0)+(res.skipped&&res.skipped.length?(", пропущено: "+res.skipped.length):"")+"\nАктивных правил: "+(res.active??"?"));renderBanCandidates();renderBlocklist();}
  else uiAlert("Не удалось: "+(res.error||"ошибка"));
}
async function renderSuspects(_try){
  _try=_try||0;
  const el=document.getElementById("suspects");if(!el)return;
  try{
    const bw=(document.getElementById("sc_win")||{}).value||"1h";
    await loadReviewed();
    const d=await fetch(_withEnv("/api/suspect_ips?window="+encodeURIComponent(bw))).then(r=>r.json());
    if(d.error){el.innerHTML=`<div class="text-red-300 text-xs">ошибка: ${esc(d.error)}</div>`;return;}
    if(d.stale&&!(d.candidates||[]).length&&_try<4){
      if(!el.innerHTML.trim()||_try===0)el.innerHTML='<div class="text-slate-600 text-xs">считаю…</div>';
      return void setTimeout(()=>renderSuspects(_try+1),3500);
    }
    const c=d.candidates||[];const real=c.filter(x=>!x.cf),cf=c.filter(x=>x.cf);
    // подтянуть уже посчитанные вердикты из кэша сервера (переживают reload)
    const need=c.map(x=>x.ip).filter(ip=>!_verdictMap[ip]);
    if(need.length){try{const vd=await fetch("/api/verdicts?ips="+encodeURIComponent(need.join(","))).then(r=>r.json());Object.assign(_verdictMap,vd.verdicts||{});}catch(e){}}
    _suspectObjs=real;
    const realHits=real.reduce((a,x)=>a+(x.count||0),0);
    const tp=(d.top_paths||[]).slice(0,5).map(p=>`${esc(p.key)} (${fmt(p.count)})`).join(" · ");
    document.getElementById("sc_summary").innerHTML=`<span class="text-slate-200 font-medium">${real.length}</span> IP · <span class="text-slate-200">${fmt(realHits)}</span> ошибок 4xx${cf.length?` · <span class="text-slate-500">+${cf.length} за Cloudflare (IP скрыт)</span>`:""}`;
    let html = real.length
      ? real.map((x,i)=>_bcRow(x,i,false,'banSuspect')).join("")
      : `<div class="text-slate-600 text-xs">чисто — аномальных 4xx нет за окно (${esc(d.window||"")})</div>`;
    if(cf.length){
      html+=`<div class="mt-2"><button onclick="toggleCfS()" class="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 hover:bg-slate-700">${_showCfS?"▾ скрыть":"▸ показать"} ${cf.length} за Cloudflare (реальный IP скрыт)</button></div>`;
      if(_showCfS) html+=`<div class="mt-1">`+cf.map((x,i)=>_bcRow(x,i,true,'banSuspect')).join("")+`</div>`;
    }
    el.innerHTML=html;
  }catch(e){el.innerHTML=`<div class="text-red-300 text-xs">ошибка загрузки</div>`;}
}
async function judgeSuspects(force){
  const btn=document.getElementById(force?"sc_recheck":"sc_judge");
  const bw=(document.getElementById("sc_win")||{}).value||"1h";
  let ips=_suspectObjs.slice(0,10).map(x=>x.ip);
  if(force) ips.forEach(ip=>delete _verdictMap[ip]); else ips=ips.filter(ip=>!_verdictMap[ip]);
  if(!ips.length){uiAlert(force?"Список пуст.":"Все уже оценены — жми «Переоценить» для форс-перепроверки.");return;}
  if(force)renderSuspects();
  const label=btn?btn.textContent:"";
  if(btn)btn.disabled=true;
  for(let k=0;k<ips.length;k++){
    if(btn)btn.textContent=`🤖 ${k+1}/${ips.length}…`;
    try{
      const d=await fetch("/api/judge_ip?window="+encodeURIComponent(bw)+"&ip="+encodeURIComponent(ips[k])+(force?"&force=1":"")).then(r=>r.json());
      const v=d.verdict; if(v)_verdictMap[ips[k]]={...v,ip:ips[k]};
      renderSuspects();
    }catch(e){}
  }
  if(btn){btn.disabled=false;btn.textContent=label;}
}
async function banAllSuspects(){
  if(!_suspectObjs.length){uiAlert("Список пуст.");return;}
  if(!await uiConfirm("Забанить ВСЕХ "+_suspectObjs.length+" подозрительных IP на ingress?"))return;
  const items=_suspectObjs.map(x=>({cidr:x.ip,reason:_banReason(x)}));
  const res=await _post("/api/block_bulk",{items,ttl:2592000,group:_banGroup||undefined});
  if(res.ok){uiAlert("Забанено: "+(res.blocked?res.blocked.length:0)+(res.skipped&&res.skipped.length?(", пропущено: "+res.skipped.length):"")+"\nАктивных правил: "+(res.active??"?"));renderSuspects();renderBlocklist();}
  else uiAlert("Не удалось: "+(res.error||"ошибка"));
}
function wcRender(job,data){
  if(!data||data.error) return `<div class="text-slate-600 text-xs">${esc(job)}: ${esc((data&&data.error)||"—")}</div>`;
  const kv=(o)=>Object.entries(o).slice(0,12).map(([k,v])=>{
    let val=typeof v==="object"?JSON.stringify(v):String(v);
    return `<div class="flex gap-2 text-xs"><span class="text-slate-500 shrink-0 w-40 truncate">${esc(k)}</span><span class="mono text-slate-300 truncate">${esc(val.slice(0,80))}</span></div>`;}).join("");
  let body;
  if(Array.isArray(data)) body=`<div class="mono text-xs text-slate-300">${esc(JSON.stringify(data).slice(0,400))}</div>`;
  else if(typeof data==="object") body=kv(data);
  else body=`<span class="text-xs text-slate-300">${esc(String(data))}</span>`;
  return `<div class="border-b border-slate-800/50 py-2"><div class="text-xs font-medium text-emerald-300 mb-1">${esc(job)}</div>${body}</div>`;
}
async function openWebcheck(domain){
  domain=(domain||"").replace(/^https?:\/\//,"").split("/")[0];
  const body=showModal("web-check · "+domain);
  body.innerHTML=`<div class="text-slate-500 text-sm">проверяю ${esc(domain)}… (несколько секунд)</div>`;
  const url="https://"+domain;
  const jobs=["ssl","headers","http-security","tech-stack","dns","ports","cookies","dnssec"];
  try{
    const results=await Promise.all(jobs.map(j=>
      fetch(`/api/webcheck?job=${j}&url=${encodeURIComponent(url)}`).then(r=>r.json()).then(d=>[j,d]).catch(()=>[j,{error:"timeout"}])));
    body.innerHTML=`<div class="text-[11px] text-slate-500 mb-2">Полный отчёт: проверки SSL, заголовков, безопасности, DNS, портов, стека.</div>`+
      results.map(([j,d])=>wcRender(j,d)).join("");
  }catch(e){body.innerHTML=`<div class="text-red-300 text-sm">ошибка web-check</div>`;}
}
let notifiedAt=0;
function notifyCritical(cur){
  if(!cur||cur.severity!=="critical")return;
  if(cur.ts===notifiedAt)return; notifiedAt=cur.ts;
  if("Notification" in window){
    if(Notification.permission==="granted") new Notification("SOC: критично",{body:cur.headline||"Атака"});
    else if(Notification.permission!=="denied") Notification.requestPermission();
  }
}
async function openIps(country){
  const body=showModal("Топ IP · "+country);
  try{const d=await fetch("/api/ips?country="+encodeURIComponent(country)+"&limit=25").then(r=>r.json());
    if(d.error){body.innerHTML=`<div class="text-red-300 text-sm">Ошибка: ${esc(d.error)}</div>`;return;}
    if(!d.ips||!d.ips.length){body.innerHTML=`<div class="text-slate-500 text-sm">нет данных</div>`;return;}
    const max=Math.max(...d.ips.map(x=>x.count));lastIPs=d.ips.map(x=>x.ip);
    body.innerHTML=`<div class="flex justify-end mb-2"><button onclick="exportList(lastIPs,'ips-${esc(country)}.txt')" class="text-xs px-2 py-1 rounded bg-red-500/15 text-red-300 border border-red-500/30 hover:bg-red-500/25">⤓ экспорт всех IP</button></div>`+
      d.ips.map(x=>`<div class="cursor-pointer hover:bg-slate-800/40 -mx-1 px-1 rounded" onclick="openProfile('${escJs(x.ip)}')"><div class="flex justify-between text-xs mb-0.5"><span class="mono text-slate-300">${esc(x.ip)} <span class="text-slate-600">↗</span></span><span class="mono text-indigo-300">${fmt(x.count)}</span></div><div class="bar-bg"><div class="h-full rounded" style="width:${(x.count/max*100).toFixed(0)}%;background:#5794f299"></div></div></div>`).join("");
  }catch(e){body.innerHTML=`<div class="text-red-300 text-sm">ошибка запроса</div>`;}
}
function reqTable(rows){
  if(!rows||!rows.length) return `<div class="text-slate-500 text-sm">нет запросов за окно</div>`;
  const sc=s=>s>="500"?"text-red-300":s>="400"?"text-amber-300":s>="300"?"text-sky-300":"text-emerald-300";
  const kv=(l,v,mono)=>`<div><span class="text-slate-500 inline-block w-24 align-top">${l}</span><span class="${mono?"mono ":""}text-slate-300 break-all">${esc(v||"—")}</span></div>`;
  return `<table class="w-full text-xs"><thead><tr class="text-slate-500 text-left">
    <th class="py-1 font-medium"></th><th class="font-medium">время</th><th class="font-medium">IP</th><th class="font-medium"></th><th class="font-medium">м</th><th class="font-medium">путь</th><th class="font-medium">код</th><th class="font-medium">хост</th></tr></thead><tbody>
    ${rows.map(r=>{
      const detail=`<tr class="hidden bg-slate-900/50"><td colspan="8" class="px-3 py-2 space-y-1 text-[11px]">
        ${kv("путь",r.path,1)}
        ${r.args?kv("args",r.args,1):""}
        ${kv("User-Agent",r.ua,1)}
        ${r.ref?kv("referer",r.ref,1):""}
        <div class="flex flex-wrap gap-4 pt-0.5">
          <span class="text-slate-500">хост: <span class="mono text-slate-300">${esc(r.host||"—")}</span></span>
          <span class="text-slate-500">страна: <span class="text-slate-300">${esc(r.country||"—")}</span></span>
          <span class="text-slate-500">время ответа: <span class="mono text-slate-300">${esc(r.rt||"—")}с</span></span>
          ${r.bytes?`<span class="text-slate-500">отдано: <span class="mono text-slate-300">${fmt(+r.bytes)} B</span></span>`:""}
        </div></td></tr>`;
      return `<tr class="border-t border-slate-800/50 hover:bg-slate-800/30 cursor-pointer" onclick="this.nextElementSibling.classList.toggle('hidden')">
      <td class="text-slate-600 w-3">▸</td>
      <td class="py-1 mono text-slate-500 whitespace-nowrap" title="${ago(r.ts)} назад">${dt(r.ts)}</td>
      <td class="mono text-slate-300"><span class="cursor-pointer hover:text-indigo-300" onclick="event.stopPropagation();openProfile('${escJs(r.ip)}')">${esc(r.ip||"")}</span> ${cfBadge(r.ip)}</td>
      <td class="text-slate-600">${esc(r.country||"")}</td>
      <td class="mono text-slate-400">${esc(r.method||"")}</td>
      <td class="mono text-slate-300 max-w-[420px]"><div class="flex items-center gap-1"><span class="truncate" title="${esc(r.path)}">${esc(r.path||"")}</span><button data-p="${escAttr(r.path||"")}" onclick="event.stopPropagation();abPathMenu(this.dataset.p,this)" title="добавить путь в правило (403 или автобан)" class="text-[10px] px-1 rounded bg-slate-800 text-indigo-300 hover:bg-indigo-500/20 shrink-0">+</button></div></td>
      <td class="mono ${sc(String(r.status))}">${esc(r.status||"")}</td>
      <td class="text-slate-500 truncate max-w-[200px]" title="${esc(r.host)}">${esc(r.host||"")}</td></tr>${detail}`;
    }).join("")}
  </tbody></table>`;
}
async function openRequests(filter,title){
  const body=showModal(title||"Запросы");
  filter=filter||{};
  window._orExtra={host:filter.host||"",ua:filter.ua||"",ref:filter.ref||""};  // pass-through (chip context)
  window._orWantCode=filter.status||"";   // preselect this code once it's in the list
  const inp=(id,val,ph,w)=>`<input id="${id}" value="${esc(val||"")}" placeholder="${ph}" onkeydown="if(event.key==='Enter')runOpenRequests()" class="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-xs mono ${w}">`;
  body.innerHTML=`
    <div class="flex flex-wrap gap-2 mb-3 items-end">
      <div><label class="block text-[10px] text-slate-500 mb-0.5">IP</label>${inp("or_ip",filter.ip,"1.2.3.4","w-32")}</div>
      <div><label class="block text-[10px] text-slate-500 mb-0.5">путь</label>${inp("or_path",filter.path,"/wp-admin","w-44")}</div>
      <div><label class="block text-[10px] text-slate-500 mb-0.5">код</label>
        <select id="or_status" onchange="orRenderFiltered()" class="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-xs"><option value="">все коды</option></select></div>
      <div><label class="block text-[10px] text-slate-500 mb-0.5">время</label>
        <select id="or_win" onchange="runOpenRequests()" class="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-xs">
          <option value="15">15м</option><option value="60">1ч</option><option value="360">6ч</option><option value="720" selected>12ч</option><option value="1440">24ч</option><option value="4320">3д</option>
        </select></div>
      <button onclick="runOpenRequests()" class="px-3 py-1 rounded bg-indigo-600/80 text-white text-xs hover:bg-indigo-600">Найти</button>
      <button onclick="orBanIPs()" class="px-3 py-1 rounded bg-red-600/80 text-white text-xs hover:bg-red-600" title="забанить IP из результата на ingress (403)">⛔ забанить на ingress</button>
    </div>
    <div id="or_out"><div class="text-slate-500 text-sm">загрузка…</div></div>`;
  runOpenRequests();
}
async function runOpenRequests(){
  // fetch WITHOUT the code filter → so the code dropdown shows every code present
  // for this ip/path over the selected window; code filtering is done client-side.
  const g=id=>{const e=document.getElementById(id);return e?e.value.trim():"";};
  const f={ip:g("or_ip"),path:g("or_path"),...(window._orExtra||{})};
  Object.keys(f).forEach(k=>{if(!f[k])delete f[k];});
  const minutes=g("or_win")||720;
  const out=document.getElementById("or_out");out.innerHTML=`<div class="text-slate-500 text-sm">поиск…</div>`;
  const qs=new URLSearchParams({...f,limit:1000,minutes}).toString();
  try{const d=await fetch(_withEnv("/api/requests?"+qs)).then(r=>r.json());
    if(d.error){out.innerHTML=`<div class="text-red-300 text-sm">Ошибка: ${esc(d.error)}</div>`;return;}
    window._orAll=d.requests||[];
    orRebuildCodes();
    orRenderFiltered();
  }catch(e){out.innerHTML=`<div class="text-red-300 text-sm">ошибка запроса</div>`;}
}
function orRebuildCodes(){
  const sel=document.getElementById("or_status");if(!sel)return;
  const cur=sel.value||window._orWantCode||"";window._orWantCode="";
  const codes=[...new Set((window._orAll||[]).map(r=>String(r.status||"")).filter(Boolean))].sort();
  const lbl=c=>c+(c[0]==="2"?" ✓":c==="403"?" ⛔":c[0]==="4"?" ⚠":c[0]==="5"?" ✖":"");
  sel.innerHTML=`<option value="">все коды (${codes.length})</option>`+
    codes.map(c=>{const n=(window._orAll||[]).filter(r=>String(r.status)===c).length;return `<option value="${c}">${lbl(c)} · ${n}</option>`;}).join("");
  if(codes.includes(cur)) sel.value=cur;
}
function orRenderFiltered(){
  const code=(document.getElementById("or_status")||{}).value||"";
  let rows=window._orAll||[];
  if(code) rows=rows.filter(r=>String(r.status)===code);
  window._orRows=rows;
  document.getElementById("or_out").innerHTML=reqTable(rows);
}
function _ip4int(ip){const p=String(ip).split(".");if(p.length!==4)return null;return ((+p[0]<<24)>>>0)+((+p[1])<<16)+((+p[2])<<8)+(+p[3]);}
function ipInCidr(ip,cidr){
  if(!cidr)return false;
  if(!cidr.includes("/"))return cidr===ip;
  const[net,bitsS]=cidr.split("/");const bits=+bitsS;
  const a=_ip4int(ip),b=_ip4int(net);if(a==null||b==null)return false;
  const mask=bits<=0?0:(bits>=32?0xffffffff:(~((1<<(32-bits))-1))>>>0);
  return ((a&mask)>>>0)===((b&mask)>>>0);
}
// Cloudflare-принадлежность IP (помечаем везде: это edge, не реальный посетитель)
const CF_CIDRS=["173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20","197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13","104.24.0.0/14","172.64.0.0/13","131.0.72.0/22"];
const CF_V6=["2400:cb00","2606:4700","2803:f800","2405:b500","2405:8100","2a06:98c0","2c0f:f248"];
function isCfIp(ip){if(!ip)return false;ip=String(ip);if(ip.includes(":")){const h=ip.toLowerCase();return CF_V6.some(p=>h.startsWith(p));}return CF_CIDRS.some(c=>ipInCidr(ip,c));}
function cfBadge(ip){return isCfIp(ip)?`<span class="px-1.5 py-0.5 rounded bg-orange-500/15 text-orange-300 text-[10px] border border-orange-500/30 shrink-0" title="IP Cloudflare — не реальный посетитель, банить бесполезно (реальный в CF-Connecting-IP)">☁ Cloudflare</span>`:"";}
async function orBanIPs(){
  const ips=[...new Set((window._orRows||[]).map(r=>r.ip).filter(Boolean))];
  if(!ips.length){uiAlert("Нет IP в результате");return;}
  let blocks=[];
  try{const d=await fetch("/api/blocklist").then(r=>r.json());
    if(!d.enabled){uiAlert("blocklist-api не настроен — бан недоступен.");return;}
    blocks=d.blocks||[];
  }catch(e){}
  const isBanned=ip=>blocks.some(b=>ipInCidr(ip,b.cidr||""));
  const matchOf=ip=>(blocks.find(b=>ipInCidr(ip,b.cidr||""))||{}).cidr;
  const already=ips.filter(isBanned), fresh=ips.filter(ip=>!isBanned(ip));
  if(ips.length===1){
    if(already.length){uiAlert("ℹ️ "+ips[0]+" уже забанен на ingress (правило "+matchOf(ips[0])+").");return;}
    return blockIP(ips[0],"из «показать запросы»");
  }
  if(!fresh.length){uiAlert("Все "+ips.length+" IP уже забанены на ingress.");return;}
  if(!await uiConfirm("Забанить "+fresh.length+" новых IP на ingress?"+(already.length?("\n("+already.length+" уже забанены — пропущу)"):"")+"\nКаждый будет получать 403."))return;
  const items=fresh.map(ip=>({cidr:ip,reason:"из «показать запросы»"}));
  const res=await _post("/api/block_bulk",{items,ttl:2592000,group:_banGroup||undefined});
  if(res.ok){uiAlert("Забанено: "+(res.blocked?res.blocked.length:0)+(res.skipped&&res.skipped.length?(", пропущено (доверенные/приватные): "+res.skipped.length):"")+(already.length?(", уже было: "+already.length):"")+"\nАктивных правил: "+(res.active??"?"));renderBlocklist();}
  else uiAlert("Не удалось: "+(res.error||"ошибка"));
}
let lastExplorer=[];
async function runExplorer(){
  const g=id=>document.getElementById(id).value.trim();
  const f={};["host","path","status","ip"].forEach(k=>{const v=g("ex_"+k);if(v)f[k]=v;});
  const out=document.getElementById("ex_out");out.innerHTML=`<div class="text-slate-500 text-sm">поиск…</div>`;
  const mins=parseInt((document.getElementById("ex_minutes")||{}).value)||60;
  const qs=new URLSearchParams({...f,limit:80,minutes:mins}).toString();
  try{const d=await fetch(_withEnv("/api/requests?"+qs)).then(r=>r.json());
    lastExplorer=d.requests||[];
    out.innerHTML=d.error?`<div class="text-red-300 text-sm">${esc(d.error)}</div>`:reqTable(d.requests);
  }catch(e){out.innerHTML=`<div class="text-red-300 text-sm">ошибка</div>`;}
}
function exportExplorerIPs(){
  const ips=[...new Set(lastExplorer.map(r=>r.ip).filter(Boolean))];
  if(!ips.length){uiAlert("Сначала «Найти» — нет результатов для экспорта");return;}
  exportList(ips,"denylist-explorer.txt");
}
async function runNL(){
  const q=document.getElementById("nl_q").value.trim();if(!q)return;
  const out=document.getElementById("ex_out");out.innerHTML=`<div class="text-slate-500 text-sm">🤖 разбираю запрос… (LLM)</div>`;
  try{const d=await fetch("/api/nl?q="+encodeURIComponent(q)).then(r=>r.json());
    lastExplorer=d.requests||[];
    const f=d.filters||{};const chips=Object.entries(f).map(([k,v])=>`<span class="px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 text-[11px] mono">${esc(k)}=${esc(String(v))}</span>`).join(" ");
    out.innerHTML=`<div class="mb-2 text-xs text-slate-500">LLM понял так: ${chips||"—"}</div>`+(d.error?`<div class="text-red-300 text-sm">${esc(d.error)}</div>`:reqTable(d.requests));
  }catch(e){out.innerHTML=`<div class="text-red-300 text-sm">ошибка</div>`;}
}
function preset(name){
  const set=(h,p,s,i)=>{ex_host.value=h;ex_path.value=p;ex_status.value=s;ex_ip.value=i;runExplorer();};
  if(name==="scanners") set("","/.env","","");
  if(name==="auth") set("","/auth","403","");
  if(name==="5xx") set("","","5","");
}

const SIG_LABEL={forbidden_new:"Заблокировано новых",status_4xx:"Ошибки 4xx",status_404:"404 (перебор путей)",status_5xx:"5xx (сервер)",crs_detections:"CRS-пейлоады (SQLi/XSS)",distinct_attacker_ips:"Атакующих IP",malicious_ratio:"Доля вредного трафика"};
const SIG_THROUGH=new Set(["status_404","status_5xx","crs_detections","distinct_attacker_ips"]);
function _sigText(s){
  const name=SIG_LABEL[s.field]||s.field;
  if(s.field==="malicious_ratio") return `${name}: ${(s.current*100).toFixed(0)}%`;
  if(s.ratio) return `${name}: ${fmt(s.current)} — было ~${fmt(s.baseline)}, рост ×${s.ratio}`;
  return `${name}: ${fmt(s.current)} (раньше почти не было)`;
}
function _whyHtml(c){
  const data=c.data||c, sig=data.signals||[];
  let h="";
  if(sig.length){
    const through=sig.some(s=>SIG_THROUGH.has(s.field));
    const v=through
      ?{t:"⚠️ Часть трафика доходит до приложения — стоит разобраться (детали ниже).",c:"bg-red-500/10 text-red-200 border-red-500/30"}
      :{t:"✅ Атака отбита: всплеск — это заблокированный трафик (deny/403), до сайта он не дошёл. Срочных действий не требуется.",c:"bg-emerald-500/10 text-emerald-200 border-emerald-500/30"};
    h+=`<div class="text-xs rounded-md border px-2.5 py-1.5 mb-2 leading-relaxed ${v.c}">${v.t}</div>`;
    h+=`<div class="mt-1 mb-2"><div class="text-[11px] uppercase tracking-wide text-slate-500 mb-1">Почему сработало</div><ul class="space-y-1">`+
      sig.map(s=>{const thr=SIG_THROUGH.has(s.field);const cls=s.level==='high'?(thr?'text-red-400':'text-amber-400'):'text-slate-400';
        const tag=thr?'<span class="text-[10px] text-red-300/70">проходит</span>':'<span class="text-[10px] text-emerald-300/60">блокируется</span>';
        return `<li class="flex gap-2 text-xs"><span class="${cls} shrink-0">▲</span><span class="text-slate-300">${esc(_sigText(s))} ${tag}</span></li>`;}).join("")+`</ul></div>`;
  }
  if(data.attention&&data.attention.length) h+=`<div class="mb-2"><div class="text-[11px] text-slate-500 mb-1">На что смотреть</div><ul class="text-xs text-slate-300 space-y-1">${data.attention.map(a=>`<li class="flex gap-2"><span class="text-amber-400 shrink-0">•</span>${esc(a)}</li>`).join("")}</ul></div>`;
  if(data.actions&&data.actions.length) h+=`<div><div class="text-[11px] text-slate-500 mb-1">Что сделать</div><ul class="text-xs text-slate-300 space-y-1">${data.actions.map(a=>`<li class="flex gap-2"><span class="text-indigo-400 shrink-0">→</span>${esc(a)}</li>`).join("")}</ul></div>`;
  return h||`<div class="text-xs text-slate-600">детали недоступны</div>`;
}
function renderInsightCurrent(c){
  const el=document.getElementById("insight-current");
  if(!c){el.innerHTML=`<div class="text-slate-500 text-sm">Ждём первый разбор от LLM…</div>`;return;}
  const sev=SEV[c.severity]||SEV.ok;
  el.innerHTML=`<div class="flex items-center justify-between mb-2"><span class="px-2.5 py-1 rounded-md text-xs font-semibold border ${sev.cls}">${sev.label.toUpperCase()}</span><span class="text-[11px] text-slate-500 mono" title="${dt(c.ts)}">${dt(c.ts)} · ${ago(c.ts)} назад</span></div>
    <h3 class="text-base font-semibold text-slate-100 mb-2">${esc(c.headline)||"Разбор трафика"}</h3>
    ${(c.summary&&c.summary!==c.headline)?`<p class="text-sm text-slate-300 leading-relaxed mb-3">${esc(c.summary)}</p>`:""}
    ${_whyHtml(c)}`;
}
function renderHistory(list){
  const el=document.getElementById("insight-history");
  if(!list||!list.length){el.innerHTML=`<div class="text-slate-600 text-xs">пусто</div>`;return;}
  el.innerHTML=`<div class="flex items-center justify-between mb-2"><div class="text-[11px] uppercase tracking-wide text-slate-500">Лента AI-разборов <span class="text-slate-600 normal-case">— клик, чтобы развернуть «почему»</span></div><div class="text-[11px] text-slate-600 mono">${list.length}</div></div>`+
    list.map(c=>{const sev=SEV[c.severity]||SEV.ok;const hl=c.headline||(c.data&&c.data.headline)||"";
    return `<details class="border-b border-slate-800/60 last:border-0 group">
      <summary class="flex items-start gap-3 py-2 cursor-pointer list-none hover:bg-slate-800/30 -mx-1 px-1 rounded">
        <span class="text-slate-600 text-[10px] mt-1 shrink-0 group-open:rotate-90 transition-transform">▶</span>
        <span class="w-2 h-2 mt-1.5 rounded-full shrink-0" style="background:${sev.dot}"></span>
        <span class="text-[11px] text-slate-500 mono shrink-0 w-[112px] mt-0.5">${dt(c.ts)}</span>
        <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold border shrink-0 ${sev.cls}">${sev.label.toUpperCase()}</span>
        <span class="text-sm text-slate-300 min-w-0"><span class="text-slate-200 font-medium">${esc(hl)}</span>${(hl&&c.summary&&c.summary!==hl)?` — <span class="text-slate-400">${esc(c.summary)}</span>`:""}</span>
      </summary>
      <div class="pl-[34px] pb-3 pr-2">${_whyHtml(c)}</div>
    </details>`;}).join("");
}

function chip(label,ok,detail){
  const col=ok===null?"var(--muted)":ok?"var(--ok)":"var(--crit)";
  return `<span class="hchip" title="${esc(detail||"")}"><span class="hd" style="background:${col}"></span><b style="color:${col}">${esc(label)}</b>${detail?` <span class="hchip-d">· ${esc(detail)}</span>`:""}</span>`;
}
function renderLLMToggle(enabled){
  const sb=document.getElementById("llm-toggle");
  if(sb)sb.textContent=enabled?"🤖 on":"🤖 off";          // hidden when off via data-llm
  const sg=document.getElementById("set-llm-toggle");      // real switch in Settings
  if(sg)sg.classList.toggle("on",!!enabled);
  const st=document.getElementById("set-llm-state");
  if(st){ st.textContent=enabled?t("llm.on"):t("llm.off"); st.style.color=enabled?"var(--ok)":"var(--faint)"; }
}
async function toggleLLM(){
  const cur=!document.body.classList.contains("llm-off");   // authoritative current state
  try{
    const d=await fetch("/api/llm/toggle",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({enabled:!cur})}).then(r=>r.json());
    document.body.classList.toggle("llm-off",!d.enabled);    // apply immediately (don't wait for refresh)
    renderLLMToggle(!!d.enabled);refresh();
  }catch(e){}
}
function renderStatus(st){
  const fr=a=>a==null?"—":(a<60?a+"с":Math.floor(a/60)+"м");
  renderLLMToggle(st.llm_enabled!==false);
  document.body.classList.toggle("llm-off", st.llm_enabled===false);
  const llmChip=st.llm_enabled===false?"":chip("LLM (Gemma)",st.llm_up===null?null:st.llm_up);
  const lk=st.loki;
  let lokiOk=st.loki_up, lokiDetail;
  if(lk){
    lokiOk = !!(lk.reachable && lk.ready && lk.query_ok);
    lokiDetail = !lk.reachable ? "недоступен"
               : !lk.ready ? "не готов"
               : !lk.query_ok ? "запрос не прошёл"
               : "ready"+(lk.ms!=null?" · "+lk.ms+" мс":"");
  }
  document.getElementById("health").innerHTML=
    chip("Loki",lokiOk,lokiDetail)+llmChip+
    chip("Данные",st.poll_age!=null&&st.poll_age<90,"обновлены "+fr(st.poll_age)+" назад")+
    (st.llm_enabled===false?"":chip("AI-разбор",st.insight_age!=null&&st.insight_age<1500,fr(st.insight_age)+" назад"))+
    (st.path403?chip("Правила 403",!!st.path403.rendered_ok,st.path403.enabled_count+" акт.· рендер "+(st.path403.rendered_ok?"OK":"дрейф!")):"");
  const b=document.getElementById("banner");
  if(st.problems&&st.problems.length){b.className="mb-4 card border-red-500/40 bg-red-500/5 p-4";
    b.innerHTML=`<div class="flex items-start gap-3"><span class="text-red-400 text-lg leading-none">⚠</span><div><div class="text-sm font-semibold text-red-300 mb-1">Проблемы в обработке (${st.problems.length})</div><ul class="text-sm text-slate-300 space-y-0.5">${st.problems.map(p=>`<li><span class="text-red-400 font-medium">${esc(p.component)}:</span> ${esc(p.msg)}</li>`).join("")}</ul></div></div>`;b.classList.remove("hidden");}
  else b.classList.add("hidden");
}

async function refresh(){
  try{
    const [sum,st]=await Promise.all([
      fetch(_withEnv("/api/summary")).then(r=>r.json()),fetch("/api/status").then(r=>r.json())]);
    // история (графики) + инсайты — раз в 60с или при смене окна (данные меняются раз в 30с)
    let histFresh=false;
    if(WIN!==lastHistKey || Date.now()-lastHistAt>60000){
      try{const [h,i]=await Promise.all([
        fetch("/api/history?limit="+(WIN_HIST[WIN]||120)).then(r=>r.json()),
        fetch("/api/insights?limit=100").then(r=>r.json())]);
        lastHist=h;lastIns=i;lastHistKey=WIN;lastHistAt=Date.now();histFresh=true;}catch(e){}
    }
    const hist=lastHist, ins=lastIns;
    // analytics — тяжёлое; тянем только при смене окна/домена или раз в 45с
    const anKey=WIN+"|"+HOST;
    if(anKey!==lastAnKey || Date.now()-lastAnAt>45000){
      const aq=(WIN!=="5m"||HOST)?`?window=${WIN}&host=${encodeURIComponent(HOST)}`:"";
      try{lastAn=await fetch(_withEnv("/api/analytics"+aq)).then(r=>r.json());lastAnKey=anKey;lastAnAt=Date.now();}catch(e){}
    }
    const an=lastAn;
    renderStatus(st);
    const s=sum.summary;
    const dot=document.getElementById("live-dot"),txt=document.getElementById("live-text");
    if(sum.loki_up){dot.className="w-2 h-2 rounded-full bg-emerald-400 pulse";txt.textContent="онлайн";txt.className="text-emerald-400";}
    else{dot.className="w-2 h-2 rounded-full bg-red-500";txt.textContent="нет связи с Loki";txt.className="text-red-400";}
    document.getElementById("updated").textContent=ago(sum.updated)+" назад";
    const cur=ins.current,sev=SEV[(cur&&cur.severity)||"ok"]||SEV.ok;
    const badge=document.getElementById("status-badge");badge.className=`px-3 py-1.5 rounded-lg text-xs font-semibold border ${sev.cls}`;badge.textContent=sev.label.toUpperCase();
    if(s){s.unique_visitors=(an.analytics||{}).unique_visitors;
      const tot=(s.status_2xx||0)+(s.status_3xx||0)+(s.status_4xx||0)+(s.status_5xx||0);
      s.availability=tot?((s.status_2xx||0)+(s.status_3xx||0))/tot:null;}
    renderStatusPct(s);
    renderStats(s);
    const sn=hist.snapshots||[];
    if(sn.length && histFresh){
      setChart(charts.traffic,sn,[x=>x.requests_total,x=>x.requests_real,x=>x.blocked_denylisted]);
      setChart(charts.threats,sn,[x=>x.forbidden_new,x=>x.crs_detections,x=>x.status_404]);
      setChart(charts.status,sn,[x=>x.status_2xx,x=>x.status_3xx,x=>x.status_4xx,x=>x.status_5xx]);
      setChart(charts.latency,sn,[x=>x.latency_p95]);
    }
    if(histFresh){renderInsightCurrent(cur);renderHistory(ins.history);}
    const a=an.analytics||{};
    bars("top_paths",a.top_paths,"text-amber-300","path");
    bars("top_user_agents",a.top_user_agents,"text-indigo-300","ua");
    bars("attack_types",a.attack_types,"text-red-300");
    bars("geo",(a.geo||[]).map(x=>({...x,display:countryLabel(x.key),sub:x.blocked})),"text-indigo-300","country");
    renderMap(a.geo||[]);
    bars("top_domains",a.top_domains,"text-indigo-300","host");
    bars("subnets",(s&&s.top_subnets||[]).map(x=>({...x,display:(x.new?"🆕 ":"")+x.subnet})),"text-amber-300","subnet");
    bars("waf_fp",a.waf_fp,"text-amber-300","path");
    const ew=(a.eff_windows||{});
    const degraded=Object.values(ew).filter(v=>v&&v!==WIN);
    document.getElementById("winnote").textContent=degraded.length?`(топы за ${degraded[0]} — больше окно упирается в лимит Loki)`:"";
    bars("crs_rules",a.crs_rules,"text-red-300","crs");
    bars("methods",a.methods,"text-indigo-300");
    bars("referers",a.referers,"text-amber-300","ref");
    bars("tls",a.tls,"text-indigo-300");
    bars("talkers",(a.top_talkers||[]).map(x=>({key:x.ip,count:x.count})),"text-indigo-300","ip");
    bars("slow_endpoints",a.slow_endpoints,"text-amber-300","path");
    bars("bytes_by_domain",a.bytes_by_domain,"text-indigo-300","host");
    notifyCritical(cur);
  }catch(e){
    console.error(e);const b=document.getElementById("banner");b.className="mb-4 card border-red-500/40 bg-red-500/5 p-4";
    b.innerHTML=`<div class="flex items-center gap-3"><span class="text-red-400 text-lg">⚠</span><div class="text-sm text-red-300">Дашборд не получает данные от backend (${esc(e.message||String(e))}).</div></div>`;b.classList.remove("hidden");
  }
}

async function loadDigest(){
  try{const d=await fetch("/api/digest").then(r=>r.json());renderDigest(d);}
  catch(e){document.getElementById("digest").innerHTML='<div class="text-slate-500 text-sm">дайджест недоступен</div>';}
}
function renderDigest(d){
  const el=document.getElementById("digest");
  const dg=(d.digest&&typeof d.digest==="object")?d.digest:{overview:(d.digest||"—"),attacks:[],recommendations:[]};
  const s=d.stats||{};
  const chip=(l,v)=>`<div class="px-2.5 py-1 rounded-md bg-slate-800/60 border border-slate-700/50"><div class="text-[10px] text-slate-500">${l}</div><div class="mono text-slate-200 text-sm">${v}</div></div>`;
  const mm=o=>o?`${fmt(o.avg)} <span class="text-slate-600">/ ${fmt(o.max)}</span>`:"—";
  let html="";
  if(s.requests_total||s.status_4xx) html+=`<div class="flex flex-wrap gap-2 mb-3">
    ${chip("Запросы avg/max",mm(s.requests_total))}${chip("4xx",mm(s.status_4xx))}${chip("404",mm(s.status_404))}${chip("5xx",mm(s.status_5xx))}${chip("Атакующих IP",mm(s.distinct_attacker_ips))}</div>`;
  if(dg.overview) html+=`<p class="text-sm text-slate-300 leading-relaxed mb-3">${esc(dg.overview)}</p>`;
  if(dg.attacks&&dg.attacks.length) html+=`<div class="mb-3"><div class="text-[11px] uppercase tracking-wide text-amber-400/80 mb-1">⚠ Замечено</div><ul class="space-y-1">${dg.attacks.map(a=>`<li class="flex gap-2 text-sm text-slate-300"><span class="text-amber-400 shrink-0">•</span>${esc(a)}</li>`).join("")}</ul></div>`;
  if(dg.recommendations&&dg.recommendations.length) html+=`<div><div class="text-[11px] uppercase tracking-wide text-emerald-400/80 mb-1">✅ Рекомендации</div><ul class="space-y-1">${dg.recommendations.map(a=>`<li class="flex gap-2 text-sm text-slate-300"><span class="text-emerald-400 shrink-0">→</span>${esc(a)}</li>`).join("")}</ul></div>`;
  el.innerHTML=html||'<div class="text-slate-500 text-sm">—</div>';
}
document.getElementById("suggest-btn").onclick=async()=>{
  const el=document.getElementById("suggest");el.textContent="генерирую… (LLM ~30с)";
  try{const r=await fetch("/api/suggest").then(r=>r.json());
    el.innerHTML=`${r.rationale?`<p class="text-slate-300 mb-2">${esc(r.rationale)}</p>`:""}
      ${(r.deny&&r.deny.length)?`<div class="mb-2"><div class="text-[11px] text-slate-500">deny</div>${r.deny.map(x=>`<code class="block mono text-xs text-amber-300">${esc(x)}</code>`).join("")}</div>`:""}
      ${(r.waf&&r.waf.length)?`<div><div class="text-[11px] text-slate-500">WAF</div>${r.waf.map(x=>`<code class="block mono text-xs text-emerald-300 whitespace-pre-wrap">${esc(x)}</code>`).join("")}</div>`:""}
      ${(!r.deny?.length&&!r.waf?.length)?'<span class="text-slate-500">Конкретных правил не предложено.</span>':""}`;
  }catch(e){el.textContent="ошибка генерации";}
};

charts.traffic=mkChart("chartTraffic",[ds("всего","var(--accent)"),ds("реальный","#38bdf8"),ds("denylist","var(--faint)")]);
charts.threats=mkChart("chartThreats",[ds("новые блоки","var(--warn)"),ds("CRS","var(--crit)"),ds("404","var(--accent2)")]);
charts.status=mkChart("chartStatus",[ds("2xx","var(--ok)",1),ds("3xx","#38bdf8",1),ds("4xx","var(--warn)",1),ds("5xx","var(--crit)",1)],true);
charts.latency=mkChart("chartLatency",[ds("p95","var(--accent2)",1)]);
let paused=false;
function togglePause(){paused=!paused;const b=document.getElementById("pause-btn");b.textContent=paused?"▶":"⏸";b.title=paused?"возобновить":"пауза авто-обновления";if(!paused)refresh();}
function setupCollapse(){
  document.querySelectorAll('h2.sec').forEach(h=>{
    const sec=h.nextElementSibling; if(!sec||sec.tagName!=='SECTION')return;
    const key='collapse:'+h.textContent.trim().slice(0,40);
    h.style.cursor='pointer'; h.title='свернуть/развернуть';
    const ind=document.createElement('span'); ind.className='text-slate-600 mr-1'; h.prepend(ind);
    const apply=c=>{sec.style.display=c?'none':'';ind.textContent=c?'▸ ':'▾ ';};
    let c=localStorage.getItem(key)==='1'; apply(c);
    h.addEventListener('click',()=>{c=!c;localStorage.setItem(key,c?'1':'0');apply(c);});
  });
}
setupCollapse();

// ===== Автобан (UI + dry-run; механизм исполнения пока не подключён) =====
let _abLoaded=false, _abWindows=["1m","5m","10m","1h","8h"], _abFamilies=[], _abArmed=false, _abEditId=null;
let _abInterval=60, _abMaxTick=20, _abLastRun=null, _abRules=null, _abIgnore=[];
let _abLogRows=[], _abLogPage=0; const _AB_LOG_PER=10;
let _view="dash";
const _VIEWS=["dash","autoban","p403","targets","dashboards","journal","logs","settings"];
function showView(name){
  if(!_VIEWS.includes(name))name="dash";
  if(name!=="logs")clearTimeout(_lgTimer);   // C3: stop the tail poll when leaving Logs
  _view=name;
  _VIEWS.forEach(v=>{
    document.getElementById("view-"+v).classList.toggle("hidden",v!==name);
    document.getElementById("navtab-"+v).classList.toggle("active",v===name);
  });
  location.hash=name==="dash"?"":("#"+name);
  const tEl=document.getElementById("view-title");
  if(tEl)tEl.textContent=name==="dash"?t("title"):t("nav."+name);
  const sb=document.getElementById("sidebar"); if(sb)sb.classList.remove("open");
  if(name==="autoban")loadAutoban();
  if(name==="p403")loadP403();
  if(name==="targets")loadTargets();
  if(name==="settings")loadSettings();
  if(name==="dashboards")loadDashboards();
  if(name==="journal")loadJournal();
  if(name==="logs")loadLogs();
}

// ── Журнал действий (audit blocklist-api + исход применения) ───────────────────
let _journal=[], _jrTimer=null;
const _JR_ACT={block:{i:"🚫",t:"бан"},unblock:{i:"✅",t:"разбан"},expire:{i:"⏱",t:"истёк TTL"},
  path_rule:{i:"🛂",t:"правило 403"},path_rule_del:{i:"🗑",t:"удалено правило 403"},
  path_master:{i:"🔁",t:"переключатель 403"}};
const _JR_BY={dashboard:"оператор",autoban:"автобан",ttl:"система"};
async function loadJournal(){
  try{
    const d=await (await fetch("/api/blocklist_audit?limit=300")).json();
    if(d.enabled===false){ document.getElementById("jr-list").innerHTML=`<div class="text-slate-500 text-xs">blocklist-api не настроен.</div>`; _journal=[]; return; }
    _journal=d.audit||[];
    renderJournal();
  }catch(e){ document.getElementById("jr-list").innerHTML=`<div class="text-red-400 text-xs">ошибка: ${esc(e.message)}</div>`; }
  if(_view==="journal"){ clearTimeout(_jrTimer); _jrTimer=setTimeout(loadJournal,15000); }
}
function _jrOutcome(a){
  const r=a.result;
  if(!r) return `<span class="text-slate-600">— нет данных о применении</span>`;
  if(r.ok){
    const n=(r.targets||[]).length;
    return `<span class="text-emerald-400">✓ применено${n?` · ${n} таргет(ов)`:""}</span>`;
  }
  const f=r.failed||{};
  const parts=Object.keys(f).map(t=>`${esc(t)}: ${esc(f[t])}`).join("; ");
  return `<span class="text-red-400" title="${esc(parts)}">⚠ ошибка → ${esc(parts).slice(0,120)}</span>`;
}
function renderJournal(){
  const el=document.getElementById("jr-list");
  const f=document.getElementById("jr-filter").value;
  let rows=_journal.filter(a=>{
    if(!f) return true;
    if(f==="fail") return a.result && !a.result.ok;
    if(f==="path") return (a.action||"").startsWith("path");
    return a.action===f;
  });
  if(!rows.length){ el.innerHTML=`<div class="text-slate-500 text-xs">нет записей под фильтр.</div>`; return; }
  el.innerHTML=rows.map(a=>{
    const m=_JR_ACT[a.action]||{i:"•",t:a.action};
    const by=_JR_BY[a.by]||esc(a.by||"");
    const bad=a.result&&!a.result.ok;
    return `<div class="flex items-start gap-2 py-1.5 px-2 rounded ${bad?'bg-red-500/5 border border-red-500/20':'hover:bg-slate-800/40'} text-[12px]">
      <span class="mono text-slate-500 w-32 shrink-0">${dt(a.ts)}</span>
      <span class="shrink-0 w-36"><span class="mr-1">${m.i}</span><span class="text-slate-300">${esc(m.t)}</span></span>
      <span class="mono text-slate-200 shrink-0 w-40 truncate" title="${esc(a.cidr||'')}">${esc(a.cidr||"")}</span>
      <span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 shrink-0">${by}</span>
      <span class="flex-1 min-w-0">${_jrOutcome(a)}${a.note?`<span class="text-slate-500"> · ${esc(a.note)}</span>`:""}</span>
    </div>`;
  }).join("");
}

// ── Настройки: суб-вкладки (Окружения / Уведомления / Глобальные) ─────────────
let _sub="notify";
function setSub(name){
  _sub=name;
  [["notify","ssec-notify"],["autoban","ssec-autoban"],["global","ssec-global"],["account","ssec-account"],["users","ssec-users"]].forEach(([n,sec])=>{
    const s=document.getElementById(sec); if(s)s.classList.toggle("hidden",n!==name);
    const b=document.getElementById("ssub-"+n); if(b)b.className="setnav-btn"+(n===name?" on":"")+(b.classList.contains("hidden")?" hidden":"");
  });
  if(name==="notify")loadNotify(); if(name==="global")loadGlobal();
  if(name==="autoban"){ loadEscalation(); loadThreatFeeds(); loadProtectedPaths(); }
  if(name==="account")loadAccount(); if(name==="users")loadUsers();
}
async function loadProtectedPaths(){
  try{ const d=await fetch("/api/autoban/rules").then(r=>r.json());
    _abIgnore=Array.isArray(d.ignore_paths)?d.ignore_paths:[]; renderAbIgnore();
  }catch(e){}
}

// ── auth: login gate, session, account, user management ─────────────────────────
let _me=null;
async function authInit(){
  try{
    const r=await fetch("/api/auth/me");
    if(r.status===200){ _me=await r.json(); authApply(); return true; }
    const d=await r.json().catch(()=>({}));
    showLogin(r.status===503&&d.setup);
    return false;
  }catch(e){ showLogin(false); return false; }
}
function showLogin(setup){
  document.getElementById("login-overlay").style.display="flex";
  document.getElementById("login-setup").classList.toggle("hidden",!setup);
  const u=document.getElementById("login-user"); if(u)setTimeout(()=>u.focus(),50);
}
function authApply(){
  document.getElementById("login-overlay").style.display="none";
  const tb=document.getElementById("topban"); if(tb)tb.classList.toggle("hidden",_me.role!=="admin");
  const chip=document.getElementById("user-chip"); chip.classList.remove("hidden"); chip.classList.add("flex");
  document.getElementById("user-name").textContent=_me.username;
  const rb=document.getElementById("user-role"); if(_me.role&&_me.role!==_me.username){rb.textContent=_me.role;rb.style.display="";}else{rb.style.display="none";}
  rb.style.background=_me.role==="admin"?"#5794f222":"#33415522"; rb.style.color=_me.role==="admin"?"#84aef0":"#94a3b8";
  const admin=_me.role==="admin";
  document.getElementById("ssub-users").classList.toggle("hidden",!admin);
  document.body.classList.toggle("role-viewer",!admin);
}
async function authLogin(){
  const msg=document.getElementById("login-msg"); msg.textContent="";
  const body={username:document.getElementById("login-user").value.trim(),
    password:document.getElementById("login-pass").value,
    totp:document.getElementById("login-totp").value.trim()};
  try{
    const r=await fetch("/api/auth/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    const d=await r.json();
    if(d.totp_required){ document.getElementById("login-totp-wrap").classList.remove("hidden");
      document.getElementById("login-totp").focus(); msg.style.color="#f0d089"; msg.textContent=_trText("нужен код 2FA"); return; }
    if(!d.ok){ msg.style.color="#f0a2a2"; msg.textContent=_trText(d.error||"вход не удался"); return; }
    location.reload();
  }catch(e){ msg.textContent="✗ "+e.message; }
}
async function authLogout(){ try{ await _post("/api/auth/logout",{}); }catch(e){} location.reload(); }

async function loadAccount(){
  try{ const d=await fetch("/api/auth/me").then(r=>r.json()); _me=d;
    document.getElementById("acc-who").textContent=d.username+(d.role&&d.role!==d.username?" · "+d.role:"");
    document.getElementById("acc-2fa-state").textContent=d.totp?"✓ enabled":"disabled";
    document.getElementById("acc-2fa-setup").classList.toggle("hidden",!!d.totp);
    document.getElementById("acc-2fa-off").classList.toggle("hidden",!d.totp);
    document.getElementById("acc-2fa-body").classList.add("hidden");
  }catch(e){}
}
async function accChangePw(){
  const msg=document.getElementById("acc-pw-msg"); msg.textContent="…";
  const r=await _post("/api/auth/password",{current:document.getElementById("acc-pw-cur").value,new:document.getElementById("acc-pw-new").value});
  if(r&&r.ok){ msg.style.color="#6fcf97"; msg.textContent="✓"; document.getElementById("acc-pw-cur").value=""; document.getElementById("acc-pw-new").value=""; }
  else { msg.style.color="#f0a2a2"; msg.textContent=_trText((r&&r.error)||"не удалось"); }
}
async function totpSetup(){
  const r=await _post("/api/auth/totp/setup",{}); if(!r||!r.secret)return;
  document.getElementById("acc-2fa-body").classList.remove("hidden");
  document.getElementById("acc-2fa-secret").innerHTML=`${esc(r.secret)}<br><span style="color:var(--faint)">${esc(r.uri)}</span>`;
}
async function totpEnable(){
  const msg=document.getElementById("acc-2fa-msg");
  const r=await _post("/api/auth/totp/enable",{code:document.getElementById("acc-2fa-code").value.trim()});
  if(r&&r.ok){ loadAccount(); } else { msg.style.color="#f0a2a2"; msg.textContent=_trText((r&&r.error)||"код не совпал"); }
}
async function totpDisable(){
  const pw=await uiPrompt(_trText("пароль для отключения 2FA:")); if(!pw)return;
  const r=await _post("/api/auth/totp/disable",{password:pw});
  if(r&&r.ok)loadAccount(); else uiAlert(_trText((r&&r.error)||"не удалось"));
}

function usrAddToggle(){ document.getElementById("usr-add").classList.toggle("hidden"); }
async function loadUsers(){
  const el=document.getElementById("usr-list"); if(!el)return;
  try{ const d=await fetch("/api/users").then(r=>r.json()); const me=(_me||{}).username;
    el.innerHTML=(d.users||[]).map(u=>`<div class="flex items-center gap-2 flex-wrap bg-slate-900/40 border border-slate-800 rounded-lg px-3 py-2 text-[12px]">
      <span class="mono text-slate-100">${esc(u.username)}</span>
      ${u.totp?'<span class="text-[10px] px-1.5 py-0.5 rounded bg-emerald-900/40 text-emerald-300">🔐 2FA</span>':''}
      ${u.username===me?'<span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">you</span>':''}
      <select onchange="usrSetRole('${escJs(u.username)}',this.value)" class="input ml-auto" style="padding:2px 6px">
        <option value="viewer"${u.role==="viewer"?" selected":""}>viewer</option>
        <option value="admin"${u.role==="admin"?" selected":""}>admin</option></select>
      <button onclick="usrResetPw('${escJs(u.username)}')" class="btn btn-ghost btn-xs" data-i18n="usr.reset">reset pw</button>
      ${u.username===me?'':`<button onclick="usrDelete('${escJs(u.username)}')" class="btn btn-ghost btn-xs" style="color:#f0a2a2">🗑</button>`}
    </div>`).join("")||`<div class="text-slate-600 text-xs">${_trText("нет данных")}</div>`;
    applyI18n();
  }catch(e){ el.innerHTML='<div class="text-red-400 text-xs">'+_trText("ошибка")+'</div>'; }
}
async function usrCreate(){
  const msg=document.getElementById("usr-msg");
  const r=await _post("/api/users",{username:document.getElementById("usr-new-name").value.trim(),
    password:document.getElementById("usr-new-pass").value,role:document.getElementById("usr-new-role").value});
  if(r&&r.ok){ document.getElementById("usr-new-name").value=""; document.getElementById("usr-new-pass").value="";
    document.getElementById("usr-add").classList.add("hidden"); loadUsers(); }
  else { msg.style.color="#f0a2a2"; msg.textContent=_trText((r&&r.error)||"не удалось"); }
}
async function usrSetRole(u,role){ await _post("/api/users",{username:u,role}); }
async function usrResetPw(u){
  const pw=await uiPrompt(_trText("новый пароль для ")+u+" (min 8):"); if(!pw)return;
  const r=await _post("/api/users",{username:u,password:pw}); uiAlert(r&&r.ok?"✓":_trText((r&&r.error)||"не удалось"));
}
async function usrDelete(u){
  if(!await uiConfirm(_trText("удалить пользователя ")+u+"?"))return;
  const r=await _post("/api/users/delete",{username:u}); if(r&&r.ok)loadUsers(); else uiAlert(_trText((r&&r.error)||"не удалось"));
}
// ── Targets: подвкладки (nginx-ноды / Cloudflare / группы) ─────────────────────
let _tsub="nginx";
function setTsub(name){
  _tsub=name;
  [["nginx","tsec-nginx"],["cf","tsec-cf"],["ingress","tsec-ingress"],["groups","tsec-groups"],["system","tsec-system"]].forEach(([n,sec])=>{
    document.getElementById(sec).classList.toggle("hidden",n!==name);
    document.getElementById("tsub-"+n).className="setnav-btn"+(n===name?" on":"");
  });
  if(name==="nginx")loadNodes(); if(name==="cf")loadCfTargets(); if(name==="ingress")loadIngress();
  if(name==="groups")loadGroups(); if(name==="system")loadSystem();
}
// Ingress = each registered ingress backend is its own manageable entity (name /
// edit / delete / activate). Under each we nest its ingress-cm targets (tagged by
// backend on /api/ban_targets). The implicit HOME backend is NOT shown here — it
// lives in the System section as the "worker".
let _ingEdit=null;   // id of the entity currently being edited inline
const _ING_SVG='<svg viewBox="0 0 24 24" width="15" height="15" class="shrink-0"><path fill="#326CE5" d="M12 2 3.6 6v8L12 22l8.4-8V6L12 2z"/><circle cx="12" cy="12" r="3.1" fill="#fff"/></svg>';
async function loadIngress(){
  const el=document.getElementById("ingress-list");if(!el)return;
  try{
    const [reg,tg]=await Promise.all([
      fetch("/api/ingress_apis").then(r=>r.json()),
      fetch("/api/ban_targets").then(r=>r.json()).catch(()=>({targets:[]}))
    ]);
    const items=(reg.items||[]);
    const targets=(tg.targets||[]);
    if(!items.length){
      el.innerHTML=`<div class="text-slate-500 text-xs">${_trText("нет подключённых ingress — нажми «Setup cluster», чтобы добавить")}</div>`;
      return;
    }
    el.innerHTML=items.map(b=>{
      const nm=b.name||b.id;
      const editing=_ingEdit===b.id;
      const head=`<div class="flex items-center gap-2 flex-wrap">
        ${_ING_SVG}
        <span class="text-sm font-semibold text-slate-100 truncate">${esc(nm)}</span>
        ${b.token_set?`<span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 shrink-0">🔑</span>`:""}
        <span class="mono text-[10px] text-slate-500 truncate">${esc(b.url)}</span>
        <span class="ml-auto flex items-center gap-2 shrink-0">
          <button onclick="ingEntityEdit('${escJs(b.id)}')" class="text-[11px] text-slate-300 hover:text-slate-100">${_trText('править')}</button>
          <button onclick="ingBackendDelete('${escJs(b.id)}')" class="text-[11px] text-rose-400/80 hover:text-rose-300">${_trText('удалить')}</button>
        </span>
      </div>`;
      const editForm=editing?`<div class="mt-2 grid sm:grid-cols-3 gap-2 text-[11px]" style="color:var(--muted)">
        <label class="block"><span>${_trText("имя")}</span><input id="inge-name-${escAttr(b.id)}" value="${escAttr(b.name||"")}" placeholder="${escAttr(b.id)}" class="input mono mt-1"></label>
        <label class="block"><span>URL</span><input id="inge-url-${escAttr(b.id)}" value="${escAttr(b.url||"")}" class="input mono mt-1"></label>
        <label class="block"><span>Token</span><input id="inge-token-${escAttr(b.id)}" placeholder="${_trText("оставь пустым — не менять")}" class="input mono mt-1"></label>
        <div class="sm:col-span-3 flex gap-2">
          <button onclick="ingEntitySave('${escJs(b.id)}')" class="text-[11px] px-3 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white">${_trText('сохранить')}</button>
          <button onclick="ingEntityEdit(null)" class="text-[11px] px-3 py-1 rounded bg-slate-700 hover:bg-slate-600 text-slate-200">${_trText('отмена')}</button>
        </div>
      </div>`:"";
      return `<div class="bg-slate-950/50 border border-slate-800 rounded-lg p-3">${head}${editForm}</div>`;
    }).join("");
  }catch(e){ el.innerHTML=`<div class="text-red-400 text-xs">ошибка: ${esc(e.message)}</div>`; }
}
function ingEntityEdit(id){ _ingEdit=id; loadIngress(); }
async function ingEntitySave(id){
  const name=(document.getElementById("inge-name-"+id)||{}).value||"";
  const url=((document.getElementById("inge-url-"+id)||{}).value||"").trim();
  const token=((document.getElementById("inge-token-"+id)||{}).value||"").trim();
  const body={id,url,name};        // keep the same id so the URL edit updates in place
  if(token)body.token=token;       // blank = keep existing secret
  try{
    const r=await fetch("/api/ingress_apis",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)}).then(x=>x.json());
    if(!r.ok){ uiAlert(_trText("не удалось: ")+(r.error||"")); return; }
    _ingEdit=null; loadIngress();
  }catch(e){ uiAlert("не удалось: "+(e.message||e)); }
}
// ── Ingress: «Подключить кластер» (генератор helm-команды + promtail + values) ──
// "Setup cluster" always starts a FRESH new-cluster form — it registers a NEW
// ingress, not an editor for an existing one (existing backends are managed in the
// list below via activate/delete). Closing just hides the panel.
function ingSetupToggle(){ const b=document.getElementById("ing-setup"); const opening=b.classList.contains("hidden"); b.classList.toggle("hidden"); if(opening){ _ingFormReset(); ingGenToken(); bcReset(); } }
// default values for a clean new-cluster form
const _ING_DEFAULTS={"ing-ns":"soc","ing-host":"block-api.example.com","ing-cns":"ingress-nginx","ing-ccm":"ingress-nginx-controller","ing-ip":"","ing-token":"","ing-loki":""};
function _ingFormReset(){ Object.entries(_ING_DEFAULTS).forEach(([id,v])=>{const e=document.getElementById(id); if(e)e.value=v;}); ingCmd(); }
// persist within a session so an accidental reload mid-setup doesn't wipe the token
// you already helm-installed (a fresh random one would 401 on Test).
const _ING_FORM=["ing-ns","ing-host","ing-cns","ing-ccm","ing-ip","ing-token","ing-loki"];
function _ingPersist(){ try{ const f={}; _ING_FORM.forEach(id=>{const e=document.getElementById(id); if(e)f[id]=e.value;}); localStorage.setItem("soc_ing_form",JSON.stringify(f)); }catch(e){} }
function _bcUrl(){ const h=_ingVal("ing-host",""); return h?(h.startsWith("http")?h.replace(/\/$/,""):"https://"+h.replace(/\/$/,"")):""; }
function bcReset(){
  document.getElementById("bc-result").textContent="";
  document.getElementById("bc-save-btn").classList.add("hidden");
  document.getElementById("bc-msg").textContent="";
}
// «Проверить соединение» — бьёт по хосту из поля «block-api hostname» (тому же,
// что в сгенерированной helm-команде) + токену рядом, до того как что-то сохранено.
async function bcTest(){
  const url=_bcUrl(), tok=_ingVal("ing-token",""), res=document.getElementById("bc-result");
  if(!url){ res.textContent="✗ "+_trText("укажи hostname выше"); res.className="text-[11px] text-rose-400"; return; }
  res.textContent="… "+_trText("проверяю"); res.className="text-[11px] text-slate-400";
  document.getElementById("bc-save-btn").classList.add("hidden");
  try{
    const r=await fetch("/api/ingress_apis/test",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url,token:tok})}).then(x=>x.json());
    if(r.ok){ res.textContent="✓ "+_trText("доступен, токен принят"); res.className="text-[11px] text-emerald-400"; document.getElementById("bc-save-btn").classList.remove("hidden"); }
    else{ res.textContent="✗ "+(r.error||(!r.reachable?_trText("нет связи"):_trText("токен не принят"))); res.className="text-[11px] text-rose-400"; }
  }catch(e){ res.textContent="✗ "+(e.message||e); res.className="text-[11px] text-rose-400"; }
}
// сохраняет проверенное подключение в реестр и сразу делает его активным
async function bcSave(){
  const msg=document.getElementById("bc-msg"), url=_bcUrl(), tok=_ingVal("ing-token","");
  msg.textContent=_trText("сохраняю…"); msg.className="text-[11px] mt-1.5 text-slate-400";
  try{
    const save=await fetch("/api/ingress_apis",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url,token:tok})}).then(x=>x.json());
    if(!save.ok){ msg.textContent="✗ "+(save.error||_trText("ошибка")); msg.className="text-[11px] mt-1.5 text-rose-400"; return; }
    msg.textContent="✓ "+_trText("добавлено"); msg.className="text-[11px] mt-1.5 text-emerald-400";
    loadIngress();   // the new ingress + its targets now appear as an entity above
  }catch(e){ msg.textContent="✗ "+(e.message||e); msg.className="text-[11px] mt-1.5 text-rose-400"; }
}
async function ingBackendDelete(id){
  if(!await uiConfirm(_trText("Удалить этот ingress?")))return;
  try{
    await fetch("/api/ingress_apis/delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id})});
    loadIngress();
  }
  catch(e){ uiAlert("не удалось: "+(e.message||e)); }
}
function ingGenToken(){ const t=Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b=>b.toString(16).padStart(2,"0")).join(""); document.getElementById("ing-token").value=t; ingCmd(); }
// note: ingCmd() runs on every field edit and persists the form (token included).
function _ingVal(id,dflt){ const el=document.getElementById(id); return ((el&&el.value)||dflt||"").trim(); }
function ingCmd(){
  const ns=_ingVal("ing-ns","soc"), host=_ingVal("ing-host","block-api.example.com"),
        cns=_ingVal("ing-cns","ingress-nginx"), ccm=_ingVal("ing-ccm","ingress-nginx-controller"),
        ip=_ingVal("ing-ip",""), tok=_ingVal("ing-token","<token>"), loki=_ingVal("ing-loki","");
  _ingPersist();
  const wl=ip?`${ip}/32`:"";
  // helm-команда — реальные ключи чарта blocklist-api
  const cmd=[`helm upgrade --install blocklist-api ./blocklist-api \\`,
    `  -n ${ns} --create-namespace \\`,
    `  --set token=${tok} \\`,
    `  --set controllerNamespace=${cns} \\`,
    `  --set controllerConfigMap=${ccm} \\`,
    `  --set ingress.host=${host}${wl?` \\`:""}`,
    wl?`  --set ingress.whitelistSourceRange=${wl}`:""].filter(Boolean).join("\n");
  const cEl=document.getElementById("ing-cmd"); if(cEl)cEl.textContent=cmd;
  // promtail — values для отправки логов ingress-nginx в Loki дашборда
  const pEl=document.getElementById("ing-promtail");
  if(pEl)pEl.textContent=
`# promtail → Loki дашборда
helm upgrade --install promtail grafana/promtail -n ${ns} \\
  --set "config.clients[0].url=${loki||"http://<loki-дашборда>:3100"}/loki/api/v1/push" \\
  --set "config.snippets.addScrapeJobLabel=true"
# (собирает поды ${cns}; в Loki прилетят как job=ingress-nginx)`;
  // values: где указывается таргет
  const vEl=document.getElementById("ing-values");
  if(vEl)vEl.textContent=
`# blocklist-api/values.yaml — таргет ingress = ns + CM контроллера
controllerNamespace: ${cns}
controllerConfigMap: ${ccm}

ingress:
  enabled: true
  host: ${host}${wl?`\n  whitelistSourceRange: "${wl}"`:""}`;
}
// Clipboard API only exists in a secure context (HTTPS/localhost). This dashboard
// is usually served over plain HTTP on an internal IP, where navigator.clipboard is
// undefined — so fall back to a hidden-textarea execCommand copy, and flash the btn.
function _copyFallback(text){
  try{ const ta=document.createElement("textarea"); ta.value=text; ta.style.position="fixed"; ta.style.top="-1000px"; ta.style.opacity="0";
    document.body.appendChild(ta); ta.focus(); ta.select(); const ok=document.execCommand("copy"); document.body.removeChild(ta); return ok; }
  catch(e){ return false; }
}
function _copyFlash(btn,ok){ if(!btn)return; const o=btn.dataset._o||btn.textContent; btn.dataset._o=o; btn.textContent=ok?"✓":"⚠"; setTimeout(()=>{btn.textContent=o;},1200); }
function _copyText(text,btn){
  if(navigator.clipboard&&window.isSecureContext){
    navigator.clipboard.writeText(text).then(()=>_copyFlash(btn,true),()=>_copyFlash(btn,_copyFallback(text)));
  } else { _copyFlash(btn,_copyFallback(text)); }
}
function ingCopyCmd(id){ const t=document.getElementById(id); if(t)_copyText(t.textContent, typeof event!=="undefined"&&event&&event.currentTarget); }
function loadTargets(){ setTsub(_tsub); }
function loadSettings(){ setSub(_sub); }

// ── CF-таргеты (именованный реестр) ──
let _cfTargets=[];
const _cfOpen=new Set();
async function loadCfTargets(){
  const el=document.getElementById("cf-list");
  try{ const d=await (await fetch("/api/cf_targets")).json();
    if(d.enabled===false){ el.innerHTML='<div class="text-slate-500 text-xs">blocklist-api не настроен.</div>'; return; }
    _cfTargets=d.targets||[]; renderCfTargets();
  }catch(e){ el.innerHTML=`<div class="text-red-400 text-xs">ошибка: ${esc(e.message)}</div>`; }
}
function renderCfTargets(){
  const el=document.getElementById("cf-list");
  el.innerHTML=_cfTargets.map(cfCard).join("")||'<div class="text-xs" style="color:var(--faint);padding:12px 2px">No Cloudflare targets yet — click “New CF target”.</div>';
  if(typeof applyI18n==="function")applyI18n();
}
function cfCard(t){
  const id=esc(t.id), open=_cfOpen.has(t.id), migr=t.env?`<span class="chip" title="migrated from environment ${esc(t.env)}">env: ${esc(t.env)}</span>`:"";
  const chips=[t.token_set?`<span class="chip" style="color:var(--ok)">token set</span>`:`<span class="chip" style="opacity:.6">no token</span>`,
               `<span class="chip">${esc(t.mode||"ip-list")}</span>`, migr].filter(Boolean).join(" ");
  return `<div class="card p-3" data-cf="${id}">
    <div class="env-row" style="cursor:pointer" onclick="cfToggle('${id}')">
      <div class="flex items-center gap-2 min-w-0 flex-wrap">
        <span id="cfchev-${id}" style="color:var(--faint)">${open?'▾':'▸'}</span>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--muted)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="shrink-0"><path d="M17.5 19a4.5 4.5 0 0 0 0-9 6 6 0 0 0-11.6-1.5A4 4 0 0 0 6 19z"/></svg><span class="text-sm font-medium">${esc(t.name||t.id)}</span>
        <span class="mono text-[11px]" style="color:var(--faint)">${id}</span>${_beBadge(t.backend)}
        <span class="flex gap-1">${chips}</span>
      </div>
      <button onclick="event.stopPropagation();cfToggle('${id}')" class="btn btn-ghost btn-xs shrink-0"><span data-i18n="edit">Edit</span></button>
    </div>
    <div id="cfbody-${id}" class="${open?'':'hidden'} mt-3">
      <div class="grid sm:grid-cols-2 gap-3 text-[11px]" style="color:var(--muted)">
        <label class="block">Name<input data-f="name" value="${esc(t.name||'')}" class="input mt-1"></label>
        <label class="block">Mode<select data-f="mode" class="input mt-1"><option ${t.mode==='ip-list'?'selected':''}>ip-list</option><option ${t.mode==='access-rules'?'selected':''}>access-rules</option></select></label>
        <label class="block">API token <span style="color:var(--faint)">${t.token_set?'(set — enter to replace)':'(required)'}</span><input data-f="token" type="password" placeholder="${t.token_set?'•••• token set':'CF API token'}" class="input mono mt-1"></label>
        <label class="block">Zone ID <span style="color:var(--faint)">(or name below)</span><input data-f="zone_id" value="${esc(t.zone_id||'')}" class="input mono mt-1"></label>
        <label class="block">Zone name<input data-f="zone_name" value="${esc(t.zone_name||'')}" placeholder="example.com" class="input mono mt-1"></label>
        <label class="block">Account ID <span style="color:var(--faint)">(optional)</span><input data-f="account_id" value="${esc(t.account_id||'')}" class="input mono mt-1"></label>
        <label class="block">IP List name <span style="color:var(--faint)">(ip-list)</span><input data-f="list_name" value="${esc(t.list_name||'')}" placeholder="soc_blocklist" class="input mono mt-1"></label>
        <label class="block">Rule desc <span style="color:var(--faint)">(optional)</span><input data-f="rule_desc" value="${esc(t.rule_desc||'')}" class="input mono mt-1"></label>
      </div>
      <div id="cfcheck-${id}" class="text-[11px] mt-2"></div>
      <div class="env-row mt-3 pt-3" style="border-top:1px solid var(--border)">
        <button onclick="cfCheck('${id}')" class="btn btn-ghost btn-xs">Test connection</button>
        <div class="flex gap-1">
          <button onclick="cfSave('${id}')" class="btn btn-primary btn-xs" data-i18n="save">Save</button>
          <button onclick="cfDelete('${id}')" class="btn btn-danger btn-xs" data-i18n="delete">Delete</button></div>
      </div>
    </div>
  </div>`;
}
function cfToggle(id){
  // NB: getElementById принимает литеральный id, НЕ CSS-селектор — CSS.escape тут
  // ломает числовые id (напр. «4444» → «\34 444»), и элемент не находится.
  const open=_cfOpen.has(id); if(open)_cfOpen.delete(id); else _cfOpen.add(id);
  const body=document.getElementById("cfbody-"+id), chev=document.getElementById("cfchev-"+id);
  if(body)body.classList.toggle("hidden",open); if(chev)chev.textContent=open?"▸":"▾";
}
async function cfNew(){
  const id=await uiPrompt(_lang==="ru"?"ID CF-таргета (напр. nginx-aaa-cloudflare):":"CF target ID (e.g. nginx-aaa-cloudflare):");
  if(!id||!id.trim())return;
  const newId=id.toLowerCase().replace(/[^a-z0-9_.:-]+/g,'-');
  if(_cfTargets.some(t=>t.id===newId)){ _cfOpen.add(newId); renderCfTargets(); return; }
  _cfTargets.push({id:newId,name:id.trim(),mode:"ip-list",token_set:false}); _cfOpen.add(newId); renderCfTargets();
}
function _cfField(id,f){ const c=document.querySelector(`[data-cf="${id}"]`),el=c&&c.querySelector(`[data-f="${f}"]`); return el?el.value:undefined; }
function _cfBackend(id){ return ((_cfTargets||[]).find(t=>t.id===id)||{}).backend; }
async function cfSave(id){
  const body={id,backend:_cfBackend(id),name:_cfField(id,"name"),mode:_cfField(id,"mode"),token:_cfField(id,"token"),
    zone_id:_cfField(id,"zone_id"),zone_name:_cfField(id,"zone_name"),account_id:_cfField(id,"account_id"),
    list_name:_cfField(id,"list_name"),rule_desc:_cfField(id,"rule_desc")};
  const d=await (await fetch("/api/cf_targets",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})).json();
  if(d.ok){ _cfOpen.add(d.id||id); loadCfTargets(); }
  else uiAlert("не сохранилось: "+(d.error||"ошибка"));
}
async function cfDelete(id){
  if(!await uiConfirm("Удалить CF-таргет «"+id+"»? Он отвяжется от групп/правил. Список/правило в самом Cloudflare не удаляются автоматически."))return;
  await fetch("/api/cf_targets/delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id,backend:_cfBackend(id)})});
  _cfOpen.delete(id); loadCfTargets();
}
async function cfCheck(id){
  const box=document.getElementById("cfcheck-"+CSS.escape(id)); if(!box)return;
  box.textContent="проверяю…"; box.className="text-[11px] mt-2 text-slate-400";
  try{
    const d=await (await fetch("/api/ban_targets/check?id="+encodeURIComponent(id))).json();
    const c=(d.checks||[]).find(x=>x.id===id)||(d.checks||[])[0];
    if(!c){ box.textContent="нет ответа."; return; }
    box.innerHTML=`<span class="${c.ok?'text-emerald-400':'text-amber-400'}">${c.ok?'✓':'⚠'} token ${c.token_valid?'ok':'нет'}, list ${c.list_id?'ok':'—'}, rule ${c.rule_id?'ok':'—'}${c.items!=null?(', items '+c.items):''}${c.error?(' — '+esc(c.error)):''}</span>`;
  }catch(e){ box.textContent="ошибка: "+e.message; box.className="text-[11px] mt-2 text-red-400"; }
}

// ── Уведомления ──
let _nf={channels:[],rules:[],events:[],severities:[]};
async function loadNotify(){
  try{ _nf=await (await fetch("/api/notify_config")).json(); }catch(e){ _nf={channels:[],rules:[]}; }
  if(_nf.enabled===false){ document.getElementById("nf-channels").innerHTML=_nfEmpty("🔌",_trText("blocklist-api не настроен.")); document.getElementById("nf-rules").innerHTML=""; return; }
  renderNotify();
}
function _nfEmpty(icon,txt){ return `<div class="rounded-lg border border-dashed border-slate-800 px-3 py-5 text-center text-[11px] text-slate-500"><div class="text-lg mb-1 opacity-70">${icon}</div>${esc(txt)}</div>`; }
function renderNotify(){
  document.getElementById("nf-channels").innerHTML=(_nf.channels||[]).map(nfChannelRow).join("")||_nfEmpty("📭",_trText("Пока нет каналов — добавь Slack или Telegram выше."));
  document.getElementById("nf-rules").innerHTML=(_nf.rules||[]).map(nfRuleRow).join("")||_nfEmpty("🧭",_trText("Пока нет правил — добавь правило, чтобы события попадали в канал."));
}
function nfChannelRow(c,i){
  const tg=c.type==="telegram";
  const accent=tg?"#229ED9":"#611f69";   // Telegram blue / Slack aubergine
  return `<div class="card p-2.5 flex flex-wrap items-center gap-2 text-[11px]" data-ch="${i}" style="border-left:3px solid ${accent}">
    <span class="px-2 py-0.5 rounded font-medium text-white shrink-0" style="background:${accent}">${tg?'Telegram':'Slack'}</span>
    <input data-cf="id" value="${esc(c.id||'')}" placeholder="id" class="w-24 mono bg-black/40 border border-slate-800 rounded px-2 py-1 text-slate-200">
    <input data-cf="label" value="${esc(c.label||'')}" placeholder="${_trText('метка')}" class="w-28 bg-black/40 border border-slate-800 rounded px-2 py-1 text-slate-200">
    ${tg?`<input data-cf="bot_token" type="password" placeholder="${c.configured?'•••• задан':'bot token'}" class="flex-1 min-w-[140px] max-w-sm mono bg-black/40 border border-slate-800 rounded px-2 py-1 text-slate-200"><input data-cf="chat_id" value="${esc(c.chat_id||'')}" placeholder="chat_id" class="w-28 mono bg-black/40 border border-slate-800 rounded px-2 py-1 text-slate-200">`:`<input data-cf="webhook" type="password" placeholder="${c.configured?'•••• задан':'Slack webhook URL'}" class="flex-1 min-w-[180px] max-w-md mono bg-black/40 border border-slate-800 rounded px-2 py-1 text-slate-200">`}
    <input type="hidden" data-cf="type" value="${tg?'telegram':'slack'}">
    <span class="flex items-center gap-1 shrink-0 ml-auto">
      ${c.last?`<span class="${c.last.ok?'text-emerald-400':'text-red-400'}" title="${esc((c.last&&c.last.error)||'')}">${c.last.ok?'✓':'✗'}</span>`:""}
      <button onclick="nfTest('${escJs(c.id||'')}')" class="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200">${_trText('тест')}</button>
      <button onclick="nfDelChannel(${i})" class="px-2 py-1 rounded text-red-400 hover:bg-red-500/10">✕</button>
    </span>
  </div>`;
}
function nfRuleRow(r,i){
  const evs=_nf.events||["ban","ban_failed","unban","node_offline","autoban","anomaly_critical","path_rule"];
  const sevs=_nf.severities||["info","notice","warning","critical"];
  const chOpts=(_nf.channels||[]).map(c=>`<option value="${esc(c.id)}" ${r.channel===c.id?'selected':''}>${esc(c.label||c.id)}</option>`).join("");
  const evChecks=evs.map(e=>`<label class="inline-flex items-center gap-1 mr-2"><input type="checkbox" data-ev="${e}" ${(r.events||[]).includes(e)?'checked':''}> ${e}</label>`).join("");
  return `<div class="card p-2 text-[11px]" data-rule="${i}">
    <div class="flex flex-wrap items-center gap-2 mb-1">
      <label class="inline-flex items-center gap-1"><input type="checkbox" data-rf="enabled" ${r.enabled!==false?'checked':''}> ${_trText('вкл')}</label>
      <span class="text-slate-500">env:</span><input data-rf="env" value="${esc(r.env||'')}" placeholder="${_trText('(любой)')}" class="w-20 mono bg-black/40 border border-slate-800 rounded px-2 py-1 text-slate-200">
      <span class="text-slate-500">${_trText('важность ≥')}</span><select data-rf="min_severity" class="bg-black/40 border border-slate-800 rounded px-1 py-1 text-slate-200">${sevs.map(s=>`<option ${r.min_severity===s?'selected':''}>${s}</option>`).join("")}</select>
      <span class="text-slate-500">→</span><select data-rf="channel" class="bg-black/40 border border-slate-800 rounded px-1 py-1 text-slate-200">${chOpts}</select>
      <button onclick="nfDelRule(${i})" class="ml-auto px-2 py-1 rounded text-red-400 hover:bg-red-500/10">✕</button>
    </div>
    <div class="text-slate-400">${evChecks}</div>
  </div>`;
}
function _nfSync(){
  _nf.channels=[...document.querySelectorAll("#nf-channels [data-ch]")].map(d=>{const o={};d.querySelectorAll("[data-cf]").forEach(el=>o[el.getAttribute("data-cf")]=el.value);return o;});
  _nf.rules=[...document.querySelectorAll("#nf-rules [data-rule]")].map(d=>{const o={events:[]};d.querySelectorAll("[data-rf]").forEach(el=>o[el.getAttribute("data-rf")]=el.type==="checkbox"?el.checked:el.value);d.querySelectorAll("[data-ev]").forEach(el=>{if(el.checked)o.events.push(el.getAttribute("data-ev"));});return o;});
}
function nfAddChannel(type){ _nfSync(); _nf.channels.push({type,id:type+"-"+(_nf.channels.length+1),label:""}); renderNotify(); }
function nfDelChannel(i){ _nfSync(); _nf.channels.splice(i,1); renderNotify(); }
function nfAddRule(){ _nfSync(); _nf.rules.push({enabled:true,events:["ban_failed"],env:"",min_severity:"warning",channel:(_nf.channels[0]||{}).id||""}); renderNotify(); }
function nfDelRule(i){ _nfSync(); _nf.rules.splice(i,1); renderNotify(); }
async function nfTest(id){
  if(!id){ uiAlert("сначала задай id канала и сохрани"); return; }
  const d=await (await fetch("/api/notify/test",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({channel:id})})).json();
  uiAlert(d.ok?"✓ отправлено":"✗ "+(d.error||"ошибка"));
}
async function saveNotify(){
  _nfSync();
  const channels=_nf.channels.map(c=>{const o={...c};["webhook","bot_token"].forEach(k=>{if(!o[k])delete o[k];});return o;});
  const msg=document.getElementById("nf-msg"); msg.textContent="сохраняю…"; msg.className="text-[11px] mt-3 text-slate-400";
  const d=await (await fetch("/api/notify_config",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({channels,rules:_nf.rules})})).json();
  if(d.ok){ msg.textContent="✓ сохранено"; msg.className="text-[11px] mt-3 text-emerald-400"; loadNotify(); }
  else{ msg.textContent="✗ "+(d.error||"ошибка"); msg.className="text-[11px] mt-3 text-red-400"; }
}

// ── Глобальные настройки (ENV + GUI) ──────────────────────────────────────────
const _setGroupMeta={llm:"🤖 LLM",cloudflare:"☁️ Cloudflare (default / fallback)",ingress:"☸️ ingress-nginx (default)",bans:"⛔ Bans: targets / groups"};
let _setLocked=false;
const _setGrpOpen=JSON.parse(localStorage.getItem("soc_setgrp_open")||"{}");  // collapse state, persisted across reloads
function setGrpToggle(btn,bodyId){ const on=!btn.classList.contains("on"); btn.classList.toggle("on",on);
  const b=document.getElementById(bodyId); if(b)b.classList.toggle("hidden",!on);
  const g=bodyId.replace("setgrp-",""); _setGrpOpen[g]=on; localStorage.setItem("soc_setgrp_open",JSON.stringify(_setGrpOpen)); }
async function loadGlobal(){
  const wrap=document.getElementById("set-groups");
  try{
    const d=await (await fetch("/api/settings")).json();
    _setLocked=!!d.locked;
    document.getElementById("set-locked").classList.toggle("hidden",!_setLocked);
    document.getElementById("set-save").disabled=_setLocked;
    document.getElementById("set-save").classList.toggle("opacity-40",_setLocked);
    const s=d.settings||{}, byGroup={};
    Object.keys(s).forEach(k=>{const g=s[k].group||"other";(byGroup[g]=byGroup[g]||[]).push(k);});
    const order=["llm","cloudflare","ingress","bans"];
    const groups=Object.keys(byGroup).sort((a,b)=>(order.indexOf(a)+1||9)-(order.indexOf(b)+1||9));
    wrap.innerHTML=groups.map(g=>{
      const rows=byGroup[g].map(k=>settingRow(k,s[k])).join("");
      const extra=g==="cloudflare"?`<button onclick="checkCF()" class="text-[11px] px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 mt-1">Проверить подключение</button><div id="set-cf-check" class="text-[11px] mt-1"></div>`:"";
      // collapsible groups (CF / ingress / bans) get a switch in the header; open by default. LLM is governed by the global LLM toggle.
      const collapsible=g!=="llm";
      const bid="setgrp-"+g, open=_setGrpOpen[g]!==false;
      const sw=collapsible?`<button type="button" class="sw${open?' on':''}" onclick="setGrpToggle(this,'${bid}')" aria-label="toggle ${g}"><i></i></button>`:"";
      return `<div class="card p-3"${g==="llm"?" data-llm":""}>
        <div class="flex items-center justify-between mb-2"><h3 class="text-xs font-medium text-slate-300">${_setGroupMeta[g]||g}</h3>${sw}</div>
        <div id="${bid}" class="space-y-2${open?'':' hidden'}">${rows}${extra}</div></div>`;
    }).join("");
  }catch(e){ wrap.innerHTML=`<div class="text-red-400 text-xs">ошибка: ${esc(e.message)}</div>`; }
}
function settingRow(key,it){
  const src=it.source==="override"?`<span class="text-[10px] px-1 rounded bg-indigo-900/50 text-indigo-300">override</span>`:`<span class="text-[10px] px-1 rounded bg-slate-800 text-slate-500">env</span>`;
  const dis=_setLocked?"disabled":"";
  let input;
  if(it.type==="secret"){
    const roDis=(it.writable===false)?"disabled":dis;
    const note=(it.writable===false)?`<div class="text-[10px] text-amber-400/80 mt-0.5">только через ENV (STORE=configmap — ConfigMap хранит открытым текстом)</div>`:"";
    input=`<input type="password" data-skey="${esc(key)}" data-stype="secret" placeholder="${it.set?'•••• задан (введите, чтобы заменить)':'не задан'}" ${roDis}
      class="w-full text-xs mono bg-black/40 border border-slate-800 rounded px-2 py-1 text-slate-200">${note}`;
  }else if(it.type==="json"){
    input=`<textarea data-skey="${esc(key)}" data-stype="json" rows="2" ${dis}
      class="w-full text-[11px] mono bg-black/40 border border-slate-800 rounded px-2 py-1 text-slate-200">${esc(JSON.stringify(it.value))}</textarea>`;
  }else if(it.choices){
    input=`<select data-skey="${esc(key)}" data-stype="str" ${dis} class="w-full text-xs bg-black/40 border border-slate-800 rounded px-2 py-1 text-slate-200">`+
      it.choices.map(c=>`<option ${c===it.value?'selected':''}>${esc(c)}</option>`).join("")+`</select>`;
  }else{
    input=`<input type="text" data-skey="${esc(key)}" data-stype="str" value="${esc(it.value==null?'':it.value)}" ${dis}
      class="w-full text-xs mono bg-black/40 border border-slate-800 rounded px-2 py-1 text-slate-200">`;
  }
  return `<div><div class="flex items-center gap-2 mb-0.5"><span class="text-[11px] text-slate-400">${esc(it.label||key)}</span>${src}</div>${input}</div>`;
}
async function saveSettings(){
  if(_setLocked)return;
  const updates={};
  document.querySelectorAll("#set-groups [data-skey]").forEach(el=>{
    const k=el.getAttribute("data-skey"), t=el.getAttribute("data-stype"), v=el.value;
    if(t==="secret"){ if(v!=="")updates[k]=v; }   // blank = keep current
    else updates[k]=v;
  });
  const msg=document.getElementById("set-msg"); msg.textContent="сохраняю…"; msg.className="text-[11px] mt-3 text-slate-400";
  try{
    const r=await fetch("/api/settings",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({updates})});
    const d=await r.json();
    if(d.ok){ msg.textContent="✓ сохранено: "+(d.applied||[]).join(", "); msg.className="text-[11px] mt-3 text-emerald-400"; loadGlobal(); }
    else{ const part=(d.applied&&d.applied.length)?(" (сохранено: "+d.applied.join(", ")+")"):""; msg.textContent="✗ "+(d.error||"ошибка")+part; msg.className="text-[11px] mt-3 text-red-400"; loadGlobal(); }
  }catch(e){ msg.textContent="✗ "+e.message; msg.className="text-[11px] mt-3 text-red-400"; }
}
async function checkCF(){
  const box=document.getElementById("set-cf-check"); box.textContent="проверяю…"; box.className="text-[11px] mt-1 text-slate-400";
  try{
    const d=await (await fetch("/api/ban_targets/check")).json();
    const cf=(d.checks||[]).filter(c=>c.type==="cloudflare");
    if(!cf.length){ box.textContent="нет Cloudflare-таргетов в targets."; return; }
    box.innerHTML=cf.map(c=>{
      const ok=c.ok; return `<div class="${ok?'text-emerald-400':'text-amber-400'}">${ok?'✓':'⚠'} ${esc(c.id||'cf')}: token ${c.token_valid?'ok':'нет'}, list ${c.list_id?'ok':'—'}, rule ${c.rule_id?'ok':'—'}${c.items!=null?(', items '+c.items):''}${c.error?(' — '+esc(c.error)):''}</div>`;
    }).join("");
  }catch(e){ box.textContent="ошибка: "+e.message; box.className="text-[11px] mt-1 text-red-400"; }
}

// ── Ноды (подключённые nginx-VM с агентом) ────────────────────────────────────
let _nodesTimer=null;
function _ago(sec){
  if(!sec)return "никогда";
  const d=Math.max(0,Math.floor(Date.now()/1000)-sec);
  if(d<60)return d+"с назад"; if(d<3600)return Math.floor(d/60)+"м назад";
  if(d<86400)return Math.floor(d/3600)+"ч назад"; return Math.floor(d/86400)+"д назад";
}
function _uptime(sec){
  if(!sec)return "—"; const d=Math.floor(sec/86400),h=Math.floor(sec%86400/3600);
  return d>0?(d+"д "+h+"ч"):(h+"ч "+Math.floor(sec%3600/60)+"м");
}
function _bar(pct,warn,crit){
  pct=Math.max(0,Math.min(100,pct||0));
  const c=pct>=crit?"bg-red-500":pct>=warn?"bg-amber-500":"bg-emerald-500";
  return `<div class="h-1.5 w-full bg-slate-800 rounded overflow-hidden"><div class="h-full ${c}" style="width:${pct}%"></div></div>`;
}
async function loadNodes(){
  try{
    const r=await fetch("/api/nodes"); const d=await r.json();
    renderNodes(d);
  }catch(e){ document.getElementById("nodes-list").innerHTML=`<div class="text-red-400 text-xs">ошибка загрузки: ${esc(e.message)}</div>`; }
  if(_view==="targets"&&_tsub==="nginx"){ clearTimeout(_nodesTimer); _nodesTimer=setTimeout(loadNodes,10000); }
}
// логотип nginx (inline SVG, self-contained) — метка для нод-агентов nginx
const _NGINX_ICON='<svg viewBox="0 0 24 24" width="15" height="15" class="shrink-0" title="nginx" aria-label="nginx"><path fill="#009639" d="M12 1.6 2.5 7v10L12 22.4 21.5 17V7L12 1.6z"/><path fill="#fff" d="M9 8.4v7.2H10.6V11.3l4 4.3H16V8.4H14.4v4.4l-4-4.4H9z"/></svg>';
function renderNodes(d){
  const el=document.getElementById("nodes-list");
  if(d.enabled===false){ el.innerHTML=`<div class="text-slate-500 text-xs">blocklist-api не настроен (BLOCKLIST_API_URL пуст) — ноды недоступны.</div>`; return; }
  // только nginx-ноды агентов; хост дашборда (role=dashboard) живёт в разделе System
  const nodes=(d.nodes||[]).filter(n=>n.role!=="dashboard");
  if(!nodes.length){ el.innerHTML=`<div class="text-slate-500 text-xs">${_trText("пока нет подключённых нод. Нажми «+ Добавить ноду».")}</div>`; return; }
  el.innerHTML=nodes.map(_nodeCard).join("");
}
function loadSystem(){ // тот же фид нод, но показываем только хост(ы) дашборда
  fetch("/api/nodes").then(r=>r.json()).then(renderSystem).catch(e=>{const el=document.getElementById("system-list");if(el)el.innerHTML=`<div class="text-red-400 text-xs">ошибка: ${esc(e.message)}</div>`;});
}
function renderSystem(d){
  const el=document.getElementById("system-list");if(!el)return;
  if(d.enabled===false){ el.innerHTML=`<div class="text-slate-500 text-xs">blocklist-api не настроен.</div>`; return; }
  const sys=(d.nodes||[]).filter(n=>n.role==="dashboard");
  const cards=sys.length?sys.map(_nodeCard):[];
  // the local blocklist-api ("worker") — the home backend that drives nginx nodes + CF.
  const home=(_backends||[]).find(b=>b.id==="__home__");
  if(home){
    cards.push(`<div class="bg-slate-950/50 border border-indigo-700/40 rounded-lg p-3 flex items-center gap-2 flex-wrap">
      <span class="w-2 h-2 rounded-full bg-emerald-500 shrink-0"></span>
      <span class="text-sm font-medium text-slate-200">${_trText("worker")}</span>
      <span class="text-[10px] px-1.5 py-0.5 rounded bg-indigo-900/60 text-indigo-300">${_trText("локальный blocklist-api")}</span>
      <span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">nginx · CF</span>
      <span class="mono text-[10px] text-slate-500 truncate ml-auto">${esc(home.url||"")}</span>
    </div>`);
  }
  el.innerHTML=cards.length?cards.join(""):`<div class="text-slate-500 text-xs">${_trText("нет данных о хосте")}</div>`;
}
function _nodeCard(n){
    const m=n.metrics||{}, online=n.online, isDash=n.role==="dashboard";
    const dot=online?"bg-emerald-500":"bg-slate-600";
    const nginxBad=m.nginx_ok===false;
    const load=m.load1!=null?(m.load1+(m.ncpu?(" / "+m.ncpu+" cpu"):"")):"—";
    const loadPct=(m.load1!=null&&m.ncpu)?(m.load1/m.ncpu*100):null;
    return `<div class="bg-slate-950/50 border ${isDash?'border-indigo-700/50':nginxBad?'border-red-800/60':'border-slate-800'} rounded-lg p-3">
      <div class="flex items-center justify-between gap-2">
        <div class="flex items-center gap-2 min-w-0">
          <span class="w-2 h-2 rounded-full ${dot} shrink-0"></span>
          ${isDash?"":_NGINX_ICON}
          <span class="text-sm font-medium text-slate-200 truncate">${esc(n.label||n.id)}</span>
          ${isDash?"":`<button onclick="renameNode('${escJs(n.id)}','${escJs(n.label||'')}')" title="rename" class="ibtn shrink-0" style="width:22px;height:22px"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/></svg></button>`}
          ${isDash?`<span class="text-[10px] px-1.5 py-0.5 rounded bg-indigo-900/60 text-indigo-300">dashboard</span>`:""}
          ${n.group?`<span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">${esc(n.group)}</span>`:""}
          ${isDash?"":_beBadge(n.backend)}
          ${nginxBad?`<span class="text-[10px] px-1.5 py-0.5 rounded bg-red-900/60 text-red-300">nginx -t ✗</span>`:""}
        </div>
        <div class="flex items-center gap-2 shrink-0">
          <span class="text-[11px] ${online?'text-emerald-400':'text-slate-500'}">${online?"online":"offline"} · ${_ago(n.last_seen)}</span>
          ${isDash?"":`<button onclick="deleteNode('${escJs(n.id)}','${escJs(n.backend||'')}')" class="btn btn-xs" style="color:var(--crit);border-color:color-mix(in srgb,var(--crit) 40%,transparent)" title="Revoke token and remove node">revoke</button>`}
        </div>
      </div>
      <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-3 text-[11px]">
        <div><div class="text-slate-500 mb-0.5">CPU load</div><div class="text-slate-300 mb-1">${esc(load)}</div>${loadPct!=null?_bar(loadPct,70,90):""}</div>
        <div><div class="text-slate-500 mb-0.5">RAM</div><div class="text-slate-300 mb-1">${m.mem_used_pct!=null?(m.mem_used_pct+"%"+(m.mem_total_mb?(" / "+(m.mem_total_mb/1024).toFixed(1)+"G"):"")):"—"}</div>${m.mem_used_pct!=null?_bar(m.mem_used_pct,75,90):""}</div>
        <div><div class="text-slate-500 mb-0.5">uptime</div><div class="text-slate-300">${_uptime(m.uptime_s)}</div></div>
        ${isDash?`<div><div class="text-slate-500 mb-0.5">role</div><div class="text-slate-300">SOC dashboard</div></div>`:`<div><div class="text-slate-500 mb-0.5">bans on node</div><div class="text-slate-300">${m.applied_cidrs!=null?m.applied_cidrs:"—"} CIDR</div></div>`}
      </div>
      <div class="text-[10px] text-slate-600 mt-2 mono">${esc(n.hostname||"")}${n.ip?(" · "+esc(n.ip)):""}${n.agent_version?(" · "+esc(n.agent_version)):""}</div>
    </div>`;
}
async function showAddNode(){
  const box=document.getElementById("nodes-add"); box.classList.remove("hidden");
  const pre=document.getElementById("nodes-install-cmd"), hint=document.getElementById("nodes-install-hint");
  pre.textContent="загрузка…"; hint.classList.add("hidden");
  try{
    const d=await (await fetch("/api/nodes/install")).json();
    if(d.enabled===false){ pre.textContent="# blocklist-api не настроен"; return; }
    if(!d.configured){ pre.textContent="# ENROLL_SECRET не задан в blocklist-api — задай его, чтобы агенты могли регистрироваться."; return; }
    if(d.needs_public_url){ hint.textContent="⚠ Задай PUBLIC_URL в blocklist-api (адрес, по которому VM достучатся до API) — без него команда неполная."; hint.classList.remove("hidden"); }
    else if(d.needs_https){ hint.textContent="⚠ PUBLIC_URL использует http:// — команда установки не выдаётся. Агент качается и запускается от root, поэтому по незашифрованному каналу это риск удалённого выполнения кода (MITM). Задай https:// PUBLIC_URL."; hint.classList.remove("hidden"); }
    pre.textContent=d.install_cmd||"# команда недоступна (нужен https PUBLIC_URL)";
  }catch(e){ pre.textContent="# ошибка: "+e.message; }
}
function copyInstallCmd(){
  const t=document.getElementById("nodes-install-cmd").textContent;
  _copyText(t, typeof event!=="undefined"&&event&&event.currentTarget);
}
async function deleteNode(id,backend){
  if(!await uiConfirm("Отозвать токен ноды «"+id+"»? Агент перестанет получать баны, пока не перерегистрируется."))return;
  await fetch("/api/nodes/delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id,backend})});
  loadNodes();
}
async function renameNode(id,cur){
  const name=await uiPrompt(_trText("Имя ноды (пусто — вернуть исходное):"),id,cur||"");
  if(name===null)return;   // отмена
  try{
    const r=await fetch("/api/nodes/label",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id,name:(name||"").trim()})}).then(x=>x.json());
    if(r&&r.ok)loadNodes(); else uiAlert("не удалось: "+((r&&r.error)||"?"));
  }catch(e){ uiAlert("не удалось: "+(e.message||e)); }
}

// ── Правила 403 (блокировка по пути) ──────────────────────────────────────────
let _p403={enabled:true,rules:[]};
function _reEsc(s){return String(s).replace(/[.*+?^${}()|[\]\\]/g,"\\$&");}
function _pathToPattern(p){p=String(p).split("?")[0];return "^"+_reEsc(p)+"(\\?|$)";}
// ── «основная пара» (одно 403 + одно автобан правило для быстрого добавления) ──
let _mainRules={path_id:null,autoban_id:null};
async function loadMainRules(){try{_mainRules=await fetch("/api/main_rules").then(r=>r.json());}catch(e){}}
async function setMainRule(kind,id){
  const body=kind==="path"?{path_id:id}:{autoban_id:id};
  const r=await _post("/api/main_rules",body);
  if(r.ok){_mainRules=r; if(_view==="p403")loadP403(); if(_view==="autoban"){_abRules=null;loadAutoban();}}
}
async function addToMain(path,el){
  const res=await _post("/api/add_to_main",{path});
  if(!res.ok){if(el){el.innerHTML="ошибка";}return;}
  const f=(x)=>x?(x.already?"уже есть":(x.ok?"✓":"✗ "+(x.error||""))):"—";
  const p=res.path403, a=res.autoban;
  if(el){el.innerHTML="403:"+f(p)+" · автобан:"+f(a);el.disabled=true;el.className+=((p&&p.ok)||(a&&a.ok))?" text-emerald-300":" text-amber-300";}
  // если что-то не настроено — подскажем
  if((p&&!p.ok&&!p.already)||(a&&!a.ok&&!a.already)){
    const probs=[]; if(p&&!p.ok&&!p.already)probs.push("403: "+(p.error||"?")); if(a&&!a.ok&&!a.already)probs.push("автобан: "+(a.error||"?"));
    setTimeout(()=>uiAlert("Добавлено частично:\n"+probs.join("\n")+"\n\nОтметь основные правила звёздочкой ★ во вкладках 403 и Автобан."),100);
  }
  if(_view==="p403")loadP403();
}
let _banGroupInfo={groups:{},targets:[],default_group:""};   // shared: 403 + auto-ban group pickers
function _groupOptions(sel){
  const names=Object.keys(_banGroupInfo.groups||{});
  const all=`<option value="" ${!sel?'selected':''}>${_trText('все таргеты')}</option>`;
  return all+names.map(g=>`<option value="${esc(g)}" ${String(sel)===String(g)?'selected':''}>${esc(g)}</option>`).join("");
}
async function loadP403(){
  try{
    const [d,st,pp,bt]=await Promise.all([
      fetch("/api/path_rules").then(r=>r.json()),
      fetch("/api/path_status").then(r=>r.json()).catch(()=>null),
      fetch("/api/protected_paths").then(r=>r.json()).catch(()=>({paths:[]})),
      fetch("/api/ban_targets").then(r=>r.json()).catch(()=>null)]);
    if(bt&&bt.enabled!==false)_banGroupInfo={groups:bt.groups||{},targets:bt.targets||[],default_group:bt.default_group||"",cf_edge_paths:!!bt.cf_edge_paths};
    await loadMainRules();
    renderP403(d);renderP403Types(st);p403ModeChange();renderP403Protected(pp.paths||[]);
    if(typeof renderP403Applies==="function"){_targetsData=bt||_targetsData;_p403RenderList();}
  }catch(e){document.getElementById("p403-list").innerHTML='<div class="text-rose-400 text-xs">не удалось загрузить: '+esc(e.message||e)+'</div>';}
}
// ── единый резолвер «правило → группа → конкретные таргеты» (для подписей) ──────
let _targetsData=null;   // {targets, groups, default_group, cf_edge_paths} из /api/ban_targets
// применяет ли Cloudflare 403 по пути на edge (WAF). Off → CF блокирует только IP.
function _cfEdgeOn(){return !!((_targetsData&&_targetsData.cf_edge_paths)||(_banGroupInfo&&_banGroupInfo.cf_edge_paths));}
// таргеты, реально применяющие 403 по пути: nginx/ingress всегда, cloudflare — если edge включён
function _pathEnforcers(list){return list.filter(t=>t.type==="nginx-file"||t.type==="ingress-cm"||(t.type==="cloudflare"&&_cfEdgeOn()));}
// привязка правила (groups[]+targets[]+all) → множество id таргетов (зеркало бэкенда)
function _ruleTargetIds(r){
  const d=_targetsData; if(!d||!d.targets) return null;
  const all=d.targets.map(t=>t.id);
  if(r.all) return new Set(all);
  const ids=new Set(r.targets||[]);
  (r.groups||[]).forEach(g=>{ ((d.groups&&d.groups[g])||[]).forEach(x=>ids.add(x)); });
  return ids;
}
function _ruleTargets(r, pathOnly){
  const ids=_ruleTargetIds(r); if(ids==null) return null;
  const byId={}; (_targetsData.targets||[]).forEach(t=>byId[t.id]=t);
  let list=[...ids].map(id=>byId[id]).filter(t=>t&&t.type!=="noop");
  if(pathOnly) list=_pathEnforcers(list);
  return list;
}
// строка «↳ применяется к: <таргеты>» под правилом (по его привязке)
function _appliesLineRule(r, pathOnly){
  const list=_ruleTargets(r, pathOnly); if(list==null) return "";
  const noAttach=!r.all && !(r.groups||[]).length && !(r.targets||[]).length;
  if(noAttach) return `<div class="text-[10px] mt-1 text-amber-400/80">↳ ${_trText("не привязано — правило не действует")}</div>`;
  if(!list.length) return `<div class="text-[10px] mt-1" style="color:var(--faint)">↳ ${_trText("применяется к")}: ${pathOnly?_trText("нет nginx/ingress таргетов"):_trText("нет таргетов")}</div>`;
  const chips=list.map(t=>`<span class="mono px-1 py-0.5 rounded bg-slate-800/70 text-slate-300 inline-flex items-center gap-1">${_typeIcon(t.type)}${esc(t.id)}<span style="color:var(--faint)">·${esc(_typeLabel(t.type))}</span></span>`).join(" ");
  return `<div class="text-[10px] mt-1 flex flex-wrap items-center gap-1" style="color:var(--faint)">↳ ${_trText("применяется к")}: ${chips}</div>`;
}
// ── редактор привязки правила (группы + таргеты + «все») ───────────────────────
// единое человеческое имя/иконка бэкенда (nginx-file → «nginx» и т.п.)
// официальные лого бэкендов (inline SVG — рендерятся в HTML; в нативном <select> нельзя)
const _ICON_CF='<svg viewBox="0 0 24 24" width="14" height="14" class="shrink-0" aria-label="Cloudflare"><path fill="#FBAD41" d="M9.5 8.5a4.5 4.5 0 0 1 8.3 1.2 3 3 0 0 1-.3 6H7.5z"/><path fill="#F38020" d="M16.6 16H6a3 3 0 0 1-.3-6 4.5 4.5 0 0 1 8.5-1.3 2.8 2.8 0 0 1 3.8 2.1 2.7 2.7 0 0 1-1.4 5.2z"/></svg>';
const _ICON_ING='<svg viewBox="0 0 24 24" width="14" height="14" class="shrink-0" aria-label="ingress"><path fill="#326CE5" d="M12 2 3.6 6v8L12 22l8.4-8V6L12 2z"/><circle cx="12" cy="12" r="3.1" fill="#fff"/></svg>';
const _ICON_DOT=c=>`<span style="display:inline-block;width:9px;height:9px;border-radius:50%;background:${c}" class="shrink-0"></span>`;
const _TGT_META={"nginx-file":{ic:"🟢",lbl:"nginx",svg:_NGINX_ICON},
                 "cloudflare":{ic:"🟠",lbl:"Cloudflare",svg:_ICON_CF},
                 "ingress-cm":{ic:"🔵",lbl:"ingress",svg:_ICON_ING},
                 "noop":{ic:"⚪",lbl:"noop",svg:_ICON_DOT("#64748b")}};
function _typeMeta(t){return _TGT_META[t]||{ic:"🎯",lbl:t||"?",svg:_ICON_DOT("#64748b")};}
function _typeLabel(t){return _typeMeta(t).lbl;}
function _typeIcon(t){return _typeMeta(t).svg;}   // SVG-лого для HTML-контекстов
// во что группа резолвится → короткая подпись «→ test-1» / «→ все» / «→ 3 таргета»
// 'empty' (ни одного таргета) | 'all' (ровно все — дубль кнопки «все таргеты») | 'some'
function _grpKind(g){
  const d=_targetsData; if(!d) return "some";
  const ids=(d.groups&&d.groups[g])||[];
  const allReal=(d.targets||[]).filter(t=>t.type!=="noop").map(t=>t.id);
  if(!ids.length) return "empty";
  if(allReal.length&&ids.length>=allReal.length&&allReal.every(id=>ids.includes(id))) return "all";
  return "some";
}
function _grpResolve(g){
  const k=_grpKind(g);
  if(k==="empty") return _trText("пусто");
  if(k==="all") return _trText("все");
  const ids=(_targetsData&&_targetsData.groups&&_targetsData.groups[g])||[];
  if(ids.length<=2) return ids.join(", ");
  return ids.length+" "+_trText("таргетов");
}
// тип таргета по id (для иконки в чипах привязки)
function _tgtTypeById(id){const t=(_targetsData&&_targetsData.targets||[]).find(x=>x.id===id);return t?t.type:"";}
// кастомная выпадашка привязки (на <details> — чтобы рендерить SVG-лого; в <select> нельзя)
function _attachMenu(r, kind){
  const d=_targetsData; if(!d) return "";
  const gs=Object.keys(d.groups||{}).filter(g=>g&&!(r.groups||[]).includes(g)&&_grpKind(g)==="some");
  const ts=(d.targets||[]).filter(t=>t.type!=="noop"&&!(r.targets||[]).includes(t.id));
  const order=["nginx-file","cloudflare","ingress-cm"];
  const types=[...new Set(ts.map(t=>t.type))].sort((a,b)=>(order.indexOf(a)+1||9)-(order.indexOf(b)+1||9));
  const close="this.closest('details').removeAttribute('open')";
  const row=(inner,tok)=>`<button type="button" onclick="${close};attachAdd('${kind}','${escJs(r.id)}','${tok}')" class="attach-row">${inner}</button>`;
  const secColor={"nginx-file":"#4ade80","cloudflare":"#fb923c","ingress-cm":"#60a5fa"};
  // "все таргеты" first (highlighted) — sets all:true rather than a specific target
  let m=`<button type="button" onclick="${close};attachAll('${kind}','${escJs(r.id)}',true)" class="attach-row" style="font-weight:500;color:#73bf69;border-bottom:1px solid var(--border)">🌐 ${_trText('все таргеты')}</button>`;
  if(gs.length) m+=`<div class="attach-sec">🗂 ${_trText('группы')}</div>`+gs.map(g=>row(`<span>${esc(g)}</span><span class="attach-res">→ ${esc(_grpResolve(g))}</span>`,"g:"+esc(g))).join("");
  types.forEach(ty=>{const mt=_typeMeta(ty);
    m+=`<div class="attach-sec" style="color:${secColor[ty]||'var(--faint)'};font-weight:500;letter-spacing:.02em">${mt.svg} ${esc(mt.lbl)}</div>`+ts.filter(t=>t.type===ty).map(t=>row(`${mt.svg}<span>${esc(t.id)}</span>`,"t:"+esc(t.id))).join("");});
  return `<details name="attach-dd" class="attach-dd"><summary class="attach-add">＋ ${_trText('привязать')}</summary><div class="attach-menu">${m}</div></details>`;
}
function _attachUI(r, kind){
  const all=!!r.all;
  const chip=(label,tok)=>`<span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">${label}<button onclick="attachRemove('${kind}','${escJs(r.id)}','${tok}')" class="text-slate-500 hover:text-rose-300" title="${_trText('убрать')}">×</button></span>`;
  const gChips=(r.groups||[]).map(g=>chip("🗂 "+esc(g)+' <span style="color:var(--faint)">→ '+esc(_grpResolve(g))+'</span>',"g:"+esc(g))).join(" ");
  const tChips=(r.targets||[]).map(t=>chip(_typeIcon(_tgtTypeById(t))+" "+esc(t),"t:"+esc(t))).join(" ");
  const allChip=all?`<span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-emerald-600/25 border border-emerald-500/40 text-emerald-200">${_trText('все таргеты')}<button onclick="attachRemove('${kind}','${escJs(r.id)}','all')" class="text-emerald-300/70 hover:text-rose-300" title="${_trText('убрать')}">×</button></span>`:"";
  const chips=all?allChip:(gChips+" "+tChips).trim();
  const icon=kind==="p403"?"":"🎯 ";
  return `<div class="flex flex-wrap items-center gap-1.5 mt-1.5 text-[11px]">
    <span style="color:var(--faint)">${icon}${_trText('привязка')}:</span>
    ${chips||`<span style="color:var(--faint)">${_trText('ничего')}</span>`}
    ${_attachMenu(r,kind)}
  </div>`;
}
function _attachRuleById(kind,id){ return kind==="p403"?(_p403.rules||[]).find(r=>String(r.id)===String(id)):(_abRules||[]).find(r=>String(r.id)===String(id)); }
async function _attachSave(kind,r){
  if(kind==="p403"){
    const res=await _post("/api/path_rule",{id:r.id,name:r.name,pattern:r.pattern,enabled:r.enabled!==false,
      groups:r.groups||[],targets:r.targets||[],all:!!r.all});
    if(res&&res.ok)loadP403(); else uiAlert("не удалось: "+((res&&res.error)||"?"));
  }else{ _abAttachSave(r); }  // автобан — Фаза 2
}
// сохранить привязку автобан-правила, не затирая остальные поля
async function _abAttachSave(r){
  const body={id:r.id, name:r.name, match_type:r.match_type, path:r.path||"",
    status:r.status||"", threshold:r.threshold, window:r.window, ttl:r.ttl,
    enabled:r.enabled?1:0, combine:r.combine, country:r.country||"",
    groups:r.groups||[], targets:r.targets||[], all:!!r.all};
  try{
    const res=await fetch("/api/autoban/rule",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)}).then(x=>x.json());
    if(res&&(res.ok||res.id))loadAutoban(); else uiAlert("не удалось: "+((res&&res.error)||"?"));
  }catch(e){ uiAlert("не удалось: "+(e.message||e)); }
}
function attachAll(kind,id,val){ const r=_attachRuleById(kind,id); if(!r)return; r.all=!!val; if(val){r.groups=[];r.targets=[];} _attachSave(kind,r); }
function attachAdd(kind,id,tok){ if(!tok)return; const r=_attachRuleById(kind,id); if(!r)return; r.all=false;
  if(tok.slice(0,2)==="g:")r.groups=[...new Set([...(r.groups||[]),tok.slice(2)])];
  else if(tok.slice(0,2)==="t:")r.targets=[...new Set([...(r.targets||[]),tok.slice(2)])];
  _attachSave(kind,r); }
function attachRemove(kind,id,tok){ const r=_attachRuleById(kind,id); if(!r)return;
  if(tok==="all")r.all=false;
  else if(tok.slice(0,2)==="g:")r.groups=(r.groups||[]).filter(g=>g!==tok.slice(2));
  else r.targets=(r.targets||[]).filter(t=>t!==tok.slice(2));
  _attachSave(kind,r); }
function _appliesTargets(group, pathOnly){
  const d=_targetsData; if(!d||!d.targets) return null;
  const byId={}; d.targets.forEach(t=>byId[t.id]=t);
  const g=group||d.default_group||"";
  const ids=(g&&d.groups&&d.groups[g])?d.groups[g]:d.targets.map(t=>t.id); // нет/неизв. группа → все
  let list=ids.map(id=>byId[id]).filter(t=>t&&t.type!=="noop");
  if(pathOnly) list=_pathEnforcers(list);
  return list;
}
// строка «→ применяется к: <таргеты>» под правилом
function _appliesLine(group, pathOnly){
  const list=_appliesTargets(group, pathOnly);
  if(list==null) return "";
  const lbl=group?(_trText("группа")+" «"+esc(group)+"»"):_trText("все таргеты");
  if(!list.length) return `<div class="text-[10px] mt-1" style="color:var(--faint)">↳ ${_trText("применяется к")}: ${lbl} — ${pathOnly?_trText("нет nginx/ingress таргетов"):_trText("нет таргетов")}</div>`;
  const chips=list.map(t=>`<span class="mono px-1 py-0.5 rounded bg-slate-800/70 text-slate-300 inline-flex items-center gap-1">${_typeIcon(t.type)}${esc(t.id)}<span style="color:var(--faint)">·${esc(_typeLabel(t.type))}</span></span>`).join(" ");
  return `<div class="text-[10px] mt-1 flex flex-wrap items-center gap-1" style="color:var(--faint)">↳ ${_trText("применяется к")}: ${chips}</div>`;
}
async function renderP403Applies(){
  const el=document.getElementById("p403-applies");if(!el)return;
  try{
    const d=await fetch("/api/ban_targets").then(r=>r.json());
    _targetsData=d; _p403RenderList();   // пере-рендер списка с подписями «применяется к»
    if(d.enabled===false){ el.innerHTML=`<span class="text-slate-500">${_trText('blocklist-api не настроен.')}</span>`; return; }
    const edge=_cfEdgeOn();
    const path=(d.targets||[]).filter(t=>t.type==="nginx-file"||t.type==="ingress-cm");
    const cfAll=(d.targets||[]).filter(t=>t.type==="cloudflare");
    const cfPath=edge?cfAll:[], cfIpOnly=edge?[]:cfAll;   // edge вкл → CF тоже 403'ит по пути
    const enf=path.concat(cfPath);
    let html=enf.length
      ? enf.map(t=>{const node=t.type==="nginx-file"&&t.enrolled!==false;
          const cf=t.type==="cloudflare";
          const tip=cf?_trText('Cloudflare WAF — 403 по пути на edge'):(node?_trText('подключённая нода — открыть во вкладке Ноды'):_trText('ingress-cm таргет'));
          const go=cf?"showView('targets');setTsub('cf')":(node?"showView('targets');setTsub('nginx')":"showView('settings');setSub('global')");
          return `<span onclick="${go}" title="${tip}" class="text-[11px] px-1.5 py-0.5 rounded bg-emerald-900/40 text-emerald-300/90 mono cursor-pointer hover:bg-emerald-900/70 inline-flex items-center gap-1">${_typeIcon(t.type)}${esc(t.id)} <span class="text-emerald-500/70">${esc(_typeLabel(t.type))}</span> ↗</span>`;}).join("")
      : `<span class="text-slate-500">${_trText('нет nginx/ingress таргетов — добавь ноду или включи ingress у env.')}</span>`;
    if(cfIpOnly.length)html+=`<span class="text-[11px] text-slate-600">· ${_trText('Cloudflare не применяет 403 по пути (только IP):')} ${cfIpOnly.map(t=>esc(t.id)).join(", ")}</span>`;
    el.innerHTML=html;
  }catch(e){ el.innerHTML=`<span class="text-slate-500">—</span>`; }
}
function renderP403Protected(paths){
  const el=document.getElementById("p403-protected");if(!el)return;
  if(!paths||!paths.length){el.innerHTML="";return;}
  el.innerHTML='🛡️ защищённые (в 403 добавить нельзя, общий список с автобаном): '+paths.map(p=>`<span class="mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">${esc(p)}</span>`).join(" ")+' <span class="text-slate-600">— меняются в <a onclick="showView(\'autoban\')" class="text-indigo-300 cursor-pointer">Автобане</a></span>';
}
const _P403_BK={"nginx-file":"nginx","ingress-cm":"ingress","cloudflare":"CF","noop":"noop"};
// маленькие пиллы вкл/выкл по каждому реальному бэкенду (nginx / cf / ingress);
// типов без активного таргета — не показываем. Клик переключает 403 для всего типа.
function renderP403Types(st){
  const el=document.getElementById("p403-types");if(!el)return;
  if(!st||!st.targets||typeof st.targets!=="object"){el.innerHTML="";return;}
  const off=new Set(st.off_types||[]);
  const byType={};
  Object.values(st.targets).forEach(t=>{if(t.type==="noop")return;(byType[t.type]=byType[t.type]||[]).push(t);});
  const types=Object.keys(byType);
  if(!types.length){el.innerHTML='<span class="text-[11px] text-amber-300/80">'+_trText("нет бэкендов")+'</span>';return;}
  el.innerHTML=types.map(ty=>{
    const bk=_P403_BK[ty]||ty, on=!off.has(ty), arr=byType[ty];
    const reachable=arr.every(t=>t.controller_reachable), ok=arr.every(t=>t.rendered_ok);
    let dot,cls,state,tip;
    if(!on){dot="bg-slate-500";cls="border-slate-700 bg-slate-800/60 text-slate-400 hover:border-slate-600";state=_trText("выкл");tip=bk+": 403 выключен — включить";}
    else if(!reachable){dot="bg-amber-400";cls="border-amber-600/40 bg-amber-900/20 text-amber-300 hover:border-amber-500";state=_trText("нет связи");tip=bk+": нет связи с бэкендом";}
    else if(!ok){dot="bg-amber-400";cls="border-amber-600/40 bg-amber-900/20 text-amber-300 hover:border-amber-500";state=_trText("дрейф");tip=bk+": дрейф рендера — нажми ↻ ресинк в Денлисте";}
    else{dot="bg-emerald-400";cls="border-emerald-600/40 bg-emerald-900/30 text-emerald-300 hover:border-emerald-500";state=_trText("вкл");tip=bk+": 403 активен — выключить";}
    const ic=(typeof _typeIcon==="function"&&typeof _TGT_META!=="undefined"&&_TGT_META[ty])?_typeIcon(ty):"";
    return `<button onclick="p403TypeToggle('${ty}',${!on})" title="${esc(tip)}" class="text-[11px] leading-none pl-2 pr-2.5 py-1.5 rounded-full border flex items-center gap-1.5 transition ${cls}">${ic}<span class="font-semibold">${esc(bk)}</span><span class="w-1.5 h-1.5 rounded-full ${dot} shrink-0"></span><span class="opacity-70 text-[10px] uppercase tracking-wide">${state}</span></button>`;
  }).join("");
}
async function p403TypeToggle(type,enabled){
  try{const r=await _post("/api/path_type",{type,enabled});if(r&&r.ok===false)throw new Error(r.error||"ошибка");}catch(e){}
  loadP403();
}
function renderP403(d){
  _p403=d||{enabled:true,rules:[]};
  _p403RenderList();
  p403FillTarget();
}
function _p403fmtDate(ts){if(!ts)return"";const d=new Date(ts*1000);return d.toLocaleDateString("ru",{day:"2-digit",month:"2-digit",year:"2-digit"});}
let _p403Grp={};   // rep-id → [{id,backend}] — the same rule replicated across backends
function _p403RenderList(){
  const rules=_p403.rules||[];
  // collapse the same logical rule (name+pattern) replicated across backends into one
  // row — a rule on "all targets" is written to every 403-capable backend and fans
  // back as one row per backend; show it once with both backend badges.
  _p403Grp={}; const order=[], byKey={};
  rules.forEach(r=>{const k=(r.name||"")+" "+(r.pattern||"");
    if(byKey[k]==null){byKey[k]={rep:r,backends:[],pairs:[]};order.push(k);}
    byKey[k].backends.push(r.backend||""); byKey[k].pairs.push({id:r.id,backend:r.backend||""});});
  const groups=order.map(k=>byKey[k]);
  groups.forEach(g=>{_p403Grp[g.rep.id]=g.pairs;});
  const q=(document.getElementById("p403-search").value||"").toLowerCase().trim();
  const filt=q?groups.filter(g=>((g.rep.name||"")+" "+(g.rep.pattern||"")).toLowerCase().includes(q)):groups;
  const enN=groups.filter(g=>g.rep.enabled!==false).length;
  document.getElementById("p403-count").textContent="· "+groups.length+" ("+enN+" on)"+(q?(" · "+filt.length+" found"):"");
  const list=document.getElementById("p403-list");
  if(!groups.length){list.innerHTML='<div class="text-xs" style="color:var(--faint);padding:12px 2px">No rules yet — add one, seed from auto-ban, or use the basic scanner set.</div>';return;}
  if(!filt.length){list.innerHTML='<div class="text-xs" style="color:var(--faint);padding:12px 2px">Nothing matches “'+esc(q)+'”.</div>';return;}
  list.innerHTML=filt.map(g=>{const r=g.rep; const en=r.enabled!==false;
    const _backends=[...new Set(g.backends.filter(Boolean))];
    const by=r.added_by?`<span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 shrink-0">${esc(r.added_by)}</span>`:"";
    const dt=r.ts?`<span class="text-[10px] text-slate-600 shrink-0">${_p403fmtDate(r.ts)}</span>`:"";
    const plen=(r.pattern||"").length;
    const isMain=String(_mainRules.path_id)===String(r.id);
    const meta=[r.added_by?esc(r.added_by):"",r.ts?_p403fmtDate(r.ts):"",plen+" chars"].filter(Boolean).join(" · ");
    return `<div class="px-1 py-3 ${en?'':'opacity-60'}" style="border-bottom:1px solid var(--border)">
      <div class="flex items-start gap-2.5">
        <button onclick="p403Toggle('${escJs(r.id)}',${!en})" title="${en?'disable':'enable'}" class="st-pill ${en?'st-on':'st-off'} shrink-0" style="margin-top:1px">${en?'on':'off'}</button>
        <div class="min-w-0 flex-1">
          <div class="flex items-center gap-1.5 flex-wrap">
            <button onclick="setMainRule('path','${escJs(r.id)}')" title="${isMain?'primary 403 rule':'make primary'}" class="star-btn ${isMain?'on':''} shrink-0">★</button>
            <span class="lrow-name truncate">${esc(r.name||'(unnamed)')}</span>
            ${isMain?'<span class="text-[10px] px-1.5 py-0.5 rounded" style="background:color-mix(in srgb,var(--warn) 15%,transparent);color:var(--warn)">primary</span>':''}
          </div>
          <div class="text-[10px] text-slate-500 mt-0.5">${meta}</div>
        </div>
        <div class="flex items-center gap-1 shrink-0">
          <button onclick="document.getElementById('pat-${esc(r.id)}').classList.toggle('hidden')" class="btn btn-xs">pattern&nbsp;▾</button>
          <button onclick="p403EditOpen('${escJs(r.id)}')" title="edit" class="ibtn"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/></svg></button>
          <button onclick="p403Delete('${escJs(r.id)}')" title="delete" class="ibtn danger"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/></svg></button>
        </div>
      </div>
      <div class="mt-2 pt-2 border-t border-slate-800/60">
        ${_attachUI(r,'p403')}
      </div>
      <div id="pat-${esc(r.id)}" class="hidden mono text-[11px] text-slate-400 break-all mt-2 bg-slate-950/60 rounded p-2 max-h-44 overflow-auto">${esc(r.pattern||"")}</div>
      <div id="ed-${esc(r.id)}" class="hidden mt-2 border-t border-slate-800 pt-2"></div>
    </div>`;}).join("");
}
// ── редактор правила: разбор паттерна на отдельные пути (top-level «|») ─────────
let _p403EditState={};
function _p403Unwrap(s){
  s=String(s||"").trim();
  if(s.length<2||s[0]!=="("||s[s.length-1]!==")")return s;
  let depth=0;
  for(let i=0;i<s.length;i++){
    if(s[i]==="\\"){i++;continue;}
    if(s[i]==="(")depth++;
    else if(s[i]===")"){depth--; if(depth===0)return i===s.length-1?s.slice(1,-1):s;}
  }
  return s;
}
function _p403TopSplit(s){           // split on | только на глубине 0 (не внутри (...) / [...])
  const out=[]; let depth=0,cur="",inCls=false;
  for(let i=0;i<s.length;i++){
    const c=s[i];
    if(c==="\\"){cur+=c+(s[i+1]||"");i++;continue;}
    if(inCls){cur+=c;if(c==="]")inCls=false;continue;}
    if(c==="["){inCls=true;cur+=c;continue;}
    if(c==="("){depth++;cur+=c;continue;}
    if(c===")"){depth--;cur+=c;continue;}
    if(c==="|"&&depth===0){out.push(cur);cur="";continue;}
    cur+=c;
  }
  out.push(cur);
  return out.filter(p=>p.length);
}
function _p403Humanize(p){
  // если в части есть НЕэкранированный regex-оператор — это паттерн, показываем как есть;
  // иначе это литеральный путь → снимаем экранирование (\. → ., \- → -) для читаемости
  for(let i=0;i<p.length;i++){
    if(p[i]==="\\"){i++;continue;}
    if("*+?^$.|()[]{}".indexOf(p[i])>=0)return {text:p,regex:true};
  }
  return {text:p.replace(/\\(.)/g,"$1"),regex:false};
}
function p403EditOpen(id){
  const panel=document.getElementById("ed-"+id);
  if(panel&&!panel.classList.contains("hidden")){panel.classList.add("hidden");return;}
  const r=(_p403.rules||[]).find(x=>String(x.id)===String(id)); if(!r)return;
  _p403EditState[id]={name:r.name||"",enabled:r.enabled!==false,parts:_p403TopSplit(_p403Unwrap(r.pattern||""))};
  _p403RenderEditor(id); panel.classList.remove("hidden");
}
function _p403RenderEditor(id){
  const st=_p403EditState[id], panel=document.getElementById("ed-"+id); if(!st||!panel)return;
  panel.innerHTML=`
    <div class="flex items-center gap-2 mb-2">
      <span class="text-[11px] text-slate-500 shrink-0">имя:</span>
      <input value="${esc(st.name)}" oninput="_p403EditState['${escJs(id)}'].name=this.value" class="input text-xs flex-1"/>
    </div>
    <div class="text-[11px] text-slate-500 mb-1">путей: ${st.parts.length} — × чтобы убрать <span class="text-slate-600">(ⓡ = регэксп, наведи — увидишь точный паттерн)</span></div>
    <div class="flex flex-wrap gap-1 mb-2">
      ${st.parts.map((p,i)=>{const h=_p403Humanize(p);return `<span class="inline-flex items-center gap-1 bg-slate-800 rounded px-1.5 py-0.5 text-[11px]"><span class="mono truncate max-w-[280px] ${h.regex?'text-amber-300':'text-slate-300'}" title="${esc(p)}">${esc(h.text)}${h.regex?' <span class="text-[9px] text-amber-500">ⓡ</span>':''}</span><button onclick="p403EditDel('${escJs(id)}',${i})" title="убрать" class="text-rose-400 hover:text-rose-300 font-bold">×</button></span>`}).join("")||'<span class="text-slate-600 text-[11px]">пусто</span>'}
    </div>
    <div class="flex items-center gap-2 mb-2">
      <input id="ed-add-${esc(id)}" onkeydown="if(event.key==='Enter')p403EditAdd('${escJs(id)}')" placeholder="добавить путь (как «Путь содержит», напр. /.env)" class="input text-xs mono flex-1"/>
      <button onclick="p403EditAdd('${escJs(id)}')" class="text-[11px] px-2 py-1 rounded bg-slate-800 text-indigo-300 hover:bg-slate-700 shrink-0">+ путь</button>
    </div>
    <div class="flex items-center gap-2">
      <button onclick="p403EditSave('${escJs(id)}')" class="text-xs px-3 py-1 rounded bg-emerald-600/80 text-white hover:bg-emerald-600">Сохранить</button>
      <button onclick="document.getElementById('ed-${esc(id)}').classList.add('hidden')" class="text-xs px-2 py-1 rounded bg-slate-800 text-slate-300">отмена</button>
    </div>`;
}
function p403EditDel(id,i){const st=_p403EditState[id];if(!st)return;st.parts.splice(i,1);_p403RenderEditor(id);}
function p403EditAdd(id){
  const inp=document.getElementById("ed-add-"+id), v=(inp.value||"").trim(); if(!v)return;
  const e=_reEsc(v);                          // как литеральный путь (экранируем)
  const st=_p403EditState[id];
  if(st.parts.includes(e)){inp.value="";inp.placeholder="«"+v+"» уже есть — пропущено";return;}
  st.parts.push(e);
  inp.value=""; inp.placeholder="добавить путь (как «Путь содержит», напр. /.env)"; _p403RenderEditor(id);
  const ni=document.getElementById("ed-add-"+id); if(ni)ni.focus();
}
async function p403EditSave(id){
  const st=_p403EditState[id]; if(!st)return;
  const parts=st.parts.map(p=>p.trim()).filter(Boolean);
  if(!parts.length){uiAlert("в правиле не осталось ни одного пути — тогда удали правило целиком.");return;}
  const pattern="("+parts.join("|")+")";
  const r=(_p403.rules||[]).find(x=>String(x.id)===String(id))||{};
  // apply the edit to every backend this rule lives on, so they don't diverge
  let ok=true;
  for(const p of _p403Pairs(id)){
    const res=await _post("/api/path_rule",{id:p.id,backend:p.backend,name:st.name,pattern,enabled:st.enabled,
      groups:r.groups||[],targets:r.targets||[],all:!!r.all});
    ok=ok&&res.ok;
  }
  if(ok)loadP403(); else uiAlert("не удалось сохранить на всех бэкендах");
}
// ── генератор паттернов: человек пишет путь/wildcard → regex для nginx ~* ──────
const P403_BENIGN=["/","/index.html","/index.php","/home","/login","/account/login","/api/users","/api/v1/orders","/dashboard","/static/app.js","/assets/main.css","/favicon.ico","/robots.txt","/images/logo.png"];
function p403GenPattern(mode,raw){
  raw=String(raw||"").trim(); if(!raw)return "";
  if(mode==="regex")return raw;                                  // как есть
  if(mode==="wildcard")                                          // * → .*  (остальное экранируем)
    return raw.replace(/[.+?^${}()|[\]\\]/g,"\\$&").replace(/\*/g,".*");
  const e=_reEsc(raw);                                           // путь/exact → литерал
  return mode==="exact" ? ("^"+e+"(\\?|$)") : e;                 // exact — якорь, path — подстрока
}
function p403ModeChange(){
  const mode=document.getElementById("p403-mode").value;
  const map={path:["Путь (подстрока)","/.env"],exact:["Точный URI","/wp-login.php"],
             wildcard:["Wildcard (* = что угодно)","/admin/*  или  *.sql"],regex:["Regex (как nginx ~*)","/\\.env|/wp-login"]};
  const [l,p]=map[mode]||map.path;
  document.getElementById("p403-raw-lbl").textContent=l;
  document.getElementById("p403-raw").placeholder=p;
  p403Preview();
}
function p403Preview(){
  const mode=document.getElementById("p403-mode").value;
  const gen=p403GenPattern(mode,document.getElementById("p403-raw").value);
  document.getElementById("p403-gen").textContent=gen||"—";
  const warn=document.getElementById("p403-warn"); warn.textContent="";
  let rx=null;
  if(gen){try{rx=new RegExp(gen,"i");}catch(e){warn.textContent="✗ некорректный regex: "+e.message;}}
  if(rx){
    if(gen.indexOf('"')>=0)warn.textContent='✗ кавычка " запрещена — сломает nginx';
    else{const hit=P403_BENIGN.find(s=>rx.test(s)); if(hit)warn.textContent="⚠ поймает обычный путь «"+hit+"» — отклонится (или включи force)";}
  }
  const t=document.getElementById("p403-test").value, res=document.getElementById("p403-test-res");
  if(!t||!rx){res.textContent="—";res.className="shrink-0 text-slate-500";}
  else if(rx.test(t)){res.textContent="🚫 забанит";res.className="shrink-0 text-rose-300 font-medium";}
  else{res.textContent="✓ пропустит";res.className="shrink-0 text-emerald-300 font-medium";}
  const ab=document.getElementById("p403-add-btn"); if(ab){ab.disabled=!gen;ab.style.opacity=gen?"":"0.4";ab.style.cursor=gen?"":"not-allowed";}   // no path → button off (no ugly warning)
}
function p403FillTarget(){
  const sel=document.getElementById("p403-target");if(!sel)return;
  const prev=sel.value, rules=_p403.rules||[], mainId=_mainRules.path_id;
  const main=rules.find(r=>String(r.id)===String(mainId));
  let opts="";
  if(main)opts+=`<option value="${esc(main.id)}">★ ${esc(main.name)} (основное)</option>`;
  rules.filter(r=>String(r.id)!==String(mainId)).forEach(r=>{opts+=`<option value="${esc(r.id)}">${r.enabled!==false?'':'(выкл) '}${esc(r.name)}</option>`;});
  opts+=`<option value="__new__">＋ новое правило</option>`;
  sel.innerHTML=opts;
  if(prev&&Array.from(sel.options).some(o=>o.value===prev))sel.value=prev;
  else sel.value="__new__";   // по умолчанию — НОВОЕ правило (дописать в существующее — в «дополнительно»)
  p403TargetChange();
}
function p403FormToggle(force){
  const b=document.getElementById("p403-form-body"),ch=document.getElementById("p403-form-chev");
  const open=force!=null?force:b.classList.contains("hidden");
  b.classList.toggle("hidden",!open); if(ch)ch.textContent=open?"▾":"▸";
}
function p403TargetChange(){
  const sel=document.getElementById("p403-target");if(!sel)return;
  const isNew=sel.value==="__new__", name=document.getElementById("p403-name"), grp=document.getElementById("p403-group");
  name.disabled=!isNew; name.classList.toggle("opacity-40",!isNew);
  name.placeholder=isNew?"напр. env-файлы":"— (имя только для нового)";
  if(grp){ grp.disabled=!isNew; grp.classList.toggle("opacity-40",!isNew);
    if(grp.options.length===0||grp.dataset.k!==Object.keys(_banGroupInfo.groups).join(","))
      { grp.innerHTML=_groupOptions(""); grp.dataset.k=Object.keys(_banGroupInfo.groups).join(","); } }
}
async function p403SetGroup(id,group){
  const r=(_p403.rules||[]).find(x=>String(x.id)===String(id));if(!r)return;
  const res=await _post("/api/path_rule",{id:r.id,name:r.name,pattern:r.pattern,enabled:r.enabled!==false,group});
  if(res.ok)loadP403(); else uiAlert("не удалось сменить группу: "+(res.error||"?"));
}
async function p403Save(){
  const mode=document.getElementById("p403-mode").value;
  const raw=document.getElementById("p403-raw").value.trim();
  const pattern=p403GenPattern(mode,raw);
  const force=document.getElementById("p403-force").checked;
  const msg=document.getElementById("p403-msg");
  const target=document.getElementById("p403-target").value;
  if(!pattern){return;}   // button is disabled when empty — no jarring warning
  msg.textContent="…";msg.className="text-xs text-slate-400";
  const _clear=()=>{document.getElementById("p403-raw").value="";document.getElementById("p403-force").checked=false;p403Preview();};
  if(target&&target!=="__new__"){               // дописать в существующее (по умолчанию — основное ★)
    const r=(_p403.rules||[]).find(x=>String(x.id)===String(target));
    if(!r){msg.textContent="правило не найдено";msg.className="text-xs text-rose-300";return;}
    const parts=_p403TopSplit(_p403Unwrap(r.pattern||""));
    if(parts.includes(pattern)){msg.textContent="• уже есть в «"+r.name+"»";msg.className="text-xs text-amber-300";return;}
    parts.push(pattern);
    const res=await _post("/api/path_rule",{id:r.id,name:r.name,pattern:"("+parts.join("|")+")",enabled:r.enabled!==false,force,
      groups:r.groups||[],targets:r.targets||[],all:!!r.all});  // сохранить привязку
    if(res.ok){msg.textContent="✓ в «"+r.name+"»";msg.className="text-xs text-emerald-300";_clear();loadP403();}
    else{msg.textContent="✗ "+(res.error||"ошибка");msg.className="text-xs text-rose-300";}
    return;
  }
  // новое правило создаётся НЕ приатаченным (просто запись) — привязку выбираешь
  // потом через attach в строке правила
  const name=document.getElementById("p403-name").value.trim();
  const res=await _post("/api/path_rule",{name,pattern,force,all:false,targets:[],enabled:false});
  if(res.ok&&res.duplicate){msg.textContent="• такое правило уже есть — не дублирую";msg.className="text-xs text-amber-300";loadP403();return;}
  if(res.ok){msg.textContent="✓ создано";msg.className="text-xs text-emerald-300";
    document.getElementById("p403-name").value="";_clear();loadP403();}
  else{msg.textContent="✗ "+(res.error||"ошибка");msg.className="text-xs text-rose-300";}
}
function _p403Pairs(id){return _p403Grp[id]||[{id,backend:_p403Backend(id)}];}
async function p403Toggle(id,enabled){let ok=true;for(const p of _p403Pairs(id)){const res=await _post("/api/path_rule/toggle",{id:p.id,enabled,backend:p.backend});ok=ok&&res.ok;}if(ok)loadP403();else uiAlert("не удалось переключить на всех бэкендах");}
async function p403Delete(id){if(!await uiConfirm("Удалить правило 403?"))return;let ok=true;for(const p of _p403Pairs(id)){const res=await _post("/api/path_rule/delete",{id:p.id,backend:p.backend});ok=ok&&res.ok;}if(ok)loadP403();else uiAlert("не удалось удалить на всех бэкендах");}
function _p403Backend(id){ return ((_p403.rules||[]).find(r=>String(r.id)===String(id))||{}).backend; }
async function p403Master(){
  const on=_p403&&_p403.enabled!==false;
  if(on&&!await uiConfirm("Выключить ВСЮ секцию 403?\nВсе правила по путям перестанут блокировать — сканеры снова будут проходить."))return;
  const res=await _post("/api/path_master",{enabled:!on});
  if(res.ok)loadP403();else uiAlert("не удалось: "+(res.error||"?"));
}
async function p403Seed(){
  if(!await uiConfirm("Добавить базовый набор правил сканеров одним правилом «base-scanners»?\n(повторный засев обновит его, не создаст дубль)"))return;
  const res=await _post("/api/path_seed",{});
  if(res.ok){loadP403();uiAlert("✓ базовый набор добавлен/обновлён.\nЕсли у тебя был свой ручной if в ингрессе — убери его, чтобы не дублировать.");}
  else uiAlert("не удалось: "+(res.error||"?"));
}
function _p403CloseSeedMenu(){const m=document.getElementById("p403-seed-menu");if(m)m.remove();document.removeEventListener("click",_p403SeedOutside,true);}
function _p403SeedOutside(e){const m=document.getElementById("p403-seed-menu");if(m&&!m.contains(e.target))_p403CloseSeedMenu();}
async function p403SeedAutoban(btn){
  _p403CloseSeedMenu();
  let rules=[];try{rules=await ensureAbRules();}catch(e){uiAlert("не удалось получить правила автобана");return;}
  const rc=btn.getBoundingClientRect();
  const m=document.createElement("div");m.id="p403-seed-menu";
  m.className="fixed z-[60] card border-slate-700 p-1.5 text-xs shadow-xl max-h-[320px] overflow-auto";
  m.style.background="#0f141c";m.style.top=(rc.bottom+4)+"px";
  m.style.left=Math.max(8,Math.min(rc.left,window.innerWidth-300))+"px";m.style.width="292px";
  let html=`<div class="text-[10px] text-slate-500 px-1.5 py-1">выбери правило автобана → станет правилом 403</div>`;
  const usable=rules.filter(r=>r.match_type!=="family");
  if(usable.length>1)html+=`<button onclick="p403SeedAutobanGo(null)" class="block w-full text-left px-2 py-1 rounded hover:bg-indigo-500/20 text-indigo-200 font-medium">★ все (${usable.length}) — кроме семейств</button><div class="border-t border-slate-800 my-1"></div>`;
  html+=rules.map(r=>{
    const fam=r.match_type==="family";
    const npath=fam?0:String(r.path||"").split("\n").filter(Boolean).length;
    if(fam)return `<div class="px-2 py-1 text-slate-600">${esc(r.name)} <span class="text-[10px]">— семейство, нельзя</span></div>`;
    return `<button onclick="p403SeedAutobanGo([${r.id}])" class="block w-full text-left px-2 py-1 rounded hover:bg-indigo-500/20 text-slate-200">${r.enabled?'🟢':'⚪'} ${esc(r.name)} <span class="text-slate-600">· ${npath} пут.</span></button>`;
  }).join("")||'<div class="px-2 py-1.5 text-slate-500">нет правил автобана.</div>';
  m.innerHTML=html;document.body.appendChild(m);
  setTimeout(()=>document.addEventListener("click",_p403SeedOutside,true),0);
}
async function p403SeedAutobanGo(ids){
  _p403CloseSeedMenu();
  const res=await _post("/api/path_seed_autoban", ids?{ids}:{});
  if(res.ok){loadP403();
    const c=(res.created||[]).length, sk=(res.skipped||[]);
    let m="✓ создано/обновлено: "+c+(c?(" ("+(res.created||[]).join(", ")+")"):"");
    if(sk.length)m+="\nпропущено: "+sk.map(x=>x.name+" ("+x.reason+")").join(", ");
    uiAlert(m);}
  else uiAlert("не удалось: "+(res.error||"?"));
}
async function p403AddPath(path,el){
  const pat=_pathToPattern(path);
  // уже ловится существующим правилом?
  try{
    const d=await fetch("/api/path_rules").then(r=>r.json());
    const hit=(d.rules||[]).filter(r=>r.enabled!==false).find(r=>{try{return new RegExp(r.pattern,"i").test(path);}catch(e){return false;}});
    if(hit&&!await uiConfirm("Путь «"+path+"» уже ловится правилом «"+(hit.name||hit.id)+"».\nВсё равно добавить отдельным правилом?")){
      if(el){el.innerHTML="уже ловится";el.disabled=true;}return;}
  }catch(e){}
  const res=await _post("/api/path_rule",{name:"путь "+String(path).slice(0,40),pattern:pat});
  if(res.ok&&res.duplicate){if(el){el.innerHTML="уже есть";el.disabled=true;}return;}
  if(el){el.innerHTML=res.ok?"✓ 403":"✗";el.disabled=true;if(res.ok)el.className+=" text-rose-300";}
  if(res.ok&&_view==="p403")loadP403();
  if(!res.ok)uiAlert("не удалось добавить в 403: "+(res.error||"?"));
}
function abMtypeChange(){
  const mt=document.getElementById("ab-mtype").value, fam=mt==="family", rate=mt==="rate";
  document.getElementById("ab-family").classList.toggle("hidden",!fam);
  // rate has no path/family at all: hide path inputs, the "+ OR" button, the combine box
  document.getElementById("ab-paths").classList.toggle("hidden",fam||rate);
  document.getElementById("ab-add-or").classList.toggle("hidden",fam||rate);
  document.getElementById("ab-combine-wrap").classList.toggle("hidden",fam||rate);
  document.getElementById("ab-rate-hint").classList.toggle("hidden",!rate);
}
function abPathRow(value){
  const wrap=document.createElement("div");wrap.className="flex gap-1.5 ab-path-row";
  wrap.innerHTML=`<input class="ab-path-inp flex-1 input mono" placeholder="/wp-login.php">
    <button type="button" onclick="this.parentElement.remove();abFixOr()" class="ab-path-del px-2 rounded bg-slate-800 text-slate-500 hover:text-red-300 hover:bg-slate-700 text-xs" title="убрать">✕</button>`;
  wrap.querySelector("input").value=value||"";
  return wrap;
}
function abFixOr(){
  // hide the ✕ when only one row remains (can't remove the last path)
  const rows=document.querySelectorAll("#ab-paths .ab-path-row");
  rows.forEach(r=>r.querySelector(".ab-path-del").style.visibility=rows.length>1?"visible":"hidden");
}
function abAddPath(value){document.getElementById("ab-paths").appendChild(abPathRow(value));abFixOr();}
function abRenderPaths(values){
  const c=document.getElementById("ab-paths");c.innerHTML="";
  (values&&values.length?values:[""]).forEach(v=>c.appendChild(abPathRow(v)));abFixOr();
}
function abPathValues(){return Array.from(document.querySelectorAll("#ab-paths .ab-path-inp")).map(i=>i.value.trim()).filter(Boolean);}
// белый список путей (предохранитель — автобан их не считает)
function renderAbIgnore(){
  const el=document.getElementById("ab-ignore");if(!el)return;
  el.innerHTML=_abIgnore.length?_abIgnore.map((p,i)=>`<span class="flex items-center gap-1 px-2 py-1 rounded bg-emerald-500/10 text-emerald-200 border border-emerald-500/25 text-[11px] mono">${esc(p)}<button onclick="abIgnoreDel(${i})" class="text-emerald-400/60 hover:text-red-300" title="убрать">✕</button></span>`).join(""):'<span class="text-slate-600 text-xs">список пуст — автобан считает все пути</span>';
}
function abIgnoreAdd(){
  const inp=document.getElementById("ab-ignore-inp"), v=(inp.value||"").trim();
  if(!v)return;
  if(!_abIgnore.includes(v))_abIgnore.push(v);
  inp.value="";renderAbIgnore();
  document.getElementById("ab-ignore-msg").textContent="не забудь «Сохранить»";
  document.getElementById("ab-ignore-msg").className="text-[11px] text-amber-300";
}
function abIgnoreDel(i){_abIgnore.splice(i,1);renderAbIgnore();
  document.getElementById("ab-ignore-msg").textContent="не забудь «Сохранить»";
  document.getElementById("ab-ignore-msg").className="text-[11px] text-amber-300";}
async function abIgnoreSave(){
  const msg=document.getElementById("ab-ignore-msg");msg.textContent="сохраняю…";msg.className="text-[11px] text-slate-500";
  try{const d=await fetch("/api/autoban/ignore",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({paths:_abIgnore})}).then(r=>r.json());
    if(!d.ok){msg.textContent="ошибка: "+(d.error||"?");msg.className="text-[11px] text-red-300";return;}
    _abIgnore=d.ignore_paths||[];renderAbIgnore();msg.textContent="✓ сохранено";msg.className="text-[11px] text-emerald-300";
  }catch(e){msg.textContent="ошибка: "+(e.message||e);msg.className="text-[11px] text-red-300";}
}
// ── threat feeds (#2) ──────────────────────────────────────────────────────
let _tf={feeds:[],presets:[],status:{},enabled:false};
async function loadThreatFeeds(){
  const en0=document.getElementById("tf-enabled"); if(!en0)return;   // section lives in Settings now
  try{ _tf=await (await fetch("/api/threat_feeds")).json(); }catch(e){ return; }
  en0.classList.toggle("on",!!_tf.enabled);
  document.getElementById("tf-body").classList.toggle("hidden",!_tf.enabled);
  const g=document.getElementById("tf-group"); if(g&&!g.value)g.value=_tf.group||"";
  const rf=document.getElementById("tf-refresh"); if(rf)rf.value=_tf.refresh_hours||6;
  document.getElementById("tf-presets").innerHTML=(_tf.presets||[]).map((p,i)=>
    `<button onclick="tfPreset(${i})" class="tray-chip">+ ${esc(p.name)}</button>`).join("");
  renderThreatFeeds();
}
function _tfAgo(ts){ if(!ts)return ""; const d=Math.floor(Date.now()/1000)-ts; return d<60?d+"s":d<3600?Math.floor(d/60)+"m":d<86400?Math.floor(d/3600)+"h":Math.floor(d/86400)+"d"; }
function renderThreatFeeds(){
  const el=document.getElementById("tf-list");
  if(!_tf.feeds.length){ el.innerHTML=`<div class="text-slate-600 text-[11px]">${_trText("нет фидов — добавь свой или возьми из пресетов ниже.")}</div>`; return; }
  el.innerHTML=_tf.feeds.map((f,i)=>{
    const st=(_tf.status||{})[f.name];
    const badge=st?(st.ok?`<span class="text-emerald-400">✓ ${st.count} · ${_tfAgo(st.ts)}</span>`:`<span class="text-red-300">✗ ${esc((st.error||"").slice(0,40))}</span>`):"";
    return `<div class="flex flex-wrap items-center gap-2 text-[11px]" data-tf="${i}">
      <button type="button" class="sw${f.enabled?' on':''}" onclick="this.classList.toggle('on')" aria-label="toggle feed"></button>
      <input data-tff="name" value="${esc(f.name||'')}" placeholder="name" class="input w-32">
      <input data-tff="url" value="${esc(f.url||'')}" placeholder="https://…/list.txt" class="input mono flex-1 min-w-[200px]">
      ${badge}
      <button onclick="tfDel(${i})" class="px-2 py-1 rounded text-red-400 hover:bg-red-500/10">✕</button>
    </div>`;}).join("");
}
function _tfSync(){ _tf.feeds=[...document.querySelectorAll("#tf-list [data-tf]")].map(d=>({
  name:d.querySelector('[data-tff="name"]').value.trim(),
  url:d.querySelector('[data-tff="url"]').value.trim(),
  enabled:d.querySelector('.sw').classList.contains('on')})); }
function tfToggle(btn){ const on=!btn.classList.contains("on"); btn.classList.toggle("on",on);
  document.getElementById("tf-body").classList.toggle("hidden",!on); tfSave(); }
function tfAdd(){ _tfSync(); _tf.feeds.push({name:"",url:"",enabled:true}); renderThreatFeeds(); }
function tfDel(i){ _tfSync(); _tf.feeds.splice(i,1); renderThreatFeeds(); }
function tfPreset(i){ _tfSync(); const p=_tf.presets[i]; if(p&&!_tf.feeds.some(f=>f.url===p.url))_tf.feeds.push({name:p.name,url:p.url,enabled:true}); renderThreatFeeds(); }
async function tfSave(){
  _tfSync(); const msg=document.getElementById("tf-msg"); msg.textContent=_trText("сохраняю…");
  const body={feeds:_tf.feeds,enabled:document.getElementById("tf-enabled").classList.contains("on"),
    group:document.getElementById("tf-group").value.trim(),refresh_hours:document.getElementById("tf-refresh").value};
  try{ const d=await (await fetch("/api/threat_feeds",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})).json();
    msg.textContent=d.ok?"✓":(_trText("ошибка")); loadThreatFeeds();
  }catch(e){ msg.textContent="✗ "+e.message; }
}
async function tfRefresh(btn){
  const msg=document.getElementById("tf-msg"); btn.disabled=true; const o=btn.textContent; btn.textContent=_trText("обновляю…");
  try{ const d=await (await fetch("/api/threat_feeds/refresh",{method:"POST"})).json();
    msg.textContent=d.ok?("✓ "+_trText("забанено: ")+d.banned):("✗ "+(d.error||"")); loadThreatFeeds();
  }catch(e){ msg.textContent="✗ "+e.message; } finally{ btn.disabled=false; btn.textContent=o; }
}
// проверить IP — забанен ли и за что
async function abWhy(){
  const ip=(document.getElementById("ab-why-ip").value||"").trim(), out=document.getElementById("ab-why");
  if(!ip){out.innerHTML='<span class="text-amber-300 text-xs">введи IP</span>';return;}
  out.innerHTML='<span class="text-slate-500 text-xs">проверяю…</span>';
  try{
    const d=await fetch("/api/autoban/why?ip="+encodeURIComponent(ip)).then(r=>r.json());
    if(d.error){out.innerHTML=`<span class="text-red-300 text-xs">${esc(d.error)}</span>`;return;}
    if(!d.banned){
      out.innerHTML=`<div class="card border-emerald-500/25 bg-emerald-500/5 p-3">
        <div class="text-emerald-300 text-sm">✓ <span class="mono">${esc(ip)}</span> НЕ в денлисте — автобаном/блоклистом не банился.${d.static_deny?' <span class="text-amber-300">(но это приватный/уже-denied статический диапазон)</span>':''}</div>
        <div class="text-[11px] text-slate-500 mt-1">Если у него есть 403 — он от nginx-правила (сканер-блок) или приложения, не от нашего бана.</div>
        <button onclick="openProfile('${escJs(ip)}')" class="text-[11px] mt-2 px-2 py-1 rounded bg-slate-700/50 text-slate-300 hover:bg-slate-700">профиль IP →</button></div>`;
      return;
    }
    const e=d.entry||{}, tt=!e.ttl?"навсегда":(e.ttl>=86400?(e.ttl/86400)+"д":(e.ttl>=3600?(e.ttl/3600)+"ч":e.ttl+"с"));
    const ruleChip=d.rule?`<span class="px-1.5 py-0.5 rounded bg-indigo-500/15 text-indigo-300 text-[10px] border border-indigo-500/30">🤖 правило: ${esc(d.rule)}</span>`:"";
    let html=`<div class="card border-red-500/30 bg-red-500/5 p-3 mb-2">
      <div class="flex items-center gap-2 flex-wrap mb-1"><span class="text-red-300 font-medium">⛔ забанен</span>${ruleChip}<span class="text-[11px] text-slate-500">источник: ${esc(d.by||"?")}</span></div>
      <div class="text-xs text-slate-300">CIDR: <span class="mono">${esc(e.cidr||"")}</span> ${cfBadge((e.cidr||'').split('/')[0])}</div>
      <div class="text-xs text-slate-400">причина: ${esc(e.reason||"—")}</div>
      <div class="text-[11px] text-slate-500">забанен: ${dt(e.ts)} · TTL: ${tt}</div>`;
    const pp=d.paths||[];
    if(pp.length){
      const show=pp.slice(0,2).map(x=>`<span class="mono text-amber-300">${esc(x.path)}</span> <span class="text-slate-500">(${fmt(x.count)})</span>`).join(", ");
      const more=pp.length>2?` <span class="text-slate-500">и ещё ${pp.length-2} ${pp.length-2===1?"путь":"путей"}</span>`:"";
      html+=`<div class="text-xs text-slate-300 mt-1.5">сошлось по путям (24ч): ${show}${more}</div>`;
    }else{
      html+=`<div class="text-[11px] text-slate-500 mt-1.5">примеры путей не найдены (активность старше 24ч)</div>`;
    }
    html+=`</div>`;
    if(d.audit&&d.audit.length){
      const act={block:"⛔ бан",unblock:"↩ разбан",expire:"⌛ истёк"};
      html+=`<div class="text-[11px] text-slate-500 mb-1">история (audit):</div>`+d.audit.map(a=>`<div class="text-[11px] text-slate-400 flex gap-2 py-0.5"><span class="mono text-slate-500 w-28 shrink-0">${dt(a.ts)}</span><span class="shrink-0">${act[a.action]||esc(a.action)}</span><span class="mono shrink-0">${esc(a.cidr)}</span><span class="text-slate-500 truncate" title="${esc(a.note||'')}">${esc(a.note||"")}</span></div>`).join("");
    }
    out.innerHTML=html;
  }catch(e){out.innerHTML=`<span class="text-red-300 text-xs">ошибка: ${esc(e.message||String(e))}</span>`;}
}
// имя правила из reason вида "автобан · <rule> · ≥N/окно"
function abRuleFromReason(reason){
  const m=/^автобан\s*·\s*([^·]+?)\s*·/.exec(reason||"");
  return m?m[1].trim():null;
}
// логи автобана — берём из audit blocklist-api (by="autoban")
async function loadAbLog(){
  const el=document.getElementById("ab-log"), sum=document.getElementById("ab-log-sum");
  try{
    const d=await fetch("/api/autoban/log?limit=300").then(r=>r.json());
    _abLogRows=d.log||[]; _abLogPage=0;
    _renderAbLogPage();
  }catch(e){el.innerHTML=`<div class="text-red-300 text-xs">ошибка загрузки логов: ${esc(e.message||String(e))}</div>`;sum.textContent="";}
}
function _renderAbLogPage(){
  const el=document.getElementById("ab-log"), sum=document.getElementById("ab-log-sum");
  if(!el)return;
  const rows=_abLogRows;
  sum.textContent=rows.length?`${rows.length} событий автобана (последние сверху)`:"событий автобана пока нет";
  if(!rows.length){el.innerHTML='<div class="text-slate-600 text-xs">Автобан ещё никого не банил (или kill-switch был выключен).</div>';return;}
  const pages=Math.ceil(rows.length/_AB_LOG_PER);
  if(_abLogPage>=pages)_abLogPage=pages-1; if(_abLogPage<0)_abLogPage=0;
  const page=rows.slice(_abLogPage*_AB_LOG_PER,_abLogPage*_AB_LOG_PER+_AB_LOG_PER);
  const act={block:"⛔ бан",unblock:"↩ разбан",expire:"⌛ истёк"};
  const body=page.map(e=>{const rule=abRuleFromReason(e.note);
    const ip=(e.cidr||'').split('/')[0];
    const pp=e.paths||[];
    const pathStr=pp.length?pp.slice(0,2).map(x=>`<span class="mono text-amber-300">${esc(x.path)}</span> <span class="text-slate-600">(${fmt(x.count)})</span>`).join(", ")+(pp.length>2?` <span class="text-slate-600">+${pp.length-2}</span>`:""):'<span class="text-slate-600">пути не сохранены</span>';
    const isBlock=e.action==="block", active=e.active;
    const action=isBlock?(active?`<button onclick="abLogUnban('${escJs(e.cidr)}',this)" class="text-[11px] px-2 py-0.5 rounded bg-slate-700/50 text-slate-300 hover:bg-slate-700">↩ разбан</button>`:`<span class="text-[11px] text-slate-600">снят</span>`):"";
    return `<div class="flex items-center gap-2 text-xs py-1.5 border-b border-slate-800/60${isBlock&&!active?' opacity-50':''}">
      <span class="text-slate-500 mono whitespace-nowrap shrink-0">${dt(e.ts)}</span>
      <span class="shrink-0">${act[e.action]||esc(e.action)}</span>
      <span class="mono text-slate-200 cursor-pointer hover:text-indigo-300 shrink-0" onclick="openProfile('${escJs(ip)}')">${esc(e.cidr)}</span>${cfBadge(ip)}
      ${rule?`<span class="px-1.5 py-0.5 rounded bg-indigo-500/15 text-indigo-300 text-[10px] border border-indigo-500/30 shrink-0">${esc(rule)}</span>`:""}
      <span class="text-[11px] text-slate-500 flex-1 min-w-0 truncate" title="сошлось по путям">${pathStr}</span>
      <span class="shrink-0">${action}</span>
    </div>`;}).join("");
  const pager=pages>1?`<div class="flex items-center justify-between mt-2 text-[11px] text-slate-500">
      <button onclick="_abLogPage--;_renderAbLogPage()" ${_abLogPage<=0?"disabled":""} class="px-2 py-0.5 rounded bg-slate-800 ${_abLogPage<=0?"opacity-40":"hover:bg-slate-700"}">←</button>
      <span>стр. ${_abLogPage+1}/${pages}</span>
      <button onclick="_abLogPage++;_renderAbLogPage()" ${_abLogPage>=pages-1?"disabled":""} class="px-2 py-0.5 rounded bg-slate-800 ${_abLogPage>=pages-1?"opacity-40":"hover:bg-slate-700"}">→</button>
    </div>`:"";
  el.innerHTML=body+pager;
}
async function abLogUnban(cidr,btn){
  if(!await uiConfirm("Разбанить "+cidr+"?"))return;
  if(btn){btn.disabled=true;btn.textContent="…";}
  try{const r=await fetch("/api/unblock",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({cidr})}).then(x=>x.json());
    if(r.ok){loadAbLog();if(typeof renderBlocklist==="function")renderBlocklist();}
    else{uiAlert("Не удалось: "+(r.error||"ошибка"));if(btn){btn.disabled=false;btn.textContent="↩ разбан";}}
  }catch(e){uiAlert("Ошибка: "+(e.message||e));if(btn){btn.disabled=false;btn.textContent="↩ разбан";}}
}
// готовые пути по группам — клик добавляет в условие текущего правила
const AB_PRESETS=[
  {g:"Секреты / dotfiles",p:["/.env","/.env.local","/.env.backup","/.env.prod","/.git/config","/.git/HEAD","/.aws/credentials","/.ssh/id_rsa","/.npmrc","/.htpasswd","/.DS_Store"]},
  {g:"WordPress",p:["/wp-login.php","/wp-admin","/xmlrpc.php","/wp-config.php","/wp-config.php.bak","/wlwmanifest.xml","/wp-content/uploads","/wp-json/wp/v2/users"]},
  {g:"Админки / БД",p:["/phpmyadmin","/pma","/myadmin","/adminer.php","/adminer","/dbadmin","/mysql","/phpMyAdmin","/sqlite","/pgadmin"]},
  {g:"Конфиги / бэкапы",p:["/config.php","/configuration.php","/web.config","/application.yml","/docker-compose.yml","/config/parameters.yml","/backup.sql","/dump.sql","/database.sql","/.env.example",".bak",".sql",".zip",".tar.gz"]},
  {g:"App-server / framework",p:["/actuator","/actuator/env","/actuator/health","/_profiler","/_ignition/execute-solution","/server-status","/server-info","/manager/html","/console/login","/solr/","/vendor/phpunit"]},
  {g:"CVE / роутеры / RCE",p:["/boaform/admin/formLogin","/HNAP1","/GponForm/diag_Form","/wls-wsat/CoordinatorPortType","/cgi-bin/","/.well-known/openvpn","/latest/meta-data","/computeMetadata"]},
];
// добавить путь (из профиля / запросов) в одно из существующих правил автобана
async function ensureAbRules(force){
  if(_abRules&&!force)return _abRules;
  try{const d=await fetch("/api/autoban/rules").then(r=>r.json());_abRules=d.rules||[];}catch(e){_abRules=[];}
  return _abRules;
}
function _abCloseMenu(){const m=document.getElementById("ab-path-menu");if(m)m.remove();document.removeEventListener("click",_abMenuOutside,true);}
function _abMenuOutside(e){const m=document.getElementById("ab-path-menu");if(m&&!m.contains(e.target))_abCloseMenu();}
async function abPathMenu(path,btn){
  _abCloseMenu();
  const [abrules,p403d]=await Promise.all([
    ensureAbRules().then(rs=>rs.filter(r=>r.match_type!=="family")).catch(()=>[]),
    fetch("/api/path_rules").then(r=>r.json()).catch(()=>({rules:[]})),
    loadMainRules()]);
  const p403rules=p403d.rules||[];
  const rc=btn.getBoundingClientRect();
  const m=document.createElement("div");m.id="ab-path-menu";m.dataset.p=path;
  m.className="fixed z-[60] card border-slate-700 p-1.5 text-xs shadow-xl max-h-[320px] overflow-auto";
  m.style.background="#0f141c";m.style.top=(rc.bottom+4)+"px";
  m.style.left=Math.max(8,Math.min(rc.left,window.innerWidth-252))+"px";m.style.width="244px";
  let html=`<div class="text-[10px] text-slate-500 px-1.5 py-1 truncate" title="${esc(path)}">путь: <span class="mono text-amber-300">${esc(path)}</span></div>`;
  const mainP=(p403rules.find(r=>String(r.id)===String(_mainRules.path_id))||{}).name;
  const mainA=(abrules.find(r=>String(r.id)===String(_mainRules.autoban_id))||{}).name;
  html+=`<button onclick="addToMainFromMenu(this)" class="block w-full text-left px-2 py-1.5 rounded bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-200 font-medium">➕ в основные (403 + автобан)</button>`;
  html+=`<div class="text-[9px] text-slate-600 px-1.5 pb-1">${mainP?("403: "+esc(mainP)):'<span class="text-amber-400">403 не выбрано ★</span>'} · ${mainA?("автобан: "+esc(mainA)):'<span class="text-amber-400">автобан не выбрано ★</span>'}</div>`;
  html+=`<div class="border-t border-slate-800 my-1"></div><div class="text-[10px] text-slate-600 px-1.5 py-0.5">🚫 добавить в правило 403:</div>`;
  if(p403rules.length)html+=p403rules.map(r=>`<button onclick="p403AppendToRule('${escJs(r.id)}',this)" class="block w-full text-left px-2 py-1 rounded hover:bg-rose-500/20 text-slate-200">${r.enabled!==false?'🟢':'⚪'} ${esc(r.name)}</button>`).join("");
  html+=`<button onclick="p403AddPathFromMenu(this)" class="block w-full text-left px-2 py-1 rounded hover:bg-rose-500/20 text-rose-300">＋ новое 403-правило</button>`;
  html+=`<div class="border-t border-slate-800 my-1"></div><div class="text-[10px] text-slate-600 px-1.5 py-0.5">⛔ в автобан (бан IP по порогу):</div>`;
  if(abrules.length)html+=abrules.map(r=>`<button onclick="abAddPathToRule(${r.id},this)" class="block w-full text-left px-2 py-1 rounded hover:bg-indigo-500/20 text-slate-200">${r.enabled?'🟢':'⚪'} ${esc(r.name)} <span class="text-slate-600">≥${r.threshold}/${r.window}</span></button>`).join("");
  else html+=`<div class="px-2 py-1.5 text-slate-500">нет автобан-правил с путями.<br><a onclick="_abCloseMenu();showView('autoban')" class="text-indigo-300 cursor-pointer">создать правило →</a></div>`;
  m.innerHTML=html;document.body.appendChild(m);
  setTimeout(()=>document.addEventListener("click",_abMenuOutside,true),0);
}
async function p403AppendToRule(ruleId,el){
  const menu=document.getElementById("ab-path-menu");const path=menu?menu.dataset.p:"";
  if(!path)return;
  try{
    const d=await fetch("/api/path_rules").then(r=>r.json());
    const r=(d.rules||[]).find(x=>String(x.id)===String(ruleId));
    if(!r){el.innerHTML="нет правила";return;}
    const parts=_p403TopSplit(_p403Unwrap(r.pattern||""));
    const e=_reEsc(path);
    if(parts.includes(e)){el.innerHTML="✓ уже есть";el.disabled=true;setTimeout(_abCloseMenu,800);return;}
    parts.push(e);
    const res=await _post("/api/path_rule",{id:r.id,name:r.name,pattern:"("+parts.join("|")+")",enabled:r.enabled!==false});
    el.innerHTML=res.ok?"✓ добавлено":"✗ "+(res.error||"ошибка");el.disabled=true;if(res.ok)el.className+=" text-emerald-300";
    if(res.ok&&_view==="p403")loadP403();
    setTimeout(_abCloseMenu,900);
  }catch(e){el.innerHTML="ошибка";}
}
function p403AddPathFromMenu(el){
  const menu=document.getElementById("ab-path-menu");const path=menu?menu.dataset.p:"";
  if(!path)return;
  p403AddPath(path,el);
  setTimeout(_abCloseMenu,800);
}
function addToMainFromMenu(el){
  const menu=document.getElementById("ab-path-menu");const path=menu?menu.dataset.p:"";
  if(!path)return;
  addToMain(path,el);
  setTimeout(_abCloseMenu,1400);
}
async function abAddPathToRule(id,el){
  const menu=document.getElementById("ab-path-menu");const path=menu?menu.dataset.p:"";
  if(!path)return;
  try{const d=await fetch("/api/autoban/add_path",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id,path})}).then(r=>r.json());
    el.innerHTML=d.already?"✓ уже есть":(d.ok?"✓ добавлено":"ошибка: "+(d.error||"?"));
    el.disabled=true;el.className+=" text-emerald-300";
    _abRules=null; if(_view==="autoban")loadAutoban();
    setTimeout(_abCloseMenu,800);
  }catch(e){el.textContent="ошибка";}
}
// строка пути с кнопкой «+автобан» (профиль)
function abPathRows(arr){
  return (arr||[]).map(x=>{const k=String(x.key);
    return `<div class="flex justify-between items-center text-xs gap-1">
      <span class="mono text-slate-300 truncate" title="${esc(k)}">${esc(k.slice(0,40))}</span>
      <span class="flex items-center gap-1 shrink-0"><span class="mono text-amber-300">${fmt(x.count)}</span>
      <button data-p="${escAttr(k)}" onclick="abPathMenu(this.dataset.p,this)" title="добавить путь в правило (403 или автобан)" class="text-[10px] px-1 rounded bg-slate-800 text-indigo-300 hover:bg-indigo-500/20">+ правило</button></span></div>`;
  }).join("")||'<span class="text-slate-600 text-xs">—</span>';
}
function renderAbPresets(){
  const el=document.getElementById("ab-presets");if(!el)return;
  el.innerHTML=AB_PRESETS.map((grp,gi)=>`<div>
    <div class="flex items-center gap-2 mb-1.5">
      <span class="text-[11px] uppercase tracking-wide text-slate-500">${esc(grp.g)}</span>
      <button onclick="abAddPresetGroup(${gi})" class="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-indigo-300 hover:bg-slate-700">+ все</button>
    </div>
    <div class="flex flex-wrap gap-1.5">${grp.p.map(p=>`<button onclick="abAddPresetPath('${escJs(p).replace(/'/g,"\\'")}')" class="text-[11px] px-2 py-1 rounded bg-slate-800/70 text-slate-300 hover:bg-indigo-500/20 hover:text-indigo-200 mono border border-slate-700/50">${esc(p)}</button>`).join("")}</div>
  </div>`).join("");
}
function _abEnsurePathMode(){
  // пресеты — это явные пути; если выбрано «семейство», переключаем на «путь содержит»
  const mt=document.getElementById("ab-mtype");
  if(mt.value==="family"){mt.value="substring";abMtypeChange();}
}
function abAddPresetPath(p){
  _abEnsurePathMode();
  const cur=abPathValues();
  if(cur.includes(p))return;   // уже добавлен
  // если есть пустая строка — заполним её, иначе добавим новую
  const empty=Array.from(document.querySelectorAll("#ab-paths .ab-path-inp")).find(i=>!i.value.trim());
  if(empty)empty.value=p; else abAddPath(p);
  abFixOr();
}
function abAddPresetGroup(gi){
  _abEnsurePathMode();
  (AB_PRESETS[gi]||{p:[]}).p.forEach(abAddPresetPath);
}
function abCardToggle(bodyId,chevId,force){
  const b=document.getElementById(bodyId), c=document.getElementById(chevId);
  if(!b)return;
  const open=(force!==undefined)?force:b.classList.contains("hidden");
  b.classList.toggle("hidden",!open);
  if(c)c.textContent=open?"▾":"▸";
}
function abMode(m){
  abCardToggle("ab-form-body","ab-form-chev",true);   // клик по табу раскрывает форму
  const json=m==="json";
  document.getElementById("ab-json-panel").classList.toggle("hidden",!json);
  document.getElementById("ab-form-panel").classList.toggle("hidden",json);
  const on="bg-indigo-500/25 text-indigo-200 border border-indigo-500/40", off="bg-slate-800 text-slate-400 hover:bg-slate-700";
  document.getElementById("ab-tab-form").className="text-[11px] px-2 py-1 rounded "+(json?off:on);
  document.getElementById("ab-tab-json").className="text-[11px] px-2 py-1 rounded "+(json?on:off);
  if(json)abFormToJson();
}
// единый формат правила (то, что я буду тебе присылать)
function abRuleToObj(){
  const p=abFormPayload();
  const o={name:p.name,match_type:p.match_type};
  if(p.match_type==="family")o.family=p.path; else o.paths=p.path?p.path.split("\n"):[];
  o.threshold=p.threshold;o.window=p.window;o.combine=!!p.combine;o.ttl=p.ttl;o.status=p.status;o.enabled=!!p.enabled;
  return o;
}
function abFormToJson(){document.getElementById("ab-json").value=JSON.stringify(abRuleToObj(),null,2);}
function abApplyObj(r){
  // нормализуем: paths[] | path("a\nb") | family
  _abEditId=null;
  document.getElementById("ab-form-title").textContent="Создать новое правило";
  document.getElementById("ab-cancel").classList.add("hidden");
  document.getElementById("ab-name").value=r.name||"";
  const mt=r.match_type||(r.family?"family":"substring");
  document.getElementById("ab-mtype").value=mt;abMtypeChange();
  if(mt==="family"){document.getElementById("ab-family").value=r.family||r.path||"";abRenderPaths([""]);}
  else{let paths=Array.isArray(r.paths)?r.paths:(typeof r.path==="string"?r.path.split("\n"):[]);abRenderPaths(paths.filter(Boolean).length?paths.filter(Boolean):[""]);}
  document.getElementById("ab-status").value=r.status||"";
  document.getElementById("ab-threshold").value=r.threshold||1;
  document.getElementById("ab-window").value=r.window||"10m";
  document.getElementById("ab-ttl").value=String(r.ttl!=null?r.ttl:0);
  document.getElementById("ab-combine").checked=(r.combine!==false&&r.combine!==0);
}
function _abParseJson(){
  const raw=document.getElementById("ab-json").value.trim(), msg=document.getElementById("ab-json-msg");
  if(!raw){msg.textContent="пусто";msg.className="text-[12px] text-amber-300";return null;}
  try{return JSON.parse(raw);}catch(e){msg.textContent="не JSON: "+e.message;msg.className="text-[12px] text-red-300";return null;}
}
function abJsonToForm(){
  const d=_abParseJson();if(d==null)return;
  const r=Array.isArray(d)?d[0]:d;
  if(Array.isArray(d)&&d.length>1)document.getElementById("ab-json-msg").textContent="массив: загрузил первое, для пачки жми «Сохранить из JSON»";
  else document.getElementById("ab-json-msg").textContent="✓ загружено в форму";
  document.getElementById("ab-json-msg").className="text-[12px] text-emerald-300";
  abApplyObj(r);abMode("form");
}
async function abSaveFromJson(){
  const d=_abParseJson();if(d==null)return;
  const arr=Array.isArray(d)?d:[d], msg=document.getElementById("ab-json-msg");
  // приводим к payload бэкенда: family→path, paths[]→"a\nb"
  const toPayload=r=>({name:r.name,match_type:r.match_type||(r.family?"family":"substring"),
    path:(r.match_type==="family"||r.family)?(r.family||r.path||""):(Array.isArray(r.paths)?r.paths.join("\n"):(r.path||"")),
    status:r.status||"",threshold:r.threshold||1,window:r.window||"10m",ttl:r.ttl!=null?r.ttl:0,
    combine:(r.combine!==false&&r.combine!==0)?1:0,enabled:r.enabled?1:0});
  msg.textContent="сохраняю…";msg.className="text-[12px] text-slate-500";
  let ok=0,fail=0;
  for(const r of arr){
    try{const res=await fetch("/api/autoban/rule",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(toPayload(r))}).then(x=>x.json());res.ok?ok++:fail++;}
    catch(e){fail++;}
  }
  msg.textContent=`✓ сохранено: ${ok}${fail?(", ошибок: "+fail):""}`;msg.className="text-[12px] "+(fail?"text-amber-300":"text-emerald-300");
  loadAutoban();
}
let _abGroups=[], _abDefaultGroup="";
function abFillSelects(){
  document.getElementById("ab-window").innerHTML=_abWindows.map(w=>`<option value="${w}"${w==="10m"?" selected":""}>${w}</option>`).join("");
  document.getElementById("ab-family").innerHTML=_abFamilies.map(f=>`<option value="${f.key}">${esc(f.label)}</option>`).join("");
  abFillGroups();
}
function abFillGroups(){
  const sel=document.getElementById("ab-group");if(!sel)return;
  const cur=sel.value;
  sel.innerHTML=`<option value="">${_trText("все таргеты")}</option>`+_abGroups.map(g=>`<option value="${esc(g)}">${esc(g)}</option>`).join("");
  if(cur)sel.value=cur;
}
// Эскалацию и «защищённые пути» (вспомогательные) опускаем под список правил —
// чтобы сверху сразу были правила автобана. Делается один раз.
let _abReordered=false;
function _abReorder(){
  if(_abReordered)return;
  const r=document.getElementById("ab-rules-sec"),e=document.getElementById("ab-esc-sec"),p=document.getElementById("ab-prot-sec");
  if(r&&e&&p){ r.after(e,p); _abReordered=true; }
}
async function loadAutoban(){
  _abReorder();
  try{
    const d=await fetch("/api/autoban/rules").then(r=>r.json());
    _abWindows=d.windows||_abWindows; _abFamilies=d.families||[]; _abArmed=!!d.armed;
    _abInterval=d.interval||60; _abMaxTick=d.max_per_tick||20; _abLastRun=d.last_run||null;
    _abIgnore=Array.isArray(d.ignore_paths)?d.ignore_paths:[]; renderAbIgnore();
    _abGroups=Array.isArray(d.groups)?d.groups:[]; _abDefaultGroup=d.default_group||"";
    if(!_abLoaded){abFillSelects();abRenderPaths([""]);abMtypeChange();_abLoaded=true;}
    else abFillGroups();
    renderArm(d.executor);
    _abRules=d.rules||[];
    await loadMainRules();
    renderAbRules(d.rules||[]);
    loadAbLog();
    loadBanTargets();
    loadThreatFeeds();
    loadEscalation();
  }catch(e){document.getElementById("ab-rules").innerHTML=`<div class="text-red-300 text-xs">ошибка загрузки: ${esc(e.message||String(e))}</div>`;}
}

let _banGroup="";
function fillBanGroupSelect(groups,dflt){
  const sel=document.getElementById("bt-group");if(!sel)return;
  const names=Object.keys(groups||{});
  sel.innerHTML=`<option value="">${_trText("все таргеты")}</option>`+names.map(g=>`<option value="${esc(g)}">${esc(g)}</option>`).join("");
  sel.value=_banGroup;
}
// ── Таргет-группы (редактор BAN_GROUPS) ───────────────────────────────────────
let _grpDraft=null;   // editable copy of explicit BAN_GROUPS {name:[target id,...]}
let _grpDirty=false;  // unsaved changes — Save is hidden until something changes
async function loadGroups(){
  const el=document.getElementById("grp-list");if(!el)return;
  try{
    const [st,bt]=await Promise.all([
      fetch("/api/settings").then(r=>r.json()).catch(()=>null),
      fetch("/api/ban_targets").then(r=>r.json()).catch(()=>null)]);
    if(bt&&bt.enabled!==false)_banGroupInfo={groups:bt.groups||{},targets:bt.targets||[],default_group:bt.default_group||"",cf_edge_paths:!!bt.cf_edge_paths};
    const raw=st&&st.settings&&st.settings.BAN_GROUPS&&st.settings.BAN_GROUPS.value;
    _grpDraft=(raw&&typeof raw==="object")?JSON.parse(JSON.stringify(raw)):{};
    _grpDirty=false;
    renderGroups();
  }catch(e){ el.innerHTML=`<span class="text-rose-300">ошибка: ${esc(e.message||e)}</span>`; }
}
function _targetType(tid){const t=(_banGroupInfo.targets||[]).find(x=>x.id===tid);return t?t.type:"";}
// плашки «через что группа реально применяет баны»: nginx / ingress / CF (по типам её таргетов)
function _levelBadges(memberIds){
  const kinds={};   // type → count
  (memberIds||[]).forEach(tid=>{const ty=_targetType(tid); if(ty&&ty!=="noop")kinds[ty]=(kinds[ty]||0)+1;});
  const order=["nginx-file","ingress-cm","cloudflare"];
  const meta={"nginx-file":["nginx","bg-emerald-900/40 text-emerald-300/90"],
              "ingress-cm":["ingress","bg-sky-900/40 text-sky-300/90"],
              "cloudflare":["CF","bg-orange-900/40 text-orange-300/90"]};
  const ks=Object.keys(kinds).sort((a,b)=>(order.indexOf(a)+1||9)-(order.indexOf(b)+1||9));
  if(!ks.length)return `<span class="text-[10px]" style="color:var(--faint)">${_trText('нет бэкендов')}</span>`;
  return ks.map(ty=>{const m=meta[ty]||[ty,"bg-slate-800 text-slate-300"];
    const note=(ty==="cloudflare"&&!_cfEdgeOn())?` <span class="opacity-60">${_trText('только IP')}</span>`:"";
    return `<span class="text-[10px] px-1.5 py-0.5 rounded ${m[1]}">${m[0]} <span class="opacity-60">×${kinds[ty]}</span>${note}</span>`;}).join(" ");
}
function renderGroups(){
  const el=document.getElementById("grp-list");if(!el)return;
  const sv=document.getElementById("grp-save-btn"); if(sv)sv.classList.toggle("hidden",!_grpDirty);
  if(!_grpDraft){el.textContent="—";return;}
  const names=Object.keys(_grpDraft);
  const allTargets=(_banGroupInfo.targets||[]).filter(t=>t.type!=="noop");
  if(!names.length){el.innerHTML=`<div class="text-slate-600 text-xs">${_trText('пока нет своих групп. Создай группу и добавь в неё таргеты.')}</div>`;return;}
  const folder='<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="#d6a35c" stroke-width="2" class="shrink-0"><path d="M4 7a2 2 0 0 1 2-2h3l2 2h7a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z"/></svg>';
  el.innerHTML=names.map(g=>{
    const members=_grpDraft[g]||[];
    const chips=members.map(tid=>{
      const ty=_targetType(tid);
      return `<span class="chip">${ty?_typeIcon(ty):""}${esc(tid)}${ty?` <span style="color:var(--faint)">${esc(_typeLabel(ty))}</span>`:''} <span onclick="grpRemoveTarget('${escJs(g)}','${escJs(tid)}')" style="cursor:pointer;color:var(--crit)">×</span></span>`;
    }).join(" ")||`<span class="text-[11px] text-slate-600">${_trText('пусто')}</span>`;
    const avail=allTargets.filter(t=>!members.includes(t.id));
    return `<div class="grp-card">
      <div class="flex items-center gap-2 mb-2 flex-wrap">
        ${folder}<span class="grp-name mono text-[13px]">${esc(g)}</span>
        <span class="flex items-center gap-1" title="${_trText('через какие бэкенды эта группа применяет баны/403')}">${_levelBadges(members)}</span>
        <button onclick="grpDelete('${escJs(g)}')" class="ml-auto text-[11px] text-rose-300 hover:bg-rose-500/10 rounded px-1.5 py-0.5">${_trText('удалить группу')}</button>
      </div>
      <div class="flex items-center gap-1.5 flex-wrap">${chips} ${_grpAddMenu(g,avail)}</div>
    </div>`;
  }).join("");
}
// выпадашка «＋ таргет» в группе — кастомная (на <details>), с лого по бэкендам
function _grpAddMenu(g,avail){
  if(!avail.length) return "";
  const order=["nginx-file","cloudflare","ingress-cm"];
  const types=[...new Set(avail.map(t=>t.type))].sort((a,b)=>(order.indexOf(a)+1||9)-(order.indexOf(b)+1||9));
  const close="this.closest('details').removeAttribute('open')";
  let m="";
  types.forEach(ty=>{const mt=_typeMeta(ty);
    m+=`<div class="attach-sec">${mt.svg} ${esc(mt.lbl)}</div>`+avail.filter(t=>t.type===ty).map(t=>`<button type="button" onclick="${close};grpAddTarget('${escJs(g)}','${escJs(t.id)}')" class="attach-row">${mt.svg}<span>${esc(t.id)}</span></button>`).join("");});
  return `<details class="attach-dd"><summary class="attach-add">＋ ${_trText('таргет')}</summary><div class="attach-menu">${m}</div></details>`;
}
function grpAddToggle(){
  const row=document.getElementById("grp-new-row"),btn=document.getElementById("grp-add-btn");
  const opening=row.classList.contains("hidden");
  row.classList.toggle("hidden"); btn.classList.toggle("hidden",opening);
  if(opening){ const inp=document.getElementById("grp-new"); if(inp){inp.value="";inp.focus();} }
}
function grpNew(){
  const inp=document.getElementById("grp-new"),name=(inp.value||"").trim();
  if(!name)return; if(!_grpDraft)_grpDraft={};
  if(_grpDraft[name]){uiAlert("такая группа уже есть");return;}
  _grpDraft[name]=[]; _grpDirty=true; inp.value=""; renderGroups(); grpAddToggle();
}
function grpDelete(g){ if(_grpDraft){delete _grpDraft[g];_grpDirty=true;renderGroups();} }
function grpAddTarget(g,tid){ if(!_grpDraft[g])_grpDraft[g]=[]; if(!_grpDraft[g].includes(tid)){_grpDraft[g].push(tid);_grpDirty=true;} renderGroups(); }
function grpRemoveTarget(g,tid){ if(_grpDraft[g])_grpDraft[g]=_grpDraft[g].filter(x=>x!==tid); _grpDirty=true; renderGroups(); }
async function grpSave(){
  const msg=document.getElementById("grp-msg"); msg.textContent="сохраняю…"; msg.className="text-[11px] mt-2 text-slate-400";
  try{
    const r=await fetch("/api/settings",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({updates:{BAN_GROUPS:JSON.stringify(_grpDraft||{})}})});
    const d=await r.json();
    if(d.ok){msg.textContent="✓ сохранено";msg.className="text-[11px] mt-2 text-emerald-400";loadGroups();loadBanTargets();}
    else{msg.textContent="✗ "+(d.error||"ошибка");msg.className="text-[11px] mt-2 text-rose-400";}
  }catch(e){msg.textContent="✗ "+e.message;msg.className="text-[11px] mt-2 text-rose-400";}
}
function _targetSource(t){
  // a human sentence answering "what is this and where do I manage it?", with a link
  const env=t.env?(" · env "+esc(t.env)):"";
  if(t.type==="nginx-file"&&t.enrolled!==false)
    return _trText("подключённая нода")+` → <a onclick="showView('targets');setTsub('nginx')" class="text-indigo-300 cursor-pointer">Targets → nginx</a>`+env;
  if(t.type==="cloudflare")
    return _trText("Cloudflare-таргет")+` → <a onclick="showView('targets');setTsub('cf')" class="text-indigo-300 cursor-pointer">Targets → Cloudflare</a>`+env;
  if(t.type==="ingress-cm")
    return _trText("ingress-cm таргет")+` → <a onclick="showView('settings');setSub('global')" class="text-indigo-300 cursor-pointer">${_trText("задан в BAN_TARGETS")}</a>`+env;
  return _trText("задан в BAN_TARGETS")+` → <a onclick="showView('settings');setSub('global')" class="text-indigo-300 cursor-pointer">${_trText("Настройки → Глобальные")}</a>`;
}
// ── Карта системы (System map): each target is a tile; click expands live detail ──
let _smpOpen=null, _smpData=null;
const _SMP_COLOR={"nginx-file":"#009639","cloudflare":"#F48120","ingress-cm":"#326CE5"};
const _SMP_TYPE={"nginx-file":"nginx","cloudflare":"Cloudflare","ingress-cm":"ingress"};
function _smpColor(t){return _SMP_COLOR[t]||"#64748b";}
function _smpList(resp){return Array.isArray(resp)?resp:(resp&&(resp.list||resp.blocked||resp.rows||resp.blocks))||[];}
function _smpSpark(counts,color){
  if(!counts||!counts.some(v=>v>0))return `<div class="text-[11px] text-slate-600">активности нет</div>`;
  const n=counts.length, max=Math.max(...counts,1);
  const pts=counts.map((v,i)=>`${(i/(n-1)*120).toFixed(1)},${(28-v/max*24).toFixed(1)}`).join(" ");
  return `<svg viewBox="0 0 120 30" width="100%" height="34" preserveAspectRatio="none" style="display:block" aria-hidden="true"><polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.5" vector-effect="non-scaling-stroke"/></svg>`;
}
function _smpToggle(id){ _smpOpen=(_smpOpen===id)?null:id; _smpRender(); }
function _smpRules(t,rules,groups){
  return (rules||[]).filter(r=>r.enabled!==false&&(r.all||(r.targets||[]).includes(t.id)||(r.groups||[]).some(g=>(groups[g]||[]).includes(t.id))));
}
function _smpRender(){
  const el=document.getElementById("ban-targets");if(!el||!_smpData)return;
  const {tg,errs,rules,groups,armed,bansByBe,recentByBe,sparkByBe}=_smpData;
  let active=0;
  const tiles=tg.map(t=>{
    const err=errs[t.id];
    const be=t.backend||"__home__";
    // a CF target with no API token enforces nothing — don't credit it with the
    // backend's shared denylist count or show it as actively banning
    const unconf=(t.type==="cloudflare"&&t.token_set===false);
    const banned=unconf?0:(bansByBe[be]||0);
    const my=_smpRules(t,rules,groups);
    const blocksPath=(t.type==="nginx-file"||t.type==="ingress-cm");
    const st=unconf?"unconf":err?"warn":(banned>0?"active":((my.length||armed)?"ready":"idle"));
    if(st==="active")active++;
    const bar=st==="active"?"#73bf69":st==="warn"?"#ff9830":st==="unconf"?"#64748b":"#334155";
    const brd=st==="warn"?"border-amber-600/40":st==="unconf"?"border-slate-700/60 border-dashed":"border-slate-800";
    const dim=((st==="idle"||st==="unconf")&&_smpOpen!==t.id)?"opacity:.6;":"";
    const stLine=st==="active"?`<span class="inline-flex items-center gap-1.5 text-[12px] text-emerald-400"><span class="smp-live w-1.5 h-1.5 rounded-full bg-emerald-400"></span>баны идут</span>`
      :st==="warn"?`<span class="inline-flex items-center gap-1.5 text-[12px] text-amber-400">⚠ ${esc(err)}</span>`
      :st==="unconf"?`<span class="inline-flex items-center gap-1.5 text-[12px] text-slate-400">⚙ ${_trText("нет токена — не банит")}</span>`
      :st==="ready"?`<span class="text-[12px] text-slate-400">готов · банов нет</span>`
      :`<span class="inline-flex items-center gap-1.5 text-[12px] text-slate-500">⏸ простаивает</span>`;
    const chips=[];
    if(my.length)chips.push(`<span class="text-[11px] px-1.5 py-0.5 rounded bg-indigo-900/40 text-indigo-300/90">403 · ${my.length}</span>`);
    chips.push(armed?`<span class="text-[11px] px-1.5 py-0.5 rounded bg-emerald-900/40 text-emerald-300/90">автобан</span>`
                    :`<span class="text-[11px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-500">автобан выкл</span>`);
    const chipsHtml=(!my.length&&!armed)?`<span class="text-[11px] text-slate-600">ничего не приатачено</span>`:chips.join(" ");
    const open=_smpOpen===t.id;
    let detail="";
    if(open){
      const rulesHtml=my.length?my.map(r=>`<div class="flex items-center gap-2 px-2 py-1 rounded border border-slate-800 bg-slate-900/50 min-w-0">
          <span class="mono text-[12px] text-slate-200 truncate min-w-0" title="${escAttr(r.pattern||r.name||"")}">${esc(r.pattern||r.name||"(правило)")}</span>
          <span class="ml-auto shrink-0 text-[11px] text-emerald-400">✓</span></div>`).join(""):`<div class="text-[12px] text-slate-500">403-правил нет</div>`;
      const rec=(recentByBe[be]||[]).slice(0,6);
      const recHtml=rec.length?rec.map(c=>`<span class="mono text-[11px] px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800">${esc(c)}</span>`).join(" "):`<span class="text-[12px] text-slate-500">—</span>`;
      detail=`<div class="mt-3 pt-3 border-t border-slate-800 grid gap-3">
        <div><div class="text-[11px] text-slate-500 mb-1">активность банов · 24ч</div>${_smpSpark(sparkByBe[be],_smpColor(t.type))}</div>
        <div class="grid gap-3" style="grid-template-columns:repeat(auto-fit,minmax(200px,1fr))">
          <div class="min-w-0"><div class="text-[11px] text-slate-500 mb-1.5">приатаченные 403-правила</div><div class="grid gap-1.5 min-w-0">${rulesHtml}</div></div>
          <div class="min-w-0"><div class="text-[11px] text-slate-500 mb-1.5">автобан</div><div class="text-[12px] ${armed?'text-emerald-400':'text-amber-400'}">${armed?'включён · банит по IP':'выключен · баны не добавляются'}</div>
            <div class="text-[11px] text-slate-500 mt-2.5 mb-1.5">способ применения</div><div class="text-[12px] text-slate-300">${_trText(blocksPath?'IP + 403-пути':'только IP')}</div></div>
        </div>
        <div><div class="text-[11px] text-slate-500 mb-1.5">последние баны</div><div class="flex flex-wrap gap-1.5">${recHtml}</div></div>
      </div>`;
    }
    return `<div class="smp-tile border ${brd} rounded-xl bg-slate-950/40 overflow-hidden cursor-pointer ${open?'smp-open':''}" style="${dim}" onclick="_smpToggle('${escJs(t.id)}')">
      <div style="height:3px;background:${bar}"></div>
      <div class="p-3">
        <div class="flex items-center gap-2">
          <span class="w-2.5 h-2.5 rounded-sm shrink-0" style="background:${_smpColor(t.type)}"></span>
          <span class="mono text-[14px] font-medium text-slate-100 truncate">${esc(t.id)}</span>
          <span class="ml-auto text-[11px] text-slate-500">${esc(_SMP_TYPE[t.type]||t.type)}</span>
          <span class="text-slate-600 text-xs">${open?'▴':'▾'}</span>
        </div>
        <div class="flex items-baseline gap-1.5 mt-2 mb-1">
          <span class="text-[24px] font-medium leading-none ${banned?'text-slate-100':'text-slate-500'}">${banned}</span>
          <span class="text-[11px] text-slate-500">IP в бане</span>
        </div>
        <div class="mb-2">${stLine}</div>
        <div class="flex flex-wrap gap-1.5">${chipsHtml}</div>
        ${detail}
      </div>
    </div>`;
  }).join("");
  el.innerHTML=`<div class="smp-grid" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:.6rem">${tiles}</div>`;
  const sumEl=document.getElementById("smp-summary");
  if(sumEl)sumEl.innerHTML=`<span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-emerald-900/30 text-emerald-400"><span class="smp-live w-1.5 h-1.5 rounded-full bg-emerald-400"></span>${active}/${tg.length} активны</span>`;
  const bnEl=document.getElementById("smp-banned");
  const total=Object.values(bansByBe).reduce((a,b)=>a+b,0);
  if(bnEl)bnEl.innerHTML=`в бане <span class="text-slate-200 font-medium">${total}</span> IP`;
}
async function loadBanTargets(){
  const el=document.getElementById("ban-targets");if(!el)return;
  try{
    const [d,pr,ab,bl,au]=await Promise.all([
      fetch("/api/ban_targets").then(r=>r.json()),
      fetch("/api/path_rules").then(r=>r.json()).catch(()=>({rules:[]})),
      fetch("/api/autoban_rules").then(r=>r.json()).catch(()=>({armed:false})),
      fetch("/api/blocklist").then(r=>r.json()).catch(()=>[]),
      fetch("/api/blocklist_audit").then(r=>r.json()).catch(()=>({audit:[]})),
    ]);
    _targetsData=d;
    if(d&&d.enabled!==false)_banGroupInfo={groups:d.groups||{},targets:d.targets||[],default_group:d.default_group||"",cf_edge_paths:!!d.cf_edge_paths};
    if(_view==="autoban"&&Array.isArray(_abRules))renderAbRules(_abRules); // подписи «применяется к»
    if(d.enabled===false){el.innerHTML=`<span class="text-slate-500">blocklist-api не настроен — баны отключены.</span>`;return;}
    const tg=(d.targets||[]).filter(t=>t.type!=="noop");
    if(!tg.length){el.innerHTML=`<span class="text-slate-500">таргетов пока нет — подключи ноду, CF-таргет или ingress.</span>`;return;}
    // aggregate bans per backend (targets sharing a backend share its denylist)
    const bans=_smpList(bl), bansByBe={}, recentByBe={};
    bans.forEach(b=>{ if(b&&b.active===false)return; const be=b.backend||"__home__";
      bansByBe[be]=(bansByBe[be]||0)+1; (recentByBe[be]=recentByBe[be]||[]).push(b.cidr||b.ip||""); });
    // 24h ban activity per backend from audit (12 buckets × 2h)
    const auRows=(au&&(au.audit||au.log||au.rows))||(Array.isArray(au)?au:[]);
    const nowS=Math.floor(Date.now()/1000), span=24*3600, nb=12, sparkByBe={};
    auRows.forEach(e=>{ const ts=e.ts||e.time||0; if(!ts||nowS-ts>span)return;
      const be=e.backend||"__home__"; const idx=Math.min(nb-1,Math.floor((ts-(nowS-span))/(span/nb)));
      (sparkByBe[be]=sparkByBe[be]||new Array(nb).fill(0))[idx]++; });
    _smpData={tg,errs:d.last_errors||{},rules:(pr&&pr.rules)||[],groups:d.groups||{},
              armed:!!(ab&&ab.armed),bansByBe,recentByBe,sparkByBe};
    _smpRender();
  }catch(e){el.innerHTML=`<span class="text-red-300">ошибка: ${esc(e.message||String(e))}</span>`;}
}

async function checkBanTargets(){
  const el=document.getElementById("ban-targets"), btn=document.getElementById("bt-check-btn");
  btn.disabled=true; const old=btn.textContent; btn.textContent="проверяю…";
  try{
    const d=await fetch("/api/ban_targets/check").then(r=>r.json());
    const checks=(d.checks||[]).filter(c=>c.type!=="noop");
    el.innerHTML=checks.map(c=>{
      const dot=c.ok?"#73bf69":"#f2495c";
      let detail="";
      if(c.type==="cloudflare"){
        detail=`token ${c.token_valid?"✓":"✗"} · list ${c.list_id?"✓":"✗"} · rule ${c.rule_id?"✓":"✗"}`+
               (c.items!=null?` · ${c.items} IP`:"");
      }
      return `<div class="flex items-center gap-2 py-1">
        <span class="w-1.5 h-1.5 rounded-full" style="background:${dot}"></span>
        <span class="text-slate-200 mono">${esc(c.id)}</span>
        <span class="text-[11px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">${esc(c.type||"")}</span>
        <span class="text-[11px] text-slate-400">${esc(detail)}</span>
        ${c.error?`<span class="text-[11px] text-red-300">${esc(c.error)}</span>`:`<span class="text-[11px] text-emerald-300">${c.ok?"OK":""}</span>`}
      </div>`;}).join("")||`<span class="text-slate-500">нет таргетов.</span>`;
  }catch(e){el.innerHTML=`<span class="text-red-300">ошибка проверки: ${esc(e.message||String(e))}</span>`;}
  finally{btn.disabled=false; btn.textContent=old;}
}
function renderArm(executor){
  const note=document.getElementById("ab-killswitch-note"), btn=document.getElementById("ab-arm-btn");
  const card=document.getElementById("ab-killswitch");
  let lr="";
  if(_abLastRun&&_abLastRun.ts){
    const r=_abLastRun;
    lr=` · прогон ${ago(r.ts)} назад: включено правил ${r.checked_rules}, новых забанено ${r.banned}`+
       (r.already?`, уже в бане ${r.already}`:"")+
       (r.deferred?`, отложено по лимиту ${r.deferred}`:"");
  }
  if(executor===false){
    note.innerHTML=`⚙️ Исполнитель не подключён — реального бана нет.`;
  }else if(_abArmed){
    note.innerHTML=`🟢 <b class="text-emerald-300">ВКЛЮЧЁН</b> — включённые правила банят на ingress каждые ${_abInterval}с (≤${_abMaxTick} новых/проход).<span class="text-slate-500">${lr}</span>`;
    card.className="card border-emerald-500/40 bg-emerald-500/5 p-4 mb-4";
  }else{
    note.innerHTML=`⚪ Выключен — ни одно правило не банит (правила можно настраивать, превью работает).<span class="text-slate-500">${lr}</span>`;
    card.className="card border-amber-500/30 bg-amber-500/5 p-4 mb-4";
  }
  btn.textContent=_abArmed?"🟢 Автобан включён":"⚪ Включить автобан";
  btn.className="px-3 py-1.5 rounded-lg text-xs border "+(_abArmed?"border-emerald-600/50 text-emerald-300 hover:bg-emerald-900/20":"border-slate-700 text-slate-300 hover:bg-slate-800");
}
async function toggleArm(){
  const turningOn=!_abArmed;
  if(turningOn){
    if(!await uiConfirm(`Включить автобан?\n\nВключённые правила начнут РЕАЛЬНО банить IP на ingress каждые ${_abInterval}с (до ${_abMaxTick} новых за проход).\nИсключаются: доверенные, приватные, Cloudflare, уже забаненные.\n\nВыключить можно этим же тумблером в любой момент.`))return;
  }
  try{const d=await fetch("/api/autoban/arm",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({armed:turningOn})}).then(r=>r.json());
    _abArmed=!!d.armed;renderArm(d.executor);if(_abArmed)setTimeout(loadAutoban,2000);}catch(e){uiAlert("не удалось: "+(e.message||e));}
}
function abFormPayload(){
  const mt=document.getElementById("ab-mtype").value;
  return {id:_abEditId||undefined, name:document.getElementById("ab-name").value.trim(), match_type:mt,
    path:mt==="family"?document.getElementById("ab-family").value:(mt==="rate"?"":abPathValues().join("\n")),
    status:document.getElementById("ab-status").value.trim(),
    threshold:parseInt(document.getElementById("ab-threshold").value)||1,
    window:document.getElementById("ab-window").value, ttl:parseInt(document.getElementById("ab-ttl").value)||0,
    combine:document.getElementById("ab-combine").checked?1:0,
    group:document.getElementById("ab-group").value||"",
    country:document.getElementById("ab-country").value||"",
    enabled:_abEditId?undefined:0};
}
async function abSaveRule(){
  const p=abFormPayload(), msg=document.getElementById("ab-form-msg");
  if(!p.name){msg.textContent="нужно имя";return;}
  if(p.match_type!=="family"&&p.match_type!=="rate"&&!p.path){msg.textContent="укажи путь";return;}
  msg.textContent="сохраняю…";
  try{const d=await fetch("/api/autoban/rule",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(p)}).then(r=>r.json());
    if(!d.ok){msg.textContent="ошибка: "+(d.error||"?");return;}
    msg.textContent="✓ сохранено";abResetForm();loadAutoban();
  }catch(e){msg.textContent="ошибка: "+(e.message||e);}
}
function abResetForm(){
  _abEditId=null;
  document.getElementById("ab-form-title").textContent="Создать новое правило";
  document.getElementById("ab-name").value="";abRenderPaths([""]);
  document.getElementById("ab-status").value="";document.getElementById("ab-threshold").value="5";
  document.getElementById("ab-mtype").value="substring";document.getElementById("ab-window").value="10m";
  document.getElementById("ab-ttl").value="2592000";document.getElementById("ab-combine").checked=true;abMtypeChange();
  document.getElementById("ab-group").value="";document.getElementById("ab-country").value="";
  document.getElementById("ab-cancel").classList.add("hidden");
  document.getElementById("ab-form-msg").textContent="";
}
function abEditRule(r){
  _abEditId=r.id;
  abCardToggle("ab-form-body","ab-form-chev",true);   // редактирование раскрывает форму
  document.getElementById("ab-form-title").textContent="Редактировать правило #"+r.id;
  document.getElementById("ab-name").value=r.name||"";
  document.getElementById("ab-mtype").value=r.match_type||"substring";abMtypeChange();
  if(r.match_type==="family"){document.getElementById("ab-family").value=r.path||"";abRenderPaths([""]);}
  else abRenderPaths((r.path||"").split("\n").filter(Boolean));
  document.getElementById("ab-status").value=r.status||"";
  document.getElementById("ab-threshold").value=r.threshold||5;
  document.getElementById("ab-window").value=r.window||"10m";
  document.getElementById("ab-ttl").value=String(r.ttl||0);
  document.getElementById("ab-combine").checked=(r.combine!==0);
  abFillGroups();document.getElementById("ab-group").value=r.group||"";
  document.getElementById("ab-country").value=r.country||"";
  document.getElementById("ab-cancel").classList.remove("hidden");
  window.scrollTo({top:0,behavior:"smooth"});
}
async function abPreview(rule){
  abCardToggle("ab-preview","ab-preview-chev",true);   // вызов превью раскрывает карточку
  const out=document.getElementById("ab-preview");out.innerHTML='<div class="text-slate-500 text-xs">считаю (Loki)…</div>';
  let qs;
  if(rule&&rule.id){qs="id="+rule.id;}
  else{const p=abFormPayload();
    if(p.match_type!=="family"&&!p.path){out.innerHTML='<div class="text-amber-300 text-xs">укажи путь/паттерн</div>';return;}
    qs=`match_type=${encodeURIComponent(p.match_type)}&path=${encodeURIComponent(p.path)}&status=${encodeURIComponent(p.status)}&threshold=${p.threshold}&window=${p.window}&combine=${p.combine}`;}
  try{const d=await fetch("/api/autoban/preview?"+qs).then(r=>r.json());
    if(d.error){out.innerHTML=`<div class="text-red-300 text-xs">${esc(d.error)}</div>`;return;}
    const m=d.matches||[], ab=d.already_banned||0;
    const abNote=ab?` <span class="text-slate-500">· ${ab} уже в денлисте (пропущено)</span>`:"";
    if(!m.length){out.innerHTML=`<div class="text-emerald-300/80 text-xs">0 новых IP под условие (≥${d.threshold} за ${d.window}).${abNote} Никого нового бы не забанило.</div>`;return;}
    out.innerHTML=`<div class="text-[12px] text-slate-400 mb-2">Забанило бы <b class="text-red-300">${m.length}</b> новых IP (≥${d.threshold} за ${d.window})${abNote}:</div>`+
      m.map(x=>`<div class="flex items-center justify-between gap-2 py-1 border-b border-slate-800/60">
        <span class="mono text-slate-200 cursor-pointer hover:text-indigo-300 min-w-0 truncate" onclick="openProfile('${escJs(x.ip)}')">${flag(x.country)} ${esc(x.ip)} ↗</span>
        <span class="flex items-center gap-1.5 shrink-0">${cfBadge(x.ip)}<span class="mono text-red-300">${fmt(x.count)}</span></span></div>
        ${x.paths&&x.paths.length?`<div class="text-[11px] text-slate-600 mono truncate mb-1">${x.paths.map(esc).join(" · ")}</div>`:""}`).join("");
  }catch(e){out.innerHTML=`<div class="text-red-300 text-xs">ошибка: ${esc(e.message||String(e))}</div>`;}
}
function renderAbRules(rules){
  const el=document.getElementById("ab-rules");
  if(!rules.length){el.innerHTML='<div class="text-xs" style="color:var(--faint);padding:12px 2px">No rules yet. Create your first on the left.</div>';return;}
  const cond=r=>r.match_type==="rate"?"rate: any path"
    :r.match_type==="family"?("family: "+((_abFamilies.find(f=>f.key===r.path)||{}).label||r.path))
    :(r.match_type==="regex"?"regex ":"path ⊃ ")+(r.path||"").split("\n").filter(Boolean).join(" OR ");
  const ccBadge=r=>{const cs=(r.country||"").split(/[,\s]+/).filter(Boolean);return cs.length?" · "+cs.map(c=>flag(c)).join(""):"";};
  const ttlL=t=>!t?"forever":(t>=86400?(t/86400)+"d":(t>=3600?(t/3600)+"h":t+"s"));
  el.innerHTML=rules.map(r=>`<div class="flex items-center gap-3 py-2 border-b border-slate-800/60 flex-wrap">
    <button onclick="abToggle(${r.id},${r.enabled?0:1})" title="${r.enabled?"disable":"enable"}" class="shrink-0 w-11 h-6 rounded-full relative transition ${r.enabled?"bg-emerald-600/70":"bg-slate-700"}">
      <span class="absolute top-0.5 ${r.enabled?"left-6":"left-0.5"} w-5 h-5 rounded-full bg-white transition-all"></span></button>
    ${r.match_type!=="family"?`<button onclick="setMainRule('autoban',${r.id})" title="${String(_mainRules.autoban_id)===String(r.id)?'primary auto-ban rule':'make primary'}" class="star-btn shrink-0 ${String(_mainRules.autoban_id)===String(r.id)?'on':''}" style="font-size:15px">★</button>`:''}
    <div class="flex-1 min-w-[200px]">
      <div class="text-sm text-slate-200 font-medium">${esc(r.name)} ${String(_mainRules.autoban_id)===String(r.id)?'<span class="text-[10px] text-amber-400">primary</span>':''} ${r.enabled?'<span class="text-[10px] text-emerald-400">on</span>':'<span class="text-[10px] text-slate-600">off</span>'}</div>
      <div class="text-[11px] text-slate-500 mono truncate">${esc(cond(r))} · ≥${r.threshold} over ${r.window}${(r.match_type==="family"||r.match_type==="rate")?"":(r.combine===0?" (per path)":" (Σ paths)")}${r.status?" · status "+esc(r.status):""}${ccBadge(r)} · ban ${ttlL(r.ttl)}</div>
      ${_attachUI(r,'autoban')}
      ${_appliesLineRule(r, false)}
    </div>
    <button onclick='abPreview(${JSON.stringify({id:r.id})})' class="btn btn-xs">preview</button>
    <button onclick='abEditRule(${JSON.stringify(r).replace(/'/g,"&#39;")})' class="btn btn-xs">edit</button>
    <button onclick="abDelete(${r.id})" class="btn btn-xs" style="color:var(--crit);border-color:color-mix(in srgb,var(--crit) 40%,transparent)">delete</button>
  </div>`).join("");
}
async function abToggle(id,enabled){
  try{await fetch("/api/autoban/toggle",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id,enabled})});loadAutoban();}
  catch(e){uiAlert("не удалось: "+(e.message||e));}
}
async function abDelete(id){
  if(!await uiConfirm("Удалить правило #"+id+"?"))return;
  try{await fetch("/api/autoban/delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id})});if(_abEditId===id)abResetForm();loadAutoban();}
  catch(e){uiAlert("не удалось: "+(e.message||e));}
}
// Only treat the hash as a view name for known views — the dashboard uses the hash
// for its own win/host params (parseHash below), which showView('dash') would wipe.
// URL is the source of truth for the current view: restore on load + follow back/forward
function _viewFromHash(){ const h=location.hash.replace(/^#/,''); const first=(h.split(/[=&]/)[0]||''); return _VIEWS.includes(first)?first:'dash'; }
{ const _v=_viewFromHash(); if(_v!=="dash")showView(_v); }               // restore view from URL (incl. dashboards)
window.addEventListener('hashchange',()=>{ const _v=_viewFromHash(); if(_v!==_view)showView(_v); });   // browser back/forward

// активна ли вкладка: не на паузе И страница на экране (скрытая вкладка не грузит Loki)
// ── кастомный брендинг (заголовок / подпись / иконка), хранится на бэке ──────────
let _branding={}, _brandDefIcon="", _brandPendIcon=null;
function applyBranding(){
  const t=document.getElementById("brand-title"), s=document.getElementById("brand-sub"), ic=document.getElementById("brand-icon");
  if(!_brandDefIcon&&ic)_brandDefIcon=ic.innerHTML;   // запомнили дефолтный SVG один раз
  if(t){ t.removeAttribute("data-i18n");t.textContent=_branding.title||"SOC"; }
  if(s){ if(_branding.subtitle){s.textContent=_branding.subtitle;s.removeAttribute("data-i18n");}else{s.setAttribute("data-i18n","tagline");} }
  if(ic){ ic.innerHTML=_branding.icon?`<img src="${_branding.icon}" class="w-full h-full object-cover" alt="logo">`:_brandDefIcon; }
  if(_branding.title)document.title=_branding.title+" Dashboard";
  if(typeof applyI18n==="function")applyI18n();
}
async function loadBranding(){
  // применяем кэш сразу (синхронно) — чтобы при перезагрузке не мигал дефолтный SOC
  try{ const c=localStorage.getItem("soc_brand"); if(c){ _branding=JSON.parse(c)||{}; applyBranding(); } }catch(e){}
  try{ _branding=await fetch("/api/branding").then(r=>r.json())||{}; localStorage.setItem("soc_brand",JSON.stringify(_branding)); }catch(e){ _branding=_branding||{}; }
  applyBranding();
}
function brandEdit(){
  document.getElementById("brand-in-title").value=_branding.title||"";
  document.getElementById("brand-in-sub").value=_branding.subtitle||"";
  _brandPendIcon=null;
  const pv=document.getElementById("brand-prev");
  pv.innerHTML=_branding.icon?`<img src="${_branding.icon}" class="w-full h-full object-cover">`:"лого";
  document.getElementById("brand-err").classList.add("hidden");
  document.getElementById("brand-modal").classList.remove("hidden");
}
function brandClose(){ document.getElementById("brand-modal").classList.add("hidden"); }
function _brandErr(m){ const e=document.getElementById("brand-err");e.textContent=m;e.classList.remove("hidden"); }
function brandFile(inp){
  const f=inp.files&&inp.files[0]; if(!f)return;
  if(f.size>180*1024){ _brandErr("файл больше 180KB — выбери поменьше");inp.value="";return; }
  const r=new FileReader();
  r.onload=()=>{ _brandPendIcon=r.result; document.getElementById("brand-prev").innerHTML=`<img src="${r.result}" class="w-full h-full object-cover">`; document.getElementById("brand-err").classList.add("hidden"); };
  r.readAsDataURL(f);
}
function brandClearIcon(){ _brandPendIcon=""; document.getElementById("brand-prev").innerHTML="лого"; }
async function brandSave(){
  const payload={title:document.getElementById("brand-in-title").value.trim(),subtitle:document.getElementById("brand-in-sub").value.trim()};
  if(_brandPendIcon!==null)payload.icon=_brandPendIcon;   // только если трогали файл
  try{
    const r=await _post("/api/branding",payload);
    if(r&&r.ok===false){ _brandErr(r.error||"ошибка сохранения");return; }
    _branding={title:r.title||"",subtitle:r.subtitle||"",icon:r.icon||""};
    try{localStorage.setItem("soc_brand",JSON.stringify(_branding));}catch(e){}
    applyBranding(); brandClose();
  }catch(e){ _brandErr("не удалось сохранить"); }
}
const isActive=()=>!paused&&document.visibilityState==="visible";
const onDash=()=>_view==="dash";
// вернулись на вкладку → сразу обновляем (а не ждём следующий тик)
document.addEventListener("visibilitychange",()=>{if(isActive()){refresh();if(onDash())renderBlocklist();}});

applyI18n();initCards();startTranslator();_densityInit();           // pure-UI, safe before auth
authInit().then(ok=>{ if(!ok)return;                               // gate app data on login
  parseHash();renderWinSel();renderStats(null);refresh();loadDigest();
  renderBlocklist();renderBanCandidates();renderSuspects();loadBranding();loadScope();
});
setInterval(()=>{if(_me&&isActive())refresh();},20000);setInterval(()=>{if(_me&&isActive())loadDigest();},300000);
setInterval(()=>{if(_me&&isActive())renderBlocklist();},60000);
setInterval(()=>{if(_me&&isActive()&&onDash()){renderBanCandidates();renderSuspects();}},180000);

// ── Command palette (Cmd/Ctrl-K) ──────────────────────────────────────────────
const _CMDK=[
 {g:'nav',ic:'◧',en:'Overview',ru:'Обзор',kw:'overview dashboard home dash обзор главная',run:()=>showView('dash')},
 {g:'nav',ic:'≣',en:'Logs',ru:'Логи',kw:'logs explore search логи поиск',run:()=>showView('logs')},
 {g:'nav',ic:'▦',en:'Dashboards',ru:'Дашборды',kw:'dashboards panels charts графики дашборды панели',run:()=>showView('dashboards')},
 {g:'nav',ic:'▤',en:'Journal',ru:'Журнал',kw:'journal audit журнал аудит',run:()=>showView('journal')},
 {g:'nav',ic:'🛡',en:'Auto-ban',ru:'Авто-бан',kw:'autoban auto ban rules автобан правила',run:()=>showView('autoban')},
 {g:'nav',ic:'⊘',en:'403 rules',ru:'403 правила',kw:'403 forbidden deny rules правила',run:()=>showView('p403')},
 {g:'nav',ic:'⧉',en:'Resources',ru:'Ресурсы',kw:'resources targets nodes ingress ресурсы ноды',run:()=>showView('targets')},
 {g:'nav',ic:'⚙',en:'Settings',ru:'Настройки',kw:'settings config настройки конфиг',run:()=>showView('settings')},
 {g:'act',ic:'⛔',en:'Ban an IP / CIDR…',ru:'Забанить IP / CIDR…',kw:'ban block ip cidr бан заблокировать',run:()=>quickBan()},
 {g:'act',ic:'⌕',en:'Open IP profile…',ru:'Профиль IP…',kw:'ip profile lookup search профиль поиск',run:()=>{const v=((document.getElementById('cmdk-q')||{}).value||'').trim();if(v)quickSearch(v);else{const t=document.getElementById('topsearch');if(t)t.focus();}}},
 {g:'act',ic:'↻',en:'Refresh view',ru:'Обновить вид',kw:'refresh reload обновить перезагрузить',run:()=>{if(typeof _view!=='undefined')showView(_view);}},
 {g:'act',ic:'🌐',en:'Toggle language (EN / RU)',ru:'Сменить язык (EN / RU)',kw:'language lang en ru locale язык',run:()=>toggleLang()},
 {g:'act',ic:'◔',en:'Account & password',ru:'Аккаунт и пароль',kw:'account password 2fa totp аккаунт пароль',run:()=>{showView('settings');if(typeof setSub==='function')setSub('account');}},
];
const _CMDK_GRP={nav:{en:'Navigate',ru:'Навигация'},act:{en:'Actions',ru:'Действия'},ip:{en:'IP',ru:'IP'}};
let _cmdkSel=0,_cmdkShown=[],_cmdkPrev=null;
function _cmdkScore(text,q){ if(!q)return 0; text=text.toLowerCase();q=q.toLowerCase();
  let ti=0,score=0,prev=-2,streak=0;
  for(let qi=0;qi<q.length;qi++){ const c=q[qi]; let f=-1;
    for(let k=ti;k<text.length;k++){ if(text[k]===c){f=k;break;} }
    if(f<0)return null;
    if(f===prev+1){streak++;score-=streak*2;}else streak=0;
    if(f===0||/[\s\-_/.]/.test(text[f-1]||' '))score-=3;
    score+=f; prev=f; ti=f+1; }
  return score; }
function _cmdkRu(){ return typeof _lang!=='undefined'&&_lang==='ru'; }
function cmdkToggle(){ const o=document.getElementById('cmdk'); if(!o)return; (o.style.display==='none')?cmdkOpen():cmdkClose(); }
function cmdkOpen(){ const o=document.getElementById('cmdk'); if(!o)return; _cmdkPrev=document.activeElement;
  o.style.display='flex'; const q=document.getElementById('cmdk-q'); q.value=''; cmdkFilter(); q.focus(); }
function cmdkClose(){ const o=document.getElementById('cmdk'); if(!o)return; o.style.display='none';
  if(_cmdkPrev&&_cmdkPrev.focus)try{_cmdkPrev.focus();}catch(e){} }
function _cmdkList(q){
  const ru=_cmdkRu();
  const items=_CMDK.map(it=>({it,label:ru?it.ru:it.en,score:_cmdkScore(it.en+' '+it.ru+' '+it.kw,q)})).filter(x=>x.score!==null);
  const ip=(q||'').trim();
  if(/^\d{1,3}(\.\d{1,3}){1,3}(\/\d{1,2})?$/.test(ip)){
    items.unshift({it:{g:'ip',ic:'⌕',run:()=>quickSearch(ip)},label:(ru?'Профиль: ':'Profile: ')+ip,score:-1000});
    items.push({it:{g:'ip',ic:'⛔',run:()=>_cmdkBan(ip)},label:(ru?'Забанить ':'Ban ')+ip+'…',score:-999});
  }
  items.sort((a,b)=>a.score-b.score);
  return items;
}
function cmdkFilter(){
  const qi=document.getElementById('cmdk-q'); if(!qi)return; const list=document.getElementById('cmdk-list');
  _cmdkShown=_cmdkList(qi.value); _cmdkSel=0;
  if(!_cmdkShown.length){ list.innerHTML=`<div class="cmdk-empty">${_cmdkRu()?'Ничего не найдено':'No matches'}</div>`; qi.setAttribute('aria-activedescendant',''); return; }
  const ru=_cmdkRu(); let html='',lastG=null;
  _cmdkShown.forEach((x,i)=>{ const g=x.it.g;
    if(g!==lastG){ lastG=g; const gl=_CMDK_GRP[g]?(ru?_CMDK_GRP[g].ru:_CMDK_GRP[g].en):g; html+=`<div class="cmdk-grp">${esc(gl)}</div>`; }
    html+=`<div class="cmdk-it${i===_cmdkSel?' sel':''}" id="cmdk-it-${i}" role="option" aria-selected="${i===_cmdkSel}" onmousemove="_cmdkHover(${i})" onclick="cmdkRun(${i})"><span class="cmdk-i2">${x.it.ic||'·'}</span><span class="cmdk-l">${esc(x.label)}</span></div>`; });
  list.innerHTML=html; _cmdkAria();
}
function _cmdkAria(){ const qi=document.getElementById('cmdk-q'); if(qi)qi.setAttribute('aria-activedescendant',_cmdkShown.length?'cmdk-it-'+_cmdkSel:''); }
function _cmdkHover(i){ if(i===_cmdkSel)return; _cmdkSel=i; _cmdkPaint(); }
function _cmdkPaint(){ const list=document.getElementById('cmdk-list'); if(!list)return;
  [...list.querySelectorAll('.cmdk-it')].forEach((el,i)=>{const on=i===_cmdkSel;el.classList.toggle('sel',on);el.setAttribute('aria-selected',on);});
  const sel=document.getElementById('cmdk-it-'+_cmdkSel); if(sel)sel.scrollIntoView({block:'nearest'}); _cmdkAria(); }
function cmdkKey(e){
  if(e.key==='ArrowDown'){e.preventDefault(); _cmdkSel=Math.min(_cmdkShown.length-1,_cmdkSel+1); _cmdkPaint();}
  else if(e.key==='ArrowUp'){e.preventDefault(); _cmdkSel=Math.max(0,_cmdkSel-1); _cmdkPaint();}
  else if(e.key==='Enter'){e.preventDefault(); cmdkRun(_cmdkSel);}
  else if(e.key==='Escape'){e.preventDefault(); cmdkClose();}
}
function cmdkRun(i){ const x=_cmdkShown[i]; if(!x)return; const fn=x.it.run; cmdkClose(); if(typeof fn==='function')setTimeout(fn,0); }
async function _cmdkBan(ip){ cmdkClose(); if(await uiConfirm(_cmdkRu()?('Забанить '+ip+' на 30 дней?'):('Ban '+ip+' for 30 days?'))) blockIP(ip,'manual (cmd-k)',2592000); }
document.addEventListener('keydown',e=>{ if((e.metaKey||e.ctrlKey)&&(e.key==='k'||e.key==='K')){ e.preventDefault(); cmdkToggle(); } },true);
// dashboard panel drilldown: delegated row-click → existing view/handler
document.addEventListener('click',e=>{ if(!e.target||!e.target.closest)return;
  const row=e.target.closest('#db-grid [data-dk]'); if(!row)return;
  const panel=row.closest('.db-panel'); if(!panel)return;
  const dash=(typeof dbCur==='function')?dbCur():null;
  const p=dash&&(dash.panels||[]).find(x=>x.id===panel.getAttribute('data-pid'));
  if(!p||!p.key||!_dbDrillable(p.key))return;
  e.preventDefault(); _dbDrillGo(p.key,row.getAttribute('data-dk')); });

// ── Keyboard shortcuts: g-then-key nav, / focus search, ? cheatsheet ──────────
const _KB_NAV={o:'dash',l:'logs',d:'dashboards',j:'journal',a:'autoban',f:'p403',r:'targets',s:'settings'};
let _kbG=false,_kbGT=null;
function _kbCheat(){
  const ru=(typeof _lang!=='undefined'&&_lang==='ru');
  const rows=[['⌘K / Ctrl-K',ru?'командная палитра':'command palette'],['/',ru?'фокус в поиск':'focus search'],
    ['g  o','Overview'],['g  l','Logs'],['g  d','Dashboards'],['g  j','Journal'],['g  a','Auto-ban'],
    ['g  f','403 rules'],['g  r','Resources'],['g  s','Settings'],['?',ru?'эта шпаргалка':'this cheatsheet'],['Esc',ru?'закрыть':'close']];
  const body=`<div class="kb-cheat">${rows.map(r=>`<div class="kb-row"><kbd>${esc(r[0])}</kbd><span>${esc(r[1])}</span></div>`).join('')}</div>`;
  if(typeof _showModal==='function')_showModal({title:ru?'Горячие клавиши':'Keyboard shortcuts',body,buttons:[{label:'OK',kind:'primary',value:true,enter:true,esc:true}]});
}
document.addEventListener('keydown',e=>{
  if(e.metaKey||e.ctrlKey||e.altKey)return;
  const el=document.activeElement,tag=el&&el.tagName;
  if(tag==='INPUT'||tag==='TEXTAREA'||tag==='SELECT'||(el&&el.isContentEditable))return;   // never hijack while typing
  const ov=document.getElementById('cmdk'); if(ov&&ov.style.display!=='none')return;         // palette open → let it handle keys
  const k=e.key;
  if(_kbG){ _kbG=false; clearTimeout(_kbGT); if(_KB_NAV[k]&&typeof showView==='function'){ e.preventDefault(); showView(_KB_NAV[k]); } return; }
  if(k==='g'){ _kbG=true; clearTimeout(_kbGT); _kbGT=setTimeout(()=>{_kbG=false;},1200); return; }
  if(k==='/'){ const t=document.getElementById('topsearch'); if(t){ e.preventDefault(); t.focus(); } return; }
  if(k==='?'){ e.preventDefault(); _kbCheat(); return; }
});

// ── Density toggle (Compact / Comfortable), persisted per-user ─────────────────
function _densityBtn(d){ const b=document.getElementById('density-btn'); if(!b)return;
  b.textContent=d==='compact'?'≣':'☰';
  b.title=(typeof _lang!=='undefined'&&_lang==='ru')?(d==='compact'?'Плотность: компактно':'Плотность: свободно'):(d==='compact'?'Density: compact':'Density: comfortable'); }
function _densityInit(){ let d='comfortable'; try{d=localStorage.getItem('soc_density')||'comfortable';}catch(e){}
  document.documentElement.setAttribute('data-density',d); _densityBtn(d); }
function toggleDensity(){ const cur=document.documentElement.getAttribute('data-density')==='compact'?'comfortable':'compact';
  document.documentElement.setAttribute('data-density',cur); try{localStorage.setItem('soc_density',cur);}catch(e){} _densityBtn(cur); }
