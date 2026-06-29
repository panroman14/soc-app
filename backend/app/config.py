"""Configuration for the soc backend. Override via environment variables."""
import os

# --- Loki ---
LOKI_URL = os.environ.get("LOKI_URL", "https://loki.example.com")
INGRESS_SELECTOR = os.environ.get("INGRESS_SELECTOR", '{app="ingress-nginx"}')
WINDOW = os.environ.get("WINDOW", "5m")          # aggregation window
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "30"))
# Tor exit-list enrichment (off by default — the ~700 KB download/refresh isn't
# worth the latency; set TOR_ENABLED=1 to re-enable).
TOR_ENABLED = os.environ.get("TOR_ENABLED", "0") not in ("0", "", "false", "False")

# --- LLM (Ollama / OpenAI-compatible) ---
LLM_URL = os.environ.get("LLM_URL", "http://192.0.2.20:11434")
LLM_MODEL = os.environ.get("LLM_MODEL", "gemma3:4b")

# --- Auth (HTTP Basic) ---
# If BASIC_AUTH_USER/PASS are unset, auth is DISABLED (dev). Set both in prod.
BASIC_AUTH_USER = os.environ.get("BASIC_AUTH_USER", "")
BASIC_AUTH_PASS = os.environ.get("BASIC_AUTH_PASS", "")
# Paths served without auth (Prometheus scrape + health probes).
AUTH_EXEMPT = {"/metrics", "/api/health"}

# --- Trusted IPs (люди/офисы — помечаем, не считаем атакой) ---
TRUSTED_IPS = {
    "192.0.2.10": "Office IP",
    "192.0.2.11": "Analyst IP",
    "192.0.2.12": "system-vpn IP",
}

# --- IP enrichment (ASN/город) через ip-api.com (free, ~45 req/min) ---
ASN_LOOKUP_URL = os.environ.get("ASN_LOOKUP_URL", "http://ip-api.com/json/")

# --- web-check (Lissy93/web-check) — локальный контейнер, проксируем за auth ---
WEBCHECK_URL = os.environ.get("WEBCHECK_URL", "http://localhost:3001")

# --- blocklist-api (in-cluster) — полуавтомат блокировки IP с дашборда ---
# Пусто = кнопки блокировки отключены (функция не настроена).
BLOCKLIST_API_URL = os.environ.get("BLOCKLIST_API_URL", "")        # https://block-api.example.com
BLOCKLIST_API_TOKEN = os.environ.get("BLOCKLIST_API_TOKEN", "")    # тот же токен, что в Secret blocklist-api

# Базовый набор сканер-путей для секции «Правила 403» (кнопка «засеять»). Это
# та же регулярка, что раньше прописывалась в ingress руками. Один большой
# alternation по $request_uri; nginx применяет как ~* (регистронезависимо).
BASE_403_PATTERN = r"""(/\.(env|git|svn|hg|aws|ssh|vscode|idea|docker|npmrc|htpasswd|htaccess|bash_history)(/|$)|/\.git/|/\.svn/|/\.hg/|/\.well-known/(?!acme-challenge/|security\.txt|openvpn)|/wp-(login|admin|includes|content|json)|/xmlrpc\.php|/wlwmanifest\.xml|/phpmyadmin|/pma|/myadmin|/phpinfo|/phpunit|/vendor/.*\.php|/composer\.(json|lock)|/\.DS_Store|/Thumbs\.db|/_wdt|/_profiler|/_ignition|/actuator(/|$)|/server-status|/server-info|/jmx-console|/manager/html|/solr/|/struts|/jenkins|/cgi-bin|/fckeditor|/adminer|/core/install\.php|/magento_version|/\.env-config\.js|/\.env\.js|/\.gitconfig|/config/parameters\.yml|/docker-compose\.yml|/application\.yml|/web\.config|/pinfo\.php|/php_info\.php|/database\.php|/db\.php|/wp-config\.php|/(config|configuration|settings|secrets|backup|dump)\.(php|ya?ml|json|ini|xml|sql)|\.(bak|old|orig|save|swp|swo|sql|sqlite|db|dump|tar|tgz|zip|rar|7z|bz2)($|\?)|(\.\./|%2e%2e/|/etc/passwd|/proc/self)|\$\{jndi:|%24%7bjndi)"""

# --- Storage ---
DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "..", "soc.db"))

# --- Already-denied ranges (excluded from "new threat" metrics) ---
# ERR matches error-log "client: IP" / "[client IP]"; ACC matches access-log
# JSON "remote_addr":"IP". Keep both in sync with the ingress deny rules.
# Example: a single /24 already denied at the ingress (replace with your own).
DENY_ERR = r'client[: ]*\[?203\.0\.113\.'
DENY_ACC = r'remote_addr":"203\.0\.113\.'
# Same ranges as CIDRs — used to exclude already-denied IPs from "ban candidates".
DENY_NETS = ["203.0.113.0/24"]

# --- Auto-ban executor ---
AUTOBAN_INTERVAL = int(os.environ.get("AUTOBAN_INTERVAL", "60"))          # seconds between rule passes
AUTOBAN_MAX_PER_TICK = int(os.environ.get("AUTOBAN_MAX_PER_TICK", "20"))  # runaway cap: max new bans / pass
# Paths the auto-ban NEVER counts (safety whitelist — legit app endpoints). Substring,
# case-insensitive. Editable at runtime via /api/autoban/ignore (stored in app_settings).
AUTOBAN_IGNORE_PATHS_DEFAULT = ["/broadcasting/auth", "/horizon", "/telescope", "/api/"]

# --- Loops ---
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "30"))    # seconds between Loki polls
ANALYTICS_INTERVAL = int(os.environ.get("ANALYTICS_INTERVAL", "60"))  # heavy breakdowns
LLM_INTERVAL = int(os.environ.get("LLM_INTERVAL", "1800"))    # seconds between LLM insights (30 min — ease CPU LLM)
DIGEST_TTL = int(os.environ.get("DIGEST_TTL", "21600"))       # daily digest cache (6h)
HISTORY_BASELINE = int(os.environ.get("HISTORY_BASELINE", "60"))  # snapshots used as baseline
