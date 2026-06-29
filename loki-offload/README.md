# Loki offload — отдельный Loki под дашборд (198.51.100.20)

Дашборд душил кластерный Loki (`loki.example.com`) тяжёлыми запросами (429).
Решение: **локальный Loki на 198.51.100.20**, существующий promtail дублирует логи туда
вторым client'ом. Дашборд запрашивает локальный Loki. Без SSL — доступ по IP,
защита cloud firewall.

```
кластер: существующий promtail ─push(http по IP)─► 198.51.100.20:3100 (Loki, Docker)
дашборд (198.51.100.20) ─query─► 127.0.0.1:3100
loki.example.com — дашбордом больше не дёргается
```

## Уже сделано на 198.51.100.20 (мной)
- Loki в Docker `loki-local`: tsdb+filesystem, ретеншн **14д**, лимиты подняты
  (max_query_series 100k — костыли с 500-series не нужны). Слушает `0.0.0.0:3100`.
  Конфиг `/opt/loki-local/config.yaml`, данные `/opt/loki-local/data`.
- Проверено: `/ready` 200, push/Query работают.
- nginx push-прокси и basic-auth — удалены (не нужны).

## Тебе сделать (2 шага)
1. **cloud firewall** на 198.51.100.20: разрешить **TCP 3100** только с **публичных IP нод кластера**.
   IP нод: `kubectl --context prod get nodes -o wide` → колонка EXTERNAL-IP.
   (Порт 3100 сейчас слушает, но cloud firewall его по умолчанию режет — пока правило не добавишь, никто не достучится, в т.ч. promtail.)
2. **Существующий promtail** (`loki_prod/values.yaml`) — добавить **второй client**:
   ```yaml
   promtail:
     enabled: true
     config:
       logLevel: info
       serverPort: 3101
       clients:
         - url: http://{{ .Release.Name }}:3100/loki/api/v1/push   # кластерный (как было)
         - url: http://198.51.100.20:3100/loki/api/v1/push          # ← дашбордовый Loki
   ```
   Затем редеплой Loki-чарта (как обычно).

## После того как логи поедут
Скажи — я переключу дашборд на локальный Loki (`LOKI_URL=http://localhost:3100`,
рестарт soc) и уберу костыли с 500-series fallback. Окна 24h/7д станут быстрыми,
429 уйдут.

## Проверка, что логи доехали (после шагов 1–2)
```bash
ssh root@198.51.100.20 'curl -s "http://127.0.0.1:3100/loki/api/v1/query?query=count_over_time(%7Bapp%3D%22ingress-nginx%22%7D%5B5m%5D)" | head -c 300'
```

Примечание: на 198.51.100.20 поедут ВСЕ логи кластера (существующий promtail шлёт всё) →
ретеншн 14д, следим за диском (сейчас 49G свободно). Если много — снизим ретеншн.
