# soc backend — Loki aggregator + LLM insight + dashboard + autoban executor.
FROM python:3.12-slim

WORKDIR /app
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# app code + the static dashboard it serves (FRONTEND_DIR = ../../frontend)
COPY backend/app /app/app
COPY frontend /frontend

ENV DB_PATH=/data/soc.db
VOLUME ["/data"]
EXPOSE 8077

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8077"]
