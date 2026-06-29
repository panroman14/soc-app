# blocklist-api — ban orchestrator (renders denylist to ingress-CM / nginx / Cloudflare).
FROM python:3.12-slim

WORKDIR /app
COPY blocklist-api/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY blocklist-api/app /app/app

# Agent installer + source served at /install/* for the one-liner enrollment.
COPY deploy/agent/soc-nginx-agent.py /opt/soc/soc-nginx-agent.py
COPY deploy/agent/install.sh /opt/soc/install.sh

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
