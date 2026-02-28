FROM python:3.11-slim

# Trust TLS endpoints
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY runner.py .

# Persist simple dedupe state
VOLUME ["/data"]

ENV CONNECTOR_INTERVAL_SEC=900 \
    CONNECTOR_TENANT=acme \
    API_BASE=http://api:8080

CMD ["python", "runner.py"]