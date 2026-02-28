import os
import time
import json
import requests
from datetime import datetime, timezone
from requests.exceptions import RequestException, ConnectionError

API = os.getenv("API_URL", "http://api:8080")
KEY = os.getenv("API_KEY", "")
TENANT = os.getenv("TENANT", "acme")
INTERVAL_SECONDS = int(os.getenv("WORKER_INTERVAL_SECONDS", "3600"))  # hourly

HDR = {
    "X-API-Key": KEY,
    "Content-Type": "application/json"
}

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def wait_for_api(max_wait=120):
    """Block until the API health endpoint responds OK, or until max_wait seconds elapse."""
    url = f"{API}/health"
    print(f"[worker] waiting for API: {url}")
    start = time.time()
    while True:
        try:
            r = requests.get(url, timeout=5)
            if r.ok:
                print("[worker] API is healthy")
                return
        except Exception:
            pass
        if time.time() - start > max_wait:
            print(f"[worker] API not ready after {max_wait}s; proceeding anyway")
            return
        time.sleep(2)

def post_with_retry(path, payload, retries=3, backoff=1.5):
    """POST to API with simple retry + backoff to ride out startup races."""
    url = f"{API}{path}"
    for i in range(retries):
        try:
            r = requests.post(url, headers=HDR, json=payload, timeout=45)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            if i == retries - 1:
                raise
            time.sleep(backoff * (i + 1))

def iso_or_default(s: str, default="1970-01-01T00:00:00Z") -> str:
    # KEV uses 2025-08-18 format with 'T00:00:00Z' sometimes; normalize
    try:
        # If it already has time, just return
        if "T" in s:
            return s
        return f"{s}T00:00:00Z"
    except Exception:
        return default

def ingest(url, payload):
    return post_with_retry(url, payload, retries=3, backoff=1.5)

def fetch_kev_and_ingest():
    r = requests.get(KEV_URL, timeout=60)
    r.raise_for_status()
    data = r.json()

    vulns = data.get("vulnerabilities", [])
    print(f"[worker] KEV: fetched {len(vulns)} items")

    ingested = 0
    for v in vulns:
        cve = v.get("cveID")
        if not cve:
            continue

        # Build a friendly message and labels
        title = v.get("vulnerabilityName") or v.get("shortDescription") or "Known exploited vulnerability"
        date_added = iso_or_default(v.get("dateAdded", "1970-01-01"))
        labels = ["kev", "known_exploited", cve]

        payload = {
            "tenant": TENANT,
            "ts": date_added,
            "sensor": "kev",
            "message": f"{cve} {title}",
            "labels": labels,
            "raw": v  # keep the full record for audit/use later
        }

        try:
            ingest("/ingest/log", payload)
            ingested += 1
        except Exception as e:
            print(f"[worker] ingest error for {cve}: {e}")

    print(f"[worker] KEV: ingested {ingested} items")

def main():
    print("[worker] starting… API:", API)
    wait_for_api()
    while True:
        try:
            fetch_kev_and_ingest()
        except Exception as e:
            print("[worker] loop error:", e)
        time.sleep(INTERVAL_SECONDS)

if __name__ == "__main__":
    main()