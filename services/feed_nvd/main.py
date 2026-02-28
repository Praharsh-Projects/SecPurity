import os, json, time, sys
from datetime import datetime, timedelta, timezone
import requests
from dateutil import parser as dtparse
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

API_URL = os.getenv("API_URL", "http://api:8080")
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
STATE_PATH = os.getenv("STATE_PATH", "/state/nvd_state.json")
WINDOW_HOURS = int(os.getenv("WINDOW_HOURS", "12"))  # how far back to look if no state

TENANT = os.getenv("TENANT", "acme").strip() or "acme"
API_KEY = os.getenv("API_KEY", "supersecret_change_me")
END_MARGIN_MIN = int(os.getenv("NVD_END_MARGIN_MINUTES", "5"))
START_OVERLAP_MIN = int(os.getenv("NVD_START_OVERLAP_MINUTES", "5"))
POST_SLEEP_SEC = float(os.getenv("POST_SLEEP_SEC", "0.02"))

def iso_ms(dtobj):
    return dtobj.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def load_state():
    try:
        with open(STATE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_state(state):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w") as f:
        json.dump(state, f)

class RateLimited(Exception): pass

@retry(reraise=True, stop=stop_after_attempt(6),
       wait=wait_exponential(multiplier=1, min=2, max=60),
       retry=retry_if_exception_type((RateLimited, requests.RequestException)))
def fetch_nvd_page(params):
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {
        "User-Agent": "SecPurityAI-NVD/1.0",
        "Accept": "application/json",
    }
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        r = requests.get(base, params=params, headers=headers, timeout=60)
    except requests.RequestException as e:
        # Allow tenacity to retry on transient network failures
        raise

    # Helpful diagnostics for common client errors
    if r.status_code == 404:
        # NVD returns 404 for invalid/missing date bounds; include params snippet for debugging
        snippet = r.text[:200]
        raise requests.HTTPError(f"NVD 404 Not Found — check lastModStartDate/lastModEndDate formatting (require .sssZ) and window validity. Params={params} Body={snippet}")
    if r.status_code == 403:
        raise requests.HTTPError("NVD 403 Forbidden — API key missing/invalid or not authorized. Set NVD_API_KEY and retry.")
    if r.status_code == 429:
        # Trigger tenacity exponential backoff
        raise RateLimited("NVD 429 rate limit")
    if 400 <= r.status_code < 500:
        snippet = r.text[:200]
        raise requests.HTTPError(f"NVD client error {r.status_code}: {snippet}")

    r.raise_for_status()
    return r.json()

def iter_cves(since_iso, end_iso, mode: str = "lastMod"):
    start = dtparse.isoparse(since_iso)
    end = dtparse.isoparse(end_iso)

    # NVD caps page size; we loop with startIndex
    start = dtparse.isoparse(since_iso)
    end = dtparse.isoparse(end_iso)
    param_start = "lastModStartDate" if mode == "lastMod" else "pubStartDate"
    param_end   = "lastModEndDate"   if mode == "lastMod" else "pubEndDate"

    start_index = 0
    page_size = 2000
    while True:
        params = {
            param_start: iso_ms(start),
            param_end:   iso_ms(end),
            "resultsPerPage": page_size,
            "startIndex": start_index,
            "noRejected": "true",
        }
        if os.getenv("DEBUG_NVD") == "1":
            print(f"[feed-nvd] GET window params ({mode}): {params}", flush=True)

        data = fetch_nvd_page(params)  # will raise on 404/403/429/etc
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break
        for it in vulns:
            yield it.get("cve", {})

        total = int(data.get("totalResults", 0))
        start_index += len(vulns)
        if start_index >= total:
            break


def cve_to_event(cve):
    cve_id = cve.get("id") or "CVE-UNKNOWN"
    descriptions = cve.get("descriptions") or []
    desc = ""
    for d in descriptions:
        if d.get("lang") == "en":
            desc = d.get("value") or ""
            break
    # labels: nvd, cve id, cvss (if any), vendor/product tokens from CPE
    labels = ["nvd", cve_id]
    metrics = cve.get("metrics") or {}
    cvss_val = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            cvss_val = arr[0].get("cvssData", {}).get("baseScore")
            break
    if cvss_val is not None:
        labels.append(f"cvss:{cvss_val}")
    labels.extend(vendor_product_labels_from_cpe(cve))
    published = cve.get("published") or cve.get("lastModified")
    try:
        ts = dtparse.isoparse(published).astimezone(timezone.utc)
    except Exception:
        ts = datetime.now(timezone.utc)
    return {
        "tenant": TENANT,
        "ts": ts.isoformat(),
        "sensor": "nvd",
        "message": f"{cve_id}: {desc}",
        "labels": labels,
        "raw": {"cve": cve},
    }

def post_event(evt):
    url = f"{API_URL.rstrip('/')}/ingest/log"
    for attempt in range(6):
        r = requests.post(url, json=evt, timeout=60, headers={"X-API-Key": API_KEY})
        if r.status_code == 429:
            ra = int(r.headers.get("Retry-After", "2"))
            time.sleep(min(ra + 1, 30))
            continue
        r.raise_for_status()
        return
    r.raise_for_status()

def vendor_product_labels_from_cpe(cve: dict, limit: int = 6):
    labs, seen = [], set()
    for conf in (cve.get("configurations") or []):
        for node in conf.get("nodes", []):
            for cm in node.get("cpeMatch", []):
                cpe = cm.get("criteria")
                if not cpe:
                    continue
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor, product = parts[3], parts[4]
                    vtok = f"vendor:{vendor}" if vendor else None
                    ptok = f"product:{product}" if product else None
                    if vtok and vtok not in seen:
                        labs.append(vtok); seen.add(vtok)
                    if ptok and ptok not in seen:
                        labs.append(ptok); seen.add(ptok)
                    if len(labs) >= limit:
                        return labs
    return labs

def run_once():
    state = load_state()

    # Compute window with margin (avoid "now") and overlap (avoid gaps)
    now = datetime.now(timezone.utc)
    end_dt = now - timedelta(minutes=END_MARGIN_MIN)
    end = end_dt.isoformat()

    since = state.get("last_mod_from")
    if since:
        try:
            since_dt = dtparse.isoparse(since) - timedelta(minutes=START_OVERLAP_MIN)
        except Exception:
            since_dt = end_dt - timedelta(hours=WINDOW_HOURS)
    else:
        since_dt = end_dt - timedelta(hours=WINDOW_HOURS)
    start = since_dt.isoformat()

    count = 0
    try:
        # Try last-modified window first
        for cve in iter_cves(start, end, mode="lastMod"):
            evt = cve_to_event(cve)
            post_event(evt)
            count += 1
            if count % 50 == 0:
                print(f"[feed-nvd] posted {count} events…", flush=True)
            time.sleep(POST_SLEEP_SEC)
    except requests.HTTPError as e:
        # If NVD returns 404 on last-mod, retry once using publication window
        if "404" in str(e):
            print("[feed-nvd] 404 on lastMod window; retrying with publication window…", flush=True)
            for cve in iter_cves(start, end, mode="pub"):
                evt = cve_to_event(cve)
                post_event(evt)
                count += 1
                if count % 50 == 0:
                    print(f"[feed-nvd] posted {count} events…", flush=True)
                time.sleep(POST_SLEEP_SEC)
        else:
            raise

    # advance watermark to the end of this window
    state["last_mod_from"] = end
    save_state(state)
    print(f"[feed-nvd] window {start}..{end} -> {count} events", flush=True)

def main():
    # simple loop with sleep
    interval = int(os.getenv("RUN_EVERY_SEC", "600"))  # default 10 minutes
    while True:
        try:
            run_once()
        except Exception as e:
            print(f"[feed-nvd] error: {e}", file=sys.stderr, flush=True)
        time.sleep(interval)

if __name__ == "__main__":
    if os.getenv("RUN_ONCE") == "1":
        run_once()
    else:
        main()