import os, json, time, datetime as dt
import requests
from dateutil import parser as dtp

API = os.environ.get("API_BASE", "http://api:8080")
API_KEY = os.environ.get("API_KEY", "supersecret_change_me")
TENANT = os.environ.get("CONNECTOR_TENANT", "acme")
INTERVAL = int(os.environ.get("CONNECTOR_INTERVAL_SEC", "900"))
STATE_PATH = os.environ.get("CONNECTOR_STATE_PATH", "/data/seen.json")

NVD_URL = os.environ.get(
    "NVD_URL",
    "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10"
)

def load_state():
    try:
        with open(STATE_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {"seen": []}

def save_state(state):
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_PATH)

def post_event(payload: dict) -> dict:
    r = requests.post(
        f"{API}/ingest/log",
        headers={"Content-Type": "application/json", "X-API-Key": API_KEY},
        data=json.dumps(payload),
        timeout=30
    )
    r.raise_for_status()
    return r.json()

def map_nvd_item(item: dict) -> dict:
    # NVD v2 wraps CVEs inside "vulnerabilities": [{"cve": {...}}]
    cve = item.get("cve", {}).get("id") or "UNKNOWN-CVE"
    descs = item.get("cve", {}).get("descriptions", [])
    desc = (descs[0]["value"] if descs else "")[:240]

    now = dt.datetime.utcnow().replace(tzinfo=dt.timezone.utc).isoformat()
    labels = ["cve"]
    cvss = None
    metrics = item.get("cve", {}).get("metrics", {})
    # Try a couple of common keys for CVSS
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
            break
    if cvss is not None:
        labels.append(f"cvss:{cvss}")

    return {
        "tenant": TENANT,
        "ts": now,
        "sensor": "nvd",
        "message": f"{cve}: {desc}",
        "labels": labels,
        "raw": {"cve": cve, "data": item},
    }

def poll_nvd(state: dict):
    try:
        res = requests.get(NVD_URL, timeout=30)
        res.raise_for_status()
        vulns = res.json().get("vulnerabilities", [])
    except Exception as e:
        print("[connector] NVD error:", e)
        return

    seen = set(state.get("seen", []))
    new_seens = []
    posted = 0

    for wrapper in vulns:
        item = wrapper.get("cve") or wrapper  # handle slight shape variance
        cve_id = item.get("id") if item else None
        if not cve_id or cve_id in seen:
            continue
        payload = map_nvd_item({"cve": item})
        try:
            resp = post_event(payload)
            print("[connector] POSTED", cve_id, resp.get("id"))
            posted += 1
            new_seens.append(cve_id)
        except Exception as e:
            print("[connector] POST failed for", cve_id, "->", e)

    if new_seens:
        state["seen"] = list(seen.union(new_seens))
        save_state(state)
        print(f"[connector] posted={posted}, total_seen={len(state['seen'])}")
    else:
        print("[connector] no new CVEs")

def main():
    state = load_state()
    print("[connector] starting; API_BASE=", API, "interval=", INTERVAL)
    while True:
        poll_nvd(state)
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()