import os, time, json, requests
from datetime import datetime, timezone, timedelta

print("[kev] starting KEV collector…", flush=True)

MAX_RPS = float(os.getenv("MAX_RPS", "3"))   # throttle: max posts per second (default 3)
MIN_INTERVAL = 1.0 / MAX_RPS
_last_post_ts = 0.0
MAX_ITEMS_PER_RUN = int(os.getenv("MAX_ITEMS_PER_RUN", "100"))  # cap per cycle to avoid flooding

def _throttle():
    global _last_post_ts
    now = time.monotonic()
    wait = MIN_INTERVAL - (now - _last_post_ts)
    if wait > 0:
        time.sleep(wait)
    _last_post_ts = time.monotonic()

API_URL = os.getenv("API_URL", "http://api:8080")
API_KEY = os.getenv("API_KEY", "supersecret_change_me")
STATE_PATH = os.getenv("STATE_PATH", "/state/kev_state.json")
RUN_EVERY_SEC = int(os.getenv("RUN_EVERY_SEC", "3600"))
# KEV URL (CISA occasionally changes; override via env if needed)
KEV_URL = os.getenv(
    "KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

HDRS = {"User-Agent": "SecPurityAI-KEV/1.0", "Accept": "application/json"}

print(f"[kev] config: API_URL={API_URL} RUN_EVERY_SEC={RUN_EVERY_SEC} MAX_RPS={MAX_RPS} MAX_ITEMS_PER_RUN={MAX_ITEMS_PER_RUN}", flush=True)

def load_state():
    try:
        with open(STATE_PATH, "r") as f: return json.load(f)
    except Exception: return {"seen": []}

def save_state(s):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w") as f: json.dump(s, f)

def to_event(item: dict) -> dict:
    cve = item.get("cveID") or item.get("cveId") or "UNKNOWN"
    desc = item.get("shortDescription", "")
    date_added = item.get("dateAdded")  # e.g., "2024-06-10"
    vendor = item.get("vendorProject")
    product = item.get("product")
    labels = ["kev", "known_exploited"]
    if vendor: labels.append(f"vendor:{vendor}")
    if product: labels.append(f"product:{product}")
    message = f"{cve} {desc}".strip()
    ts = (date_added + "T00:00:00Z") if date_added else datetime.now(timezone.utc).isoformat()
    return {
        "tenant": "acme",
        "ts": ts,
        "sensor": "kev",
        "message": message,
        "labels": labels,
        "raw": item,
    }

def post_event(ev: dict):
    # throttle to avoid 429
    for attempt in range(6):  # ~1 + 2 + 4 + 8 + 16 + 32s worst case
        _throttle()
        r = requests.post(
            f"{API_URL}/ingest/log",
            headers={"Content-Type": "application/json", "X-API-Key": API_KEY},
            data=json.dumps(ev),
            timeout=30,
        )
        if r.status_code == 429:
            ra = r.headers.get("Retry-After")
            try:
                delay = float(ra) if ra else (2 ** attempt)
            except Exception:
                delay = (2 ** attempt)
            print(f"[kev] 429 rate-limited; retrying in {delay:.1f}s (attempt {attempt+1}/6)", flush=True)
            time.sleep(delay)
            continue
        r.raise_for_status()
        return r.json()
    raise RuntimeError("Too many 429s when posting to /ingest/log")


def poll_once():
    r = requests.get(KEV_URL, headers=HDRS, timeout=120)
    r.raise_for_status()
    data = r.json()
    vulns = data.get("vulnerabilities") or data.get("vulnerabilities", [])
    state = load_state()
    seen = set(state.get("seen", []))
    new = 0
    for it in vulns:
        if new >= MAX_ITEMS_PER_RUN:
            print(f"[kev] hit MAX_ITEMS_PER_RUN={MAX_ITEMS_PER_RUN}; will continue next cycle", flush=True)
            break
        cve = it.get("cveID") or it.get("cveId")
        if not cve or cve in seen:
            continue
        ev = to_event(it)
        try:
            post_event(ev)
            seen.add(cve)
            new += 1
        except Exception as e:
            print("post failed:", e, flush=True)
    state["seen"] = sorted(list(seen))
    save_state(state)
    print(f"[kev] posted {new} new events; total seen {len(seen)}")

def main():
    while True:
        try: poll_once()
        except Exception as e: print("[kev] error:", e)
        time.sleep(RUN_EVERY_SEC)

if __name__ == "__main__":
    main()