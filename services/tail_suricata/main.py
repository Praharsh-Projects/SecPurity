import os, time, json, sys
from datetime import datetime, timezone
import requests
from dateutil import parser as dtparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from watchdog.observers.polling import PollingObserver

API_URL   = os.getenv("API_URL", "http://api:8080").rstrip("/")
API_KEY   = os.getenv("API_KEY", "supersecret_change_me")
TENANT    = (os.getenv("TENANT", "acme") or "acme").strip()
EVE_PATH  = os.getenv("EVE_PATH", "/data/eve.json")
SEEK_END  = os.getenv("SEEK_END", "1") == "1"        # start at end by default
SLEEP_SEC = float(os.getenv("SLEEP_SEC", "0.25"))    # poll sleep between reads
POST_SLEEP_SEC = float(os.getenv("POST_SLEEP_SEC", "0.01"))
HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT_SEC", "30"))

def post_event(evt):
    url = f"{API_URL}/ingest/log"
    for attempt in range(6):
        r = requests.post(url, json=evt, timeout=HTTP_TIMEOUT, headers={"X-API-Key": API_KEY})
        if r.status_code == 429:
            ra = int(r.headers.get("Retry-After", "2"))
            time.sleep(min(ra + 1, 30))
            continue
        r.raise_for_status()
        return
    r.raise_for_status()

def iso(ts):
    if isinstance(ts, datetime):
        return ts.astimezone(timezone.utc).isoformat()
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    try:
        return dtparse.isoparse(str(ts)).astimezone(timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()

def map_suricata(line):
    # Suricata EVE JSON; parse any line (alert/dns/http/tls/flow)
    try:
        obj = json.loads(line)
    except Exception:
        return None

    # timestamps: prefer event timestamp, else flow.start, else now
    ts_raw = obj.get("timestamp") or obj.get("@timestamp") or obj.get("flow", {}).get("start") or datetime.now(timezone.utc)
    ts = iso(ts_raw)

    etype = obj.get("event_type") or "log"
    src = obj.get("src_ip")
    dst = obj.get("dest_ip") or obj.get("dst_ip")
    proto = obj.get("proto") or obj.get("proto_transport")
    dport = obj.get("dest_port") or obj.get("dst_port")

    # base labels
    labels = ["suricata", etype]

    # Alert details
    alert = obj.get("alert") or {}
    sig = alert.get("signature")
    sid = alert.get("signature_id")
    cat = alert.get("category")
    sev = alert.get("severity")
    if alert:
        labels.append("ioc_hit")
        if sid: labels.append(f"sid:{sid}")
        if cat: labels.append(f"category:{cat}")
        if sev is not None: labels.append(f"severity:{sev}")

    # Protocol-specific hints
    if etype == "dns":
        q = (obj.get("dns") or {}).get("rrname")
        if q: labels.append(f"dns:{q}")
    if etype == "http":
        host = (obj.get("http") or {}).get("hostname")
        if host: labels.append(f"http_host:{host}")
    if etype == "tls":
        sni = (obj.get("tls") or {}).get("sni")
        if sni: labels.append(f"sni:{sni}")

    msg = sig or etype or "suricata event"

    evt = {
        "tenant": TENANT,
        "ts": ts,
        "sensor": "suricata",
        # normalize to fields our API/store expects:
        "src": src,
        "dst": dst,
        "proto": proto,
        "port": dport,
        "message": msg,
        "labels": labels,
        "raw": obj
    }
    return evt

class TailHandler(FileSystemEventHandler):
    def __init__(self, path):
        self.path = path
        self._pos = 0
        # initialize at end if SEEK_END=1
        try:
            with open(self.path, "rb") as f:
                if SEEK_END:
                    f.seek(0, 2)
                    self._pos = f.tell()
                else:
                    self._pos = 0
        except FileNotFoundError:
            self._pos = 0

    def on_modified(self, event):
        if event.src_path != self.path:
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                # handle truncation: if file shorter than our pos, reset
                try:
                    f.seek(0, 2)
                    end_size = f.tell()
                except Exception:
                    end_size = None
                if end_size is not None and end_size < self._pos:
                    self._pos = 0
                f.seek(self._pos)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    evt = map_suricata(line)
                    if evt:
                        try:
                            post_event(evt)
                            time.sleep(POST_SLEEP_SEC)
                        except Exception as e:
                            print(f"[tail] post error: {e}", file=sys.stderr, flush=True)
                self._pos = f.tell()
        except Exception as e:
            print(f"[tail] read error: {e}", file=sys.stderr, flush=True)

def main():
    if not os.path.isdir(os.path.dirname(EVE_PATH) or "."):
        os.makedirs(os.path.dirname(EVE_PATH) or ".", exist_ok=True)
    if not os.path.exists(EVE_PATH):
        print(f"[tail] waiting for {EVE_PATH}…", flush=True)
    observer = PollingObserver()
    handler = TailHandler(EVE_PATH)
    watch_dir = os.path.abspath(os.path.dirname(EVE_PATH) or ".")
    observer.schedule(handler, watch_dir, recursive=False)
    observer.start()
    print(f"[tail] start tenant={TENANT} path={EVE_PATH} api={API_URL} seek_end={SEEK_END}", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()