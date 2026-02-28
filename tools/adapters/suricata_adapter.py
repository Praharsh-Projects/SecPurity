#!/usr/bin/env python3
import argparse, json, sys, time
from typing import Dict, Any
import requests

def map_suricata_to_ingest(obj: Dict[str, Any], tenant: str) -> Dict[str, Any]:
    ts = obj.get("timestamp") or obj.get("flow", {}).get("start") or obj.get("event_timestamp") or obj.get("time")
    sensor = "suricata"
    src_ip = obj.get("src_ip")
    dst_ip = obj.get("dest_ip") or obj.get("dst_ip")
    dst_port = obj.get("dest_port") or obj.get("dst_port")
    proto = obj.get("proto")
    message = None
    labels = []

    # if it's an alert, include signature
    alert = obj.get("alert")
    if alert:
        sig = alert.get("signature")
        sid = alert.get("signature_id")
        message = sig or message
        if sid: labels.append(f"sid:{sid}")
        labels.append("suricata_alert")

    return {
        "tenant": tenant,
        "ts": ts or "",
        "sensor": sensor,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": int(dst_port) if isinstance(dst_port, (int, str)) and str(dst_port).isdigit() else None,
        "proto": str(proto).upper() if proto else None,
        "message": message,
        "labels": labels or None
    }

def main():
    ap = argparse.ArgumentParser(description="Suricata eve.json → /ingest/log")
    ap.add_argument("file", help="Path to eve.json (JSON lines)")
    ap.add_argument("--tenant", required=True, help="Tenant/org id")
    ap.add_argument("--api", default="http://localhost:8080", help="API base URL")
    ap.add_argument("--sleep", type=float, default=0.0, help="Sleep seconds between posts")
    args = ap.parse_args()

    url = f"{args.api.rstrip('/')}/ingest/log"
    ok = err = 0
    with open(args.file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                raw = json.loads(line)
                payload = map_suricata_to_ingest(raw, args.tenant)
                r = requests.post(url, json=payload, timeout=5)
                if r.ok:
                    ok += 1
                else:
                    err += 1
                    sys.stderr.write(f"HTTP {r.status_code}: {r.text}\n")
                if args.sleep: time.sleep(args.sleep)
            except Exception as e:
                err += 1
                sys.stderr.write(f"ERR: {e}\n")
    print(f"done: ok={ok} err={err}")

if __name__ == "__main__":
    main()