#!/usr/bin/env python3
import argparse, json, sys, time
from typing import Dict, Any
import requests

def map_zeek_conn_to_ingest(obj: Dict[str, Any], tenant: str) -> Dict[str, Any]:
    ts = obj.get("ts") or obj.get("_path_ts")
    sensor = "zeek"
    # Zeek fields for conn.log
    src_ip = obj.get("id.orig_h") or obj.get("orig_h") or obj.get("id_orig_h")
    dst_ip = obj.get("id.resp_h") or obj.get("resp_h") or obj.get("id_resp_h")
    dst_port = obj.get("id.resp_p") or obj.get("resp_p") or obj.get("id_resp_p")
    proto = obj.get("proto")
    message = obj.get("service") or obj.get("_path") or "conn"

    # Normalize proto (zeek uses lowercase)
    proto_norm = str(proto).upper() if proto else None

    return {
        "tenant": tenant,
        "ts": str(ts) if ts is not None else "",
        "sensor": sensor,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": int(dst_port) if isinstance(dst_port, (int, str)) and str(dst_port).isdigit() else None,
        "proto": proto_norm,
        "message": message,
        "labels": ["zeek_conn"]
    }

def main():
    ap = argparse.ArgumentParser(description="Zeek conn.log (JSON) → /ingest/log")
    ap.add_argument("file", help="Path to JSON lines file (conn.log in JSON)")
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
                payload = map_zeek_conn_to_ingest(raw, args.tenant)
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