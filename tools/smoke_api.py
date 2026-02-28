#!/usr/bin/env python3
"""
Minimal end-to-end smoke test for SecPurityAI API.

Usage:
  API_BASE=http://localhost:8080 API_KEY=supersecret_change_me python3 tools/smoke_api.py
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from typing import Any, Dict, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


API_BASE = os.getenv("API_BASE", "http://localhost:8080").rstrip("/")
API_KEY = os.getenv("API_KEY", "supersecret_change_me")
TIMEOUT_SEC = int(os.getenv("SMOKE_TIMEOUT_SEC", "120"))


def _request(method: str, path: str, payload: Optional[Dict[str, Any]] = None, auth: bool = False) -> Dict[str, Any]:
    url = f"{API_BASE}{path}"
    body = None
    headers = {"Content-Type": "application/json"}
    if auth:
        headers["X-API-Key"] = API_KEY
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")

    req = Request(url=url, data=body, method=method, headers=headers)
    with urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def _wait_for_health() -> None:
    deadline = time.time() + TIMEOUT_SEC
    last_err = None
    while time.time() < deadline:
        try:
            health = _request("GET", "/health")
            if not isinstance(health, dict):
                time.sleep(2)
                continue
            if health.get("ok") is True:
                return
            if str(health.get("status", "")).lower() == "ok":
                return
        except Exception as exc:  # noqa: BLE001
            last_err = exc
        time.sleep(2)
    raise RuntimeError(f"API did not become healthy within {TIMEOUT_SEC}s. last_error={last_err}")


def main() -> int:
    try:
        print(f"[smoke] waiting for {API_BASE}/health", flush=True)
        _wait_for_health()

        stores = _request("GET", "/stores/ping")
        print(f"[smoke] stores: {stores}")

        marker = f"smoke-{uuid.uuid4()}"
        event = {
            "tenant": "acme",
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "sensor": "smoke",
            "src_ip": "10.10.10.10",
            "dst_ip": "8.8.8.8",
            "dst_port": 443,
            "proto": "TCP",
            "message": f"Smoke event {marker} CVE-2024-12345",
            "labels": ["smoke", "cve:CVE-2024-12345"],
            "raw": {"smoke_marker": marker},
        }
        ing = _request("POST", "/ingest/log", payload=event, auth=True)
        event_id = ing.get("id")
        if not event_id:
            raise RuntimeError(f"ingest did not return id: {ing}")
        print(f"[smoke] ingested event_id={event_id}")

        events = _request("GET", "/events?" + urlencode({"q": marker, "limit": 5}))
        items = events.get("items", [])
        if not any(i.get("id") == event_id for i in items):
            raise RuntimeError(f"new event not found in /events response: {events}")
        print("[smoke] event listing ok")

        evt = _request("GET", f"/events/{event_id}")
        if evt.get("id") != event_id:
            raise RuntimeError(f"/events/{event_id} mismatch: {evt}")
        print("[smoke] event drilldown ok")

        try:
            idx = _request("POST", f"/index/event/{event_id}", auth=True)
            if not idx.get("ok"):
                raise RuntimeError(f"indexing failed: {idx}")
            sim = _request("GET", "/similar?" + urlencode({"event_id": event_id, "limit": 3}))
            if "items" not in sim:
                raise RuntimeError(f"/similar unexpected response: {sim}")
            print("[smoke] vector index/similarity ok")
        except HTTPError as e:
            # Allow smoke to continue if vector backends are temporarily unavailable
            print(f"[smoke] warning: vector checks skipped (HTTP {e.code})")
        except URLError as e:
            print(f"[smoke] warning: vector checks skipped ({e})")

        alerts = _request("GET", "/alerts?limit=5")
        print(f"[smoke] alerts count={len(alerts.get('items', []))}")

        print("[smoke] PASS", flush=True)
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"[smoke] FAIL: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
