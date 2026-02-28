import json
import os
import sys
import time

import requests


API_URL = os.getenv("API_URL", "http://api:8080").rstrip("/")
API_KEY = os.getenv("API_KEY", "supersecret_change_me")
RUN_EVERY_SEC = int(os.getenv("RUN_EVERY_SEC", "86400"))
SUITE = os.getenv("EVAL_SUITE", "nightly")
INCLUDE_INGEST = os.getenv("INCLUDE_INGEST", "1") == "1"
RETRY_ON_ERROR_SEC = int(os.getenv("RETRY_ON_ERROR_SEC", "60"))


def wait_for_api(max_wait_sec: int = 180) -> None:
    health = f"{API_URL}/health"
    start = time.time()
    while time.time() - start < max_wait_sec:
        try:
            r = requests.get(health, timeout=5)
            if r.ok:
                return
        except Exception:
            pass
        time.sleep(2)
    raise RuntimeError(f"API health did not become ready within {max_wait_sec}s")


def run_once() -> None:
    url = f"{API_URL}/evaluation/run"
    payload = {"suite": SUITE, "include_ingest": INCLUDE_INGEST}
    headers = {"Content-Type": "application/json", "X-API-Key": API_KEY}
    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=120)
    r.raise_for_status()
    j = r.json()
    print(
        f"[evaluator] suite={SUITE} passed={j.get('passed')} pass_rate={j.get('pass_rate')} id={j.get('id')}",
        flush=True,
    )

    gate_url = f"{API_URL}/governance/release-gate/run"
    gate_payload = {"environment": "staging", "include_ingest": INCLUDE_INGEST, "generate_cards": True}
    gr = requests.post(gate_url, headers=headers, data=json.dumps(gate_payload), timeout=120)
    gr.raise_for_status()
    gj = gr.json()
    print(
        f"[evaluator] release_gate passed={gj.get('passed')} eval_rate={gj.get('evaluation', {}).get('pass_rate')}",
        flush=True,
    )


def main() -> None:
    print(
        f"[evaluator] starting API_URL={API_URL} interval={RUN_EVERY_SEC}s suite={SUITE} include_ingest={INCLUDE_INGEST}",
        flush=True,
    )
    while True:
        try:
            wait_for_api()
            run_once()
            sleep_sec = RUN_EVERY_SEC
        except Exception as e:
            print(f"[evaluator] error: {e}", file=sys.stderr, flush=True)
            sleep_sec = min(RETRY_ON_ERROR_SEC, RUN_EVERY_SEC)
        time.sleep(max(1, sleep_sec))


if __name__ == "__main__":
    main()
