#!/usr/bin/env python3
"""Drive every playground walkthrough through the playground's own API.

Used by the `e2e-playground` CI job and runnable locally against a booted
stack (`deploy/docker-compose.playground.yml`). It clicks what a visitor
clicks: one session cookie, every scenario, every step in order, asserting
the step's declared expectation and its invariants - plus, for the erasure
walkthrough, that the signed webhook actually lands in the inbox.

No dependencies beyond the standard library, like the demo scripts.
"""

import http.cookiejar
import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("PLAYGROUND_URL", "http://localhost:8081")
TIMEOUT = 30

opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
)


def call(path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path, data=data,
        headers={"Content-Type": "application/json"} if data else {},
    )
    with opener.open(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode() or "{}")


def wait_for_playground():
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            with opener.open(BASE + "/healthz", timeout=5):
                return
        except (urllib.error.URLError, OSError):
            time.sleep(1)
    sys.exit(f"FAIL: {BASE} never became healthy")


def main():
    wait_for_playground()
    listing = call("/api/scenarios")
    scenarios = listing["scenarios"]
    if not scenarios:
        sys.exit("FAIL: the playground served no scenarios")
    print(f"instance: {listing['instance']}, {len(scenarios)} walkthrough(s)")

    failures = []
    for sc in scenarios:
        missing = sc.get("missing_roles") or []
        if missing:
            failures.append(f"{sc['id']}: no credential for {', '.join(missing)}")
            continue
        print(f"\n=== {sc['id']}: {sc['title']}")
        for i, step in enumerate(sc["steps"]):
            res = call("/api/run", {"scenario": sc["id"], "step": i})["result"]
            mark = "PASS" if res["ok"] else "FAIL"
            print(f"  {mark} step {i + 1}: {step['label']} -> HTTP {res['status']}"
                  f" (expected {res['expect']}) {res.get('error', '')}")
            if not res["ok"]:
                failures.append(
                    f"{sc['id']} step {i + 1} ({step['label']}): expected "
                    f"{res['expect']}, got {res['status']} {res.get('error', '')} "
                    f"{res.get('response', {}).get('body', '')}")
            for a in res.get("assertions") or []:
                print(f"       assert {a['kind']}({a['left']}, {a['right']}):"
                      f" {'OK' if a['ok'] else 'FAILED'}")
                if not a["ok"]:
                    failures.append(f"{sc['id']} step {i + 1}: invariant failed - {a['message']}")

        # The erasure walkthrough is only proven when the signed callback
        # has actually arrived and verified: the queue drains out of band.
        if sc["panel"] == "webhook":
            deliveries = []
            deadline = time.time() + 30
            while time.time() < deadline:
                deliveries = call("/api/inbox")["deliveries"]
                if deliveries:
                    break
                time.sleep(2)
            if not deliveries:
                failures.append(f"{sc['id']}: no erasure webhook was delivered within 30s")
            else:
                for d in deliveries:
                    print(f"  delivery {d['event']} scope={d['scope']} "
                          f"erasure={d['erasure_id']} signature={d['signature']}")
                    if d["signature"] != "valid":
                        failures.append(
                            f"{sc['id']}: delivery signature was {d['signature']}, not valid")

    if failures:
        print("\n--- failures ---", file=sys.stderr)
        for f in failures:
            print("  " + f, file=sys.stderr)
        sys.exit(1)
    print("\nevery walkthrough passed")


if __name__ == "__main__":
    main()
