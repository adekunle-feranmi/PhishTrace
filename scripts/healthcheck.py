#!/usr/bin/env python3
"""Container healthcheck: the public /health endpoint must answer 200."""

from __future__ import annotations

import json
import sys
import urllib.request

URL = "http://127.0.0.1:8088/health"


def main() -> int:
    try:
        with urllib.request.urlopen(URL, timeout=5) as response:  # noqa: S310 - fixed loopback URL
            body = json.loads(response.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - any failure means unhealthy
        print(f"unhealthy: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if response.status != 200 or body.get("status") != "ok":
        print(f"unhealthy: HTTP {response.status} {body}", file=sys.stderr)
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
