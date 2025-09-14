import os
import time
from typing import Optional
from urllib.parse import urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter, Retry


# Allow overriding the RPC endpoint via env. When only ALYNCOIN_RPC_URL is set,
# derive host/port so other parts of the app behave consistently.
RPC_URL_ENV = os.environ.get("ALYNCOIN_RPC_URL")
RPC_HOST = os.environ.get("ALYNCOIN_RPC_HOST", "127.0.0.1")
RPC_PORT = os.environ.get("ALYNCOIN_RPC_PORT", "1567")
RPC_PATH = "/rpc"

if RPC_URL_ENV:
    try:
        parsed = urlparse(RPC_URL_ENV)
        if parsed.hostname:
            RPC_HOST = parsed.hostname
        if parsed.port:
            RPC_PORT = str(parsed.port)
        parsed = parsed._replace(path=RPC_PATH)
        RPC_URL = urlunparse(parsed)
    except Exception:
        base = RPC_URL_ENV.rstrip("/")
        RPC_URL = base + RPC_PATH if not base.endswith(RPC_PATH) else base
else:
    RPC_URL = f"http://{RPC_HOST}:{RPC_PORT}{RPC_PATH}"

RPC_PORT = int(RPC_PORT)

# Shared session with retries for robustness
SESSION = requests.Session()
adapter = HTTPAdapter(
    max_retries=Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=frozenset(["POST"]),
    )
)
SESSION.mount("http://", adapter)
SESSION.mount("https://", adapter)

# Mining a block can be slow at high difficulty — allow generous timeout.
TIMEOUT_S = 300


def alyncoin_rpc(method: str, params=None, id_: Optional[int] = None):
    """Call the AlynCoin JSON-RPC server and return the ``result`` value.

    Raises ``RuntimeError`` on RPC or HTTP failures.
    """

    headers = {"Content-Type": "application/json"}
    body = {
        "jsonrpc": "2.0",
        "id": id_ if id_ is not None else (int(time.time() * 1000) & 0x7FFFFFFF),
        "method": method,
        "params": params or [],
    }

    try:
        resp = SESSION.post(RPC_URL, headers=headers, json=body, timeout=TIMEOUT_S)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        raise RuntimeError(f"RPC request failed: {e}") from e

    if isinstance(data, dict) and data.get("error"):
        err = data["error"]
        if isinstance(err, dict):
            code = err.get("code", -32000)
            msg = err.get("message", "Unknown RPC error")
            raise RuntimeError(f"RPC error {code}: {msg}")
        raise RuntimeError(str(err))

    return data.get("result")


__all__ = ["alyncoin_rpc", "RPC_URL", "RPC_HOST", "RPC_PORT"]

