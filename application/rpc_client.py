import os
import requests
from requests.adapters import HTTPAdapter, Retry

# Allow overriding the RPC endpoint via environment variables. When only
# ``ALYNCOIN_RPC_URL`` is provided, also derive the host and port so that other
# parts of the application (e.g. node auto-launch checks) behave consistently.
RPC_URL_ENV = os.environ.get("ALYNCOIN_RPC_URL")
RPC_HOST = os.environ.get("ALYNCOIN_RPC_HOST", "127.0.0.1")
RPC_PORT = os.environ.get("ALYNCOIN_RPC_PORT", "1567")
RPC_PATH = "/rpc"

if RPC_URL_ENV:
    try:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(RPC_URL_ENV)
        if parsed.hostname:
            RPC_HOST = parsed.hostname
        if parsed.port:
            RPC_PORT = str(parsed.port)
        # Ensure we hit the correct RPC path regardless of user supplied path
        path = parsed.path.rstrip("/") or RPC_PATH
        if path != RPC_PATH:
            parsed = parsed._replace(path=RPC_PATH)
        RPC_URL = urlunparse(parsed)
    except Exception:
        RPC_URL = RPC_URL_ENV
else:
    RPC_URL = f"http://{RPC_HOST}:{RPC_PORT}{RPC_PATH}"

RPC_PORT = int(RPC_PORT)

# Shared session with retries for robustness
SESSION = requests.Session()
SESSION.mount(
    "http://",
    HTTPAdapter(
        max_retries=Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
    ),
)

# Timeout for RPC calls (seconds)
# Mining a single block can take several minutes at high
# difficulty, so allow a generous timeout.
TIMEOUT_S = 300

def alyncoin_rpc(method, params=None):
    headers = {"Content-Type": "application/json"}
    body = {"method": method, "params": params or []}
    try:
        resp = SESSION.post(
            RPC_URL,
            headers=headers,
            json=body,
            timeout=TIMEOUT_S
        )
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            raise Exception(data["error"])
        return data.get("result", None)
    except Exception as e:
        print(f"❌ RPC error: {e}")
        return {"error": str(e)}


def l2_vm_selftest():
    return alyncoin_rpc("l2-vm-selftest")
