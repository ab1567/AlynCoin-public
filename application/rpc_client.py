import os
import requests

# Allow overriding the RPC endpoint via environment variables. When only
# ``ALYNCOIN_RPC_URL`` is provided, also derive the host and port so that other
# parts of the application (e.g. node auto-launch checks) behave consistently.
RPC_URL_ENV = os.environ.get("ALYNCOIN_RPC_URL")
RPC_HOST = os.environ.get("ALYNCOIN_RPC_HOST", "127.0.0.1")
RPC_PORT = os.environ.get("ALYNCOIN_RPC_PORT", "1567")

if RPC_URL_ENV:
    RPC_URL = RPC_URL_ENV
    try:
        from urllib.parse import urlparse
        parsed = urlparse(RPC_URL_ENV)
        if parsed.hostname:
            RPC_HOST = parsed.hostname
        if parsed.port:
            RPC_PORT = str(parsed.port)
    except Exception:
        pass
else:
    RPC_URL = f"http://{RPC_HOST}:{RPC_PORT}/rpc"

RPC_PORT = int(RPC_PORT)

def alyncoin_rpc(method, params=None):
    headers = {"Content-Type": "application/json"}
    body = {"method": method, "params": params or []}
    try:
        resp = requests.post(RPC_URL, headers=headers, json=body, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            raise Exception(data["error"])
        return data.get("result", None)
    except Exception as e:
        print(f"❌ RPC error: {e}")
        return {"error": str(e)}