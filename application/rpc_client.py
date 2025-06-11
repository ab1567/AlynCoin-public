import os
import requests

RPC_HOST = os.environ.get("ALYNCOIN_RPC_HOST", "127.0.0.1")
RPC_PORT = int(os.environ.get("ALYNCOIN_RPC_PORT", "1567"))
RPC_URL = os.environ.get("ALYNCOIN_RPC_URL", f"http://{RPC_HOST}:{RPC_PORT}/rpc")

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
