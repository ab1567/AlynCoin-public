import json
import os
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter, Retry

# -----------------------------------------------------------------------------
# Endpoint configuration (overridable via env)
# -----------------------------------------------------------------------------

# Example single var: ALYNCOIN_RPC_URL=http://127.0.0.1:1567/rpc
RPC_URL_ENV = os.environ.get("ALYNCOIN_RPC_URL")

# Or specify components:
RPC_HOST = os.environ.get("ALYNCOIN_RPC_HOST", "127.0.0.1")
RPC_PORT = int(os.environ.get("ALYNCOIN_RPC_PORT", "1567"))  # override if your RPC != 1567
RPC_BASE = f"http://{RPC_HOST}:{RPC_PORT}"

# If you know it, set ALYNCOIN_RPC_PATH to '/json_rpc' or '/rpc'
explicit_path = os.environ.get("ALYNCOIN_RPC_PATH")

# Try common JSON-RPC paths (order matters)
if explicit_path:
    CANDIDATE_PATHS = [explicit_path]
else:
    CANDIDATE_PATHS = ["/rpc", "/json_rpc"]

# Small timeout keeps the UI responsive when the daemon is down.
TIMEOUT = float(os.environ.get("ALYNCOIN_RPC_TIMEOUT", "3.0"))

# Optional metrics fallback for peer count
ENABLE_METRICS = os.environ.get("ALYNCOIN_METRICS_FALLBACK", "").lower() in (
    "1",
    "true",
    "yes",
)

# Shared session with mild retries for transient hiccups
SESSION = requests.Session()
SESSION.mount(
    "http://",
    HTTPAdapter(
        max_retries=Retry(
            total=2,
            backoff_factor=0.3,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=frozenset({"POST", "GET"}),
        )
    ),
)
SESSION.mount("https://", SESSION.adapters["http://"])


def _resolved_base() -> str:
    """
    If ALYNCOIN_RPC_URL is provided, prefer its scheme://host:port while still
    letting us try multiple paths.
    """
    if not RPC_URL_ENV:
        return RPC_BASE
    try:
        p = urlparse(RPC_URL_ENV)
        host = p.hostname or RPC_HOST
        port = p.port or RPC_PORT
        scheme = p.scheme or "http"
        return f"{scheme}://{host}:{port}"
    except Exception:
        return RPC_BASE


def _post_jsonrpc(url: str, method: str, params: Optional[Dict[str, Any]]):
    payload: Dict[str, Any] = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        payload["params"] = params
    # Let requests handle JSON serialization to avoid extraneous bytes that can
    # trip up strict servers.  This mirrors the approach used in earlier
    # revisions that did not exhibit parse errors.
    return SESSION.post(
        url,
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=TIMEOUT,
    )


def alyncoin_rpc(method: str, params: Optional[Dict[str, Any]] = None) -> Any:
    """
    Robust RPC wrapper:
      - Tries multiple candidate paths.
      - Returns either the 'result' or {'error': {...}} (no exceptions).
      - Optionally falls back to /metrics for 'peercount'.
    """
    base = _resolved_base()

    # 1) Try JSON-RPC on common paths
    for path in CANDIDATE_PATHS:
        url = f"{base}{path}"
        try:
            resp = _post_jsonrpc(url, method, params)
        except requests.RequestException:
            continue

        try:
            body = resp.json()
        except ValueError:
            body = None

        if isinstance(body, dict):
            if "result" in body:
                return body["result"]
            if "error" in body:
                # Consistent shape back to UI
                return body

    # 2) Fallback for non-JSON endpoints: best-effort peer count via /metrics
    if method == "peercount" and ENABLE_METRICS:
        try:
            m = SESSION.get(f"{base}/metrics", timeout=TIMEOUT)
            if m.ok:
                for line in m.text.splitlines():
                    if line.startswith("peer_count"):
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                return int(float(parts[-1]))
                            except Exception:
                                pass
        except requests.RequestException:
            pass

    # 3) Uniform error when nothing worked
    return {"error": {"code": -1, "message": f"RPC '{method}' unreachable or not supported"}}


__all__ = ["alyncoin_rpc", "RPC_HOST", "RPC_PORT", "RPC_BASE"]
