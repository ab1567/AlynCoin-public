import json
import os
import time
from typing import Optional, Tuple
from urllib.parse import urlparse, urlunparse

# ``requests`` is optional on macOS; fall back to ``urllib`` if it's missing
try:  # pragma: no cover - simple import guard
    import requests
    from requests.adapters import HTTPAdapter, Retry

    # Shared session with retries for robustness
    SESSION = requests.Session()
    adapter = HTTPAdapter(
        max_retries=Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[502, 503, 504],
            allowed_methods=frozenset(["GET", "POST"]),
            raise_on_status=False,
        )
    )
    SESSION.mount("http://", adapter)
    SESSION.mount("https://", adapter)
except ModuleNotFoundError:  # pragma: no cover
    import urllib.request

    json_module = json  # alias to avoid clashing with ``json`` parameter below

    class _SimpleResponse:
        def __init__(self, data: bytes, code: int):
            self._data = data.decode()
            self.text = self._data
            self.status_code = code

        def json(self):
            return json_module.loads(self._data)

        @property
        def ok(self) -> bool:
            return self.status_code < 400

    class _SimpleSession:
        def _normalize_timeout(self, timeout):
            if isinstance(timeout, (tuple, list)) and timeout:
                try:
                    return float(max(timeout))
                except Exception:
                    return 30.0
            try:
                return float(timeout)
            except Exception:
                return 30.0

        def post(self, url, headers=None, json=None, data=None, timeout=30):
            if json is not None:
                data_bytes = json_module.dumps(json).encode()
            else:
                data_bytes = data if isinstance(data, (bytes, bytearray)) else (data or "").encode()
            req = urllib.request.Request(url, data=data_bytes, headers=headers or {}, method="POST")
            with urllib.request.urlopen(req, timeout=self._normalize_timeout(timeout)) as resp:
                return _SimpleResponse(resp.read(), resp.getcode())

        def get(self, url, timeout=30):
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=self._normalize_timeout(timeout)) as resp:
                return _SimpleResponse(resp.read(), resp.getcode())

    # ``requests`` not available — use the simple urllib-based session
    requests = None  # type: ignore
    SESSION = _SimpleSession()


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

DEFAULT_CONNECT_TIMEOUT = float(os.environ.get("ALYNCOIN_RPC_CONNECT_TIMEOUT", "2.0"))
DEFAULT_READ_TIMEOUT = float(os.environ.get("ALYNCOIN_RPC_READ_TIMEOUT", "10.0"))
DEFAULT_TIMEOUT: Tuple[float, float] = (DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT)
# Mining a block can be slow at high difficulty — allow generous timeout.
MINING_TIMEOUT = float(os.environ.get("ALYNCOIN_RPC_MINING_TIMEOUT", "300.0"))


class RpcClientError(RuntimeError):
    """Base class for RPC related errors."""


class RpcNotReady(RpcClientError):
    """Raised when the RPC endpoint is unreachable or times out."""


class RpcDecodeError(RpcClientError):
    """Raised when the HTTP response cannot be decoded as JSON."""


class RpcError(RpcClientError):
    """Raised when the RPC server returns an ``error`` object."""


def _should_use_long_timeout(method: str) -> bool:
    return method in {"mineonce", "rollup", "recursive-rollup"}


def _build_timeout(method: str, timeout):
    if timeout is not None:
        return timeout
    if _should_use_long_timeout(method):
        return (DEFAULT_CONNECT_TIMEOUT, MINING_TIMEOUT)
    return DEFAULT_TIMEOUT


def alyncoin_rpc(method: str, params=None, id_: Optional[int] = None, *, timeout=None):
    """Call the AlynCoin JSON-RPC server and return the ``result`` value.

    Raises ``RuntimeError`` on RPC or HTTP failures.  When talking to older
    nodes that predate the JSON-RPC 2.0 envelope, the function automatically
    retries with the legacy request format.
    """

    headers = {"Content-Type": "application/json"}
    body = {
        "jsonrpc": "2.0",
        "id": id_ if id_ is not None else (int(time.time() * 1000) & 0x7FFFFFFF),
        "method": method,
        "params": params or [],
    }

    def _do_request(payload, use_json=True):
        req_timeout = _build_timeout(method, timeout)
        try:
            if use_json:
                resp = SESSION.post(
                    RPC_URL, headers=headers, json=payload, timeout=req_timeout
                )
            else:
                resp = SESSION.post(
                    RPC_URL, headers=headers, data=payload, timeout=req_timeout
                )
        except Exception as e:
            raise RpcNotReady(f"RPC request failed: {e}") from e

        text = getattr(resp, "text", "")
        try:
            data = resp.json()
        except Exception as e:
            msg = text or str(e)
            raise RpcDecodeError(f"Failed to decode RPC response: {msg}") from e

        if getattr(resp, "status_code", 200) >= 400:
            return data
        return data

    data = _do_request(body, use_json=True)

    if isinstance(data, dict) and data.get("error"):
        err = data["error"]
        if isinstance(err, dict):
            code = err.get("code", -32000)
            msg = err.get("message", "Unknown RPC error")
            # Legacy nodes may return a parse error (-32700) when they don't
            # understand the JSON-RPC 2.0 envelope. Retry with the original
            # format for backward compatibility.
            if code == -32700:
                legacy_body = json.dumps({"method": method, "params": params or []})
                data = _do_request(legacy_body, use_json=False)
                if isinstance(data, dict) and data.get("error"):
                    err = data["error"]
                    if isinstance(err, dict):
                        code = err.get("code", -32000)
                        msg = err.get("message", "Unknown RPC error")
                        raise RpcError(f"{code}: {msg}")
                    raise RpcError(str(err))
                return data.get("result")
            raise RpcError(f"{code}: {msg}")
        raise RpcError(str(err))

    return data.get("result")


def _rpc_healthcheck(timeout: float = 2.0) -> bool:
    metrics_url = f"http://{RPC_HOST}:{RPC_PORT}/metrics"
    try:
        resp = SESSION.get(metrics_url, timeout=(timeout, timeout))
        if getattr(resp, "status_code", 0) == 200:
            return True
    except Exception:
        pass

    probe_body = {"jsonrpc": "2.0", "id": "health", "method": "ping", "params": []}
    try:
        _ = SESSION.post(
            RPC_URL,
            headers={"Content-Type": "application/json"},
            json=probe_body,
            timeout=(timeout, timeout),
        )
        return True
    except Exception:
        return False


def wait_for_rpc_ready(timeout: float = 15.0, interval: float = 0.25) -> bool:
    """Poll the metrics endpoint (and fall back to ``ping``) until ready."""

    deadline = time.time() + timeout
    while time.time() < deadline:
        if _rpc_healthcheck(timeout=interval * 2):
            return True
        time.sleep(interval)
    print("⚠️  RPC not ready: timed out waiting for health check")
    return False


__all__ = [
    "alyncoin_rpc",
    "RPC_URL",
    "RPC_HOST",
    "RPC_PORT",
    "wait_for_rpc_ready",
    "RpcClientError",
    "RpcNotReady",
    "RpcDecodeError",
    "RpcError",
]

