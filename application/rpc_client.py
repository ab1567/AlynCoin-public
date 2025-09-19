import json
import os
import time
from typing import Optional
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
            allowed_methods=frozenset(["POST"]),
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

    class _SimpleSession:
        def post(self, url, headers=None, json=None, data=None, timeout=30):
            if json is not None:
                data_bytes = json_module.dumps(json).encode()
            else:
                data_bytes = data if isinstance(data, (bytes, bytearray)) else (data or "").encode()
            req = urllib.request.Request(url, data=data_bytes, headers=headers or {}, method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
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

# Mining a block can be slow at high difficulty — allow generous timeout.
TIMEOUT_S = 300


def alyncoin_rpc(method: str, params=None, id_: Optional[int] = None):
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
        try:
            if use_json:
                resp = SESSION.post(
                    RPC_URL, headers=headers, json=payload, timeout=TIMEOUT_S
                )
            else:
                resp = SESSION.post(
                    RPC_URL, headers=headers, data=payload, timeout=TIMEOUT_S
                )
        except Exception as e:
            raise RuntimeError(f"RPC request failed: {e}") from e

        text = getattr(resp, "text", "")
        try:
            data = resp.json()
        except Exception as e:
            msg = text or str(e)
            raise RuntimeError(f"Failed to decode RPC response: {msg}") from e

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
                        raise RuntimeError(f"RPC error {code}: {msg}")
                    raise RuntimeError(str(err))
                return data.get("result")
            raise RuntimeError(f"RPC error {code}: {msg}")
        raise RuntimeError(str(err))

    return data.get("result")


def wait_for_rpc_ready(timeout: float = 10.0, interval: float = 0.25) -> bool:
    """Poll ``peercount`` until the RPC server responds or ``timeout`` elapses."""

    deadline = time.time() + timeout
    last_error: Optional[Exception] = None
    while time.time() < deadline:
        try:
            alyncoin_rpc("peercount", [])
            return True
        except RuntimeError as exc:
            last_error = exc
        except Exception as exc:  # pragma: no cover - defensive guard
            last_error = exc
        time.sleep(interval)

    if last_error:
        print(f"⚠️  RPC not ready: {last_error}")
    return False


def safe_alyncoin_rpc(method: str, params=None, id_: Optional[int] = None):
    """Wrapper around :func:`alyncoin_rpc` that returns error dicts.

    The desktop wallet has a number of buttons that trigger JSON-RPC calls in
    response to user interaction.  Previously any networking issue (for
    example, the bundled node taking a little longer to expose its RPC port)
    would bubble up as a ``RuntimeError`` and crash the Qt slot.  Returning a
    ``{"error": "..."}`` structure allows the UI to surface a friendly
    message instead of raising an unhandled exception.
    """

    try:
        return alyncoin_rpc(method, params, id_)
    except RuntimeError as exc:
        return {"error": str(exc)}


__all__ = [
    "alyncoin_rpc",
    "safe_alyncoin_rpc",
    "RPC_URL",
    "RPC_HOST",
    "RPC_PORT",
    "wait_for_rpc_ready",
]

