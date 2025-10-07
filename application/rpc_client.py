import json
import os
import time
from typing import Optional
from urllib.parse import urlparse, urlunparse

# ``requests`` is optional on macOS; fall back to ``urllib`` if it's missing
try:  # pragma: no cover - simple import guard
    import requests
    from requests.adapters import HTTPAdapter, Retry
    from requests import exceptions as requests_exceptions
    REQUESTS_BASE_EXCEPTION = requests_exceptions.RequestException

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
            effective_timeout = timeout
            if isinstance(timeout, tuple):
                effective_timeout = sum(timeout)
            with urllib.request.urlopen(req, timeout=effective_timeout) as resp:
                return _SimpleResponse(resp.read(), resp.getcode())

    # ``requests`` not available — use the simple urllib-based session
    requests = None  # type: ignore
    requests_exceptions = None  # type: ignore
    REQUESTS_BASE_EXCEPTION = ()  # type: ignore
    SESSION = _SimpleSession()


# Allow overriding the RPC endpoint via env. When only ALYNCOIN_RPC_URL is set,
# derive host/port so other parts of the app behave consistently.
RPC_URL_ENV = os.environ.get("ALYNCOIN_RPC_URL")
RPC_HOST = os.environ.get("ALYNCOIN_RPC_HOST", "127.0.0.1")
RPC_PORT = os.environ.get("ALYNCOIN_RPC_PORT", "1567")
RPC_PATH = "/rpc"

KEY_DIR = os.path.expanduser(os.environ.get("ALYNCOIN_KEY_DIR", "~/.alyncoin/keys"))
WALLET_DATA_DIR = os.path.dirname(os.path.normpath(KEY_DIR)) or os.path.expanduser("~/.alyncoin")
WALLET_MAP_PATH = os.path.join(WALLET_DATA_DIR, "wallet_map.json")

_WALLET_MAP_CACHE = {}
_WALLET_MAP_MTIME = None

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

# Mining a block can be slow at high difficulty — allow generous timeout, but
# keep the connection timeout short so the UI stays responsive when the node
# is offline. ``TIMEOUT_S`` is kept for backward compatibility with older
# imports.
CONNECT_TIMEOUT_S = float(os.environ.get("ALYNCOIN_RPC_CONNECT_TIMEOUT", "0.75"))
READ_TIMEOUT_S = float(os.environ.get("ALYNCOIN_RPC_TIMEOUT", "300"))
TIMEOUT_S = READ_TIMEOUT_S
REQUEST_TIMEOUT = (CONNECT_TIMEOUT_S, READ_TIMEOUT_S)


def _format_rpc_exception(exc: Exception) -> str:
    """Return a user-friendly message for RPC connection failures."""

    detail = ""
    if (
        requests is not None
        and REQUESTS_BASE_EXCEPTION
        and isinstance(exc, REQUESTS_BASE_EXCEPTION)
    ):
        connect_timeout = getattr(requests_exceptions, "ConnectTimeout", ())
        read_timeout = getattr(requests_exceptions, "ReadTimeout", ())
        timeout = getattr(requests_exceptions, "Timeout", ())
        conn_error = getattr(requests_exceptions, "ConnectionError", ())
        if isinstance(exc, connect_timeout):
            detail = "connection attempt timed out"
        elif isinstance(exc, read_timeout):
            detail = "RPC response timed out"
        elif isinstance(exc, timeout):
            detail = "request timed out"
        elif isinstance(exc, conn_error):
            inner = getattr(exc, "__cause__", None)
            if inner and hasattr(inner, "strerror"):
                detail = getattr(inner, "strerror") or str(inner)
            elif inner:
                detail = str(inner)
            else:
                detail = "connection failed"
    elif isinstance(exc, (TimeoutError, OSError)):
        if getattr(exc, "strerror", None):
            detail = exc.strerror or ""
        if not detail:
            detail = str(exc)
    else:
        detail = str(exc)

    detail = (detail or "").strip()
    base = f"Unable to reach AlynCoin RPC at {RPC_HOST}:{RPC_PORT}"
    if detail:
        return f"{base} ({detail})"
    return base


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
                    RPC_URL, headers=headers, json=payload, timeout=REQUEST_TIMEOUT
                )
            else:
                resp = SESSION.post(
                    RPC_URL, headers=headers, data=payload, timeout=REQUEST_TIMEOUT
                )
        except Exception as e:
            raise RuntimeError(_format_rpc_exception(e)) from e

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
            status = alyncoin_rpc("peerstatus", [])
            if isinstance(status, dict):
                return True
        except RuntimeError as exc:
            last_error = exc
        except Exception as exc:  # pragma: no cover - defensive guard
            last_error = exc
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


def fetch_peer_status() -> dict:
    """Return the current peer connection summary.

    The dictionary always contains ``connected`` (int), ``state`` (str), and
    ``peers`` (list[str]) keys.  RPC failures propagate as ``RuntimeError`` so
    callers can surface an error message to the user.
    """

    raw = alyncoin_rpc("peerstatus")
    if not isinstance(raw, dict):
        return {"connected": 0, "state": "offline", "peers": []}

    connected = raw.get("connected", 0)
    state = raw.get("state", "offline")
    peers = raw.get("peers", [])

    try:
        connected = int(connected)
    except Exception:
        connected = 0

    if not isinstance(state, str):
        state = "offline"

    if isinstance(peers, list):
        peers = [str(p) for p in peers]
    else:
        peers = []

    return {"connected": connected, "state": state, "peers": peers}


def _load_wallet_map():
    global _WALLET_MAP_CACHE, _WALLET_MAP_MTIME
    try:
        stat = os.stat(WALLET_MAP_PATH)
    except FileNotFoundError:
        _WALLET_MAP_CACHE = {}
        _WALLET_MAP_MTIME = None
        return _WALLET_MAP_CACHE
    if _WALLET_MAP_MTIME == stat.st_mtime:
        return _WALLET_MAP_CACHE

    try:
        with open(WALLET_MAP_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            _WALLET_MAP_CACHE = {
                str(k).lower(): str(v).lower()
                for k, v in data.items()
                if isinstance(k, str) and isinstance(v, str)
            }
        else:
            _WALLET_MAP_CACHE = {}
    except Exception:
        _WALLET_MAP_CACHE = {}
    _WALLET_MAP_MTIME = stat.st_mtime
    return _WALLET_MAP_CACHE


def _has_key_files(prefix: str) -> bool:
    priv = os.path.join(KEY_DIR, f"{prefix}_private.pem")
    dil = os.path.join(KEY_DIR, f"{prefix}_dilithium.key")
    fal = os.path.join(KEY_DIR, f"{prefix}_falcon.key")
    return all(os.path.exists(path) for path in (priv, dil, fal))


def resolve_local_key_identifier(token: str) -> Optional[str]:
    canonical = (token or "").strip().lower()
    if not canonical:
        return None

    mapping = _load_wallet_map()
    mapped = mapping.get(canonical)
    if mapped:
        return mapped

    if _has_key_files(canonical):
        return canonical

    return None


def ensure_wallet_ready(address: str, key_id: Optional[str] = None):
    """Return ``(True, key_id)`` if required key files are present."""

    address = (address or "").strip()
    key_id = (key_id or "").strip()

    if not address and not key_id:
        return False, "No wallet loaded."

    candidates = []
    if key_id:
        candidates.append(key_id)

    resolved_from_address = None
    if address:
        resolved_from_address = resolve_local_key_identifier(address)
        if resolved_from_address and resolved_from_address not in candidates:
            candidates.append(resolved_from_address)
        if address not in candidates:
            candidates.append(address)

    attempts = []
    for candidate in candidates:
        if not candidate:
            continue
        priv = os.path.join(KEY_DIR, f"{candidate}_private.pem")
        dil = os.path.join(KEY_DIR, f"{candidate}_dilithium.key")
        fal = os.path.join(KEY_DIR, f"{candidate}_falcon.key")
        missing = [p for p in (priv, dil, fal) if not os.path.exists(p)]
        if not missing:
            return True, candidate
        attempts.append((candidate, missing))

    if attempts:
        candidate, missing = attempts[0]
        missing_names = ", ".join(os.path.basename(p) for p in missing)
        hint = ""
        if (
            resolved_from_address
            and candidate == resolved_from_address
            and address.lower() != candidate.lower()
        ):
            hint = f" (resolved from {address})"
        return False, f"Missing key files for '{candidate}'{hint}: {missing_names}"

    return False, "Missing key files for wallet."


def safe_alyncoin_rpc(method: str, params=None, id_: Optional[int] = None):
    """Return RPC result or an ``{"error": str}`` mapping on failure.

    The desktop GUI triggers many RPC calls from Qt slots.  If a call raises a
    ``RuntimeError`` (for example when the local node is still syncing or the
    RPC service dropped), PyQt will propagate the exception to the event loop
    and terminate the application.  Returning a structured error keeps the GUI
    responsive while surfacing the failure to the user.
    """

    try:
        return alyncoin_rpc(method, params, id_)
    except RuntimeError as exc:
        return {"error": str(exc)}
    except Exception as exc:  # pragma: no cover - defensive guard
        return {"error": f"{type(exc).__name__}: {exc}"}


__all__ = [
    "alyncoin_rpc",
    "safe_alyncoin_rpc",
    "RPC_URL",
    "RPC_HOST",
    "RPC_PORT",
    "wait_for_rpc_ready",
    "ensure_wallet_ready",
    "resolve_local_key_identifier",
]

