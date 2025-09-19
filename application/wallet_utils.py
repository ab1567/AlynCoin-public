"""Utilities shared by wallet-aware tabs."""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Tuple

KEY_DIR_ENV = "ALYNCOIN_KEY_DIR"
_DEFAULT_KEY_DIR = "~/.alyncoin/keys"


def get_wallet_dir() -> Path:
    """Return the directory where wallet key files are stored."""

    configured = os.environ.get(KEY_DIR_ENV, _DEFAULT_KEY_DIR)
    path = Path(os.path.expanduser(configured)).resolve()
    try:
        path.mkdir(parents=True, exist_ok=True)
    except Exception:
        # Directory creation failures are handled by callers when they try to
        # use the returned path.  Keeping the helper silent avoids noisy logs in
        # read-only environments while still returning a usable Path object.
        pass
    return path


def _candidate_stems(address: str, key_id: str | None) -> List[str]:
    stems: List[str] = []
    for candidate in (key_id or "", address or ""):
        candidate = candidate.strip()
        if candidate and candidate not in stems:
            stems.append(candidate)
    return stems


def _expected_files(stem: str) -> Tuple[Path, Path]:
    base = get_wallet_dir()
    return base / f"{stem}_private.pem", base / f"{stem}_public.pem"


def ensure_wallet_ready(address: str, key_id: str | None = None) -> Tuple[bool, str]:
    """Verify that the selected wallet has the required key material locally.

    Returns ``(True, "")`` when the wallet looks usable.  If files are missing,
    ``False`` is returned alongside a human-readable explanation.
    """

    address = (address or "").strip()
    if not address:
        return False, "No active wallet selected. Please create or import a wallet first."

    stems = _candidate_stems(address, key_id)
    if not stems:
        stems = [address]

    missing_reports: List[str] = []
    for stem in stems:
        priv, pub = _expected_files(stem)
        missing = [p.name for p in (priv, pub) if not p.exists()]
        if not missing:
            return True, ""
        missing_reports.append(f"{stem}: {', '.join(missing)}")

    base = get_wallet_dir()
    detail = "; ".join(missing_reports)
    return False, (
        "Missing key files for wallet. "
        f"Looked in {base} and could not find: {detail}."
    )


__all__ = ["ensure_wallet_ready", "get_wallet_dir"]
