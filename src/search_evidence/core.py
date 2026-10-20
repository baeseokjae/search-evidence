"""Value semantics shared by providers, storage, CLI and MCP."""

from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, Field


class EvidenceError(Exception):
    """Only controlled codes cross a public interface; never raw HTTP exceptions."""

    def __init__(self, code: str, *, retryable: bool = False):
        self.code = code
        self.retryable = retryable
        super().__init__(code)


class Result(BaseModel):
    ok: bool = True
    data: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    error: dict[str, Any] | None = None


def failure(code: str, retryable: bool = False) -> Result:
    return Result(ok=False, error={"code": code, "retryable": retryable})


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def atomic_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        Path(name).unlink(missing_ok=True)


def number(value: Any, *, position: bool = False) -> float | int | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        n = float(value)
    except (ValueError, TypeError, OverflowError):
        return None
    if not math.isfinite(n) or n < 0 or (position and n <= 0):
        return None
    return int(n) if n.is_integer() else n


def metrics(clicks: Any, impressions: Any, position: Any = None, *, position_supported=True) -> dict:
    c, i, p = number(clicks), number(impressions), number(position, position=True)
    reasons = {}
    if c is None:
        reasons["clicks"] = "missing_or_invalid"
    if i is None:
        reasons["impressions"] = "missing_or_invalid"
    ctr = c / i if c is not None and i and c <= i else None
    if ctr is None:
        reasons["ctr"] = "zero_denominator" if i == 0 else "missing_or_invalid"
    if p is None:
        reasons["position"] = "missing_or_invalid" if position_supported else "unsupported"
    return {"clicks": c, "impressions": i, "ctr": ctr, "position": p, "missing": reasons}


def window(start: str, end: str) -> tuple[date, date]:
    try:
        a, b = date.fromisoformat(start), date.fromisoformat(end)
    except (TypeError, ValueError):
        raise EvidenceError("invalid_date_window") from None
    if a > b:
        raise EvidenceError("invalid_date_window")
    return a, b


def in_property(url: str, site: str) -> bool:
    """Scope validation only. No URL normalization or alias collapsing."""
    if not isinstance(url, str) or any(ord(c) < 32 for c in url):
        return False
    try:
        u = urlsplit(url)
        if u.scheme not in ("https", "http") or not u.hostname or u.username or u.password:
            return False
        if site.startswith("sc-domain:"):
            domain = site.removeprefix("sc-domain:").lower()
            return u.hostname == domain or u.hostname.endswith("." + domain)
        s = urlsplit(site)
        return (u.scheme, u.netloc.lower()) == (s.scheme, s.netloc.lower()) and u.path.startswith(s.path)
    except ValueError:
        return False


def secret_free_error(exc: Exception) -> Result:
    if isinstance(exc, EvidenceError):
        return failure(exc.code, exc.retryable)
    # No exception messages: libraries may include credentials, query text or paths.
    return failure("internal_error")
