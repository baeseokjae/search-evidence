from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .core import EvidenceError


@dataclass(frozen=True)
class Profile:
    site: str
    state_dir: Path
    google_credentials: Path | None = None
    bing_key: Path | None = None
    content_root: Path | None = None
    build_root: Path | None = None
    allowed_hosts: tuple[str, ...] = ()
    body_selector: str = ".post-content, main, article"
    max_calls: int = 200
    max_seconds: int = 180
    max_bytes: int = 4_194_304
    inspection_daily_limit: int = 20
    inspection_run_limit: int = 6


def load_profile(path: str | Path | None = None) -> Profile:
    name = path or os.getenv("SEARCH_EVIDENCE_PROFILE")
    if not name:
        raise EvidenceError("profile_required")
    source = Path(name).expanduser().resolve()
    try:
        data = tomllib.loads(source.read_text())
    except (OSError, ValueError):
        raise EvidenceError("invalid_profile") from None
    allowed = set(Profile.__dataclass_fields__)
    if set(data) - allowed or not {"site", "state_dir"} <= data.keys():
        raise EvidenceError("invalid_profile_fields")
    for key in ("state_dir", "google_credentials", "bing_key", "content_root", "build_root"):
        if data.get(key):
            p = Path(data[key]).expanduser()
            data[key] = (source.parent / p).resolve() if not p.is_absolute() else p.resolve()
    if not isinstance(data["site"], str):
        raise EvidenceError("invalid_property")
    site = data["site"]
    host = site.removeprefix("sc-domain:") if site.startswith("sc-domain:") else urlsplit(site).hostname
    if not host:
        raise EvidenceError("invalid_property")
    data["allowed_hosts"] = tuple(data.get("allowed_hosts", [host]))
    for key, ceiling in (
        ("max_calls", 2000),
        ("max_seconds", 1800),
        ("max_bytes", 20_000_000),
        ("inspection_daily_limit", 2000),
        ("inspection_run_limit", 100),
    ):
        if key in data and (type(data[key]) is not int or not 1 <= data[key] <= ceiling):
            raise EvidenceError("invalid_budget")
    return Profile(**data)
