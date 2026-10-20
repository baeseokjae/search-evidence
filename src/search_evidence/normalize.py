from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from .core import EvidenceError, metrics, number

BING_TABLES = {
    "GetRankAndTrafficStats": "daily",
    "GetPageStats": "pages",
    "GetQueryStats": "queries",
    "GetPageQueryStats": "page_queries",
}


def google_rows(raw: dict, dimensions: list[str]) -> list[dict]:
    if not isinstance(raw, dict) or "error" in raw or not isinstance(raw.get("rows", []), list):
        raise EvidenceError("invalid_google_response")
    out = []
    for row in raw.get("rows", []):
        if not isinstance(row, dict) or len(row.get("keys", [])) != len(dimensions):
            raise EvidenceError("invalid_google_row")
        dims = dict(zip(dimensions, row.get("keys", []), strict=True))
        if any(not isinstance(v, str) for v in dims.values()):
            raise EvidenceError("invalid_google_dimension")
        out.append(
            {
                "dimensions": dims,
                "url": dims.get("page"),
                "metrics": metrics(row.get("clicks"), row.get("impressions"), row.get("position")),
            }
        )
    return out


def bing_date(raw) -> dict:
    out = {
        "raw": raw,
        "epoch_ms": None,
        "offset": None,
        "label_date": None,
        "timezone": "unknown",
        "bucket_interval": "unknown",
    }
    match = re.fullmatch(r"/Date\((-?\d+)([+-]\d{4})?\)/", raw or "")
    if match:
        epoch, offset = int(match[1]), match[2]
        out.update(epoch_ms=epoch, offset=offset)
        try:
            dt = datetime.fromtimestamp(epoch / 1000, timezone.utc)
            if offset:
                mins = (int(offset[1:3]) * 60 + int(offset[3:5])) * (1 if offset[0] == "+" else -1)
                if abs(mins) >= 1440:
                    raise ValueError
                dt = dt.astimezone(timezone(timedelta(minutes=mins)))
            out["label_date"] = dt.date().isoformat()
        except (ValueError, OverflowError, OSError):
            pass
    return out


def bing_rows(raw: dict | list, method: str) -> list[dict]:
    payload = raw.get("d") if isinstance(raw, dict) else raw
    if not isinstance(payload, list):
        raise EvidenceError("invalid_bing_envelope")
    out = []
    for row in payload:
        if not isinstance(row, dict) or "Date" not in row:
            raise EvidenceError("invalid_bing_row")
        dims = {"bing_date_raw": row["Date"]}
        url = None
        if method in ("GetPageStats", "GetQueryStats", "GetPageQueryStats"):
            q = row.get("Query")
            if not isinstance(q, str):
                raise EvidenceError("invalid_bing_query")
            dims["page" if method == "GetPageStats" else "query"] = q
            if method == "GetPageStats":
                url = q
        met = metrics(
            row.get("Clicks"),
            row.get("Impressions"),
            row.get("AvgImpressionPosition"),
            position_supported=method != "GetRankAndTrafficStats",
        )
        if method != "GetRankAndTrafficStats":
            met["click_position"] = number(row.get("AvgClickPosition"), position=True)
            if met["click_position"] is None:
                met["missing"]["click_position"] = "missing_or_invalid"
        out.append({"dimensions": dims, "url": url, "metrics": met, "date": bing_date(row["Date"])})
    return out


def google_coverage(
    raw: dict, *, exhausted: bool, truncated: bool, requested_state="final", imported=False
) -> dict:
    metadata = raw.get("metadata") or {}
    return {
        "pagination_exhausted": exhausted,
        "may_be_truncated": truncated,
        "provider_limited": True,
        "anonymized_queries_excluded": True,
        "requested_data_state": requested_state,
        "first_incomplete_date": metadata.get("first_incomplete_date", metadata.get("firstIncompleteDate")),
        "aggregation": raw.get("responseAggregationType"),
        "timezone": "America/Los_Angeles",
        "imported": imported,
        "complete_export": False,
    }
