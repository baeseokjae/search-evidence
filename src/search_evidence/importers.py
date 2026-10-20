"""Explicit local imports; no access to operational modules or settings."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from .core import EvidenceError, metrics, now, window
from .normalize import BING_TABLES, bing_rows, google_coverage, google_rows
from .store import Store


def import_json(store: Store, site: str, path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
    except (ValueError, OSError):
        raise EvidenceError("invalid_import_file") from None
    if not isinstance(data, dict) or data.get("site") != site or not data.get("captured_at"):
        raise EvidenceError("import_property_or_timestamp_mismatch")
    stamp = data["captured_at"]
    ids = []
    if data.get("version") == 2 and isinstance(data.get("sources"), dict):
        for source, value in data["sources"].items():
            if source not in ("gsc", "bing", "ga4") or not isinstance(value, dict):
                continue
            if value.get("status") != "available":
                ids.append(
                    store.put(
                        source=source,
                        site=site,
                        table="source_status",
                        request={},
                        raw={"status": "unavailable"},
                        rows=[],
                        observed_at=stamp,
                        status="unavailable",
                        error="legacy_source_unavailable",
                    )["id"]
                )
                continue
            if source == "gsc":
                for name, table in value.items():
                    if not isinstance(table, dict) or "rows" not in table:
                        continue
                    request = {
                        "startDate": table["start"],
                        "endDate": table["end"],
                        "dimensions": table["dimensions"],
                        "type": value.get("search_type", "web"),
                        "dataState": "final",
                        "aggregationType": "auto",
                    }
                    raw = {
                        "rows": table["rows"],
                        "responseAggregationType": table.get("response_aggregation_type"),
                    }
                    ids.append(
                        store.put(
                            source=source,
                            site=site,
                            table=name,
                            request=request,
                            raw=raw,
                            rows=google_rows(raw, request["dimensions"]),
                            observed_at=stamp,
                            coverage=google_coverage(
                                raw,
                                exhausted=not table["may_be_truncated"],
                                truncated=table["may_be_truncated"],
                                imported=True,
                            ),
                        )["id"]
                    )
            elif source == "bing":
                for method, raw in value.get("raw", {}).items():
                    if method in BING_TABLES:
                        ids.append(
                            store.put(
                                source=source,
                                site=site,
                                table=BING_TABLES[method],
                                request={"method": method, "siteUrl": site},
                                raw={"d": raw},
                                rows=bing_rows(raw, method),
                                observed_at=stamp,
                                coverage={
                                    "timezone": "unknown",
                                    "bucket_interval": "unknown",
                                    "date_filter_supported": False,
                                    "imported": True,
                                },
                            )["id"]
                        )
            else:
                # GA4 remains a separate, nonadditive source. Never use sessions as search clicks.
                for name, table in value.items():
                    if not isinstance(table, dict) or "rows" not in table:
                        continue
                    ids.append(
                        store.put(
                            source="ga4",
                            site=site,
                            table=name,
                            request={
                                "startDate": data["requested_start"],
                                "endDate": data["requested_end"],
                                "dimensions": [x["name"] for x in table.get("dimensionHeaders", [])],
                            },
                            raw=table,
                            rows=[],
                            observed_at=stamp,
                            status="available",
                            coverage={
                                "raw_only": True,
                                "timezone": value.get("timezone"),
                                "users_additive": False,
                                "metadata": table.get("metadata", {}),
                                "normalized_rows_supported": False,
                            },
                        )["id"]
                    )
    elif isinstance(data.get("gsc"), dict):
        for name, table in data["gsc"].items():
            if not isinstance(table, dict) or not {"request", "response"} <= table.keys():
                continue
            req, raw = table["request"].copy(), table["response"]
            req.pop("rowLimit", None)
            req.pop("startRow", None)
            req.setdefault("aggregationType", "auto")
            ids.append(
                store.put(
                    source="gsc",
                    site=site,
                    table=name,
                    request=req,
                    raw=raw,
                    rows=google_rows(raw, req.get("dimensions", [])),
                    observed_at=stamp,
                    coverage=google_coverage(
                        raw, exhausted=False, truncated=len(raw.get("rows", [])) >= 25000, imported=True
                    ),
                )["id"]
            )
    else:
        raise EvidenceError("unsupported_import_format")
    return {"snapshot_ids": ids, "snapshots": len(ids), "protected_urls": len(store.protected(site))}


def import_csv(
    store: Store, site: str, path: Path, start: str, end: str, observed_at: str | None = None
) -> dict:
    """Canonical page CSV: url,clicks,impressions,position. Blank != zero."""
    window(start, end)
    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not {"url", "clicks", "impressions"} <= set(reader.fieldnames or []):
            raise EvidenceError("csv_columns_required")
        raw = list(reader)
    rows = [
        {
            "dimensions": {"page": r["url"]},
            "url": r["url"],
            "metrics": metrics(r["clicks"], r["impressions"], r.get("position")),
        }
        for r in raw
    ]
    return store.put(
        source="csv",
        site=site,
        table="pages",
        request={"startDate": start, "endDate": end, "dimensions": ["page"]},
        raw=raw,
        rows=rows,
        observed_at=observed_at or now(),
        coverage={"timezone": "unknown", "imported": True, "complete_export": False},
    )
