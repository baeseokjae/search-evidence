# Data semantics

| Observation | Representation |
|---|---|
| Observed zero clicks | `clicks: 0` |
| Missing or invalid count | `null`, with a reason |
| Provider request failure | Snapshot `unavailable` or `partial`, controlled error code |
| Unsupported position | `null`, reason `unsupported` |
| Absent query/page row | Unknown; never synthesized as zero |
| Positive clicks in any retained snapshot | Raw URL stays `protected` |
| No positive-click evidence | `review_required` |
| Unverified deployment/index content | Explicit `false` verification flag, not a completion claim |

CTR is a fraction. `0.03` means 3%. It is derived from valid clicks divided by
positive impressions; zero denominator is unknown. Position zero and negative
sentinels are unknown. A comparison with a zero baseline has an absolute delta
but no fabricated relative percentage.

## Google

Requests record property, dimensions, search type, aggregation, filters, date
range and requested data state. Dates use `America/Los_Angeles`; daylight saving
is handled by the timezone database.

Dimension-free totals remain separate from page and query totals. Top-row
selection, aggregation differences and anonymized queries prevent treating every
dimension table as a full accounting of the property.

`finality` uses date-dimension `dataState=all` observations and preserves
`first_incomplete_date`. It reports observed final dates; absent dates are not
asserted to be finalized zero-traffic days. A requested `final` state alone does
not prove that every requested day was returned.

Comparison requires matching conditions, aggregation and timezone, equal-length
nonoverlapping date windows and available snapshots. Date-dimension rows require
an explicit alignment strategy and are rejected in this release.

## Bing

Page URLs come from the `Query` field of `GetPageStats`. `AvgImpressionPosition`
and `AvgClickPosition` remain distinct. Rank/traffic rows do not invent a position.
Null counters remain unknown.

Date strings retain their epoch, explicit offset and original value. A derived
date is just a display label. It does not establish the service's reporting
timezone, bucket length, or comparability with Google's window.

Repeated history requests are separate snapshots. Their rows are not added
together. Date and provider boundaries remain explicit in CSV output.

## Imports

Version-2 JSON expects:

```json
{
  "version": 2,
  "site": "https://example.com/",
  "captured_at": "2026-02-01T00:00:00Z",
  "requested_start": "2026-01-01",
  "requested_end": "2026-01-28",
  "sources": {
    "gsc": {
      "status": "available",
      "pages": {
        "dimensions": ["page"],
        "start": "2026-01-01",
        "end": "2026-01-28",
        "response_aggregation_type": "byPage",
        "may_be_truncated": false,
        "rows": [{"keys": ["https://example.com/a/"], "clicks": 1, "impressions": 20}]
      }
    }
  }
}
```

Historical Google request/response imports instead contain `site`, `captured_at`
and `gsc: {table_name: {request: {...}, response: {...}}}`. Imported capture times
are retained; an import is not relabeled as a fresh API observation.

GA4 tables are stored raw with timezone and response metadata. Normalized GA4
rows are explicitly unsupported, so the traffic interface returns no fabricated
rows. Sessions/users/page views are not search clicks and are not used for URL
protection.

## Official API documentation

- [Google Search Analytics query](https://developers.google.com/webmaster-tools/v1/searchanalytics/query)
- [Google extraction limits](https://developers.google.com/webmaster-tools/v1/how-tos/all-your-data)
- [Google quotas](https://developers.google.com/webmaster-tools/limits)
- [Google URL Inspection](https://developers.google.com/webmaster-tools/v1/urlInspection.index/inspect)
- [Bing Webmaster API](https://learn.microsoft.com/en-us/bingwebmaster/)
- [Bing page statistics](https://learn.microsoft.com/en-us/dotnet/api/microsoft.bing.webmaster.api.interfaces.iwebmasterapi.getpagestats)
