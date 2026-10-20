import json

import pytest
from conftest import gsc_snapshot

from search_evidence.core import EvidenceError, in_property, metrics
from search_evidence.importers import import_csv, import_json
from search_evidence.normalize import bing_date, bing_rows, google_coverage
from search_evidence.store import Store


@pytest.mark.parametrize("value", [None, "", "NaN", "inf", -1, False])
def test_missing_metrics_never_become_zero(value):
    m = metrics(value, value, value)
    assert m["clicks"] is None and m["impressions"] is None and m["position"] is None
    assert m["ctr"] is None


def test_true_zero_and_ctr_units():
    assert metrics(0, 100)["ctr"] == 0
    assert metrics(3, 100)["ctr"] == 0.03
    assert metrics(0, 0)["ctr"] is None
    assert metrics(5, 2)["ctr"] is None


@pytest.mark.parametrize("suffix", ["/A", "/a", "/a/", "/a?q=1", "/a?q=2", "/%61", "/a#part"])
def test_raw_url_variants_preserved(service, suffix):
    url = "https://example.com" + suffix
    gsc_snapshot(service, rows=[{"keys": [url], "clicks": 1, "impressions": 1}])
    assert url in service.store.protected(service.profile.site)


def test_failure_and_zero_do_not_erase_click_history(service):
    first = gsc_snapshot(service)
    gsc_snapshot(service, rows=[], status="unavailable", stamp="2026-02-02T00:00:00Z")
    gsc_snapshot(
        service,
        rows=[{"keys": ["https://example.com/a/"], "clicks": 0, "impressions": 2}],
        stamp="2026-02-03T00:00:00Z",
    )
    p = service.protect_urls(["https://example.com/a/", "https://example.com/b/"])["rows"]
    assert p[0]["decision"] == "protected" and p[0]["evidence"][0]["snapshot"] == first["id"]
    assert p[1]["decision"] == "review_required"
    assert service.traffic()["rows"][0]["metrics"]["clicks"] == 0


def test_snapshot_idempotence_and_backup(service):
    a = gsc_snapshot(service)
    b = gsc_snapshot(service)
    assert a == b
    assert len(service.store.snapshots(service.profile.site)) == 1
    assert len(service.store.protected(service.profile.site)["https://example.com/a/"]["evidence"]) == 1
    backup = service.store.backup()
    restored = Store(__import__("pathlib").Path(backup["backup"]))
    try:
        assert restored.raw(a["id"]) == service.store.raw(a["id"])
        assert restored.protected(service.profile.site) == service.store.protected(service.profile.site)
    finally:
        restored.close()


def test_raw_integrity_failure(service):
    s = gsc_snapshot(service)
    h = s["raw_hash"]
    (service.store.root / "raw" / h[:2] / (h + ".json.gz")).write_bytes(b"corrupt")
    with pytest.raises(EvidenceError, match="raw_integrity_failure"):
        service.store.raw(s["id"])


def test_transaction_does_not_leave_successful_snapshot_without_facts(service, monkeypatch):
    # A serialization failure during fact insertion rolls the transaction back.
    with pytest.raises(TypeError):
        service.store.put(
            source="gsc",
            site=service.profile.site,
            table="pages",
            request={},
            raw={},
            rows=[{"invalid": object()}],
        )
    assert service.store.snapshots(service.profile.site) == []


def test_comparison_absence_and_zero_base(service):
    before = gsc_snapshot(
        service,
        rows=[
            {"keys": ["https://example.com/a/"], "clicks": 0, "impressions": 10},
            {"keys": ["https://example.com/b/"], "clicks": 3, "impressions": 10},
        ],
    )
    after = gsc_snapshot(
        service,
        start="2026-02-01",
        end="2026-02-28",
        rows=[{"keys": ["https://example.com/a/"], "clicks": 3, "impressions": 10}],
    )
    rows = service.compare(before["id"], after["id"])["rows"]
    assert rows[0]["metrics"]["clicks"]["absolute"] == 3
    assert rows[0]["metrics"]["clicks"]["relative"] is None
    assert rows[1]["metrics"]["clicks"]["after"] is None
    assert rows[1]["metrics"]["clicks"]["absolute"] is None


def test_incompatible_comparison_rejected(service):
    a = gsc_snapshot(service)
    b = gsc_snapshot(service, start="2026-02-01", end="2026-02-27")
    with pytest.raises(EvidenceError, match="equal_nonoverlapping"):
        service.compare(a["id"], b["id"])


def test_cursor_cannot_cross_snapshots_filters_or_be_tampered(service):
    a = gsc_snapshot(
        service,
        rows=[{"keys": [f"https://example.com/{i}/"], "clicks": i, "impressions": 9} for i in range(3)],
    )
    token = service.traffic(snapshot_id=a["id"], limit=1)["next_cursor"]
    assert service.traffic(snapshot_id=a["id"], cursor=token)["rows"][0]["metrics"]["clicks"] == 1
    b = gsc_snapshot(service, stamp="2026-03-01T00:00:00Z")
    for kwargs in (
        {"snapshot_id": b["id"], "cursor": token},
        {"snapshot_id": a["id"], "cursor": token, "url": "https://example.com/1/"},
        {"snapshot_id": a["id"], "cursor": token[:-1] + ("1" if token[-1] != "1" else "2")},
    ):
        with pytest.raises(EvidenceError, match="cursor"):
            service.traffic(**kwargs)


def test_bing_position_mapping_dates_and_missing():
    d = "/Date(1767225600000-0700)/"
    r = bing_rows(
        {
            "d": [
                {
                    "Date": d,
                    "Query": "https://example.com/a/",
                    "Clicks": 4,
                    "Impressions": 80,
                    "AvgClickPosition": 3,
                    "AvgImpressionPosition": 5,
                }
            ]
        },
        "GetPageStats",
    )[0]
    assert r["metrics"]["position"] == 5 and r["metrics"]["click_position"] == 3
    assert r["date"]["raw"] == d and r["date"]["label_date"] == "2025-12-31"
    assert r["date"]["bucket_interval"] == "unknown"
    rank = bing_rows([{"Date": d, "Clicks": 0}], "GetRankAndTrafficStats")[0]
    assert rank["metrics"]["impressions"] is None
    assert rank["metrics"]["missing"]["position"] == "unsupported"
    assert bing_date("unknown")["label_date"] is None
    with pytest.raises(EvidenceError, match="envelope"):
        bing_rows({"error": "denied"}, "GetPageStats")


def test_finality_preserves_official_snake_case():
    c = google_coverage(
        {"metadata": {"first_incomplete_date": "2026-01-03"}}, exhausted=True, truncated=False
    )
    assert c["first_incomplete_date"] == "2026-01-03"
    assert c["complete_export"] is False


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com.evil/a",
        "https://evil.com/a",
        "file:///etc/passwd",
        "https://u:p@example.com/a",
        "https://example.com/\n",
        "not a URL",
    ],
)
def test_untrusted_url_never_protected(service, url):
    gsc_snapshot(service, rows=[{"keys": [url], "clicks": 5, "impressions": 10}])
    assert service.store.protected(service.profile.site) == {}


def test_property_prefix_and_domain():
    assert in_property("https://sub.example.com/a/", "sc-domain:example.com")
    assert not in_property("https://badexample.com/", "sc-domain:example.com")
    assert not in_property("https://example.com/other/", "https://example.com/blog/")


def test_import_csv_blank_is_unknown(service, tmp_path):
    f = tmp_path / "data.csv"
    f.write_text(
        "url,clicks,impressions,position\nhttps://example.com/a/,1,10,3\nhttps://example.com/b/,,,\n"
    )
    s = import_csv(
        service.store, service.profile.site, f, "2026-01-01", "2026-01-31", observed_at="2026-02-01T00:00:00Z"
    )
    assert service.store.facts(s["id"])[1]["metrics"]["clicks"] is None
    assert len(service.store.protected(service.profile.site)) == 1
    assert (
        import_csv(
            service.store,
            service.profile.site,
            f,
            "2026-01-01",
            "2026-01-31",
            observed_at="2026-02-01T00:00:00Z",
        )["id"]
        == s["id"]
    )


def test_legacy_import_idempotent_and_separate_ga4(service, tmp_path):
    data = {
        "version": 2,
        "site": service.profile.site,
        "captured_at": "2026-02-01T00:00:00Z",
        "requested_start": "2026-01-01",
        "requested_end": "2026-01-28",
        "sources": {
            "gsc": {
                "status": "available",
                "pages": {
                    "rows": [{"keys": ["https://example.com/a/"], "clicks": 2, "impressions": 10}],
                    "dimensions": ["page"],
                    "start": "2026-01-01",
                    "end": "2026-01-28",
                    "may_be_truncated": False,
                    "response_aggregation_type": "byPage",
                },
            },
            "bing": {"status": "unavailable"},
            "ga4": {
                "status": "available",
                "timezone": "Asia/Seoul",
                "pages": {"rows": [{"metricValues": [{"value": "999"}]}]},
            },
        },
    }
    f = tmp_path / "legacy.json"
    f.write_text(json.dumps(data))
    x = import_json(service.store, service.profile.site, f)
    assert import_json(service.store, service.profile.site, f) == x
    assert len(service.store.protected(service.profile.site)) == 1
    assert service.traffic(source="ga4")["snapshot"]["coverage"]["raw_only"]
    assert service.traffic(source="ga4")["rows"] == []


def test_private_state_required(tmp_path):
    tmp_path.chmod(0o755)
    with pytest.raises(EvidenceError, match="private"):
        Store(tmp_path)
