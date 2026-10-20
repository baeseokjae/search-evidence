import json

import pytest
import requests

from search_evidence.core import EvidenceError
from search_evidence.providers import Budget, Providers, Transport


class Response:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code, self.body, self.headers = status, body or {}, headers or {}
        self.closed = False

    def iter_content(self, size):
        yield json.dumps(self.body).encode()

    def close(self):
        self.closed = True


class Session:
    def __init__(self, responses):
        self.responses, self.calls = iter(responses), []

    def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        result = next(self.responses)
        if isinstance(result, Exception):
            raise result
        return result


def test_retry_after_and_global_budget():
    waits = []
    s = Session([Response(429, headers={"Retry-After": "4"}), Response(200, {"d": []})])
    b = Budget(calls=2, seconds=30, sleep=waits.append)
    assert Transport(b, session=s).request("GET", "https://example.com/") == {"d": []}
    assert b.calls == 2 and waits == [4]
    with pytest.raises(EvidenceError, match="call_budget"):
        b.take()


def test_retry_deadline_defers_without_sleep():
    s = Session([Response(429, headers={"Retry-After": "3600"})])
    with pytest.raises(EvidenceError, match="retry_deferred"):
        Transport(Budget(seconds=10), session=s).request("GET", "https://example.com/")
    assert len(s.calls) == 1


@pytest.mark.parametrize(
    "status,reason,code",
    [
        (403, "quotaExceeded", "quota_deferred"),
        (403, "forbidden", "permission_denied"),
        (401, "", "authentication_failed"),
        (400, "", "http_400"),
    ],
)
def test_permanent_and_quota_errors_are_not_hammered(status, reason, code):
    s = Session([Response(status, {"error": {"errors": [{"reason": reason}]}})])
    with pytest.raises(EvidenceError, match=code):
        Transport(Budget(), session=s).request("GET", "https://example.com/")
    assert len(s.calls) == 1


def test_secret_in_exception_is_never_returned():
    s = Session([requests.ConnectionError("https://example.com/?apikey=TOPSECRET")] * 3)
    with pytest.raises(EvidenceError) as exc:
        Transport(Budget(sleep=lambda n: None), session=s).request("GET", "https://example.com/")
    assert "TOPSECRET" not in str(exc.value)
    assert str(exc.value) == "transport_unavailable"


def test_successful_error_envelope_and_size_are_errors():
    with pytest.raises(EvidenceError, match="provider_error"):
        Transport(Budget(), session=Session([Response(body={"ErrorCode": 3})])).request("GET", "x")
    with pytest.raises(EvidenceError, match="response_too_large"):
        Transport(Budget(), max_bytes=2, session=Session([Response(body={"x": "long"})])).request("GET", "x")


def test_pagination_resume_25000_plus_1(profile, service, monkeypatch):
    provider = Providers(profile, service.store)
    page = {
        "rows": [
            {"keys": [f"https://example.com/{i}/"], "clicks": 1, "impressions": 10} for i in range(25000)
        ],
        "responseAggregationType": "byPage",
    }
    offsets = []

    def interrupted(path, body):
        offsets.append(body["startRow"])
        if body["startRow"] == 0:
            return page
        raise EvidenceError("deadline_exceeded")

    monkeypatch.setattr(provider, "google", interrupted)
    partial = provider.collect_google_table("pages", "2026-01-01", "2026-01-01", "resume-test")
    assert partial["status"] == "partial" and partial["row_count"] == 25000

    def resumed(path, body):
        offsets.append(body["startRow"])
        return {"rows": [{"keys": ["https://example.com/last/"], "clicks": 2, "impressions": 3}]}

    monkeypatch.setattr(provider, "google", resumed)
    complete = provider.collect_google_table("pages", "2026-01-01", "2026-01-01", "resume-test")
    assert offsets == [0, 25000, 25000]
    assert complete["status"] == "available" and complete["row_count"] == 25001
    assert complete["coverage"]["pagination_exhausted"]
    assert len(service.store.protected(profile.site)) == 25001
    # A completed checkpoint causes no further API request.
    assert provider.collect_google_table("pages", "2026-01-01", "2026-01-01", "resume-test") == complete
    assert len(offsets) == 3


def test_bing_partial_success_and_repeated_history_never_sum(profile, service, monkeypatch):
    provider = Providers(profile, service.store)

    def api(method, **kwargs):
        if method == "GetQueryStats":
            raise EvidenceError("permission_denied")
        row = {"Date": "/Date(1767225600000)/", "Clicks": 7, "Impressions": 100}
        if method == "GetPageStats":
            row["Query"] = "https://example.com/a/"
        return {"d": [row]}

    monkeypatch.setattr(provider, "bing", api)
    first = provider.collect("2026-01-01", "2026-01-28", sources=["bing"])
    second = provider.collect("2026-01-01", "2026-01-28", sources=["bing"])
    assert not first["complete"] and not second["complete"]
    assert [s["status"] for s in first["snapshots"]] == ["available", "available", "unavailable"]
    assert service.traffic(source="bing")["rows"][0]["metrics"]["clicks"] == 7
    assert len(service.store.protected(profile.site)) == 1
    with pytest.raises(EvidenceError, match="resume_scope_mismatch"):
        provider.collect("2026-01-01", "2026-01-29", sources=["bing"], resume=first["job"])


def test_selected_page_required_and_readonly_allowlist(profile, service):
    provider = Providers(profile, service.store)
    with pytest.raises(EvidenceError, match="selected_page_required"):
        provider.collect_google_table("page_queries", "2026-01-01", "2026-01-01", "job")
    with pytest.raises(EvidenceError, match="endpoint_not_allowed"):
        provider.bing("SubmitUrl", url=profile.site)
    with pytest.raises(EvidenceError, match="endpoint_not_allowed"):
        provider.google("/webmasters/v3/sites/delete", {})


def test_inspection_quota_and_unknown_bing_indexing(profile, service, monkeypatch):
    provider = Providers(profile, service.store)
    monkeypatch.setattr(
        provider,
        "google",
        lambda *a: {
            "inspectionResult": {
                "indexStatusResult": {"verdict": "PASS", "lastCrawlTime": "2026-01-01T00:00:00Z"}
            }
        },
    )
    monkeypatch.setattr(provider, "bing", lambda *a, **kw: {"d": {"Url": "https://example.com/a/"}})
    result = provider.inspect(["https://example.com/a/"])["results"][0]
    assert result["google"]["indexed"] is True and result["bing"]["indexed"] is None
    assert result["indexed_content_version_verified"] is False
    service.store.reserve_inspection("2026-01-01", profile.site, 1)
    with pytest.raises(EvidenceError, match="daily_budget"):
        service.store.reserve_inspection("2026-01-01", profile.site, 1)


@pytest.mark.parametrize(
    "code,retryable",
    [("permission_denied", False), ("google_credentials_unavailable", False), ("http_429", True)],
)
def test_whole_collection_failure_preserves_retry_semantics(service, monkeypatch, code, retryable):
    monkeypatch.setattr(
        Providers,
        "collect",
        lambda *a, **kw: {
            "complete": False,
            "snapshots": [{"status": "unavailable", "row_count": 0, "error": code}],
        },
    )
    result = service.invoke("search_collect", {"start": "2026-01-01", "end": "2026-01-28"})
    assert not result.ok and result.error["retryable"] is retryable
    assert result.data["snapshots"][0]["error"] == code
