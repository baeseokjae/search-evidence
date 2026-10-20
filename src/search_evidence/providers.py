"""Read-only official endpoints, bounded calls, resumable Google pages."""

from __future__ import annotations

import email.utils
import fcntl
import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import quote
from zoneinfo import ZoneInfo

import google.auth
import requests
from google.auth.transport.requests import Request

from .config import Profile
from .core import EvidenceError, digest, in_property, now, window
from .normalize import BING_TABLES, bing_rows, google_coverage, google_rows
from .store import Store

SCOPE = "https://www.googleapis.com/auth/webmasters.readonly"
GOOGLE = "https://searchconsole.googleapis.com"
BING = "https://ssl.bing.com/webmaster/api.svc/json/"
GOOGLE_TABLES = {
    "totals": [],
    "pages": ["page"],
    "queries": ["query"],
    "daily": ["date"],
    "page_queries": ["page", "query"],
}
BING_ALLOWED = set(BING_TABLES) | {"GetUserSites", "GetUrlInfo", "GetCrawlIssues"}


class Budget:
    def __init__(self, calls=200, seconds=180, *, clock=time.monotonic, sleep=time.sleep):
        self.max_calls, self.calls = calls, 0
        self.clock, self.sleep = clock, sleep
        self.deadline = clock() + seconds

    def remaining(self):
        seconds = self.deadline - self.clock()
        if seconds <= 0:
            raise EvidenceError("deadline_exceeded", retryable=True)
        return seconds

    def take(self):
        self.remaining()
        if self.calls >= self.max_calls:
            raise EvidenceError("call_budget_exhausted", retryable=True)
        self.calls += 1

    def wait(self, seconds: float):
        if seconds >= self.remaining():
            raise EvidenceError("retry_deferred", retryable=True)
        self.sleep(seconds)


def retry_after(value: str | None) -> float:
    if value:
        try:
            return max(0, float(value))
        except ValueError:
            try:
                return max(
                    0, (email.utils.parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()
                )
            except (ValueError, TypeError, OverflowError):
                pass
    return 1


class Transport:
    def __init__(self, budget: Budget, max_bytes=4_194_304, session=None):
        self.budget, self.max_bytes = budget, max_bytes
        self.session = session or requests.Session()
        self.session.trust_env = False

    def request(self, method: str, url: str, **kwargs) -> dict:
        for attempt in range(3):
            self.budget.take()
            response = None
            delay = 2**attempt
            try:
                response = self.session.request(
                    method,
                    url,
                    timeout=min(25, self.budget.remaining()),
                    allow_redirects=False,
                    stream=True,
                    **kwargs,
                )
                data_bytes = bytearray()
                for chunk in response.iter_content(65536):
                    self.budget.remaining()
                    data_bytes.extend(chunk)
                    if len(data_bytes) > self.max_bytes:
                        raise EvidenceError("response_too_large")
                try:
                    data = json.loads(data_bytes)
                except (ValueError, UnicodeError):
                    data = None
                status = response.status_code
                if 200 <= status < 300:
                    if not isinstance(data, dict):
                        raise EvidenceError("invalid_json_envelope")
                    if "error" in data or "ErrorCode" in data or "Message" in data:
                        raise EvidenceError("provider_error")
                    return data
                if status == 401:
                    raise EvidenceError("authentication_failed")
                if status == 403:
                    err = data.get("error", {}) if isinstance(data, dict) else {}
                    reasons = {x.get("reason") for x in err.get("errors", []) if isinstance(x, dict)}
                    code = (
                        "quota_deferred"
                        if reasons
                        & {
                            "rateLimitExceeded",
                            "userRateLimitExceeded",
                            "quotaExceeded",
                            "dailyLimitExceeded",
                        }
                        else "permission_denied"
                    )
                    raise EvidenceError(code, retryable=code == "quota_deferred")
                if status not in (408, 429, 500, 502, 503, 504):
                    raise EvidenceError(f"http_{status}")
                delay = max(delay, retry_after(response.headers.get("Retry-After")))
                code = f"http_{status}"
            except (requests.RequestException, TimeoutError, OSError):
                code = "transport_unavailable"
            finally:
                if response is not None:
                    response.close()
            if attempt == 2:
                raise EvidenceError(code, retryable=True)
            self.budget.wait(delay)
        raise EvidenceError("retry_exhausted")


class Providers:
    def __init__(self, profile: Profile, store: Store, *, transport=None):
        self.profile, self.store = profile, store
        self.transport = transport or Transport(
            Budget(profile.max_calls, profile.max_seconds), profile.max_bytes
        )
        self.credentials = None

    def google_headers(self, force=False):
        try:
            if self.credentials is None:
                if self.profile.google_credentials:
                    self.credentials, _ = google.auth.load_credentials_from_file(
                        str(self.profile.google_credentials), scopes=[SCOPE]
                    )
                else:
                    self.credentials, _ = google.auth.default(scopes=[SCOPE])
            if force or not self.credentials.valid:
                budget = self.transport.budget
                session = requests.Session()
                session.trust_env = False
                request = Request(session=session)

                def bounded_request(*args, **kwargs):
                    budget.take()
                    kwargs["timeout"] = min(20, budget.remaining())
                    return request(*args, **kwargs)

                self.credentials.refresh(bounded_request)
                session.close()
            return {"Authorization": "Bearer " + self.credentials.token}
        except EvidenceError:
            raise
        except Exception:
            raise EvidenceError("google_credentials_unavailable") from None

    def google(self, path: str, body: dict | None = None):
        # Only callers inside this module select endpoint paths.
        if not (
            path == "/webmasters/v3/sites"
            or path.endswith("/searchAnalytics/query")
            or path == "/v1/urlInspection/index:inspect"
        ):
            raise EvidenceError("endpoint_not_allowed")
        for attempt in range(2):
            try:
                return self.transport.request(
                    "GET" if body is None else "POST",
                    GOOGLE + path,
                    headers=self.google_headers(force=bool(attempt)),
                    json=body,
                )
            except EvidenceError as exc:
                if exc.code != "authentication_failed" or attempt:
                    raise
        raise EvidenceError("authentication_failed")

    def bing(self, method: str, **params):
        if method not in BING_ALLOWED:
            raise EvidenceError("endpoint_not_allowed")
        try:
            key = self.profile.bing_key.read_text().strip() if self.profile.bing_key else ""
            if not key or len(key) > 2048 or "\n" in key:
                raise ValueError
        except (OSError, ValueError):
            raise EvidenceError("bing_credentials_unavailable") from None
        data = self.transport.request("GET", BING + method, params={"apikey": key, **params})
        if "d" not in data or data["d"] is None:
            raise EvidenceError("invalid_bing_envelope")
        return data

    def status(self) -> dict:
        out = {}
        for source in ("gsc", "bing"):
            try:
                raw = self.google("/webmasters/v3/sites") if source == "gsc" else self.bing("GetUserSites")
                sites = raw.get("siteEntry", []) if source == "gsc" else raw["d"]
                if not isinstance(sites, list):
                    raise EvidenceError("invalid_sites_response")
                entries = [
                    {"site": x.get("siteUrl") or x.get("Url"), "permission": x.get("permissionLevel")}
                    for x in sites
                ]
                matched = [x for x in entries if x["site"] == self.profile.site]
                out[source] = {
                    "status": "available" if matched else "property_not_listed",
                    "configured_property": matched,
                    "account_property_count": len(entries),
                }
            except EvidenceError as exc:
                out[source] = {"status": "unavailable", "error": exc.code}
        return out

    def collect_google_table(
        self, table: str, start: str, end: str, job: str, data_state="final", page_url=None
    ) -> dict:
        if table not in GOOGLE_TABLES or data_state not in ("final", "all"):
            raise EvidenceError("invalid_google_query")
        if table == "page_queries" and not in_property(page_url, self.profile.site):
            raise EvidenceError("selected_page_required")
        request = {
            "startDate": start,
            "endDate": end,
            "dimensions": GOOGLE_TABLES[table],
            "type": "web",
            "dataState": data_state,
            "aggregationType": "auto",
        }
        if page_url:
            if not in_property(page_url, self.profile.site):
                raise EvidenceError("url_outside_property")
            request["dimensionFilterGroups"] = [
                {"filters": [{"dimension": "page", "operator": "equals", "expression": page_url}]}
            ]
        key = digest({"property": self.profile.site, "table": table, "request": request})
        checkpoint = self.store.checkpoint(job, key) or {"pages": [], "offset": 0}
        if "complete" in checkpoint:
            return self.store.snapshot(checkpoint["complete"])
        pages, offset = checkpoint["pages"], checkpoint["offset"]
        status, error, exhausted = "available", None, False
        try:
            while offset < 50000:
                raw = self.google(
                    "/webmasters/v3/sites/" + quote(self.profile.site, safe="") + "/searchAnalytics/query",
                    {**request, "rowLimit": 25000, "startRow": offset},
                )
                google_rows(raw, request["dimensions"])  # Validate before advancing checkpoint.
                pages.append(raw)
                size = len(raw.get("rows", []))
                offset += size
                self.store.checkpoint(job, key, {"pages": pages, "offset": offset})
                if size < 25000:
                    exhausted = True
                    break
        except EvidenceError as exc:
            status, error = ("partial" if pages else "unavailable"), exc.code
        combined = {"rows": [r for p in pages for r in p.get("rows", [])]}
        if pages:
            combined.update({k: v for k, v in pages[-1].items() if k != "rows"})
        coverage = google_coverage(
            combined, exhausted=exhausted, truncated=not exhausted, requested_state=data_state
        )
        coverage["job"] = job
        coverage["date_window_is_single_day"] = start == end
        return self.store.put(
            source="gsc",
            site=self.profile.site,
            table=table,
            request=request,
            raw={"pages": pages},
            rows=google_rows(combined, request["dimensions"]),
            status=status,
            error=error,
            coverage=coverage,
            checkpoint=(job, key) if status == "available" else None,
        )

    def collect(
        self,
        start: str,
        end: str,
        *,
        sources=("gsc", "bing"),
        tables=("totals", "pages", "queries"),
        daily=True,
        resume=None,
        page_url=None,
    ) -> dict:
        job = resume or uuid.uuid4().hex
        lock_path = self.store.root / ("job-" + digest(job) + ".lock")
        with lock_path.open("a") as lock:
            lock_path.chmod(0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise EvidenceError("collection_already_running", retryable=True) from None
            try:
                return self._collect(
                    start, end, sources=sources, tables=tables, daily=daily, resume=job, page_url=page_url
                )
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def _collect(self, start: str, end: str, *, sources, tables, daily, resume, page_url) -> dict:
        a, b = window(start, end)
        if (b - a).days > 550 or not set(sources) <= {"gsc", "bing"} or not sources:
            raise EvidenceError("invalid_collection_scope")
        if not set(tables) <= GOOGLE_TABLES.keys() or not tables:
            raise EvidenceError("invalid_tables")
        job = resume or uuid.uuid4().hex
        identity = dict(
            start=start,
            end=end,
            sources=list(sources),
            tables=list(tables),
            daily=daily,
            property=self.profile.site,
            page_url=page_url,
        )
        existing = self.store.checkpoint(job, "identity")
        if existing and existing != identity:
            raise EvidenceError("resume_scope_mismatch")
        self.store.checkpoint(job, "identity", identity)
        results = []
        deferred = 0
        if "gsc" in sources:
            periods = [(a + timedelta(days=n), a + timedelta(days=n)) for n in range((b - a).days + 1)]
            if not daily:
                periods = [(a, b)]
            for left, right in periods:
                for table in tables:
                    try:
                        self.transport.budget.remaining()
                        if self.transport.budget.calls >= self.transport.budget.max_calls:
                            raise EvidenceError("call_budget_exhausted")
                    except EvidenceError:
                        deferred += 1
                        continue
                    results.append(
                        self.collect_google_table(
                            table, left.isoformat(), right.isoformat(), job, page_url=page_url
                        )
                    )
        if "bing" in sources:
            for method, table in BING_TABLES.items():
                if method == "GetPageQueryStats":
                    continue  # Explicit selected-page inspection only, not a full-site query.
                req = {"method": method, "siteUrl": self.profile.site}
                key = digest(req)
                prior = self.store.checkpoint(job, key)
                if prior and "complete" in prior:
                    results.append(self.store.snapshot(prior["complete"]))
                    continue
                raw, rows, status, error = {}, [], "available", None
                try:
                    raw = self.bing(method, siteUrl=self.profile.site)
                    rows = bing_rows(raw, method)
                except EvidenceError as exc:
                    status, error = "unavailable", exc.code
                results.append(
                    self.store.put(
                        source="bing",
                        site=self.profile.site,
                        table=table,
                        request=req,
                        raw=raw,
                        rows=rows,
                        status=status,
                        error=error,
                        coverage={
                            "timezone": "unknown",
                            "bucket_interval": "unknown",
                            "date_filter_supported": False,
                            "job": job,
                        },
                        checkpoint=(job, key) if status == "available" else None,
                    )
                )
        payload = {
            "property": self.profile.site,
            "job": job,
            "snapshots": results,
            "calls": self.transport.budget.calls,
            "deferred_google_partitions": deferred,
            "complete": deferred == 0 and bool(results) and all(s["status"] == "available" for s in results),
            "cross_provider_totals_comparable": False,
        }
        payload["collection_id"] = self.store.artifact("collection", payload)
        return payload

    def finality(self, start: str, end: str) -> dict:
        window(start, end)
        result = self.collect_google_table("daily", start, end, uuid.uuid4().hex, data_state="all")
        dates = [r["dimensions"]["date"] for r in self.store.facts(result["id"])]
        incomplete = result["coverage"].get("first_incomplete_date")
        return {
            "snapshot": result,
            "observed_dates": dates,
            "first_incomplete_date": incomplete,
            "observed_final_dates": [d for d in dates if not incomplete or d < incomplete],
            "missing_dates_are_zero": False,
        }

    def inspect(self, urls: list[str]) -> dict:
        if not urls or len(urls) > self.profile.inspection_run_limit:
            raise EvidenceError("inspection_run_budget")
        if any(not in_property(u, self.profile.site) for u in urls):
            raise EvidenceError("url_outside_property")
        results = []
        day = datetime.now(ZoneInfo("America/Los_Angeles")).date().isoformat()
        for url in urls:
            entry = {"url": url, "google": {}, "bing": {}, "indexed_content_version_verified": False}
            try:
                self.store.reserve_inspection(day, self.profile.site, self.profile.inspection_daily_limit)
                raw = self.google(
                    "/v1/urlInspection/index:inspect",
                    {"inspectionUrl": url, "siteUrl": self.profile.site, "languageCode": "en-US"},
                )
                state = raw.get("inspectionResult", {}).get("indexStatusResult", {})
                verdict = state.get("verdict")
                entry["google"] = {
                    "status": "available",
                    "indexed": True
                    if verdict == "PASS"
                    else False
                    if verdict in ("FAIL", "NEUTRAL")
                    else None,
                    "index_status": state,
                    "scope": "Google indexed version; not a live fetch",
                }
            except EvidenceError as exc:
                entry["google"] = {"status": "unavailable", "indexed": None, "error": exc.code}
            try:
                raw = self.bing("GetUrlInfo", siteUrl=self.profile.site, url=url)
                entry["bing"] = {
                    "status": "available",
                    "record": raw["d"],
                    "indexed": None,
                    "reason": "record_presence_does_not_prove_indexing",
                }
            except EvidenceError as exc:
                entry["bing"] = {"status": "unavailable", "indexed": None, "error": exc.code}
            results.append(entry)
        payload = {
            "property": self.profile.site,
            "observed_at": now(),
            "results": results,
            "shared_provider_quota_known": False,
        }
        return {"inspection_id": self.store.artifact("inspection", payload), **payload}
