from pathlib import Path

import pytest

from search_evidence.config import Profile
from search_evidence.normalize import google_rows
from search_evidence.service import Service


@pytest.fixture
def profile(tmp_path):
    return Profile("https://example.com/", tmp_path / "state", allowed_hosts=("example.com",))


@pytest.fixture
def service(profile):
    s = Service(profile)
    yield s
    s.close()


def gsc_snapshot(
    service,
    *,
    rows=None,
    start="2026-01-01",
    end="2026-01-28",
    dimensions=None,
    status="available",
    stamp="2026-02-01T00:00:00Z",
):
    dimensions = dimensions if dimensions is not None else ["page"]
    raw = {
        "rows": rows
        if rows is not None
        else [{"keys": ["https://example.com/a/"], "clicks": 3, "impressions": 100, "position": 4.0}]
    }
    return service.store.put(
        source="gsc",
        site=service.profile.site,
        table="pages",
        request={
            "startDate": start,
            "endDate": end,
            "dimensions": dimensions,
            "type": "web",
            "dataState": "final",
            "aggregationType": "auto",
        },
        raw=raw,
        rows=google_rows(raw, dimensions),
        status=status,
        observed_at=stamp,
        coverage={"aggregation": "byPage", "timezone": "America/Los_Angeles"},
    )


def page_html(
    url="https://example.com/a/",
    body="<p>A checked result.</p>",
    description="A description",
    robots="index,follow",
):
    return f"""<!doctype html><html><head><title>A page</title>
<meta name="description" content="{description}"><meta name="robots" content="{robots}">
<link rel="canonical" href="{url}">
<script type="application/ld+json">{{"@type":"Article","description":"{description}"}}</script>
</head><body><nav><a href="/">Home</a></nav><h1>A page</h1>
<div class="post-content">{body}</div></body></html>"""


def make_build(root: Path, urls):
    root.mkdir()
    for url in urls:
        from urllib.parse import urlsplit

        path = root / urlsplit(url).path.lstrip("/") / "index.html"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(page_html(url))
