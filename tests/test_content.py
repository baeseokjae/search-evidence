import json
import socket
from dataclasses import replace

import pytest
from conftest import gsc_snapshot, make_build, page_html

from search_evidence.audit import audit_content, prioritize
from search_evidence.core import EvidenceError
from search_evidence.live import build_path, fingerprint, register_manifest, resolve_public, verify_manifest


@pytest.mark.parametrize(
    "ip", ["127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.1.1", "::1", "fc00::1", "::ffff:127.0.0.1"]
)
def test_ssrf_rejects_private_addresses(ip):
    def resolver(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]

    with pytest.raises(EvidenceError, match="non_public"):
        resolve_public("https://example.com/", ("example.com",), resolver)


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/",
        "file:///etc/passwd",
        "https://user:pass@example.com/",
        "https://example.com:8080/",
        "https://example.com\\@127.0.0.1/",
        "https://other.example/",
    ],
)
def test_url_allowlist(url):
    with pytest.raises(EvidenceError, match="unsafe_url"):
        resolve_public(url, ("example.com",))


def test_mixed_dns_answer_rejected():
    def resolver(*args, **kwargs):
        return [(2, 1, 6, "", ("93.184.216.34", 443)), (2, 1, 6, "", ("127.0.0.1", 443))]

    with pytest.raises(EvidenceError, match="non_public"):
        resolve_public("https://example.com/", ("example.com",), resolver)


def test_build_path_rejects_traversal(tmp_path):
    with pytest.raises(EvidenceError, match="path_outside_build"):
        build_path(tmp_path, "https://example.com/", "https://example.com/%2e%2e/secrets")


def test_fingerprint_semantic_changes_not_whitespace():
    original = page_html(body='<p>A result. <a href="/a/" rel="sponsored">Source</a></p>')
    baseline = fingerprint(original)
    assert fingerprint(original.replace("<p>A result.", "<p>  A   result.")) == baseline
    for altered in (
        original.replace("A result.", "A false result."),
        original.replace('rel="sponsored"', 'rel="nofollow"'),
        original.replace("A description", "Changed description"),
        original.replace("index,follow", "noindex"),
        original.replace('"@type":"Article"', '"@type":"Review"'),
    ):
        assert fingerprint(altered) != baseline
    assert fingerprint(page_html(body="<pre>x  y</pre>")) != fingerprint(page_html(body="<pre>x y</pre>"))


def test_live_200_different_body_fails_and_noindex_fails(service, profile, tmp_path, monkeypatch):
    root = tmp_path / "public"
    make_build(root, ["https://example.com/a/"])
    profile = replace(profile, build_root=root)
    m = register_manifest(service.store, profile, ["https://example.com/a/"], "claimed-revision")

    def response(body, final="https://example.com/a/"):
        return {
            "url": "https://example.com/a/",
            "final_url": final,
            "status": 200,
            "redirects": [],
            "html": body,
            "x_robots_tag": None,
        }

    monkeypatch.setattr(
        "search_evidence.live.fetch_public", lambda *a, **kw: response(page_html(body="<p>Stale</p>"))
    )
    r = verify_manifest(service.store, profile, m["manifest_id"])
    assert not r["passed"] and "body_hash" in r["pages"][0]["differing_fields"]
    monkeypatch.setattr("search_evidence.live.fetch_public", lambda *a, **kw: response(page_html()))
    r = verify_manifest(service.store, profile, m["manifest_id"])
    assert r["passed"] and r["deployment_revision_verified"] is False
    monkeypatch.setattr(
        "search_evidence.live.fetch_public", lambda *a, **kw: response(page_html(), "https://example.com/b/")
    )
    assert not verify_manifest(service.store, profile, m["manifest_id"])["passed"]
    monkeypatch.setattr(
        "search_evidence.live.fetch_public", lambda *a, **kw: response(page_html(robots="noindex"))
    )
    assert not verify_manifest(service.store, profile, m["manifest_id"])["passed"]


def test_claims_duplicates_and_dates_preserve_both_urls(service, profile, tmp_path):
    root = tmp_path / "content"
    root.mkdir()
    body = """We tested 100 systems and measured a 50% improvement.

```python
# TODO: this is a code example, not unfinished prose.
```
"""
    for name in ("a", "b"):
        (root / (name + ".md")).write_text(
            f"---\ndate: 2026-01-02\nlastmod: 2026-01-01\nurl: /{name}/\n---\n" + body
        )
    profile = replace(profile, content_root=root)
    gsc_snapshot(
        service,
        rows=[{"keys": [f"https://example.com/{x}/"], "clicks": 1, "impressions": 5} for x in ("a", "b")],
    )
    audit = audit_content(service.store, profile)
    for page in audit["pages"]:
        codes = {x["code"] for x in page["findings"]}
        assert "firsthand_claim_needs_evidence" in codes and "exact_duplicate_body" in codes
        assert "lastmod_before_publication" in codes and "placeholder" not in codes
        assert page["protected"]
    priorities = prioritize(service.store, profile, audit["audit_id"])
    assert all(p["url_action"] == "keep_url" and p["priority_tier"] == 1 for p in priorities["pages"])
    assert (root / "a.md").read_text().endswith(body)


def test_report_escapes_html_and_csv(service):
    url = "https://example.com/<script>alert(1)</script>"
    service.store.protect(service.profile.site, url, "manual")
    report = service.render_report()
    directory = service.store.root / report["state_relative_directory"]
    rendered = (directory / "report.html").read_text()
    assert "<script>" not in rendered and "&lt;script&gt;" in rendered
    assert "Content-Security-Policy" in rendered
    assert json.loads((directory / "report.json").read_text())["protection"][0]["url"] == url


def test_reviewed_alias_preserves_raw_url_and_verifies_target(service, profile, tmp_path, monkeypatch):
    root = tmp_path / "public"
    target = "https://example.com/new/"
    old = "https://example.com/old/"
    make_build(root, [old, target])
    alias = (
        f'<html><head><link rel="canonical" href="{target}">'
        f'<meta http-equiv="refresh" content="0; url={target}"></head>'
        "<body>Article moved.</body></html>"
    )
    build_path(root, profile.site, old).write_text(alias)
    profile = replace(profile, build_root=root)
    service.store.protect(profile.site, old, "historical clicks")
    manifest = register_manifest(service.store, profile, [old])

    def fetch(url, *args, **kwargs):
        return {
            "url": url,
            "final_url": url,
            "status": 200,
            "redirects": [],
            "html": alias if url == old else page_html(target),
            "x_robots_tag": None,
        }

    monkeypatch.setattr("search_evidence.live.fetch_public", fetch)
    result = verify_manifest(service.store, profile, manifest["manifest_id"])
    assert result["passed"] and result["pages"][0]["alias_target"] == target
    assert result["pages"][0]["raw_url_still_protected"]
    assert old in service.store.protected(profile.site)


def test_soft404_is_not_a_success_even_if_it_matches_build(service, profile, tmp_path, monkeypatch):
    root = tmp_path / "public"
    url = "https://example.com/a/"
    make_build(root, [url])
    body = page_html().replace("A page", "Page not found")
    build_path(root, profile.site, url).write_text(body)
    profile = replace(profile, build_root=root)
    manifest = register_manifest(service.store, profile, [url])
    monkeypatch.setattr(
        "search_evidence.live.fetch_public",
        lambda *a, **kw: {
            "url": url,
            "final_url": url,
            "status": 200,
            "redirects": [],
            "html": body,
            "x_robots_tag": None,
        },
    )
    result = verify_manifest(service.store, profile, manifest["manifest_id"])
    assert not result["passed"] and result["pages"][0]["possible_soft_404"]


def test_audit_pagination_reuses_immutable_artifact(service, profile, tmp_path):
    root = tmp_path / "content"
    root.mkdir()
    for i in range(3):
        (root / f"{i}.md").write_text("---\nurl: /" + str(i) + "/\n---\nExample prose.")
    service.profile = replace(profile, content_root=root)
    first = service.audit(limit=1)
    assert first["total_rows"] == 3 and len(first["rows"]) == 1
    (root / "0.md").write_text("Changed after the audit")
    second = service.audit(audit_id=first["audit_id"], cursor=first["next_cursor"], limit=1)
    assert second["audit_id"] == first["audit_id"] and second["rows"][0]["file"] == "1.md"


def test_spreadsheet_query_injection_escaped(service):
    gsc_snapshot(
        service, dimensions=["query"], rows=[{"keys": ['=HYPERLINK("evil")'], "clicks": 1, "impressions": 2}]
    )
    report = service.render_report()
    text = (service.store.root / report["state_relative_directory"] / "traffic.csv").read_text()
    assert "'=HYPERLINK" in text
