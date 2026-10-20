import json
import socket
import threading
import time
from dataclasses import replace
from urllib.parse import urlsplit

import anyio
import pytest
from conftest import make_build, page_html
from mcp import Client

from search_evidence.audit import audit_content
from search_evidence.core import EvidenceError
from search_evidence.live import fetch_public, register_manifest, resolve_public, verify_manifest
from search_evidence.mcp_server import build_server
from search_evidence.providers import Budget


@pytest.mark.parametrize(
    "ip",
    [
        "224.0.0.1",
        "239.255.255.250",
        "ff02::1",
        "ff0e::1",
        "64:ff9b::7f00:1",
        "64:ff9b::a00:1",
        "64:ff9b:1::1",
        "2002:7f00:1::",
        "2001::1",
        "100.64.0.1",
        "240.0.0.1",
        "::ffff:169.254.169.254",
    ],
)
def test_special_network_addresses_are_not_public_fetch_targets(ip):
    def resolver(*args, **kwargs):
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, 1, 6, "", (ip, 443))]

    with pytest.raises(EvidenceError, match="non_public_address"):
        resolve_public("https://example.com/", ("example.com",), resolver)


@pytest.mark.parametrize("ip", ["93.184.216.34", "2606:4700:4700::1111"])
def test_public_unicast_addresses_remain_usable(ip):
    def resolver(*args, **kwargs):
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, 1, 6, "", (ip, 443))]

    assert resolve_public("https://example.com/", ("example.com",), resolver)[2] == ip


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize(
    "tool", ["search_audit_content", "search_prioritize", "search_verify_live", "search_render_report"]
)
def test_artifact_ids_do_not_bypass_property_scope(service, profile, tmp_path, tool, legacy):
    content = tmp_path / "content"
    content.mkdir()
    (content / "draft.md").write_text("---\nurl: /draft/\n---\nTODO: synthetic private draft excerpt\n")
    audit = audit_content(service.store, replace(profile, content_root=content))
    if legacy:
        audit.pop("property")
        audit.pop("audit_id")
        aid = service.store.artifact("audit", audit)
    else:
        aid = audit["audit_id"]
    verification = {"pages": [{"url": profile.site + "draft/", "passed": True}]}
    if not legacy:
        verification["property"] = profile.site
    vid = service.store.artifact("verification", verification)
    if not legacy:
        service.profile = replace(profile, site="https://other.example/")
    args = {"verification_id": vid} if tool == "search_verify_live" else {"audit_id": aid}
    result = service.invoke(tool, args)
    expected = "artifact_property_unknown" if legacy else "artifact_property_mismatch"
    assert not result.ok and result.error["code"] == expected
    assert "synthetic private draft excerpt" not in result.model_dump_json()
    assert not (service.store.root / "reports").exists()
    # Report's verification-only path must apply the same check.
    report = service.invoke("search_render_report", {"verification_id": vid})
    assert not report.ok and report.error["code"] == expected


def test_new_verification_and_audit_can_be_read_in_their_property(service, profile, tmp_path, monkeypatch):
    build, content = tmp_path / "public", tmp_path / "content"
    content.mkdir()
    (content / "draft.md").write_text("TODO: synthetic draft\n")
    url = profile.site + "a/"
    make_build(build, [url])
    service.profile = replace(profile, content_root=content, build_root=build)
    audit = service.audit()
    assert service.audit(audit_id=audit["audit_id"])["rows"] == audit["rows"]
    manifest = register_manifest(service.store, service.profile, [url])
    monkeypatch.setattr(
        "search_evidence.live.fetch_public",
        lambda *a, **kw: {
            "url": url,
            "final_url": url,
            "status": 200,
            "redirects": [],
            "html": page_html(url),
            "x_robots_tag": None,
        },
    )
    verification = verify_manifest(service.store, service.profile, manifest["manifest_id"])
    assert service.verify(verification_id=verification["verification_id"])["passed"]
    report = service.render_report(
        audit_id=audit["audit_id"], verification_id=verification["verification_id"]
    )
    saved = json.loads((service.store.root / report["state_relative_directory"] / "report.json").read_text())
    assert saved["property"] == profile.site
    assert saved["verification"]["property"] == profile.site


def local_response(monkeypatch, parts, delay=0):
    """A loopback test server; only this fixture replaces production DNS validation."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    done = threading.Event()

    def serve():
        try:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(2)
                conn.recv(4096)
                for part in parts:
                    conn.sendall(part)
                    if delay:
                        time.sleep(delay)
        except OSError:
            pass
        finally:
            listener.close()
            done.set()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    monkeypatch.setattr(
        "search_evidence.live.resolve_public",
        lambda url, hosts: (urlsplit(url), port, "127.0.0.1"),
    )
    return done


@pytest.mark.parametrize("phase", ["headers", "body", "chunk_header"])
def test_trickled_responses_cannot_extend_deadline(profile, monkeypatch, phase):
    if phase == "headers":
        parts = [b"HTTP/1.1 200 OK\r\nX-Slow: "] + [b"x"] * 100
    elif phase == "chunk_header":
        parts = [b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;"] + [b"x"] * 100
    else:
        parts = [b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"] + [b"x"] * 100
    done = local_response(monkeypatch, parts, delay=0.025)
    start = time.monotonic()
    with pytest.raises(EvidenceError, match="deadline_exceeded"):
        fetch_public("http://example.com/", profile, budget=Budget(seconds=0.15))
    assert time.monotonic() - start < 1.2
    assert done.wait(1)


@pytest.mark.parametrize(
    "wire",
    [
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        b"HTTP/1.0 200 OK\r\n\r\nhello",
    ],
)
def test_bounded_live_reads_complete_normally(profile, monkeypatch, wire):
    done = local_response(monkeypatch, [wire])
    result = fetch_public("http://example.com/", profile, budget=Budget(seconds=2))
    assert result["html"] == "hello" and result["status"] == 200
    assert done.wait(1)


def test_truncated_response_is_not_accepted(profile, monkeypatch):
    done = local_response(monkeypatch, [b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nshort"])
    with pytest.raises(EvidenceError, match="incomplete_live_response"):
        fetch_public("http://example.com/", profile, budget=Budget(seconds=2))
    assert done.wait(1)


def test_https_redirect_cannot_downgrade_to_plaintext(profile, monkeypatch):
    import http.client

    done = local_response(
        monkeypatch, [b"HTTP/1.1 301 Moved\r\nLocation: http://example.com/\r\nContent-Length: 0\r\n\r\n"]
    )
    monkeypatch.setattr(
        "search_evidence.live.http.client.HTTPSConnection",
        lambda host, port, timeout, context: http.client.HTTPConnection(host, port, timeout=timeout),
    )
    with pytest.raises(EvidenceError, match="https_redirect_downgrade"):
        fetch_public("https://example.com/", profile, budget=Budget(seconds=2))
    assert done.wait(1)


def test_mcp_rejects_oversized_arguments_before_invoking_service(profile, monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("Invalid input reached the service")

    monkeypatch.setattr("search_evidence.service.Service.invoke", unexpected)

    async def scenario():
        async with Client(build_server(profile)) as client:
            for name, args in [
                ("search_inspect_urls", {"urls": ["https://example.com/" + "x" * 4096]}),
                ("search_protect_urls", {"urls": ["x" * 4097]}),
                ("search_collect", {"start": "x" * 10000, "end": "2026-01-01"}),
                ("search_collect", {"start": "2026-01-01", "end": "2026-01-02", "tables": ["pages"] * 1000}),
            ]:
                result = await client.call_tool(name, args)
                assert result.is_error and result.structured_content["error"]["code"] == "invalid_arguments"

    anyio.run(scenario)
