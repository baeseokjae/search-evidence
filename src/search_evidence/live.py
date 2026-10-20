"""Bounded public HTTP fetches and reviewed-build fingerprints."""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup, Comment, NavigableString, Tag

from .config import Profile
from .core import EvidenceError, digest, in_property, now
from .providers import Budget
from .store import Store


def public_unicast(ip: str) -> bool:
    address = ipaddress.ip_address(ip)
    if (
        not address.is_global
        or address.is_multicast
        or address.is_reserved
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
    ):
        return False
    if isinstance(address, ipaddress.IPv6Address):
        # A globally classified translation address can still reach a private
        # IPv4 destination on a host with the corresponding routing support.
        if address.ipv4_mapped is not None:
            return public_unicast(str(address.ipv4_mapped))
        if address.sixtofour is not None or address.teredo is not None:
            return False
        if address in ipaddress.IPv6Network("64:ff9b::/96"):
            return False
        if address in ipaddress.IPv6Network("64:ff9b:1::/48"):
            return False
    return True


def resolve_public(url: str, allowed_hosts: tuple[str, ...], resolver=socket.getaddrinfo):
    try:
        parts = urlsplit(url)
        if (
            parts.scheme not in ("https", "http")
            or parts.hostname not in allowed_hosts
            or parts.username
            or parts.password
            or parts.port not in (None, 80, 443)
            or any(ord(c) < 33 for c in url)
            or "\\" in url
        ):
            raise EvidenceError("unsafe_url")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        addresses = resolver(parts.hostname, port, type=socket.SOCK_STREAM)
        ips = list(dict.fromkeys(a[4][0] for a in addresses))
        if not ips or any(not public_unicast(ip) for ip in ips):
            raise EvidenceError("non_public_address")
        return parts, port, ips[0]
    except (ValueError, OSError):
        raise EvidenceError("dns_or_url_invalid") from None


def fetch_public(url: str, profile: Profile, *, budget: Budget | None = None) -> dict:
    budget = budget or Budget(calls=6, seconds=35)
    current, chain = url, []
    for _ in range(6):
        budget.take()
        parts, port, ip = resolve_public(current, profile.allowed_hosts)
        timeout = min(10, budget.remaining())
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(
                parts.hostname, port, timeout=timeout, context=ssl.create_default_context()
            )
        else:
            conn = http.client.HTTPConnection(parts.hostname, port, timeout=timeout)
        # Pin the validated IP. TLS still verifies the original hostname, closing the DNS-rebinding gap.
        conn._create_connection = lambda address, timeout=None, source_address=None: socket.create_connection(
            (ip, port), timeout, source_address
        )
        response, timer = None, None
        try:
            conn.connect()
            budget.remaining()
            connected_socket = conn.sock

            def interrupt_read(sock=connected_socket):
                # read()/header parsing can keep consuming a trickle forever
                # despite an idle timeout. Wake blocked reads at the deadline.
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            timer = threading.Timer(budget.remaining(), interrupt_read)
            timer.daemon = True
            timer.start()
            target = urlunsplit(("", "", parts.path or "/", parts.query, ""))
            conn.request(
                "GET",
                target,
                headers={
                    "User-Agent": "SearchEvidence/0.1 (+read-only-verifier)",
                    "Accept-Encoding": "identity",
                    "Accept": "text/html",
                },
            )
            response = conn.getresponse()
            status = response.status
            headers = {k.lower(): v for k, v in response.getheaders()}
            body = bytearray()
            while True:
                connected_socket.settimeout(min(10, budget.remaining()))
                chunk = response.read1(min(65536, profile.max_bytes + 1 - len(body)))
                budget.remaining()
                if not chunk:
                    if response.length not in (None, 0):
                        raise EvidenceError("incomplete_live_response", retryable=True)
                    break
                body.extend(chunk)
                if len(body) > profile.max_bytes:
                    raise EvidenceError("response_too_large")
                if response.isclosed():
                    if response.length not in (None, 0):
                        raise EvidenceError("incomplete_live_response", retryable=True)
                    break
            if status in (301, 302, 303, 307, 308):
                location = headers.get("location")
                if not location:
                    raise EvidenceError("redirect_without_location")
                if parts.scheme == "https" and urlsplit(urljoin(current, location)).scheme != "https":
                    raise EvidenceError("https_redirect_downgrade")
                chain.append({"url": current, "status": status, "location": urljoin(current, location)})
                current = urljoin(current, location)
                continue
            charset = re.search(r"charset=([-\w]+)", headers.get("content-type", ""), re.I)
            encoding = charset[1] if charset else "utf-8"
            try:
                html = bytes(body).decode(encoding)
            except (UnicodeError, LookupError):
                raise EvidenceError("invalid_html_encoding") from None
            return {
                "url": url,
                "final_url": current,
                "status": status,
                "redirects": chain,
                "html": html,
                "content_type": headers.get("content-type"),
                "x_robots_tag": ", ".join(response.headers.get_all("X-Robots-Tag", [])) or None,
                "etag": headers.get("etag"),
            }
        except (OSError, http.client.HTTPException):
            budget.remaining()
            raise EvidenceError("live_transport_unavailable", retryable=True) from None
        finally:
            if timer is not None:
                timer.cancel()
            if response is not None:
                response.close()
            conn.close()
    raise EvidenceError("redirect_limit")


def text(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def node_value(node, preserve=False):
    if isinstance(node, Comment):
        return None
    if isinstance(node, NavigableString):
        value = str(node).replace("\r\n", "\n")
        return value if preserve else text(value)
    if not isinstance(node, Tag):
        return None
    if node.name in ("script", "style"):
        return None
    # Content semantics, not theme-generated CSS IDs/classes.
    attrs = {
        k: v
        for k, v in node.attrs.items()
        if k in ("href", "src", "srcset", "alt", "title", "rel", "datetime", "id", "colspan", "rowspan")
    }
    children = [node_value(c, preserve or node.name in ("pre", "code")) for c in node.children]
    return [node.name, attrs, [c for c in children if c is not None and c != ""]]


def fingerprint(html: str, selector=".post-content, main, article") -> dict:
    soup = BeautifulSoup(html, "html.parser")
    # Respect the configured preference order; CSS union selectors follow document order.
    body = next((soup.select_one(s.strip()) for s in selector.split(",") if soup.select_one(s.strip())), None)
    if body is None:
        raise EvidenceError("content_selector_not_found")
    metas = {}
    for tag in soup.find_all("meta"):
        key = tag.get("name") or tag.get("property")
        if key and key.lower() in (
            "description",
            "robots",
            "googlebot",
            "bingbot",
            "og:title",
            "og:description",
            "article:published_time",
            "article:modified_time",
        ):
            metas.setdefault(key.lower(), []).append(tag.get("content", ""))
    canonical_tags = soup.find_all("link", rel="canonical")
    schemas = []
    for script in soup.find_all("script", type="application/ld+json"):
        try:
            schemas.append(json.loads(script.string or script.get_text()))
        except ValueError:
            schemas.append({"invalid_json_ld": True, "text_hash": digest(script.get_text())})
    return {
        "title": text(soup.title.get_text()) if soup.title else None,
        "h1": [text(t.get_text(" ", strip=True)) for t in soup.find_all("h1")],
        "metadata": metas,
        "canonical": canonical_tags[0].get("href") if canonical_tags else None,
        "canonical_count": len(canonical_tags),
        "refresh": [
            t.get("content")
            for t in soup.find_all("meta", attrs={"http-equiv": re.compile("^refresh$", re.IGNORECASE)})
        ],
        "body_hash": digest(node_value(body)),
        "body_text_hash": digest(text(body.get_text(" ", strip=True))),
        "body_text_length": len(text(body.get_text(" ", strip=True))),
        "links": [
            {"href": a.get("href"), "rel": sorted(a.get("rel", []))} for a in body.find_all("a", href=True)
        ],
        "images": [{"src": i.get("src"), "alt": i.get("alt")} for i in body.find_all("img")],
        "navigation": [
            {"href": a.get("href"), "text": text(a.get_text(" ", strip=True))}
            for a in soup.select("header a[href], nav a[href]")
        ],
        "schema": sorted(schemas, key=digest),
    }


def alias_target(html: str, site: str) -> str | None:
    """Recognize an explicit, reviewed zero-delay alias; never infer URL equivalence."""
    soup = BeautifulSoup(html, "html.parser")
    refresh = soup.find_all("meta", attrs={"http-equiv": re.compile("^refresh$", re.IGNORECASE)})
    canonical_tags = soup.find_all("link", rel="canonical")
    if len(refresh) != 1 or len(canonical_tags) != 1:
        return None
    match = re.fullmatch(r"\s*0\s*;\s*url\s*=\s*(.+?)\s*", refresh[0].get("content", ""), re.IGNORECASE)
    target = match[1].strip("'\"") if match else None
    if target and target == canonical_tags[0].get("href") and in_property(target, site):
        return target
    return None


def build_path(root: Path, site: str, url: str) -> Path:
    if not in_property(url, site):
        raise EvidenceError("url_outside_property")
    path = unquote(urlsplit(url).path)
    prefix = urlsplit(site).path if not site.startswith("sc-domain:") else "/"
    relative = path[len(prefix) :] if path.startswith(prefix) else path.lstrip("/")
    candidate = root / relative
    if path.endswith("/") or not candidate.suffix:
        candidate = candidate / "index.html"
    candidate = candidate.resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise EvidenceError("path_outside_build")
    return candidate


def register_manifest(store: Store, profile: Profile, urls: list[str], revision: str | None = None) -> dict:
    if profile.build_root is None or not urls or len(urls) > 2000:
        raise EvidenceError("build_root_and_urls_required")
    pages = []
    for url in dict.fromkeys(urls):
        path = build_path(profile.build_root, profile.site, url)
        try:
            html = path.read_text()
        except OSError:
            raise EvidenceError("build_page_missing") from None
        target = alias_target(html, profile.site)
        if target:
            if target == url:
                raise EvidenceError("alias_loop")
            try:
                target_html = build_path(profile.build_root, profile.site, target).read_text()
            except OSError:
                raise EvidenceError("alias_target_missing_from_build") from None
            if alias_target(target_html, profile.site):
                raise EvidenceError("alias_chain_requires_review")
            pages.append(
                {
                    "url": url,
                    "kind": "alias",
                    "fingerprint": fingerprint(html, "body"),
                    "target_url": target,
                    "target_fingerprint": fingerprint(target_html, profile.body_selector),
                }
            )
        else:
            pages.append(
                {"url": url, "kind": "page", "fingerprint": fingerprint(html, profile.body_selector)}
            )
    payload = {
        "created_at": now(),
        "property": profile.site,
        "source_revision_claim": revision,
        "source_revision_verified": False,
        "selector": profile.body_selector,
        "pages": pages,
        "build_hash": digest(pages),
    }
    return {
        "manifest_id": store.artifact("manifest", payload),
        "pages": len(pages),
        "build_hash": digest(pages),
    }


def verify_manifest(store: Store, profile: Profile, manifest_id: str, cache_check=False) -> dict:
    manifest = store.get_artifact(manifest_id, "manifest", site=profile.site)
    deadline = time.monotonic() + profile.max_seconds

    def one(page):
        url, expected = page["url"], page["fingerprint"]
        result = {
            "url": url,
            "checked_at": now(),
            "content_match": False,
            "identity_match": False,
            "indexability": "unknown",
            "indexed_content_version_verified": False,
        }
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise EvidenceError("verification_deadline_exceeded", retryable=True)
            response = fetch_public(url, profile, budget=Budget(seconds=min(35, remaining), calls=6))
            original_html = response.pop("html")
            selector = "body" if page.get("kind") == "alias" else manifest["selector"]
            actual = fingerprint(original_html, selector)
            fields = [k for k in expected if expected[k] != actual[k]]
            result.update(
                response,
                differing_fields=fields,
                content_match=not fields and response["status"] == 200,
                identity_match=(
                    response["final_url"] == url
                    and actual["canonical"] == url
                    and actual["canonical_count"] == 1
                ),
            )
            robot_values = actual["metadata"].get("robots", []) + actual["metadata"].get("googlebot", [])
            blocked = any(
                re.search(r"\b(noindex|none)\b", v, re.IGNORECASE)
                for v in robot_values + [response["x_robots_tag"] or ""]
            )
            soft404 = (
                bool(
                    re.search(
                        r"\b404\b|page not found",
                        " ".join([actual["title"] or ""] + actual["h1"]),
                        re.IGNORECASE,
                    )
                )
                or not actual["body_text_length"]
            )
            invalid_schema = any(isinstance(s, dict) and s.get("invalid_json_ld") for s in actual["schema"])
            result["indexability"] = "blocked_by_noindex" if blocked else "no_noindex_observed"
            result["possible_soft_404"] = soft404
            result["passed"] = (
                result["content_match"]
                and result["identity_match"]
                and not blocked
                and not soft404
                and not invalid_schema
            )
            result["actual_fingerprint_hash"] = digest(actual)
            result["expected_fingerprint_hash"] = digest(expected)
            if page.get("kind") == "alias":
                target = page["target_url"]
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise EvidenceError("verification_deadline_exceeded", retryable=True)
                target_response = fetch_public(
                    target, profile, budget=Budget(seconds=min(35, remaining), calls=6)
                )
                target_fp = fingerprint(target_response.pop("html"), manifest["selector"])
                target_fields = [
                    k for k in page["target_fingerprint"] if page["target_fingerprint"][k] != target_fp[k]
                ]
                target_robots = (
                    target_fp["metadata"].get("robots", [])
                    + target_fp["metadata"].get("googlebot", [])
                    + [target_response.get("x_robots_tag") or ""]
                )
                target_blocked = any(
                    re.search(r"\b(noindex|none)\b", r, re.IGNORECASE) for r in target_robots
                )
                target_valid = (
                    target_response["status"] == 200
                    and target_response["final_url"] == target
                    and target_fp["canonical"] == target
                    and target_fp["canonical_count"] == 1
                )
                target_soft404 = not target_fp["body_text_length"] or bool(
                    re.search(
                        r"\b404\b|page not found",
                        " ".join([target_fp["title"] or ""] + target_fp["h1"]),
                        re.IGNORECASE,
                    )
                )
                target_valid = (
                    target_valid
                    and not target_soft404
                    and not any(isinstance(s, dict) and s.get("invalid_json_ld") for s in target_fp["schema"])
                )
                result.update(
                    kind="alias",
                    alias_target=target,
                    target_differing_fields=target_fields,
                    target_fingerprint_hash=digest(target_fp),
                    content_match=not fields and not target_fields and response["status"] == 200,
                    identity_match=(
                        response["final_url"] == url
                        and alias_target(original_html, profile.site) == target
                        and target_valid
                    ),
                    indexability="alias_target_blocked"
                    if target_blocked
                    else "alias_target_no_noindex_observed",
                    raw_url_still_protected=(url in protected_urls),
                    alias_evidence="reviewed_meta_refresh_and_canonical; no_protection_entries_removed",
                )
                result["passed"] = result["content_match"] and result["identity_match"] and not target_blocked
            if cache_check:
                parts = urlsplit(url)
                query = parts.query + ("&" if parts.query else "") + "_se_verify=" + quote(now())
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise EvidenceError("verification_deadline_exceeded", retryable=True)
                fresh = fetch_public(
                    urlunsplit(parts._replace(query=query)),
                    profile,
                    budget=Budget(seconds=min(35, remaining), calls=6),
                )
                fresh_fp = fingerprint(fresh["html"], selector)
                result["cache_check_match"] = fresh_fp == actual and fresh["status"] == 200
                result["passed"] = result["passed"] and result["cache_check_match"]
        except EvidenceError as exc:
            result.update(error=exc.code, passed=False)
        return result

    protected_urls = set(store.protected(profile.site))
    with ThreadPoolExecutor(max_workers=4) as pool:
        pages = list(pool.map(one, manifest["pages"]))
    payload = {
        "property": profile.site,
        "manifest_id": manifest_id,
        "checked_at": now(),
        "pages": pages,
        "passed": all(x["passed"] for x in pages),
        "pages_checked": len(pages),
        "source_revision_claim": manifest["source_revision_claim"],
        "deployment_revision_verified": False,
        "limitations": [
            "HTTP content comparison does not prove deployment provenance or search indexing.",
            "robots.txt accessibility is not established by the noindex check.",
        ],
    }
    return {"verification_id": store.artifact("verification", payload), **payload}
