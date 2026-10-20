"""Deterministic editorial review candidates. Findings are not policy verdicts."""

from __future__ import annotations

import re
import tomllib
from collections import defaultdict
from datetime import date, datetime, timezone
from urllib.parse import urljoin

import yaml

from .config import Profile
from .core import EvidenceError, digest, in_property, now
from .live import build_path
from .store import Store


def parse_markdown(raw: str) -> tuple[dict, str]:
    if raw.startswith("---\n"):
        parts = raw.split("\n---", 1)
        if len(parts) != 2:
            raise EvidenceError("unclosed_frontmatter")
        try:
            meta = yaml.safe_load(parts[0][4:]) or {}
        except yaml.YAMLError:
            raise EvidenceError("invalid_frontmatter") from None
        if not isinstance(meta, dict):
            raise EvidenceError("invalid_frontmatter")
        return meta, parts[1].lstrip("\r\n")
    if raw.startswith("+++\n"):
        parts = raw.split("\n+++", 1)
        if len(parts) != 2:
            raise EvidenceError("unclosed_frontmatter")
        try:
            return tomllib.loads(parts[0][4:]), parts[1].lstrip("\r\n")
        except ValueError:
            raise EvidenceError("invalid_frontmatter") from None
    return {}, raw


def without_code(body: str) -> str:
    lines, fence = [], None
    for line in body.splitlines():
        match = re.match(r"^\s*(`{3,}|~{3,})", line)
        if match:
            token = match[1]
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            lines.append("")
        else:
            lines.append("" if fence else re.sub(r"`[^`]*`", "", line))
    return "\n".join(lines)


def parse_date(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):
        return datetime.combine(value, datetime.min.time(), timezone.utc)
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def audit_content(store: Store, profile: Profile) -> dict:
    if not profile.content_root or not profile.content_root.is_dir():
        raise EvidenceError("content_root_required")
    protected = store.protected(profile.site)
    pages, groups = [], defaultdict(list)
    root = profile.content_root.resolve()
    for path in sorted(root.rglob("*.md")):
        if not path.resolve().is_relative_to(root):
            continue
        relative = str(path.relative_to(root))
        findings = []
        try:
            meta, body = parse_markdown(path.read_text())
        except (OSError, UnicodeError, EvidenceError):
            pages.append(
                {
                    "file": relative,
                    "url": None,
                    "findings": [
                        {
                            "code": "frontmatter_or_encoding_invalid",
                            "category": "technical",
                            "certainty": "observed",
                        }
                    ],
                }
            )
            continue
        slug = str(meta.get("slug") or path.stem)
        url = urljoin(
            profile.site
            if not profile.site.startswith("sc-domain:")
            else "https://" + profile.site[10:] + "/",
            str(meta.get("url") or f"/posts/{slug}/"),
        )
        if not in_property(url, profile.site):
            findings.append(
                {"code": "url_outside_property", "category": "technical", "certainty": "observed"}
            )
        prose = without_code(body)
        source_lines = body.splitlines()
        for n, line in enumerate(prose.splitlines(), 1):
            if re.search(r"\b(TODO|TBD|FIXME|lorem ipsum)\b|내용\s*추가|작성\s*예정", line, re.I):
                findings.append(
                    {
                        "code": "placeholder",
                        "line": n,
                        "category": "quality",
                        "certainty": "review_required",
                        "excerpt": line[:240],
                    }
                )
            claim = re.search(
                r"\b(we|I)\s+(tested|benchmarked|measured|ran|evaluated)\b|직접\s*(테스트|측정)", line, re.I
            )
            numeric = re.search(
                r"\d[\d,.]*\s*(%|percent|million|billion|times faster)|[$€₩]\s*\d", line, re.I
            )
            if claim or numeric:
                near = "\n".join(source_lines[max(0, n - 2) : n + 1])
                findings.append(
                    {
                        "code": "firsthand_claim_needs_evidence" if claim else "numeric_claim_needs_evidence",
                        "line": n,
                        "category": "quality",
                        "certainty": "review_required",
                        "nearby_link_present": bool(re.search(r"\]\(https?://", near)),
                        "excerpt": line[:240],
                    }
                )
        if not re.search(r"\]\(https?://", body):
            findings.append(
                {"code": "no_external_citations_detected", "category": "quality", "certainty": "heuristic"}
            )
        dates = {name: parse_date(meta.get(name)) for name in ("date", "lastmod")}
        for name, value in dates.items():
            if name in meta and value is None:
                findings.append({"code": "invalid_" + name, "category": "technical", "certainty": "observed"})
            if value and value > datetime.now(timezone.utc):
                findings.append(
                    {
                        "code": "future_" + name,
                        "category": "technical",
                        "certainty": "review_required",
                        "draft": bool(meta.get("draft")),
                    }
                )
        if dates["date"] and dates["lastmod"] and dates["lastmod"] < dates["date"]:
            findings.append(
                {"code": "lastmod_before_publication", "category": "technical", "certainty": "observed"}
            )
        if not prose.strip():
            findings.append({"code": "empty_prose", "category": "quality", "certainty": "observed"})
        if profile.build_root:
            for target in re.findall(r"(?<!!)\[[^\]]*\]\(([^)\s]+)", prose):
                if target.startswith(("#", "mailto:", "tel:")):
                    continue
                absolute = urljoin(url, target)
                if not in_property(absolute, profile.site):
                    continue
                try:
                    if not build_path(profile.build_root, profile.site, absolute).is_file():
                        findings.append(
                            {
                                "code": "internal_target_missing_from_build",
                                "target": target,
                                "category": "technical",
                                "certainty": "review_required",
                            }
                        )
                except EvidenceError:
                    findings.append(
                        {
                            "code": "unsafe_internal_target",
                            "target": target,
                            "category": "technical",
                            "certainty": "observed",
                        }
                    )
        rec = {
            "file": relative,
            "url": url,
            "protected": url in protected,
            "findings": findings,
            "source_hash": digest(body),
            "draft": bool(meta.get("draft")),
        }
        pages.append(rec)
        if body.strip():
            groups[digest(re.sub(r"\s+", " ", body).strip())].append(rec)
    for group in groups.values():
        if len(group) > 1:
            for page in group:
                page["findings"].append(
                    {
                        "code": "exact_duplicate_body",
                        "category": "quality",
                        "certainty": "observed",
                        "other_urls": [p["url"] for p in group if p is not page],
                        "action": "review_both_urls; keep_every_protected_url",
                    }
                )
    payload = {
        "property": profile.site,
        "created_at": now(),
        "pages": pages,
        "articles_checked": len(pages),
        "findings": sum(len(p["findings"]) for p in pages),
        "limitations": [
            "Claims require human source verification; flagged claims are not declared false.",
            "Internal target checks use the configured build; external links are not crawled.",
            "File-to-URL mapping assumes a posts/slug layout unless frontmatter sets url.",
            "No AdSense approval prediction or minimum word-count rule.",
        ],
    }
    return {"audit_id": store.artifact("audit", payload), **payload}


def prioritize(store: Store, profile: Profile, audit_id: str) -> dict:
    audit = store.get_artifact(audit_id, "audit", site=profile.site)
    protected = store.protected(profile.site)
    pages = []
    for page in audit["pages"]:
        if not page["findings"]:
            continue
        is_protected = page.get("url") in protected
        technical = any(f["category"] == "technical" for f in page["findings"])
        tier = 1 if is_protected and technical else 2 if is_protected else 3 if technical else 4
        pages.append(
            {
                **page,
                "protected": is_protected,
                "priority_tier": tier,
                "url_action": "keep_url" if is_protected else "review_required",
            }
        )
    return {
        "audit_id": audit_id,
        "pages": sorted(pages, key=lambda p: (p["priority_tier"], p["file"])),
        "ordering": "Protected technical issues; protected quality issues; other technical; other quality",
        "deletion_recommendations": False,
    }
