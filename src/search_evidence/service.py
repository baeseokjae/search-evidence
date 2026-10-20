from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import html
import io
import json
import secrets
import time

from .audit import audit_content, prioritize
from .config import Profile
from .core import EvidenceError, Result, atomic_file, canonical, digest, now, secret_free_error, window
from .live import verify_manifest
from .providers import Providers
from .store import Store


class Service:
    def __init__(self, profile: Profile):
        self.profile, self.store = profile, Store(profile.state_dir)
        self.cursor_key = self.store.root / "cursor.key"
        if not self.cursor_key.exists():
            # Exclusive creation avoids parallel clients replacing the signing key.
            try:
                with self.cursor_key.open("xb") as f:
                    self.cursor_key.chmod(0o600)
                    f.write(secrets.token_bytes(32))
            except FileExistsError:
                pass

    def close(self):
        self.store.close()

    def page(self, rows: list, identity: dict, limit=50, cursor=None) -> dict:
        if type(limit) is not int or not 1 <= limit <= 500:
            raise EvidenceError("invalid_page_limit")
        binding = digest(identity)
        offset = 0
        secret = self.cursor_key.read_bytes()
        if cursor:
            try:
                if len(cursor) > 1024:
                    raise ValueError
                token, sig = cursor.split(".")
                expected = hmac.new(secret, token.encode(), hashlib.sha256).hexdigest()
                payload = json.loads(base64.urlsafe_b64decode(token))
                if not hmac.compare_digest(sig, expected) or payload["binding"] != binding:
                    raise ValueError
                if payload["expires"] < time.time() or type(payload["offset"]) is not int:
                    raise ValueError
                offset = payload["offset"]
                if offset < 0 or offset > len(rows):
                    raise ValueError
            except (ValueError, KeyError, TypeError):
                raise EvidenceError("invalid_or_expired_cursor") from None
        next_cursor = None
        if offset + limit < len(rows):
            token = base64.urlsafe_b64encode(
                canonical({"binding": binding, "offset": offset + limit, "expires": int(time.time()) + 3600})
            ).decode()
            next_cursor = token + "." + hmac.new(secret, token.encode(), hashlib.sha256).hexdigest()
        return {"rows": rows[offset : offset + limit], "total_rows": len(rows), "next_cursor": next_cursor}

    def status(self, remote=False) -> dict:
        snapshots = self.store.snapshots(self.profile.site)
        latest = {}
        last_good = {}
        for s in snapshots:
            key = s["source"] + "/" + s["table"]
            latest.setdefault(key, s)
            if s["status"] == "available":
                last_good.setdefault(key, s)
        out = {
            "property": self.profile.site,
            "latest": latest,
            "last_good": last_good,
            "protected_urls": len(self.store.protected(self.profile.site)),
            "credentials": {
                "google_file_configured": self.profile.google_credentials is not None,
                "bing_file_configured": self.profile.bing_key is not None,
            },
            "remote_checked": remote,
        }
        if remote:
            out["remote"] = Providers(self.profile, self.store).status()
        return out

    def traffic(self, source="gsc", table="pages", snapshot_id=None, limit=50, cursor=None, url=None) -> dict:
        if snapshot_id:
            snapshot = self.store.snapshot(snapshot_id)
            if snapshot["property"] != self.profile.site:
                raise EvidenceError("snapshot_property_mismatch")
        else:
            snapshots = self.store.snapshots(self.profile.site, source, table)
            if not snapshots:
                raise EvidenceError("no_snapshot")
            snapshot = snapshots[0]
        rows = self.store.facts(snapshot["id"])
        if url is not None:
            rows = [r for r in rows if r.get("url") == url]
        return {
            "snapshot": snapshot,
            **self.page(rows, {"snapshot": snapshot["id"], "url": url}, limit, cursor),
            "absence_means_zero": False,
            "combined_across_snapshots": False,
        }

    def compare(self, before: str, after: str, limit=50, cursor=None) -> dict:
        a, b = self.store.snapshot(before), self.store.snapshot(after)
        if a["property"] != self.profile.site or b["property"] != self.profile.site:
            raise EvidenceError("snapshot_property_mismatch")
        if a["source"] != "gsc" or b["source"] != "gsc":
            raise EvidenceError("period_comparison_requires_google_dates")
        if a["status"] != "available" or b["status"] != "available":
            raise EvidenceError("comparison_requires_available_snapshots")
        left, right = a["request"], b["request"]

        def identity(r):
            return {k: v for k, v in r.items() if k not in ("startDate", "endDate")}

        if identity(left) != identity(right):
            raise EvidenceError("comparison_conditions_mismatch")
        if any(a["coverage"].get(k) != b["coverage"].get(k) for k in ("aggregation", "timezone")):
            raise EvidenceError("comparison_aggregation_mismatch")
        x, y = window(left["startDate"], left["endDate"]), window(right["startDate"], right["endDate"])
        if (x[1] - x[0]) != (y[1] - y[0]) or max(x[0], y[0]) <= min(x[1], y[1]):
            raise EvidenceError("comparison_requires_equal_nonoverlapping_windows")
        if "date" in left.get("dimensions", []):
            raise EvidenceError("date_rows_require_explicit_alignment")

        def by_key(sid):
            return {canonical(r["dimensions"]).decode(): r for r in self.store.facts(sid)}

        old, new = by_key(before), by_key(after)
        rows = []
        for key in sorted(old.keys() | new.keys()):
            p, q = old.get(key), new.get(key)
            deltas = {}
            for metric in ("clicks", "impressions", "ctr", "position"):
                pv = p["metrics"].get(metric) if p else None
                qv = q["metrics"].get(metric) if q else None
                delta = qv - pv if pv is not None and qv is not None else None
                deltas[metric] = {
                    "before": pv,
                    "after": qv,
                    "absolute": delta,
                    "relative": delta / pv if delta is not None and pv != 0 else None,
                }
            rows.append(
                {
                    "dimensions": json.loads(key),
                    "metrics": deltas,
                    "presence": "both" if p and q else "not_returned_after" if p else "not_returned_before",
                }
            )
        return {
            "before": a,
            "after": b,
            **self.page(rows, {"before": before, "after": after}, limit, cursor),
            "warnings": [
                "Absent rows remain unknown, including withheld queries.",
                "CTR absolute changes use fraction units; multiply by 100 for percentage points.",
            ],
        }

    def protect_urls(self, urls: list[str] | None = None, limit=50, cursor=None) -> dict:
        protected = self.store.protected(self.profile.site)
        candidates = sorted(set(urls if urls is not None else protected))
        rows = [
            protected.get(
                u,
                {
                    "url": u,
                    "decision": "review_required",
                    "evidence": [],
                    "reason": "no_positive_click_evidence; absence_is_not_zero",
                },
            )
            for u in candidates
        ]
        return {
            **self.page(rows, {"protection": digest(rows)}, limit, cursor),
            "raw_urls_preserved": True,
            "automatic_alias_collapse": False,
            "deletion_authorized": False,
        }

    def audit(self, audit_id=None, limit=50, cursor=None):
        if cursor and not audit_id:
            raise EvidenceError("audit_id_required_for_cursor")
        if audit_id:
            data = self.store.get_artifact(audit_id, "audit", site=self.profile.site)
        else:
            data = audit_content(self.store, self.profile)
            audit_id = data["audit_id"]
        return {
            "audit_id": audit_id,
            "articles_checked": data["articles_checked"],
            "findings": data["findings"],
            "limitations": data["limitations"],
            **self.page(data["pages"], {"audit": audit_id}, limit, cursor),
        }

    def priorities(self, audit_id, limit=50, cursor=None):
        data = prioritize(self.store, self.profile, audit_id)
        pages = data.pop("pages")
        return {**data, **self.page(pages, {"priorities": digest(pages), "audit": audit_id}, limit, cursor)}

    def verify(self, manifest_id=None, verification_id=None, cache_check=False, limit=50, cursor=None):
        if bool(manifest_id) == bool(verification_id) or (cursor and not verification_id):
            raise EvidenceError("select_manifest_or_existing_verification")
        if verification_id:
            data = self.store.get_artifact(verification_id, "verification", site=self.profile.site)
        else:
            data = verify_manifest(self.store, self.profile, manifest_id, cache_check=cache_check)
            verification_id = data["verification_id"]
        pages = data.pop("pages")
        return {
            **data,
            "verification_id": verification_id,
            "pages_passed": sum(p["passed"] for p in pages),
            **self.page(pages, {"verification": verification_id}, limit, cursor),
        }

    def render_report(self, audit_id=None, verification_id=None) -> dict:
        payload = {
            "property": self.profile.site,
            "generated_at": now(),
            "status": self.status(),
            "protection": list(self.store.protected(self.profile.site).values()),
        }
        if audit_id:
            payload["priorities"] = prioritize(self.store, self.profile, audit_id)
        if verification_id:
            payload["verification"] = self.store.get_artifact(
                verification_id, "verification", site=self.profile.site
            )
        rid = self.store.artifact("report", payload)
        directory = self.store.root / "reports" / rid
        atomic_file(directory / "report.json", canonical(payload))
        out = io.StringIO(newline="")
        writer = csv.writer(out)
        writer.writerow(["url", "decision", "sources", "evidence_count"])

        def safe_cell(value):
            value = str(value)
            return "'" + value if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else value

        for row in payload["protection"]:
            writer.writerow(
                [
                    safe_cell(row["url"]),
                    row["decision"],
                    ",".join(sorted({e["source"] for e in row["evidence"]})),
                    len(row["evidence"]),
                ]
            )
        atomic_file(directory / "protected-urls.csv", out.getvalue().encode())
        traffic_csv = io.StringIO(newline="")
        traffic_writer = csv.writer(traffic_csv)
        traffic_writer.writerow(
            [
                "source",
                "table",
                "snapshot_id",
                "observed_at",
                "start",
                "end",
                "status",
                "url",
                "query",
                "date",
                "clicks",
                "impressions",
                "ctr_fraction",
                "position",
            ]
        )
        for snapshot in payload["status"]["latest"].values():
            for row in self.store.facts(snapshot["id"]):
                dims, met = row.get("dimensions", {}), row.get("metrics", {})
                traffic_writer.writerow(
                    [
                        safe_cell("" if value is None else value)
                        for value in (
                            snapshot["source"],
                            snapshot["table"],
                            snapshot["id"],
                            snapshot["observed_at"],
                            snapshot["request"].get("startDate"),
                            snapshot["request"].get("endDate"),
                            snapshot["status"],
                            row.get("url"),
                            dims.get("query"),
                            dims.get("date", dims.get("bing_date_raw")),
                            met.get("clicks"),
                            met.get("impressions"),
                            met.get("ctr"),
                            met.get("position"),
                        )
                    ]
                )
        atomic_file(directory / "traffic.csv", traffic_csv.getvalue().encode())
        cards = "".join(
            "<tr><td>"
            + html.escape(k)
            + "</td><td>"
            + html.escape(v["status"])
            + "</td><td>"
            + html.escape(v["observed_at"])
            + "</td><td>"
            + str(v["row_count"])
            + "</td></tr>"
            for k, v in payload["status"]["latest"].items()
        )
        document = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Search Evidence report</title><style>
body{font:16px/1.6 system-ui,sans-serif;max-width:1100px;margin:40px auto;padding:0 24px;color:#182838}
table{border-collapse:collapse;width:100%}td,th{padding:10px;border-bottom:1px solid #ccd}
th{text-align:left}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f6f8;padding:20px}
.note{border-left:4px solid #168079;padding:12px 20px}summary{cursor:pointer;font-weight:600}
</style><h1>Search Evidence</h1>"""
        document += (
            "<p>" + html.escape(self.profile.site) + " · " + html.escape(payload["generated_at"]) + "</p>"
        )
        document += (
            "<p class=note>"
            + str(len(payload["protection"]))
            + (
                " raw URLs protected. Missing data is unknown. Provider totals are kept separate. "
                "Content review findings are not AdSense policy verdicts.</p>"
            )
        )
        document += "<h2>Latest observations</h2><table><tr><th>Table</th><th>Status</th><th>Observed</th>"
        document += "<th>Rows</th></tr>" + cards + "</table>"
        for section in ("protection", "priorities", "verification"):
            if section in payload:
                document += (
                    "<h2>" + section.title() + "</h2><details><summary>Inspect evidence</summary><pre>"
                )
                document += (
                    html.escape(json.dumps(payload[section], ensure_ascii=False, indent=2))
                    + "</pre></details>"
                )
        document += "</html>"
        atomic_file(directory / "report.html", document.encode())
        return {
            "report_id": rid,
            "files": ["report.json", "protected-urls.csv", "traffic.csv", "report.html"],
            "state_relative_directory": "reports/" + rid,
        }

    def invoke(self, method: str, arguments: dict) -> Result:
        handlers = {
            "search_status": self.status,
            "search_collect": lambda **kw: Providers(self.profile, self.store).collect(**kw),
            "search_traffic": self.traffic,
            "search_compare": self.compare,
            "search_protect_urls": self.protect_urls,
            "search_prioritize": self.priorities,
            "search_inspect_urls": lambda **kw: Providers(self.profile, self.store).inspect(**kw),
            "search_audit_content": self.audit,
            "search_verify_live": self.verify,
            "search_render_report": self.render_report,
        }
        try:
            if method not in handlers:
                raise EvidenceError("unknown_tool")
            data = handlers[method](**arguments)
            if method == "search_collect" and not data["complete"]:
                useful = any(s["status"] == "available" or s["row_count"] > 0 for s in data["snapshots"])
                transient = {
                    "call_budget_exhausted",
                    "deadline_exceeded",
                    "retry_deferred",
                    "quota_deferred",
                    "transport_unavailable",
                    "http_408",
                    "http_429",
                    "http_500",
                    "http_502",
                    "http_503",
                    "http_504",
                }
                retryable = bool(data.get("deferred_google_partitions")) or any(
                    s.get("error") in transient for s in data["snapshots"]
                )
                return Result(
                    ok=useful,
                    data=data,
                    warnings=["Collection is incomplete; inspect per-table status."],
                    error=None if useful else {"code": "collection_unavailable", "retryable": retryable},
                )
            return Result(data=data)
        except Exception as exc:
            return secret_free_error(exc)
