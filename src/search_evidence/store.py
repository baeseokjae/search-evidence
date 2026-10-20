from __future__ import annotations

import gzip
import json
import sqlite3
from pathlib import Path

from .core import EvidenceError, atomic_file, canonical, digest, in_property, now

SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots(
 id TEXT PRIMARY KEY, source TEXT NOT NULL, property TEXT NOT NULL, table_name TEXT NOT NULL,
 observed_at TEXT NOT NULL, status TEXT NOT NULL, request_key TEXT NOT NULL,
 raw_hash TEXT NOT NULL, metadata TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS snapshot_lookup ON snapshots(source,property,table_name,observed_at);
CREATE TABLE IF NOT EXISTS facts(
 snapshot_id TEXT NOT NULL REFERENCES snapshots(id), ordinal INTEGER NOT NULL, payload TEXT NOT NULL,
 PRIMARY KEY(snapshot_id,ordinal)
);
CREATE TABLE IF NOT EXISTS protection(
 property TEXT NOT NULL,url TEXT NOT NULL,snapshot_id TEXT NOT NULL REFERENCES snapshots(id),
 source TEXT NOT NULL,clicks REAL NOT NULL, PRIMARY KEY(property,url,snapshot_id)
);
CREATE TABLE IF NOT EXISTS manual_protection(
 property TEXT NOT NULL,url TEXT NOT NULL,reason TEXT NOT NULL,created_at TEXT NOT NULL,
 PRIMARY KEY(property,url)
);
CREATE TABLE IF NOT EXISTS checkpoints(
 job TEXT NOT NULL,request_key TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(job,request_key)
);
CREATE TABLE IF NOT EXISTS artifacts(id TEXT PRIMARY KEY,kind TEXT NOT NULL,payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS quota(day TEXT NOT NULL,property TEXT NOT NULL,used INTEGER NOT NULL,
 PRIMARY KEY(day,property));
"""


class Store:
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if root.stat().st_mode & 0o077:
            raise EvidenceError("state_directory_must_be_private")
        self.path = root / "evidence.sqlite"
        self.db = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        self.path.chmod(0o600)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA busy_timeout=30000")
        self.db.executescript(SCHEMA)

    def close(self):
        self.db.close()

    def put(
        self,
        *,
        source: str,
        site: str,
        table: str,
        request: dict,
        raw: dict | list,
        rows: list,
        observed_at: str | None = None,
        status="available",
        coverage=None,
        error: str | None = None,
        checkpoint: tuple | None = None,
    ) -> dict:
        observed_at = observed_at or now()
        raw_hash = digest(raw)
        raw_path = self.root / "raw" / raw_hash[:2] / f"{raw_hash}.json.gz"
        if not raw_path.exists():
            atomic_file(raw_path, gzip.compress(canonical(raw), mtime=0))
        meta = dict(
            source=source,
            property=site,
            table=table,
            request=request,
            observed_at=observed_at,
            status=status,
            coverage=coverage or {},
            raw_hash=raw_hash,
            row_count=len(rows),
            error=error,
        )
        sid = digest(meta)
        meta["id"] = sid
        with self.db:
            self.db.execute(
                "INSERT OR IGNORE INTO snapshots VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    sid,
                    source,
                    site,
                    table,
                    observed_at,
                    status,
                    digest(request),
                    raw_hash,
                    canonical(meta).decode(),
                ),
            )
            for n, row in enumerate(rows):
                self.db.execute(
                    "INSERT OR IGNORE INTO facts VALUES(?,?,?)", (sid, n, canonical(row).decode())
                )
                url, clicks = row.get("url"), row.get("metrics", {}).get("clicks")
                if in_property(url, site) and clicks is not None and clicks > 0:
                    self.db.execute(
                        "INSERT OR IGNORE INTO protection VALUES(?,?,?,?,?)", (site, url, sid, source, clicks)
                    )
            if checkpoint:
                job, key = checkpoint
                self.db.execute(
                    "INSERT OR REPLACE INTO checkpoints VALUES(?,?,?)",
                    (job, key, canonical({"complete": sid}).decode()),
                )
        return meta

    def snapshot(self, sid: str) -> dict:
        row = self.db.execute("SELECT metadata FROM snapshots WHERE id=?", (sid,)).fetchone()
        if row is None:
            raise EvidenceError("snapshot_not_found")
        return json.loads(row[0])

    def snapshots(self, site: str, source: str | None = None, table: str | None = None) -> list[dict]:
        args, clauses = [site], ["property=?"]
        for col, val in (("source", source), ("table_name", table)):
            if val:
                clauses.append(f"{col}=?")
                args.append(val)
        return [
            json.loads(r[0])
            for r in self.db.execute(
                "SELECT metadata FROM snapshots WHERE "
                + " AND ".join(clauses)
                + " ORDER BY observed_at DESC,id DESC",
                args,
            )
        ]

    def facts(self, sid: str) -> list[dict]:
        self.snapshot(sid)
        return [
            json.loads(r[0])
            for r in self.db.execute("SELECT payload FROM facts WHERE snapshot_id=? ORDER BY ordinal", (sid,))
        ]

    def raw(self, sid: str):
        raw_hash = self.snapshot(sid)["raw_hash"]
        try:
            data = json.loads(
                gzip.decompress((self.root / "raw" / raw_hash[:2] / f"{raw_hash}.json.gz").read_bytes())
            )
        except (OSError, ValueError):
            raise EvidenceError("raw_integrity_failure") from None
        if digest(data) != raw_hash:
            raise EvidenceError("raw_integrity_failure")
        return data

    def protected(self, site: str) -> dict[str, dict]:
        out = {}
        query = """SELECT p.*,s.observed_at FROM protection p JOIN snapshots s ON s.id=p.snapshot_id
                   WHERE p.property=? ORDER BY s.observed_at,p.url"""
        for r in self.db.execute(query, (site,)):
            rec = out.setdefault(r["url"], {"url": r["url"], "decision": "protected", "evidence": []})
            rec["evidence"].append(
                {
                    "source": r["source"],
                    "snapshot": r["snapshot_id"],
                    "observed_at": r["observed_at"],
                    "clicks": r["clicks"],
                }
            )
        for r in self.db.execute("SELECT * FROM manual_protection WHERE property=?", (site,)):
            rec = out.setdefault(r["url"], {"url": r["url"], "decision": "protected", "evidence": []})
            rec["manual_reason"] = r["reason"]
        return out

    def protect(self, site: str, url: str, reason: str):
        if not in_property(url, site) or not reason.strip():
            raise EvidenceError("invalid_manual_protection")
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO manual_protection VALUES(?,?,?,?)", (site, url, reason, now())
            )

    def checkpoint(self, job: str, key: str, value: dict | None = None):
        if value is not None:
            with self.db:
                self.db.execute(
                    "INSERT OR REPLACE INTO checkpoints VALUES(?,?,?)", (job, key, canonical(value).decode())
                )
        r = self.db.execute(
            "SELECT payload FROM checkpoints WHERE job=? AND request_key=?", (job, key)
        ).fetchone()
        return json.loads(r[0]) if r else None

    def artifact(self, kind: str, payload: dict) -> str:
        aid = digest({"kind": kind, "payload": payload})
        with self.db:
            self.db.execute(
                "INSERT OR IGNORE INTO artifacts VALUES(?,?,?)", (aid, kind, canonical(payload).decode())
            )
        return aid

    def get_artifact(self, aid: str, kind: str, *, site: str) -> dict:
        r = self.db.execute("SELECT payload FROM artifacts WHERE id=? AND kind=?", (aid, kind)).fetchone()
        if r is None:
            raise EvidenceError("artifact_not_found")
        payload = json.loads(r[0])
        # IDs identify immutable evidence; knowing an ID does not grant access
        # through a profile for another property. Old unscoped artifacts fail closed.
        if "property" not in payload:
            raise EvidenceError("artifact_property_unknown")
        if payload["property"] != site:
            raise EvidenceError("artifact_property_mismatch")
        return payload

    def reserve_inspection(self, day: str, site: str, limit: int):
        # Counts attempts before the remote request; failed calls still consume the local allowance.
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO quota VALUES(?,?,0)", (day, site))
            updated = self.db.execute(
                "UPDATE quota SET used=used+1 WHERE day=? AND property=? AND used<?", (day, site, limit)
            ).rowcount
            if not updated:
                raise EvidenceError("inspection_daily_budget")

    def backup(self) -> dict:
        target = self.root / "backups" / now().replace(":", "-")
        target.mkdir(parents=True, mode=0o700)
        with sqlite3.connect(target / "evidence.sqlite") as db:
            self.db.backup(db)
            hashes = [r[0] for r in db.execute("SELECT DISTINCT raw_hash FROM snapshots")]
        (target / "evidence.sqlite").chmod(0o600)
        for h in hashes:
            src = self.root / "raw" / h[:2] / f"{h}.json.gz"
            atomic_file(target / "raw" / h[:2] / src.name, src.read_bytes())
        atomic_file(target / "manifest.json", canonical({"raw_hashes": hashes, "created_at": now()}))
        return {"backup": str(target), "raw_files": len(hashes)}
