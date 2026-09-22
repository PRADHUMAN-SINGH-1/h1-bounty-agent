from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Settings

try:
    from vercel.blob import BlobClient
except ImportError:
    BlobClient = None  # type: ignore[assignment]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    """Durable Vercel Blob when available; safe SQLite fallback if Blob is unavailable."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.blob = None
        if BlobClient is not None and settings.blob_token:
            try:
                self.blob = BlobClient(token=settings.blob_token)
            except Exception:
                self.blob = None

        # Always keep the local schema available as an emergency fallback.
        self.path = Path(settings.database_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    @property
    def durable(self) -> bool:
        return self.blob is not None

    def _disable_blob(self) -> None:
        if self.blob is not None:
            try:
                self.blob.close()
            except Exception:
                pass
        self.blob = None

    def close(self) -> None:
        self._disable_blob()

    # ---------- Blob backend ----------

    def _blob_path(self, category: str, key: str) -> str:
        return f"h1-agent/{category}/{key}.json"

    def _blob_put(self, category: str, key: str, value: dict[str, Any]) -> None:
        if self.blob is None:
            raise RuntimeError("Blob storage unavailable")
        self.blob.put(
            self._blob_path(category, key),
            json.dumps(value, ensure_ascii=False).encode("utf-8"),
            access="private",
            content_type="application/json",
            overwrite=True,
            token=self.settings.blob_token,
        )

    def _blob_get(self, category: str, key: str) -> dict[str, Any]:
        if self.blob is None:
            raise RuntimeError("Blob storage unavailable")
        result = self.blob.get(
            self._blob_path(category, key),
            access="private",
            token=self.settings.blob_token,
        )
        return json.loads(bytes(result).decode("utf-8"))

    def _blob_list(self, category: str) -> list[dict[str, Any]]:
        if self.blob is None:
            raise RuntimeError("Blob storage unavailable")
        prefix = f"h1-agent/{category}/"
        rows: list[dict[str, Any]] = []
        for item in self.blob.iter_objects(
            prefix=prefix,
            limit=1000,
            token=self.settings.blob_token,
        ):
            pathname = str(item.pathname)
            key = pathname[len(prefix) :].removesuffix(".json")
            try:
                rows.append(self._blob_get(category, key))
            except Exception:
                continue
        return rows

    # ---------- SQLite backend ----------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _migrate(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS programs (
                    handle TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    fetched_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scopes (
                    program_handle TEXT NOT NULL,
                    scope_id TEXT,
                    asset_type TEXT NOT NULL,
                    asset_identifier TEXT NOT NULL,
                    eligible_for_bounty INTEGER NOT NULL,
                    eligible_for_submission INTEGER NOT NULL,
                    instruction TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    fetched_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    program_handle TEXT NOT NULL,
                    target TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT,
                    state TEXT NOT NULL,
                    summary TEXT NOT NULL DEFAULT '',
                    impact TEXT NOT NULL DEFAULT '',
                    reproduction_json TEXT NOT NULL DEFAULT '[]',
                    evidence_json TEXT NOT NULL,
                    structured_scope_id TEXT,
                    weakness_id INTEGER,
                    report_json TEXT,
                    created_at TEXT NOT NULL,
                    approved_at TEXT,
                    submitted_at TEXT,
                    h1_report_id TEXT
                );
                """
            )

    def _save_finding_sqlite(self, record: dict[str, Any]) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO findings(program_handle,target,title,severity,state,summary,impact,
                reproduction_json,evidence_json,structured_scope_id,weakness_id,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    record["program_handle"], record["target"], record["title"],
                    record["severity"], record["state"], record["summary"], record["impact"],
                    json.dumps(record["reproduction"]), json.dumps(record["evidence"]),
                    record["structured_scope_id"], record["weakness_id"], record["created_at"],
                ),
            )
            return int(cur.lastrowid)

    # ---------- Public methods ----------

    def save_program(self, payload: dict[str, Any]) -> None:
        attrs = payload.get("data", {}).get("attributes", {})
        handle = attrs.get("handle")
        if not handle:
            return

        record = {
            "handle": handle,
            "name": attrs.get("name", handle),
            "raw_json": payload,
            "fetched_at": utc_now(),
        }
        if self.blob is not None:
            try:
                self._blob_put("programs", str(handle), record)
                return
            except Exception:
                self._disable_blob()

        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO programs(handle,name,raw_json,fetched_at) VALUES(?,?,?,?)",
                (handle, record["name"], json.dumps(payload), record["fetched_at"]),
            )

    def save_scopes(self, handle: str, payload: dict[str, Any]) -> None:
        if self.blob is not None:
            try:
                self._blob_put(
                    "scopes",
                    handle,
                    {"program_handle": handle, "raw_json": payload, "fetched_at": utc_now()},
                )
                return
            except Exception:
                self._disable_blob()

        with self._connect() as conn:
            conn.execute("DELETE FROM scopes WHERE program_handle=?", (handle,))
            for item in payload.get("data", []):
                attrs = item.get("attributes", {})
                conn.execute(
                    """INSERT INTO scopes(program_handle,scope_id,asset_type,asset_identifier,
                    eligible_for_bounty,eligible_for_submission,instruction,raw_json,fetched_at)
                    VALUES(?,?,?,?,?,?,?,?,?)""",
                    (
                        handle, item.get("id"), attrs.get("asset_type", ""),
                        attrs.get("asset_identifier", ""),
                        int(bool(attrs.get("eligible_for_bounty", False))),
                        int(bool(attrs.get("eligible_for_submission", True))),
                        str(attrs.get("instruction") or ""), json.dumps(item), utc_now(),
                    ),
                )

    def create_finding(self, data: dict[str, Any]) -> int:
        finding_id = int(time.time() * 1000)
        record = {
            "id": finding_id,
            "program_handle": data["program_handle"],
            "target": data["target"],
            "title": data["title"],
            "severity": data.get("severity"),
            "state": data.get("state", "needs_review"),
            "summary": data.get("summary", ""),
            "impact": data.get("impact", ""),
            "reproduction": data.get("reproduction", []),
            "evidence": data.get("evidence", []),
            "structured_scope_id": data.get("structured_scope_id"),
            "weakness_id": data.get("weakness_id"),
            "report_json": None,
            "created_at": utc_now(),
            "approved_at": None,
            "submitted_at": None,
            "h1_report_id": None,
        }
        if self.blob is not None:
            try:
                self._blob_put("findings", str(finding_id), record)
                return finding_id
            except Exception:
                self._disable_blob()

        return self._save_finding_sqlite(record)

    def get_finding(self, finding_id: int) -> dict[str, Any]:
        if self.blob is not None:
            try:
                return self._blob_get("findings", str(finding_id))
            except Exception:
                self._disable_blob()

        with self._connect() as conn:
            row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not row:
            raise KeyError(f"Finding {finding_id} not found")
        data = dict(row)
        data["reproduction"] = json.loads(data.pop("reproduction_json") or "[]")
        data["evidence"] = json.loads(data.pop("evidence_json") or "[]")
        return data

    def set_state(self, finding_id: int, state: str) -> None:
        data = self.get_finding(finding_id)
        data["state"] = state
        if state == "approved":
            data["approved_at"] = utc_now()

        if self.blob is not None:
            try:
                self._blob_put("findings", str(finding_id), data)
                return
            except Exception:
                self._disable_blob()

        with self._connect() as conn:
            if state == "approved":
                conn.execute(
                    "UPDATE findings SET state=?, approved_at=? WHERE id=?",
                    (state, data["approved_at"], finding_id),
                )
            else:
                conn.execute("UPDATE findings SET state=? WHERE id=?", (state, finding_id))

    def mark_submitted(self, finding_id: int, payload: dict[str, Any]) -> None:
        data = self.get_finding(finding_id)
        data["state"] = "submitted"
        data["report_json"] = payload
        data["submitted_at"] = utc_now()
        data["h1_report_id"] = str(payload.get("data", {}).get("id") or "")

        if self.blob is not None:
            try:
                self._blob_put("findings", str(finding_id), data)
                return
            except Exception:
                self._disable_blob()

        with self._connect() as conn:
            conn.execute(
                "UPDATE findings SET state='submitted', report_json=?, submitted_at=?, h1_report_id=? WHERE id=?",
                (json.dumps(payload), data["submitted_at"], data["h1_report_id"], finding_id),
            )

    def list_findings(self) -> list[dict[str, Any]]:
        if self.blob is not None:
            try:
                rows = self._blob_list("findings")
                return sorted(rows, key=lambda x: int(x.get("id", 0)), reverse=True)
            except Exception:
                self._disable_blob()

        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id,program_handle,target,title,severity,state,h1_report_id,created_at "
                "FROM findings ORDER BY id DESC"
            ).fetchall()
        return [dict(r) for r in rows]
