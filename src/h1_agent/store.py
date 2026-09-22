from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Settings


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    """Request-scoped local store.

    Vercel Functions have ephemeral filesystems, so this store is intentionally
    used as a runtime queue/cache, not as the source of durable history.
    Durable cloud storage is a separate later layer.
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self.path = Path(settings.database_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    @property
    def durable(self) -> bool:
        return False

    def close(self) -> None:
        return None

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

    def save_program(self, payload: dict[str, Any]) -> None:
        attrs = payload.get("data", {}).get("attributes", {})
        handle = attrs.get("handle")
        if not handle:
            return
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO programs(handle,name,raw_json,fetched_at) VALUES(?,?,?,?)",
                (
                    handle,
                    attrs.get("name", handle),
                    json.dumps(payload),
                    utc_now(),
                ),
            )

    def save_scopes(self, handle: str, payload: dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM scopes WHERE program_handle=?", (handle,))
            for item in payload.get("data", []):
                attrs = item.get("attributes", {})
                conn.execute(
                    """INSERT INTO scopes(program_handle,scope_id,asset_type,asset_identifier,
                    eligible_for_bounty,eligible_for_submission,instruction,raw_json,fetched_at)
                    VALUES(?,?,?,?,?,?,?,?,?)""",
                    (
                        handle,
                        item.get("id"),
                        attrs.get("asset_type", ""),
                        attrs.get("asset_identifier", ""),
                        int(bool(attrs.get("eligible_for_bounty", False))),
                        int(bool(attrs.get("eligible_for_submission", True))),
                        str(attrs.get("instruction") or ""),
                        json.dumps(item),
                        utc_now(),
                    ),
                )

    def create_finding(self, data: dict[str, Any]) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO findings(program_handle,target,title,severity,state,summary,impact,
                reproduction_json,evidence_json,structured_scope_id,weakness_id,created_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    data["program_handle"],
                    data["target"],
                    data["title"],
                    data.get("severity"),
                    data.get("state", "needs_review"),
                    data.get("summary", ""),
                    data.get("impact", ""),
                    json.dumps(data.get("reproduction", [])),
                    json.dumps(data.get("evidence", [])),
                    data.get("structured_scope_id"),
                    data.get("weakness_id"),
                    utc_now(),
                ),
            )
            return int(cur.lastrowid)

    def get_finding(self, finding_id: int) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE id=?",
                (finding_id,),
            ).fetchone()
        if not row:
            raise KeyError(f"Finding {finding_id} not found")
        data = dict(row)
        data["reproduction"] = json.loads(data.pop("reproduction_json") or "[]")
        data["evidence"] = json.loads(data.pop("evidence_json") or "[]")
        return data

    def set_state(self, finding_id: int, state: str) -> None:
        with self._connect() as conn:
            if state == "approved":
                conn.execute(
                    "UPDATE findings SET state=?, approved_at=? WHERE id=?",
                    (state, utc_now(), finding_id),
                )
            else:
                conn.execute(
                    "UPDATE findings SET state=? WHERE id=?",
                    (state, finding_id),
                )

    def mark_submitted(self, finding_id: int, payload: dict[str, Any]) -> None:
        report_id = str(payload.get("data", {}).get("id") or "")
        with self._connect() as conn:
            conn.execute(
                "UPDATE findings SET state='submitted', report_json=?, submitted_at=?, h1_report_id=? WHERE id=?",
                (json.dumps(payload), utc_now(), report_id, finding_id),
            )

    def list_findings(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id,program_handle,target,title,severity,state,h1_report_id,created_at "
                "FROM findings ORDER BY id DESC"
            ).fetchall()
        return [dict(row) for row in rows]
