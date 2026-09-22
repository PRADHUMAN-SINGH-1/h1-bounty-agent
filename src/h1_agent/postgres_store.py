from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

import psycopg
from psycopg.rows import dict_row


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class PostgresStore:
    def __init__(self, database_url: str | None = None):
        self.database_url = database_url or os.getenv("DATABASE_URL", "")
        if not self.database_url:
            raise RuntimeError("DATABASE_URL is required for PostgresStore.")
        self._ensure_schema()

    @property
    def durable(self) -> bool:
        return True

    def _connect(self):
        return psycopg.connect(
            self.database_url,
            row_factory=dict_row,
            connect_timeout=15,
            application_name="h1-bounty-agent",
            autocommit=True,
        )

    def _ensure_schema(self) -> None:
        statements = [
            """
            CREATE TABLE IF NOT EXISTS h1_programs (
                handle TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                raw_json JSONB NOT NULL,
                fetched_at TIMESTAMPTZ NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS h1_scopes (
                handle TEXT PRIMARY KEY,
                raw_json JSONB NOT NULL,
                fetched_at TIMESTAMPTZ NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS h1_findings (
                id BIGSERIAL PRIMARY KEY,
                program_handle TEXT NOT NULL,
                target TEXT NOT NULL,
                title TEXT NOT NULL DEFAULT '',
                severity TEXT,
                state TEXT NOT NULL DEFAULT 'needs_review',
                summary TEXT NOT NULL DEFAULT '',
                impact TEXT NOT NULL DEFAULT '',
                reproduction JSONB NOT NULL DEFAULT '[]'::jsonb,
                evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
                structured_scope_id TEXT,
                weakness_id INTEGER,
                report_json JSONB,
                created_at TIMESTAMPTZ NOT NULL,
                approved_at TIMESTAMPTZ,
                submitted_at TIMESTAMPTZ,
                h1_report_id TEXT,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS h1_research_memory (
                scope_key TEXT PRIMARY KEY,
                items JSONB NOT NULL DEFAULT '[]'::jsonb,
                updated_at TIMESTAMPTZ NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS h1_surface_snapshots (
                scope_key TEXT PRIMARY KEY,
                urls JSONB NOT NULL DEFAULT '[]'::jsonb,
                updated_at TIMESTAMPTZ NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS h1_research_jobs (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                programs JSONB NOT NULL DEFAULT '[]'::jsonb,
                mode TEXT NOT NULL DEFAULT 'full',
                progress JSONB NOT NULL DEFAULT '{}'::jsonb,
                result JSONB,
                error TEXT,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL
            )
            """,
        ]
        with self._connect() as conn:
            for statement in statements:
                conn.execute(statement)

            migrations = [
                "ALTER TABLE h1_findings ADD COLUMN IF NOT EXISTS title TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE h1_findings ADD COLUMN IF NOT EXISTS severity TEXT",
                "ALTER TABLE h1_findings ADD COLUMN IF NOT EXISTS state TEXT NOT NULL DEFAULT 'needs_review'",
                "ALTER TABLE h1_findings ADD COLUMN IF NOT EXISTS summary TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE h1_findings ADD COLUMN IF NOT EXISTS impact TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE h1_findings ADD COLUMN IF NOT EXISTS reproduction JSONB NOT NULL DEFAULT '[]'::jsonb",
                "ALTER TABLE h1_findings ADD COLUMN IF NOT EXISTS evidence JSONB NOT NULL DEFAULT '[]'::jsonb",
                "ALTER TABLE h1_findings ADD COLUMN IF NOT EXISTS structured_scope_id TEXT",
                "ALTER TABLE h1_findings ADD COLUMN IF NOT EXISTS weakness_id INTEGER",
                "ALTER TABLE h1_findings ADD COLUMN IF NOT EXISTS report_json JSONB",
                "ALTER TABLE h1_findings ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()",
                "ALTER TABLE h1_findings ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ",
                "ALTER TABLE h1_findings ADD COLUMN IF NOT EXISTS submitted_at TIMESTAMPTZ",
                "ALTER TABLE h1_findings ADD COLUMN IF NOT EXISTS h1_report_id TEXT",
                "ALTER TABLE h1_findings ADD COLUMN IF NOT EXISTS metadata JSONB NOT NULL DEFAULT '{}'::jsonb",
                "ALTER TABLE h1_research_jobs ADD COLUMN IF NOT EXISTS programs JSONB NOT NULL DEFAULT '[]'::jsonb",
                "ALTER TABLE h1_research_jobs ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'full'",
                "ALTER TABLE h1_research_jobs ADD COLUMN IF NOT EXISTS progress JSONB NOT NULL DEFAULT '{}'::jsonb",
                "ALTER TABLE h1_research_jobs ADD COLUMN IF NOT EXISTS result JSONB",
                "ALTER TABLE h1_research_jobs ADD COLUMN IF NOT EXISTS error TEXT",
                "ALTER TABLE h1_research_jobs ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()",
                "ALTER TABLE h1_research_jobs ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()",
            ]
            for statement in migrations:
                conn.execute(statement)

    def close(self) -> None:
        return None

    @staticmethod
    def _serialize(value: Any) -> Any:
        return value

    def save_program(self, payload: dict[str, Any]) -> None:
        attrs = payload.get("data", {}).get("attributes", {})
        handle = attrs.get("handle")
        if not handle:
            return
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO h1_programs(handle, name, raw_json, fetched_at)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT(handle) DO UPDATE SET
                    name = EXCLUDED.name,
                    raw_json = EXCLUDED.raw_json,
                    fetched_at = EXCLUDED.fetched_at
                """,
                (handle, attrs.get("name", handle), json.dumps(payload), utc_now()),
            )

    def save_scopes(self, handle: str, payload: dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO h1_scopes(handle, raw_json, fetched_at)
                VALUES (%s, %s, %s)
                ON CONFLICT(handle) DO UPDATE SET
                    raw_json = EXCLUDED.raw_json,
                    fetched_at = EXCLUDED.fetched_at
                """,
                (handle, json.dumps(payload), utc_now()),
            )

    def create_finding(self, data: dict[str, Any]) -> int:
        with self._connect() as conn:
            row = conn.execute(
                """
                INSERT INTO h1_findings(
                    program_handle, target, title, severity, state, summary, impact,
                    reproduction, evidence, structured_scope_id, weakness_id,
                    created_at, metadata
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    data["program_handle"],
                    data["target"],
                    data.get("title", ""),
                    data.get("severity"),
                    data.get("state", "needs_review"),
                    data.get("summary", ""),
                    data.get("impact", ""),
                    json.dumps(data.get("reproduction", [])),
                    json.dumps(data.get("evidence", [])),
                    data.get("structured_scope_id"),
                    data.get("weakness_id"),
                    utc_now(),
                    json.dumps(data.get("metadata", {})),
                ),
            ).fetchone()
            return int(row["id"])

    def _row(self, row: dict[str, Any]) -> dict[str, Any]:
        result = dict(row)
        for key in ("reproduction", "evidence", "metadata"):
            value = result.get(key)
            if isinstance(value, str):
                result[key] = json.loads(value)
        if result.get("report_json") is not None and isinstance(result["report_json"], str):
            result["report_json"] = json.loads(result["report_json"])
        for key in ("created_at", "approved_at", "submitted_at"):
            if result.get(key) is not None and not isinstance(result[key], str):
                result[key] = result[key].isoformat()
        return result

    def get_finding(self, finding_id: int) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM h1_findings WHERE id = %s",
                (finding_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"Finding {finding_id} not found")
        return self._row(row)

    def set_state(self, finding_id: int, state_name: str) -> None:
        approved_at = utc_now() if state_name == "approved" else None
        with self._connect() as conn:
            updated = conn.execute(
                """
                UPDATE h1_findings
                SET state = %s, approved_at = COALESCE(%s::timestamptz, approved_at)
                WHERE id = %s
                """,
                (state_name, approved_at, finding_id),
            ).rowcount
        if not updated:
            raise KeyError(f"Finding {finding_id} not found")

    def mark_submitted(self, finding_id: int, payload: dict[str, Any]) -> None:
        with self._connect() as conn:
            updated = conn.execute(
                """
                UPDATE h1_findings
                SET state = 'submitted',
                    report_json = %s,
                    submitted_at = %s,
                    h1_report_id = %s
                WHERE id = %s
                """,
                (
                    json.dumps(payload),
                    utc_now(),
                    str(payload.get("data", {}).get("id") or ""),
                    finding_id,
                ),
            ).rowcount
        if not updated:
            raise KeyError(f"Finding {finding_id} not found")

    def list_findings(self) -> list[dict[str, Any]]:
        last_error: Exception | None = None
        for _ in range(2):
            try:
                with self._connect() as conn:
                    rows = conn.execute(
                        "SELECT * FROM h1_findings ORDER BY id DESC"
                    ).fetchall()
                return [self._row(row) for row in rows]
            except (psycopg.Error, OSError) as exc:
                last_error = exc
        if last_error is not None:
            raise RuntimeError("Persistent findings storage is unavailable.") from last_error
        return []

    def save_memory(self, scope_key: str, items: list[dict[str, Any]]) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO h1_research_memory(scope_key, items, updated_at)
                VALUES (%s, %s, %s)
                ON CONFLICT(scope_key) DO UPDATE SET
                    items = EXCLUDED.items,
                    updated_at = EXCLUDED.updated_at
                """,
                (scope_key, json.dumps(items[-200:]), utc_now()),
            )

    def get_memory(self, scope_key: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT items FROM h1_research_memory WHERE scope_key = %s",
                (scope_key,),
            ).fetchone()
        if not row:
            return []
        value = row["items"]
        return json.loads(value) if isinstance(value, str) else list(value or [])

    def save_surface_snapshot(self, scope_key: str, urls: list[str]) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT urls FROM h1_surface_snapshots WHERE scope_key = %s",
                (scope_key,),
            ).fetchone()
            previous_value = row["urls"] if row else []
            if isinstance(previous_value, str):
                previous_value = json.loads(previous_value)
            current = sorted(set(urls))[:500]
            conn.execute(
                """
                INSERT INTO h1_surface_snapshots(scope_key, urls, updated_at)
                VALUES (%s, %s, %s)
                ON CONFLICT(scope_key) DO UPDATE SET
                    urls = EXCLUDED.urls,
                    updated_at = EXCLUDED.updated_at
                """,
                (scope_key, json.dumps(current), utc_now()),
            )
        return {"previous": list(previous_value or []), "current": current}

    def get_surface_snapshot(self, scope_key: str) -> list[str]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT urls FROM h1_surface_snapshots WHERE scope_key = %s",
                (scope_key,),
            ).fetchone()
        if not row:
            return []
        value = row["urls"]
        return json.loads(value) if isinstance(value, str) else list(value or [])

    def create_research_job(self, data: dict[str, Any]) -> str:
        with self._connect() as conn:
            row = conn.execute("SELECT id FROM h1_research_jobs ORDER BY created_at DESC LIMIT 1").fetchone()
            previous = str(row["id"]) if row else ""
            number = int(previous.rsplit("-", 1)[-1]) + 1 if previous.rsplit("-", 1)[-1].isdigit() else 1
            job_id = f"job-{number}"
            now = utc_now()
            conn.execute(
                """
                INSERT INTO h1_research_jobs(id, status, programs, mode, progress, result, created_at, updated_at)
                VALUES (%s, 'queued', %s, %s, %s, NULL, %s, %s)
                """,
                (job_id, json.dumps(list(data.get("programs", []))), data.get("mode", "full"),
                 json.dumps({"program": None, "target": None, "completed_targets": 0, "planned_targets": 0}),
                 now, now),
            )
        return job_id

    def update_research_job(self, job_id: str, patch: dict[str, Any]) -> None:
        existing = self.get_research_job(job_id)
        merged = dict(existing)
        merged.update(patch)
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE h1_research_jobs
                SET status=%s, programs=%s, mode=%s, progress=%s, result=%s, error=%s, updated_at=%s
                WHERE id=%s
                """,
                (
                    merged.get("status", "queued"),
                    json.dumps(merged.get("programs", [])),
                    merged.get("mode", "full"),
                    json.dumps(merged.get("progress", {})),
                    json.dumps(merged.get("result")) if merged.get("result") is not None else None,
                    merged.get("error"),
                    utc_now(),
                    job_id,
                ),
            )

    def get_research_job(self, job_id: str) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM h1_research_jobs WHERE id=%s", (job_id,)).fetchone()
        if not row:
            raise KeyError(f"Research job {job_id} not found")
        result = dict(row)
        for key in ("programs", "progress"):
            value = result.get(key)
            if isinstance(value, str):
                result[key] = json.loads(value)
        if isinstance(result.get("result"), str):
            result["result"] = json.loads(result["result"])
        for key in ("created_at", "updated_at"):
            if result.get(key) is not None and not isinstance(result[key], str):
                result[key] = result[key].isoformat()
        return result
