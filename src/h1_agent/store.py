from __future__ import annotations

import json
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Settings


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    """Small request-safe JSON state store.

    On Vercel this lives in /tmp and is therefore ephemeral. It is deliberately
    dependency-free so the serverless API path remains reliable.
    """

    def __init__(self, settings: Settings):
        base = Path(settings.database_path)
        self.path = base.with_suffix(".json")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write({
                "programs": {},
                "scopes": {},
                "findings": {},
            })

    @property
    def durable(self) -> bool:
        return False

    def close(self) -> None:
        return None

    def _read(self) -> dict[str, Any]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return {"programs": {}, "scopes": {}, "findings": {}}

    def _write(self, state: dict[str, Any]) -> None:
        fd, tmp = tempfile.mkstemp(
            dir=str(self.path.parent),
            prefix=".h1-state-",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass

    def save_program(self, payload: dict[str, Any]) -> None:
        attrs = payload.get("data", {}).get("attributes", {})
        handle = attrs.get("handle")
        if not handle:
            return
        state = self._read()
        state["programs"][handle] = {
            "name": attrs.get("name", handle),
            "raw_json": payload,
            "fetched_at": utc_now(),
        }
        self._write(state)

    def save_scopes(self, handle: str, payload: dict[str, Any]) -> None:
        state = self._read()
        state["scopes"][handle] = {
            "raw_json": payload,
            "fetched_at": utc_now(),
        }
        self._write(state)

    def create_finding(self, data: dict[str, Any]) -> int:
        state = self._read()
        existing_ids = [int(x) for x in state["findings"].keys() if str(x).isdigit()]
        finding_id = max(existing_ids, default=0) + 1
        record = {
            "id": finding_id,
            "program_handle": data["program_handle"],
            "target": data["target"],
            "title": data.get("title", ""),
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
            "metadata": data.get("metadata", {}),
        }
        state["findings"][str(finding_id)] = record
        self._write(state)
        return finding_id

    def get_finding(self, finding_id: int) -> dict[str, Any]:
        state = self._read()
        record = state["findings"].get(str(finding_id))
        if record is None:
            raise KeyError(f"Finding {finding_id} not found")
        return dict(record)

    def set_state(self, finding_id: int, state_name: str) -> None:
        state = self._read()
        record = state["findings"].get(str(finding_id))
        if record is None:
            raise KeyError(f"Finding {finding_id} not found")
        record["state"] = state_name
        if state_name == "approved":
            record["approved_at"] = utc_now()
        state["findings"][str(finding_id)] = record
        self._write(state)

    def mark_submitted(self, finding_id: int, payload: dict[str, Any]) -> None:
        state = self._read()
        record = state["findings"].get(str(finding_id))
        if record is None:
            raise KeyError(f"Finding {finding_id} not found")
        record["state"] = "submitted"
        record["report_json"] = payload
        record["submitted_at"] = utc_now()
        record["h1_report_id"] = str(payload.get("data", {}).get("id") or "")
        state["findings"][str(finding_id)] = record
        self._write(state)

    def list_findings(self) -> list[dict[str, Any]]:
        state = self._read()
        rows = list(state["findings"].values())
        return sorted(rows, key=lambda row: int(row.get("id", 0)), reverse=True)
