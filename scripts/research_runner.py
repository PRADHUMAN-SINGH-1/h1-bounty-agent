from __future__ import annotations

import json
import os
import sys
import traceback

from h1_agent.config import Settings
from h1_agent.store import Store
from h1_agent.worker import run_cycle


def main() -> int:
    settings = Settings()
    store = Store(settings)
    job = store.claim_next_research_job()
    if not job:
        store.close()
        print("No queued research jobs.")
        return 0

    job_id = str(job["id"])
    programs = {str(x).strip() for x in job.get("programs", []) if str(x).strip()}
    mode = str(job.get("mode") or "full")

    try:
        def progress(payload: dict) -> None:
            store.update_research_job(
                job_id,
                {
                    "status": "running",
                    "progress": payload,
                },
            )

        result = run_cycle(
            settings,
            requested_programs=programs,
            mode=mode,
            on_progress=progress,
        )
        store.update_research_job(
            job_id,
            {
                "status": "completed" if result.get("status") in {"ok", "blocked"} else "error",
                "result": result,
                "progress": {
                    "program": None,
                    "target": None,
                    "planned_targets": result.get("researched_targets", 0),
                    "completed_targets": result.get("researched_targets", 0),
                },
            },
        )
        print(json.dumps({
            "job_id": job_id,
            "status": result.get("status"),
            "targets": result.get("researched_targets", 0),
            "candidates": result.get("created_findings", 0),
        }))
        return 0
    except Exception as exc:
        store.update_research_job(
            job_id,
            {
                "status": "error",
                "error": f"{exc.__class__.__name__}: {exc}",
                "progress": {"program": None, "target": None, "completed_targets": 0, "planned_targets": 0},
            },
        )
        traceback.print_exc()
        return 1
    finally:
        store.close()


if __name__ == "__main__":
    sys.exit(main())
