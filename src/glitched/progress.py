"""
Scan progress: fold the events glitched.checks.run_checks reports (plan,
start, item, done, manual) into the job state a page shows. Standard library
only - the local UI uses it now, the hosted console will too.
"""

from __future__ import annotations


def apply(job: dict, event: dict) -> None:
    """Update job["steps"] / job["manual"] in place for one progress event."""
    kind = event.get("type")
    if kind == "plan":
        job["steps"] = [{**step, "state": "pending", "items": []} for step in event["steps"]]
    elif kind == "manual":
        job["manual"] = event["count"]
    else:
        step = next((s for s in job.get("steps", []) if s["ref_id"] == event.get("ref_id")), None)
        if step is None:
            return
        if kind == "start":
            step["state"] = "running"
        elif kind == "item":
            step["items"].append({k: event[k] for k in ("label", "result", "flag")})
        elif kind == "done":
            step.update(state="done", status=event["status"], detail=event["detail"])
