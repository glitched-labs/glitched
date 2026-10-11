"""
Running one job from the console - the part that touches the company's
network, so every rule is checked here, locally, before anything is sent:

1. A closed set of job types. A job names one host and what to run; it never
   carries ports, URLs, payloads or code - those are built into the runner.
2. Expired jobs and jobs seen before (replays) are refused.
3. The local pause switch and the policy's hourly limit.
4. The host is resolved once; every address must pass the local policy, and
   probes connect only to that pinned address.

Everything is written to the local audit log, including refusals.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from glitched import catalog, checks, targets
from glitched.runner.audit import AuditLog
from glitched.runner.policy import Policy
from glitched.runner.state import State

KINDS = ("preflight", "detect")      # what this version runs
LATER = ("scan", "recheck")          # known, arriving with a later version
DETECT_PORTS = tuple(sorted(set(checks.COMMON_PORTS) | set(catalog.PORT_HINTS)))
CLOCK_SKEW_SECONDS = 120


def refused(reason: str) -> dict[str, Any]:
    return {"status": "refused", "reason": reason}


def execute(job: dict[str, Any], policy: Policy | None, state: State, audit: AuditLog,
            policy_error: str = "") -> dict[str, Any]:
    """Run one job; returns what to report to the console ({status, reason?, result?})."""
    job_id, kind, host = str(job.get("id", "")), job.get("kind"), str(job.get("host") or "")
    audit.record("job.received", job=job_id, kind=kind, host=host)
    outcome = _run(job_id, kind, host, job, policy, state, audit, policy_error)
    if outcome["status"] == "refused":
        audit.record("job.refused", job=job_id, kind=kind, host=host, reason=outcome["reason"])
    else:
        audit.record("job.done", job=job_id, kind=kind, host=host, **_brief(outcome))
    return outcome


def _brief(outcome: dict[str, Any]) -> dict[str, Any]:
    result = outcome.get("result", {})
    brief: dict[str, Any] = {"addresses": result.get("addresses")}
    if "allowed" in result:
        brief["allowed"] = result["allowed"]
    if "probes" in result:
        brief["open_ports"] = [p["port"] for p in result["probes"] if p["open"]]
    return brief


def _run(job_id: str, kind: Any, host: str, job: dict[str, Any], policy: Policy | None, state: State,
         audit: AuditLog, policy_error: str) -> dict[str, Any]:
    if kind in LATER:
        return refused(f"This runner version doesn't run {kind} jobs yet - update it.")
    if kind not in KINDS:
        return refused(f"Unknown job type {kind!r}.")
    if set(job) - {"id", "kind", "host", "expires_at", "nonce"}:
        return refused("The job carries fields this runner doesn't accept.")
    if not job_id or not job.get("nonce"):
        return refused("The job has no id.")
    try:
        expires = datetime.fromisoformat(str(job.get("expires_at")))
    except ValueError:
        return refused("The job has no valid expiry.")
    if expires.tzinfo is None:
        return refused("The job's expiry has no time zone.")
    if (datetime.now(timezone.utc) - expires).total_seconds() > CLOCK_SKEW_SECONDS:
        return refused("The job expired before it reached the runner.")
    if not state.take(f"{job_id}:{job['nonce']}"):
        return refused("This job was already run once (replay refused).")
    if state.paused:
        return refused("The runner is paused on site (glitched-runner resume to continue).")
    if policy is None:
        return refused(f"The runner's policy can't be used: {policy_error}")
    if state.jobs_in_last_hour() > policy.max_jobs_per_hour:
        return refused(f"The policy allows at most {policy.max_jobs_per_hour} jobs an hour.")
    try:
        host = targets.validate_single_host(host)
        target = targets.resolve(host)
    except ValueError as exc:
        return refused(str(exc))
    verdict = policy.check(target)

    if kind == "preflight":  # nothing is sent to the robot
        return {"status": "done", "result": {"addresses": list(target.addresses), "allowed": verdict.allowed,
                                              "reason": verdict.reason}}
    if not verdict.allowed:
        return refused(verdict.reason)
    probes = [checks._probe_port(target, port) for port in DETECT_PORTS]
    if policy.evidence == "minimal":
        for probe in probes:
            probe["banner"] = ""
    return {"status": "done", "result": {"addresses": list(target.addresses), "address": target.address,
                                          "probes": probes}}
