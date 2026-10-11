"""
Scans in three steps, so no database transaction is open while a robot is
probed:

  prepare   (read)   which threats apply and which passive checks to run
  probe     (no tx)  glitched.checks.run_checks against the pinned address
  record    (write)  create the assessment, store results and evidence, and
                     bring the device's findings up to date

The record half (`record_scan`, `record_results`, `findings.apply_recheck`)
doesn't care where the probes ran - locally here, or on an on-site runner.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from psycopg2.extensions import cursor as Cursor

from glitched import checks, safety
from glitched import findings as robot_findings
from glitched.checks import PASSIVE_CHECKS, UNREACHABLE, Progress, _report
from glitched.db import run_in_transaction
from glitched.paths import data_home
from glitched.queries import THREATS_FOR_PROPERTIES_SQL
from glitched.targets import Target

EVIDENCE_DIR = data_home() / "evidence"
NO_ADDRESS = "No address given - nothing was checked."


def _schema() -> str:
    from glitched.cli import SCHEMA  # the app schema lives with the CLI; imported late to avoid a cycle

    return SCHEMA


# --------------------------------------------------------------------------
# Planning
# --------------------------------------------------------------------------


def validate_properties(cur: Cursor, property_ids: list[str]) -> None:
    cur.execute("SELECT id FROM emb3d_properties WHERE id = ANY(%s)", (property_ids,))
    unknown = set(property_ids) - {row[0] for row in cur.fetchall()}
    if unknown:
        raise SystemExit(f"unknown EMB3D property ids: {sorted(unknown)}")


def threats_for(cur: Cursor, property_ids: list[str], all_threats: bool, has_host: bool) -> list[tuple[str, str]]:
    """The EMB3D threats an assessment plans: the properties' (or all), plus every passive check if there's a host."""
    if all_threats:
        cur.execute("SELECT id, name FROM emb3d_threats WHERE is_current ORDER BY id")
    else:
        cur.execute(THREATS_FOR_PROPERTIES_SQL, (property_ids,))
    threats = [(row[0], row[1]) for row in cur.fetchall()]
    if has_host:
        # The passive checks are connect-only and safe, so a target with an address
        # always gets all of them: the profile ranks findings, it doesn't decide
        # whether the scan looks (otherwise only weaknesses already declared are found).
        planned = {t for t, _ in threats}
        missing = [ref for ref in checks.checks_to_run(planned, True) if ref not in planned]
        if missing:
            cur.execute("SELECT id, name FROM emb3d_threats WHERE id = ANY(%s) ORDER BY id", (missing,))
            threats += [(row[0], row[1]) for row in cur.fetchall()]
    if not threats:
        raise SystemExit("no applicable threats - declare properties with `create --properties`, "
                         "or re-run with --all for full catalogue coverage")
    return threats


def automated(threats: list[tuple[str, str]]) -> list[str]:
    return [ref for ref, _ in threats if ref in PASSIVE_CHECKS]


def create_assessment(cur: Cursor, target_name: str, host: str | None, authorization: str,
                      property_ids: list[str], allow_public: bool = False) -> int:
    cur.execute("""INSERT INTO assessments (target_name, target_host, authz_note, allow_public)
                   VALUES (%s, %s, %s, %s) RETURNING id""", (target_name, host, authorization, allow_public))
    assessment_id = cur.fetchone()[0]
    if property_ids:
        validate_properties(cur, property_ids)
        for pid in property_ids:
            cur.execute("INSERT INTO assessment_properties (assessment_id, property_id) VALUES (%s, %s)",
                        (assessment_id, pid))
    return assessment_id


def insert_planned(cur: Cursor, assessment_id: int, threats: list[tuple[str, str]]) -> int:
    planned = 0
    for ref_id, name in threats:
        activity = "passive" if ref_id in PASSIVE_CHECKS else "active"
        cur.execute("""INSERT INTO findings (assessment_id, source, ref_id, title, activity, status)
                       VALUES (%s, 'emb3d', %s, %s, %s, 'planned')
                       ON CONFLICT (assessment_id, source, ref_id) DO NOTHING""",
                    (assessment_id, ref_id, name, activity))
        planned += cur.rowcount
    return planned


# --------------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------------


def target_for(host: str, allow_public: bool) -> Target:
    """
    Resolve the host once, check it may be scanned, and return the pinned
    target the probes connect to. Same rules as before: the authorized-use
    notice accepted, and a public address only if it was approved.
    """
    safety.require_acknowledgement()
    target = safety.resolve(host)
    if target.public and not allow_public:
        raise SystemExit(f"{host} now resolves to a public address ({', '.join(target.addresses)}), "
                         "which wasn't approved - not scanning it.")
    return target


# --------------------------------------------------------------------------
# Recording
# --------------------------------------------------------------------------


def write_evidence(assessment_id: int, finding_id: int, ref_id: str, text: str) -> Path:
    out_dir = EVIDENCE_DIR / str(assessment_id)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = out_dir / f"{finding_id:04d}_{ref_id}_{stamp}.txt"
    path.write_text(text)
    return path


def update_finding(cur: Cursor, finding_id: int, status: str, detail: str | None,
                   evidence_path: str | None, evidence: str | None = None) -> None:
    cur.execute("UPDATE findings SET status=%s, detail=%s, evidence_path=%s, evidence=%s, updated_at=now() "
                "WHERE id=%s", (status, detail, evidence_path, evidence, finding_id))


def record_results(cur: Cursor, assessment_id: int, results: list[dict], checked_at: datetime | None = None,
                   files: bool = True) -> list[dict]:
    """
    Store probe results on an assessment's planned findings; every other
    planned finding is gated for a person. `results` are checks.run_checks
    output. Returns the rows that ran (ref_id, title, category, status,
    detail, evidence_path). `files` also writes evidence files (local only).
    """
    by_ref = {r["ref_id"]: r for r in results}
    cur.execute("""SELECT f.id, f.ref_id, f.activity, f.title, t.category
                   FROM findings f JOIN emb3d_threats t ON t.id = f.ref_id
                   WHERE f.assessment_id = %s AND f.status = 'planned' ORDER BY f.id""", (assessment_id,))
    ran_rows = []
    for finding_id, ref_id, activity, title, category in cur.fetchall():
        if activity == "passive" and ref_id in PASSIVE_CHECKS:
            result = by_ref.get(ref_id)
            if result is None:
                update_finding(cur, finding_id, "skipped", NO_ADDRESS, None)
                continue
            path = str(write_evidence(assessment_id, finding_id, ref_id, result["evidence"])) if files else None
            update_finding(cur, finding_id, result["status"], result["detail"], path, result["evidence"])
            ran_rows.append({"ref_id": ref_id, "title": title, "category": category, "status": result["status"],
                             "detail": result["detail"], "evidence_path": path})
        else:
            update_finding(cur, finding_id, "awaiting_approval", "Active step - operator must execute and approve.",
                           None)
    cur.execute("UPDATE assessments SET checked_at = %s WHERE id = %s",
                (checked_at or datetime.now(timezone.utc), assessment_id))
    return ran_rows


def record_scan(cur: Cursor, target_name: str, host: str | None, authorization: str, property_ids: list[str],
                threats: list[tuple[str, str]], results: list[dict], checked_at: datetime | None = None,
                profile_id: int | None = None, device_id: int | None = None, allow_public: bool = False,
                files: bool = True) -> dict:
    """Create the assessment for a finished scan and store its results (one transaction)."""
    assessment_id = create_assessment(cur, target_name, host, authorization, property_ids, allow_public)
    cur.execute("UPDATE assessments SET profile_id = %s, device_id = %s WHERE id = %s",
                (profile_id, device_id, assessment_id))
    insert_planned(cur, assessment_id, threats)
    ran_rows = record_results(cur, assessment_id, results, checked_at, files)
    cur.execute("SELECT count(*) FROM findings WHERE assessment_id = %s AND status = 'awaiting_approval'",
                (assessment_id,))
    return {"assessment_id": assessment_id, "total": len(threats), "n_passive": len(automated(threats)),
            "ran_rows": ran_rows, "gated": cur.fetchone()[0],
            "unreachable": any(r["detail"] == UNREACHABLE for r in ran_rows)}


def compare_with_previous(cur: Cursor, previous: int | None, current: int) -> dict:
    def confirmed(assessment_id: int | None) -> set[str]:
        if assessment_id is None:
            return set()
        cur.execute("SELECT ref_id FROM findings WHERE assessment_id = %s AND status = 'confirmed'", (assessment_id,))
        return {r[0] for r in cur.fetchall()}

    now, before = confirmed(current), confirmed(previous)
    return {"confirmed": sorted(now),
            # On a device's first scan everything is "new" - report it as new only from the second scan on.
            "new": sorted(now - before) if previous is not None else [],
            "resolved": sorted(before - now)}


# --------------------------------------------------------------------------
# Local scans: prepare -> probe (no transaction) -> record
# --------------------------------------------------------------------------


def probe(host: str | None, allow_public: bool, refs: list[str], manual: int,
          progress: Progress | None = None) -> tuple[list[dict], datetime]:
    """Run the passive checks (no database involved). Returns (results, when they ran)."""
    started = datetime.now(timezone.utc)
    results = checks.run_checks(target_for(host, allow_public), refs, progress) if host and refs else []
    if not (host and refs):
        _report(progress, type="plan", steps=[])
    _report(progress, type="manual", count=manual)
    return results, started


def scan(database_url: str, target_name: str, host: str | None, authorization: str, property_ids: list[str],
         allow_public: bool = False, profile_store: Callable[[Cursor], int | None] | None = None,
         progress: Progress | None = None) -> dict:
    """A one-off scan (`glitched scan`): plan, probe, then record it all in one transaction."""
    plan: dict = {}

    def prepare(cur: Cursor) -> None:
        if property_ids:
            validate_properties(cur, property_ids)
        plan["threats"] = threats_for(cur, property_ids, all_threats=not property_ids, has_host=bool(host))

    run_in_transaction(database_url, _schema(), prepare)
    refs = automated(plan["threats"]) if host else []
    results, checked_at = probe(host, allow_public, refs, len(plan["threats"]) - len(refs), progress)
    outcome: dict = {}

    def record(cur: Cursor) -> None:
        profile_id = profile_store(cur) if profile_store else None
        outcome.update(record_scan(cur, target_name, host, authorization, property_ids, plan["threats"], results,
                                   checked_at, profile_id=profile_id, allow_public=allow_public))

    run_in_transaction(database_url, _schema(), record)
    return outcome


def scan_device(database_url: str, device_id: int, progress: Progress | None = None) -> dict:
    """
    One passive scan of one registered device, then bring its findings up to
    date. Returns {} if another run is scanning it. Raises SystemExit when the
    safety rules refuse (e.g. its host now resolves to an unapproved public address).
    """
    spec: dict = {}

    def prepare(cur: Cursor) -> None:
        # Claim the device (a claim older than 15 minutes is a crashed run's and can be taken over).
        cur.execute("""UPDATE devices SET scan_started_at = now()
                       WHERE id = %s AND (scan_started_at IS NULL OR scan_started_at < now() - interval '15 minutes')
                       RETURNING name, host, authz_note, profile_id, allow_public""", (device_id,))
        row = cur.fetchone()
        if row is None:
            return  # another run has it (or there's no such device)
        name, host, authz, profile_id, allow_public = row
        property_ids = []
        if profile_id is not None:
            cur.execute("SELECT property_id FROM profile_properties WHERE profile_id = %s", (profile_id,))
            property_ids = [r[0] for r in cur.fetchall()]
        cur.execute("SELECT max(id) FROM assessments WHERE device_id = %s", (device_id,))
        spec.update(name=name, host=host, authz=authz, profile_id=profile_id, allow_public=allow_public,
                    property_ids=property_ids, previous=cur.fetchone()[0],
                    threats=threats_for(cur, property_ids, all_threats=not property_ids, has_host=True))

    run_in_transaction(database_url, _schema(), prepare)
    if not spec:
        return {}
    try:
        refs = automated(spec["threats"])
        results, checked_at = probe(spec["host"], spec["allow_public"], refs, len(spec["threats"]) - len(refs),
                                    progress)
        result: dict = {}

        def record(cur: Cursor) -> None:
            outcome = record_scan(cur, spec["name"], spec["host"], spec["authz"], spec["property_ids"],
                                  spec["threats"], results, checked_at, profile_id=spec["profile_id"],
                                  device_id=device_id, allow_public=spec["allow_public"])
            if outcome["unreachable"]:
                # Not a scan: autoscan tries again next time, and nothing is resolved or reopened.
                cur.execute("UPDATE devices SET last_unreachable_at = now(), scan_started_at = NULL WHERE id = %s",
                            (device_id,))
                result.update(outcome, name=spec["name"], host=spec["host"], findings={}, confirmed=[], new=[],
                              resolved=[])
                return
            cur.execute("UPDATE devices SET last_scanned_at = now(), scan_started_at = NULL WHERE id = %s",
                        (device_id,))
            result.update(outcome, name=spec["name"], host=spec["host"],
                          findings=robot_findings.sync(cur, device_id, database_url),
                          **compare_with_previous(cur, spec["previous"], outcome["assessment_id"]))

        run_in_transaction(database_url, _schema(), record)
        return result
    finally:
        # Whatever happened, release the claim (a no-op if record already did).
        run_in_transaction(database_url, _schema(), lambda cur: cur.execute(
            "UPDATE devices SET scan_started_at = NULL WHERE id = %s", (device_id,)))


def run_assessment(database_url: str, assessment_id: int, progress: Progress | None = None) -> list[dict]:
    """`glitched run`: run an existing assessment's planned passive checks, then record them."""
    spec: dict = {}

    def prepare(cur: Cursor) -> None:
        cur.execute("SELECT target_host, allow_public FROM assessments WHERE id = %s", (assessment_id,))
        row = cur.fetchone()
        if row is None:
            raise SystemExit(f"no assessment {assessment_id}")
        cur.execute("SELECT ref_id, activity FROM findings WHERE assessment_id = %s AND status = 'planned'",
                    (assessment_id,))
        planned = cur.fetchall()
        spec.update(host=row[0], allow_public=row[1],
                    refs=sorted({ref for ref, activity in planned if activity == "passive" and ref in PASSIVE_CHECKS}),
                    total=len(planned))

    run_in_transaction(database_url, _schema(), prepare)
    results, checked_at = probe(spec["host"], spec["allow_public"], spec["refs"], spec["total"] - len(spec["refs"]),
                                progress)
    ran: list[dict] = []
    run_in_transaction(database_url, _schema(), lambda cur: ran.extend(
        record_results(cur, assessment_id, results, checked_at)))
    return ran


def recheck_finding(database_url: str, finding_id: int, progress: Progress | None = None) -> dict[str, Any]:
    """Re-run only the check behind an observed finding: read, probe (no transaction), record."""
    spec: dict = {}
    run_in_transaction(database_url, _schema(), lambda cur: spec.update(robot_findings.recheck_target(cur, finding_id)))
    target = target_for(spec["host"], spec["allow_public"])
    _report(progress, type="start", ref_id=spec["ref_id"])
    result, detail, evidence = PASSIVE_CHECKS[spec["ref_id"]](target, progress=progress)
    out = EVIDENCE_DIR / "rechecks"
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    (out / f"{finding_id:05d}_{spec['ref_id']}_{stamp}.txt").write_text(evidence)
    outcome: dict = {}
    run_in_transaction(database_url, _schema(), lambda cur: outcome.update(
        robot_findings.apply_recheck(cur, finding_id, result, detail, evidence)))
    return outcome

