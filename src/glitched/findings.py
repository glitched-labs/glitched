"""
A robot's findings: one list per device that persists across scans.

Everything Glitched knows about a registered device becomes a finding of one
of four kinds (see docs/decisions/0001-robot-scan-ui-runs-locally.md):

  observed             a passive check confirmed it (latest scan)
  declared             the device's profile says so (e.g. "debug port reachable")
  known_vulnerability  a CVE matched by platform or component + version
  possible             an EMB3D threat that fits the profile but wasn't tested

`sync()` runs after each scan - the only time findings change; new answers or
a new software list wait for the next scan. It collects what is present and
applies the lifecycle rules in
`plan_sync()` (pure, unit-tested): new -> open; resolved but present again ->
open; fix applied but a newer scan still sees it -> open; gone -> resolved.
Accepted risks and not-applicable are the user's call and never changed by a
scan, except that an accepted risk past its date returns to open.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from psycopg2.extensions import cursor as Cursor

from glitched import catalog
from glitched.device_profile import DeviceProfile
from glitched.queries import get_exposure

KINDS = ("observed", "declared", "known_vulnerability", "possible")
SEVERITIES = ("critical", "high", "medium", "low")
STATUSES = ("open", "fix_applied", "resolved", "accepted_risk", "not_applicable")
USER_STATUSES = ("open", "fix_applied", "accepted_risk", "not_applicable")
ACTIVE = ("open", "fix_applied")  # still a problem

SCHEMA = """
CREATE TABLE IF NOT EXISTS device_findings (
    id SERIAL PRIMARY KEY,
    device_id INT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('observed', 'declared', 'known_vulnerability', 'possible')),
    source TEXT NOT NULL,
    ref_id TEXT NOT NULL,
    part TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT,
    evidence TEXT,
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'fix_applied', 'resolved', 'accepted_risk', 'not_applicable')),
    status_note TEXT,
    accepted_until TIMESTAMPTZ,
    rank REAL NOT NULL DEFAULT 9,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    last_assessment_id INT REFERENCES assessments(id) ON DELETE SET NULL,
    UNIQUE (device_id, source, ref_id)
);

CREATE TABLE IF NOT EXISTS device_finding_events (
    id SERIAL PRIMARY KEY,
    finding_id INT NOT NULL REFERENCES device_findings(id) ON DELETE CASCADE,
    at TIMESTAMPTZ NOT NULL DEFAULT now(),
    from_status TEXT,
    to_status TEXT NOT NULL,
    actor TEXT NOT NULL CHECK (actor IN ('scan', 'recheck', 'sync', 'user')),
    note TEXT
);

-- When a check last looked at an observed finding (scan or recheck), so an
-- older scan never overrides a newer recheck.
ALTER TABLE device_findings ADD COLUMN IF NOT EXISTS last_checked_at TIMESTAMPTZ;
ALTER TABLE device_findings ADD COLUMN IF NOT EXISTS fix TEXT;
ALTER TABLE device_findings ADD COLUMN IF NOT EXISTS severity TEXT;
"""

# EMB3D threat category -> diagram part, for findings that don't say better.
CATEGORY_PART = {
    "networking": "network",
    "hardware": "main_controller",
    "system software": "main_controller",
    "application software": "main_controller",
}


@dataclass
class Item:
    """Something present on the device right now."""

    kind: str
    source: str
    ref_id: str
    part: str
    title: str
    detail: str | None = None
    evidence: str | None = None
    rank: float = 9.0
    fix: str | None = None  # a specific fix, when known (e.g. the version to update to)
    severity: str = "low"
    assessment_id: int | None = None  # observed only: the scan that saw it
    checked_at: datetime | None = None  # observed only: when that scan ran

    @property
    def key(self) -> tuple[str, str]:
        return self.source, self.ref_id


@dataclass
class Existing:
    id: int
    kind: str
    status: str
    last_assessment_id: int | None
    accepted_until: datetime | None = None
    last_checked_at: datetime | None = None


@dataclass
class Plan:
    inserts: list[Item] = field(default_factory=list)
    updates: list[tuple[int, Item]] = field(default_factory=list)  # refresh text/evidence
    transitions: list[tuple[int, str, str, str, str]] = field(default_factory=list)  # id, from, to, actor, note


def plan_sync(existing: dict[tuple[str, str], Existing], present: list[Item],
              checked_absent: dict[tuple[str, str], tuple[int, datetime | None]], now: datetime) -> Plan:
    """
    The lifecycle rules, without a database. `checked_absent` maps an observed
    finding's key to (assessment, when it ran) for a check that said it's not
    present. A scan older than the finding's last check (e.g. a recheck)
    changes nothing.
    """
    plan = Plan()
    seen = set()
    for item in present:
        seen.add(item.key)
        row = existing.get(item.key)
        if row is None:
            plan.inserts.append(item)
            continue
        if item.kind == "observed" and _stale(row, item.checked_at):
            continue
        plan.updates.append((row.id, item))
        new_scan = item.kind == "observed" and item.assessment_id != row.last_assessment_id
        if row.status == "resolved":
            plan.transitions.append((row.id, "resolved", "open", _actor(item), "reappeared"))
        elif row.status == "fix_applied" and new_scan:
            # Only a newer scan can say the fix didn't work; declared and matched
            # findings wait for the profile to change (answer, SBOM version).
            plan.transitions.append((row.id, "fix_applied", "open", _actor(item), "still present"))
        elif row.status == "accepted_risk" and row.accepted_until and row.accepted_until <= now:
            plan.transitions.append((row.id, "accepted_risk", "open", "sync", "accepted risk expired"))

    for key, row in existing.items():
        if key in seen or row.status not in ACTIVE:
            continue
        if row.kind == "observed":
            # Only a check that ran and said "not present" resolves it;
            # inconclusive or not run changes nothing.
            assessment, checked_at = checked_absent.get(key, (None, None))
            if (assessment is not None and assessment != row.last_assessment_id
                    and not _stale(row, checked_at)):
                plan.transitions.append((row.id, row.status, "resolved", "scan", "check passed"))
        else:
            plan.transitions.append((row.id, row.status, "resolved", "sync", "no longer applies"))
    return plan


# Plaintext services that carry robot control or credentials.
_SENSITIVE_PLAINTEXT = ("telnet", "rosbridge", "ros-master", "mqtt")


def observed_severity(ref_id: str, detail: str | None) -> str:
    """How serious a problem a check confirmed is."""
    detail = (detail or "").lower()
    if ref_id == "TID-406":
        return "critical" if "websocket" in detail else "high"  # an open control channel vs open data
    if ref_id == "TID-408":
        return "high" if any(s in detail for s in _SENSITIVE_PLAINTEXT) else "medium"
    return "medium"


def cve_severity(score: float | None, exploited: bool) -> str:
    if exploited or (score is not None and score >= 9):
        return "critical"
    if score is None:
        return "medium"
    return "high" if score >= 7 else "medium" if score >= 4 else "low"


def _stale(row: Existing, checked_at: datetime | None) -> bool:
    return bool(row.last_checked_at and checked_at and checked_at <= row.last_checked_at)


def _actor(item: Item) -> str:
    return "scan" if item.kind == "observed" else "sync"


# --------------------------------------------------------------------------
# Collecting what's present
# --------------------------------------------------------------------------


def latest_check_results(cur: Cursor, device_id: int
                         ) -> tuple[list[Item], dict[tuple[str, str], tuple[int, datetime | None]]]:
    """Observed findings from the device's latest scan, and the checks it passed."""
    cur.execute("SELECT id, coalesce(checked_at, created_at) FROM assessments WHERE device_id = %s "
                "ORDER BY id DESC LIMIT 1", (device_id,))
    row = cur.fetchone()
    if row is None:
        return [], {}
    assessment_id, checked_at = row
    cur.execute(
        "SELECT ref_id, status, detail, evidence, evidence_path FROM findings "
        "WHERE assessment_id = %s AND activity = 'passive' AND status IN ('confirmed', 'not_present')",
        (assessment_id,),
    )
    present, absent = [], {}
    for ref_id, status, detail, evidence_text, evidence_path in cur.fetchall():
        title, part = catalog.CHECK_FINDINGS.get(ref_id, (ref_id, "network"))
        if status == "not_present":
            absent[("check", ref_id)] = (assessment_id, checked_at)
            continue
        evidence = evidence_text or _read(evidence_path)  # older scans kept evidence only in files
        present.append(Item("observed", "check", ref_id, part, title, detail, evidence,
                            rank=0.0, assessment_id=assessment_id, checked_at=checked_at,
                            severity=observed_severity(ref_id, detail)))
    return present, absent


def profile_items(profile: DeviceProfile, database_url: str, checked: set[str]) -> list[Item]:
    """Declared, known-vulnerability and possible findings from the device's profile."""
    items = []
    declared = [pid for pid in profile.properties if pid in catalog.DECLARED_FINDINGS]
    names = _property_names(database_url, declared)
    for pid in declared:
        title, part = catalog.DECLARED_FINDINGS[pid]
        what = names.get(pid, pid)
        items.append(Item("declared", "profile", pid, part, title,
                          detail=f"You described this robot as: {what[0].lower() + what[1:]}.",
                          evidence=f"Device profile: {pid} - {what}", rank=0.5,
                          severity=catalog.DECLARED_SEVERITY.get(pid, "medium")))

    rows = get_exposure(profile.tags, profile.properties, profile.ml, database_url,
                        components=[(c.name, c.version) for c in profile.components],
                        ros_distro=profile.ros_distro)
    categories = _threat_categories(database_url, [r["ref_id"] for r in rows if r["source"] == "emb3d"])
    for r in rows:
        if r["source"] == "cve" and not r["related"]:
            fix = None
            if r.get("component") and r.get("fixed_in"):
                target = (f"a version {r['fixed_in']}" if r["fixed_in"].startswith("newer than")
                          else f"{r['fixed_in']} or later")
                fix = (f"Update {r['component']} to {target}, then update the robot's software list "
                       "(Robot details) so Glitched can confirm it.")
            items.append(Item("known_vulnerability", "cve", r["ref_id"], "main_controller",
                              r.get("summary") or f"Known vulnerability {r['ref_id']}", detail=r["title"],
                              evidence=f"{r['ref_id']} · {r['severity']} - {r['reason']}", rank=r["rank"], fix=fix,
                              severity=cve_severity(r.get("score"), r.get("kev", False))))
        elif r["source"] == "emb3d" and r["ref_id"] not in checked:
            # A threat a check has tested is reported by the check, not as "possible".
            items.append(Item("possible", "emb3d", r["ref_id"],
                              CATEGORY_PART.get(categories.get(r["ref_id"], ""), "whole_robot"),
                              r["title"], detail=r["reason"], evidence=r["severity"], rank=r["rank"],
                              severity="low"))
    return items


def _property_names(database_url: str, ids: list[str]) -> dict[str, str]:
    """EMB3D's wording for each property ("Device includes a debugging capabilities", ...)."""
    if not ids:
        return {}
    from glitched.db import query
    rows = query("SELECT id, name FROM emb3d_properties WHERE id = ANY(%s)", [ids], database_url=database_url)
    return {r["id"]: r["name"] for r in rows}


def _threat_categories(database_url: str, ids: list[str]) -> dict[str, str]:
    if not ids:
        return {}
    from glitched.db import query
    rows = query("SELECT id, category FROM emb3d_threats WHERE id = ANY(%s)", [ids], database_url=database_url)
    return {r["id"]: r["category"] for r in rows}


def _read(path: str | None) -> str | None:
    if not path:
        return None
    try:
        return Path(path).read_text()[:4000]
    except OSError:
        return None


# --------------------------------------------------------------------------
# Applying
# --------------------------------------------------------------------------


def sync(cur: Cursor, device_id: int, database_url: str) -> dict[str, int]:
    """Bring a device's findings up to date (the caller has created the schema). Returns what changed."""
    cur.execute("SELECT p.yaml FROM devices d LEFT JOIN profiles p ON p.id = d.profile_id WHERE d.id = %s",
                (device_id,))
    row = cur.fetchone()
    if row is None:
        raise SystemExit(f"no device {device_id}")
    present, absent = latest_check_results(cur, device_id)
    checked = {ref for _, ref in [*absent, *(i.key for i in present)]}
    if row[0]:
        present += profile_items(DeviceProfile.from_yaml(row[0]), database_url, checked)

    cur.execute("SELECT source, ref_id, id, kind, status, last_assessment_id, accepted_until, last_checked_at "
                "FROM device_findings WHERE device_id = %s", (device_id,))
    existing = {(r[0], r[1]): Existing(*r[2:]) for r in cur.fetchall()}
    plan = plan_sync(existing, present, absent, datetime.now(timezone.utc))

    for item in plan.inserts:
        cur.execute(
            """INSERT INTO device_findings (device_id, kind, source, ref_id, part, title, detail, evidence,
                                            rank, last_assessment_id, last_checked_at, fix, severity)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
            (device_id, item.kind, item.source, item.ref_id, item.part, item.title, item.detail,
             item.evidence, item.rank, item.assessment_id, item.checked_at, item.fix, item.severity),
        )
        _event(cur, cur.fetchone()[0], None, "open", _actor(item), "found")
    for finding_id, item in plan.updates:
        cur.execute(
            """UPDATE device_findings SET kind = %s, part = %s, title = %s, detail = %s,
                      evidence = coalesce(%s, evidence), rank = %s, last_seen_at = now(),
                      last_assessment_id = coalesce(%s, last_assessment_id),
                      last_checked_at = greatest(last_checked_at, %s), fix = %s, severity = %s
               WHERE id = %s""",
            (item.kind, item.part, item.title, item.detail, item.evidence, item.rank,
             item.assessment_id, item.checked_at, item.fix, item.severity, finding_id),
        )
    for finding_id, old, new, actor, note in plan.transitions:
        _set(cur, finding_id, old, new, actor, note)
    return {"new": len(plan.inserts),
            "resolved": sum(1 for t in plan.transitions if t[2] == "resolved"),
            "reopened": sum(1 for t in plan.transitions if t[2] == "open")}


def set_status(cur: Cursor, finding_id: int, status: str, note: str | None = None,
               accept_days: int | None = None) -> None:
    """A user's status change. Accepting a risk needs a reason and expires."""
    if status not in USER_STATUSES:
        raise SystemExit(f"status must be one of: {', '.join(USER_STATUSES)}")
    if status == "accepted_risk" and not note:
        raise SystemExit("accepting a risk needs a reason (--note)")
    cur.execute("SELECT status FROM device_findings WHERE id = %s FOR UPDATE", (finding_id,))
    row = cur.fetchone()
    if row is None:
        raise SystemExit(f"no finding {finding_id}")
    until = (datetime.now(timezone.utc) + timedelta(days=accept_days or 90)
             if status == "accepted_risk" else None)
    cur.execute("UPDATE device_findings SET accepted_until = %s WHERE id = %s", (until, finding_id))
    _set(cur, finding_id, row[0], status, "user", note)


def _set(cur: Cursor, finding_id: int, old: str | None, new: str, actor: str, note: str | None) -> None:
    cur.execute(
        """UPDATE device_findings
           SET status = %s, status_note = %s,
               resolved_at = CASE WHEN %s = 'resolved' THEN now() ELSE NULL END
           WHERE id = %s""",
        (new, note, new, finding_id),
    )
    _event(cur, finding_id, old, new, actor, note)


def _event(cur: Cursor, finding_id: int, old: str | None, new: str, actor: str, note: str | None) -> None:
    cur.execute("INSERT INTO device_finding_events (finding_id, from_status, to_status, actor, note) "
                "VALUES (%s, %s, %s, %s, %s)", (finding_id, old, new, actor, note))


def recheck_target(cur: Cursor, finding_id: int) -> dict[str, Any]:
    """
    What re-running the check behind an observed finding needs: {ref_id,
    host, allow_public}. Read only - nothing is locked while the probe runs.
    Raises SystemExit for findings that aren't rechecked by probing.
    """
    from glitched.checks import PASSIVE_CHECKS

    cur.execute(
        """SELECT f.kind, f.ref_id, d.host, d.allow_public
           FROM device_findings f JOIN devices d ON d.id = f.device_id WHERE f.id = %s""",
        (finding_id,),
    )
    row = cur.fetchone()
    if row is None:
        raise SystemExit(f"no finding {finding_id}")
    kind, ref_id, host, allow_public = row
    if kind != "observed" or ref_id not in PASSIVE_CHECKS:
        raise SystemExit(RECHECK_HELP.get(kind, "only findings a scan observed can be rechecked"))
    return {"ref_id": ref_id, "host": host, "allow_public": allow_public}


def apply_recheck(cur: Cursor, finding_id: int, result: str, detail: str, evidence: str) -> dict[str, Any]:
    """
    Record a recheck's outcome: passed -> resolved; still seen -> open;
    inconclusive -> unchanged. Returns {status, detail, evidence, to_status}.
    """
    cur.execute("SELECT ref_id, status FROM device_findings WHERE id = %s FOR UPDATE", (finding_id,))
    row = cur.fetchone()
    if row is None:
        raise SystemExit(f"no finding {finding_id}")
    ref_id, status = row
    cur.execute("UPDATE device_findings SET detail = %s, evidence = %s, last_checked_at = now(), "
                "severity = coalesce(%s, severity) WHERE id = %s",
                (detail, evidence, observed_severity(ref_id, detail) if result == "confirmed" else None, finding_id))

    to_status = status
    if result == "not_present" and status != "resolved":
        to_status = "resolved"
        _set(cur, finding_id, status, "resolved", "recheck", "check passed")
    elif result == "confirmed" and status in ("fix_applied", "resolved"):
        to_status = "open"
        _set(cur, finding_id, status, "open", "recheck", "still present")
    else:
        _event(cur, finding_id, status, status, "recheck",
               "still present" if result == "confirmed" else "inconclusive - nothing changed")
    return {"status": result, "detail": detail, "evidence": evidence, "to_status": to_status}


RECHECK_HELP = {
    "declared": "this comes from your answers - change the answer in Robot details, then scan again",
    "known_vulnerability": "this comes from a CVE match - update the package, update the robot's software "
                           "list, then scan again",
    "possible": "nothing tests this automatically - verify it by hand, then mark it",
}


def fix_for(cur: Cursor, kind: str, source: str, ref_id: str, specific: str | None = None,
            ros_distro: str | None = None, evidence: str | None = None) -> str:
    """The recommended fix for one finding, in plain language."""
    if specific:
        return specific
    if source == "check" and ref_id in catalog.CHECK_FIXES:
        if ref_id == "TID-406" and ros_distro and re.search(r"\bwss?://", evidence or ""):
            return catalog.ROSBRIDGE_FIXES[catalog.ROS_DISTROS[ros_distro]]  # we know which rosbridge it is
        return catalog.CHECK_FIXES[ref_id]
    if source == "profile" and ref_id in catalog.DECLARED_FIXES:
        return catalog.DECLARED_FIXES[ref_id]
    if source == "cve":
        return ("Update the affected component to a version outside the vulnerable range (see the NVD entry "
                f"for {ref_id}), then update the SBOM. Until then, limit who can reach the robot.")
    cur.execute(
        """SELECT m.name FROM emb3d_mitigation_threats mt JOIN emb3d_mitigations m ON m.id = mt.mitigation_id
           WHERE mt.threat_id = %s AND mt.is_current ORDER BY m.id LIMIT 3""",
        (ref_id,),
    )
    names = [r[0] for r in cur.fetchall()]
    if names:
        return "EMB3D mitigations: " + "; ".join(names) + "."
    return "No specific fix recorded yet - check the EMB3D threat description."


def finding_detail(cur: Cursor, finding_id: int) -> dict[str, Any]:
    """One finding with its fix, what a recheck sends, and its history."""
    cur.execute(
        """SELECT id, device_id, kind, source, ref_id, part, title, detail, evidence, status, status_note,
                  accepted_until, first_seen_at, last_seen_at, last_checked_at, fix AS specific_fix,
                  coalesce(severity, CASE kind WHEN 'observed' THEN 'high' WHEN 'possible' THEN 'low' ELSE 'medium' END) AS severity
           FROM device_findings WHERE id = %s""",
        (finding_id,),
    )
    row = cur.fetchone()
    if row is None:
        raise SystemExit(f"no finding {finding_id}")
    finding = dict(zip([d[0] for d in cur.description], row, strict=True))
    cur.execute("SELECT p.yaml FROM devices d JOIN profiles p ON p.id = d.profile_id WHERE d.id = %s",
                (finding["device_id"],))
    row = cur.fetchone()
    distro = DeviceProfile.from_yaml(row[0]).ros_distro if row else None
    finding["fix"] = fix_for(cur, finding["kind"], finding["source"], finding["ref_id"],
                             finding.pop("specific_fix"), distro, finding["evidence"])
    finding["recheck"] = (catalog.CHECK_ACTIVITY.get(finding["ref_id"]) if finding["kind"] == "observed"
                          else None)
    finding["recheck_help"] = RECHECK_HELP.get(finding["kind"])
    cur.execute("SELECT at, from_status, to_status, actor, note FROM device_finding_events "
                "WHERE finding_id = %s ORDER BY id", (finding_id,))
    finding["history"] = [dict(zip(("at", "from", "to", "actor", "note"), r, strict=True))
                          for r in cur.fetchall()]
    return finding


def scanned(cur: Cursor, device_id: int) -> bool:
    """
    Findings are shown only once a scan has completed: before that, a robot's
    list would be nothing but guesses from its answers and threat intel. A scan
    that couldn't reach the robot doesn't count.
    """
    cur.execute("SELECT last_scanned_at IS NOT NULL FROM devices WHERE id = %s", (device_id,))
    row = cur.fetchone()
    return bool(row and row[0])


def list_findings(cur: Cursor, device_id: int, include_closed: bool = False) -> list[dict[str, Any]]:
    cur.execute(
        """SELECT id, kind, source, ref_id, part, title, detail, evidence, status, status_note,
                  accepted_until, first_seen_at, last_seen_at, coalesce(severity, CASE kind WHEN 'observed' THEN 'high' WHEN 'possible' THEN 'low' ELSE 'medium' END) AS severity
           FROM device_findings
           WHERE device_id = %s AND (%s OR status IN ('open', 'fix_applied'))
           ORDER BY CASE coalesce(severity, CASE kind WHEN 'observed' THEN 'high' WHEN 'possible' THEN 'low' ELSE 'medium' END) WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                    CASE kind WHEN 'observed' THEN 0 WHEN 'declared' THEN 1
                              WHEN 'known_vulnerability' THEN 2 ELSE 3 END, rank, ref_id""",
        (device_id, include_closed),
    )
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r, strict=True)) for r in cur.fetchall()]
