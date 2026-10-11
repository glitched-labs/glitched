"""
Glitch assessment agent.

Given a target embedded/robotics device the operator OWNS or is AUTHORIZED to
test, this drives an evidence-collecting security assessment against the threat
catalogue already loaded into Postgres (see emb3d.py / mitre.py):

  1. profile   the operator describes the device - either `onboard` (plain-
               language questions / SBOM / scan -> glitch.yaml, then `scan
               --profile`) or raw EMB3D property ids via `create --properties`.
               Optional: skip it and use `plan --all` for full-catalogue coverage.
  2. plan      the agent selects applicable threats and writes one 'planned'
               finding per threat - either the ones the declared properties
               expose, or (with --all) every threat in the EMB3D catalogue.
  3. run       PASSIVE checks (inspection / recon) run automatically and record
               evidence; ACTIVE checks are NOT executed - they are flipped to
               'awaiting_approval' as tracked work items for the operator.
  4. approve   the operator performs an active step themselves and records the
               outcome + evidence via the CLI.
  5. report    findings are summarised, each tied to its threat ID and evidence.

Design guardrail: the agent never autonomously executes intrusive actions
(moving actuators, writing firmware, sending crafted/malformed traffic). Those
are always operator-driven and human-approved. Passive checks are limited to
non-destructive connect-only recon against the single declared target host.
"""

from __future__ import annotations

import argparse
import importlib
import logging
import time
from pathlib import Path

import psycopg2
import psycopg2.errors
from psycopg2.extensions import cursor as Cursor
from rich.console import Console
from rich.table import Table

import glitched
from glitched import catalog
from glitched import device_profile
from glitched import findings as robot_findings
from glitched import visuals as robot_visuals
from glitched import ui
from glitched.db import DATABASE_URL, run_in_transaction
from glitched.checks import (  # noqa: F401 - re-exported: the checks used to live here
    COMMON_PORTS,
    CheckFn,
    CheckResult,
    HTTP_PROBE_PORTS,
    LOGIN_WORDS,
    NEVER_SENT,
    PASSIVE_CHECKS,
    PASSWORD_FIELD,
    Progress,
    TITLE,
    UNREACHABLE,
    WEAK_TLS_VERSIONS,
    WEBSOCKET_PORTS,
    _encryption,
    _http_probe,
    _port_result,
    _probe_port,
    _probe_ports,
    _read_greeting,
    _report,
    _wants_websocket,
    _websocket_probe,
    check_plaintext_comms,
    check_traffic,
    check_unauthenticated_access,
    check_weak_tls,
    checks_to_run,
    classify_access,
    classify_comms,
    classify_http,
)
from glitched.device_profile import DeviceProfile
from glitched.maintenance import (cmd_config_path, cmd_config_set, cmd_config_show, cmd_config_unset,
                                  cmd_debug_bundle, cmd_doctor, cmd_setup, cmd_snapshot_export,
                                  cmd_snapshot_import,
                                  database_help)
from glitched import safety, scanning, targets
from glitched.scanning import (  # noqa: F401 - the scan helpers used to live here
    EVIDENCE_DIR,
    compare_with_previous as _compare_with_previous,
    create_assessment as _create_assessment,
    scan_device,
    update_finding as _update_finding,
    validate_properties as _validate_properties,
    write_evidence as _write_evidence,
)
from glitched.pipelines import run as pipeline_run
from glitched.queries import THREATS_FOR_PROPERTIES_SQL, get_exposure

logger = logging.getLogger(__name__)
console = Console()

STATUS_STYLE = {
    "confirmed": "bold red",
    "not_present": "green",
    "inconclusive": "yellow",
    "awaiting_approval": "dim",
}

# Threat-intel loaders re-run by `exposure --refresh` (all idempotent).
# Sources `exposure --refresh` reloads (fast ones; NVD and papers run via `setup`).
REFRESH_SOURCES = ("mitre", "emb3d", "research")

VALID_STATUSES = {
    "planned", "awaiting_approval", "confirmed", "not_present",
    "inconclusive", "skipped",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS assessments (
    id SERIAL PRIMARY KEY,
    target_name TEXT NOT NULL,
    target_host TEXT,
    authz_note TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS assessment_properties (
    assessment_id INT REFERENCES assessments(id) ON DELETE CASCADE,
    property_id TEXT REFERENCES emb3d_properties(id),
    PRIMARY KEY (assessment_id, property_id)
);

CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    assessment_id INT REFERENCES assessments(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    ref_id TEXT NOT NULL,
    title TEXT,
    activity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'planned',
    detail TEXT,
    evidence_path TEXT,
    updated_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE (assessment_id, source, ref_id)
);

CREATE TABLE IF NOT EXISTS profiles (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    yaml TEXT NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS profile_properties (
    profile_id INT REFERENCES profiles(id) ON DELETE CASCADE,
    property_id TEXT REFERENCES emb3d_properties(id),
    PRIMARY KEY (profile_id, property_id)
);

-- What each profile has already been shown, so `exposure` can flag NEW items.
CREATE TABLE IF NOT EXISTS exposure_seen (
    profile_id INT REFERENCES profiles(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    ref_id TEXT NOT NULL,
    first_seen TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (profile_id, source, ref_id)
);

ALTER TABLE assessments
    ADD COLUMN IF NOT EXISTS profile_id INT REFERENCES profiles(id) ON DELETE SET NULL;

-- Devices registered for automatic re-scanning (`device add`, `autoscan`).
CREATE TABLE IF NOT EXISTS devices (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    host TEXT NOT NULL,                  -- one host; ranges are refused
    authz_note TEXT NOT NULL,            -- attestation recorded at registration
    profile_id INT REFERENCES profiles(id) ON DELETE SET NULL,
    scan_interval_hours INT NOT NULL DEFAULT 24 CHECK (scan_interval_hours >= 1),
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_scanned_at TIMESTAMPTZ
);

ALTER TABLE assessments
    ADD COLUMN IF NOT EXISTS device_id INT REFERENCES devices(id) ON DELETE SET NULL;

-- Explicit approval to scan a public (non-private) address; see glitched.safety.
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS allow_public BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS allow_public BOOLEAN NOT NULL DEFAULT false;
-- A scan where nothing answered isn't a scan: remembered separately.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_unreachable_at TIMESTAMPTZ;
-- Evidence text kept with the result (files are a local convenience only), and
-- when the probes actually ran - set when a scan's results are recorded.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS evidence TEXT;
ALTER TABLE assessments ADD COLUMN IF NOT EXISTS checked_at TIMESTAMPTZ;
-- A scan in progress claims its device, so overlapping runs never scan it twice
-- (instead of holding a row lock while the robot is probed).
ALTER TABLE devices ADD COLUMN IF NOT EXISTS scan_started_at TIMESTAMPTZ;
""" + robot_findings.SCHEMA + robot_visuals.SCHEMA




# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


AUTHZ_QUESTION = "Authorization attestation (confirm you own or are authorized to test this device)"
HOST_QUESTION = "Target host/IP (isolated lab only, leave blank if none)"

COMMAND_DESCRIPTIONS = {
    "setup": "first run: create the database and load all threat intel",
    "doctor": "check your install and say how to fix anything wrong",
    "onboard": "describe your device and see which vulns affect it",
    "exposure": "re-check what affects your profiled device (flags new items)",
    "scan": "one-shot: create + plan + run, styled summary table",
    "autoscan": "re-scan every registered device that's due (see `device add`)",
    "ui": "open the robot scan UI in your browser",
    "findings": "a registered device's findings, across scans",
    "properties": "list EMB3D device properties",
    "create": "create an assessment",
    "plan": "select applicable threats -> planned findings",
    "run": "run passive checks; gate active steps",
    "approve": "record an operator-executed active step",
    "report": "summarise findings and evidence",
    "posture": "roll findings up into a security-posture summary",
}


def _choose_command() -> str:
    """No subcommand given - show every available command and let the operator pick one."""
    default = "exposure" if device_profile.DEFAULT_PROFILE_PATH.exists() else "onboard"
    return ui.select(
        "What do you want to do?",
        [(f"{name:<11} {desc}", name) for name, desc in COMMAND_DESCRIPTIONS.items()]
        + [("exit", "exit")],
        default=default,
    )


def _choose_assessment(database_url: str) -> int:
    """List existing assessments and let the operator pick one by id."""
    rows: list[tuple] = []

    def read(cur: Cursor) -> None:
        cur.execute(
            "SELECT id, target_name, target_host, created_at FROM assessments ORDER BY id DESC"
        )
        rows.extend(cur.fetchall())

    run_in_transaction(database_url, SCHEMA, read)
    if not rows:
        raise SystemExit("no assessments yet - run `scan` or `create` first")

    return ui.select(
        "Which assessment?",
        [(f"{aid:>3}  {name}  host={host or '-'}  {created:%Y-%m-%d}", aid)
         for aid, name, host, created in rows],
    )


def _choose_finding(database_url: str, assessment_id: int) -> int:
    """List findings awaiting approval for an assessment and let the operator pick one."""
    rows: list[tuple] = []

    def read(cur: Cursor) -> None:
        cur.execute(
            "SELECT id, ref_id, title FROM findings "
            "WHERE assessment_id = %s AND status = 'awaiting_approval' ORDER BY id",
            (assessment_id,),
        )
        rows.extend(cur.fetchall())

    run_in_transaction(database_url, SCHEMA, read)
    if not rows:
        raise SystemExit(f"no findings awaiting approval in assessment {assessment_id}")

    return ui.select(
        "Which finding?",
        [(f"{ref_id:<9} {title}", fid) for fid, ref_id, title in rows],
    )


def cmd_properties(args: argparse.Namespace) -> None:
    """List EMB3D device properties the operator can declare for a target."""

    def read(cur: Cursor) -> None:
        cur.execute(
            "SELECT id, category, name FROM emb3d_properties WHERE is_current ORDER BY category, id"
        )
        for pid, category, name in cur.fetchall():
            print(f"{pid:<10} [{category or '-'}] {name}")

    run_in_transaction(args.database_url, SCHEMA, read)


def _plan_threats(cur: Cursor, assessment_id: int, all_threats: bool) -> tuple[int, int, int]:
    """Returns (newly_planned, total_applicable, n_passive)."""
    cur.execute("SELECT property_id FROM assessment_properties WHERE assessment_id = %s", (assessment_id,))
    property_ids = [row[0] for row in cur.fetchall()]
    cur.execute("SELECT target_host FROM assessments WHERE id = %s", (assessment_id,))
    threats = scanning.threats_for(cur, property_ids, all_threats, has_host=bool(cur.fetchone()[0]))
    planned = scanning.insert_planned(cur, assessment_id, threats)
    return planned, len(threats), len(scanning.automated(threats))


def _prompt_for_target_config(args: argparse.Namespace, properties_question: str) -> None:
    """
    Interactively fill in target-name/host/authorization/properties - but only
    if the command was invoked fully bare (no target/host/authorization/
    properties flags given at all). If any one of them was passed, this is
    scripted/partial usage: prompt for nothing, just enforce the two hard
    requirements with a clear error instead of hanging on stdin.
    """
    interactive = (
        args.target_name is None and args.host is None
        and args.authorization is None and not args.properties
    )
    if not interactive:
        if not args.target_name:
            raise SystemExit("--target-name is required")
        if not args.authorization:
            raise SystemExit("--authorization is required")
        return

    args.target_name = ui.text("Target name", required=True)
    args.host = ui.text(HOST_QUESTION) or None
    args.authorization = ui.text(AUTHZ_QUESTION, required=True)

    if ui.confirm(properties_question, default=True):
        return  # leave args.properties as "" - unscoped / --all coverage

    properties: list[tuple] = []

    def read(cur: Cursor) -> None:
        cur.execute("SELECT id, category, name FROM emb3d_properties WHERE is_current ORDER BY category, id")
        properties.extend(cur.fetchall())

    run_in_transaction(args.database_url, SCHEMA, read)
    picked = ui.checkbox(
        "Which EMB3D properties does the device have?",
        [(f"{pid:<10} [{category or '-'}] {name}", pid) for pid, category, name in properties],
    )
    args.properties = ",".join(picked)


def _approve_host(args: argparse.Namespace) -> bool:
    """Acknowledgement + public-address check for a command that targets args.host."""
    if not args.host:
        return False
    safety.require_acknowledgement()
    return safety.approve_target(args.host, args.allow_public)


def cmd_create(args: argparse.Namespace) -> None:
    """Create an assessment with an explicit authorization attestation."""
    _prompt_for_target_config(
        args, "Leave properties unscoped for now? (use `plan --all` later)"
    )
    property_ids = [p.strip() for p in args.properties.split(",") if p.strip()]
    allow_public = _approve_host(args)

    def write(cur: Cursor) -> None:
        assessment_id = _create_assessment(cur, args.target_name, args.host, args.authorization,
                                           property_ids, allow_public)
        print(f"created assessment {assessment_id} for {args.target_name!r} "
              f"({len(property_ids)} properties)")

    run_in_transaction(args.database_url, SCHEMA, write)


def cmd_plan(args: argparse.Namespace) -> None:
    """
    Select applicable threats and write planned findings.

    Default: threats linked to the assessment's declared EMB3D properties.
    --all: every threat in the EMB3D catalogue, regardless of declared
    properties - use this for full coverage when you haven't mapped the
    device's properties (or don't want to guess them up front).
    """
    interactive = args.assessment_id is None
    if interactive:
        args.assessment_id = _choose_assessment(args.database_url)
    if interactive and not args.all:
        args.all = ui.confirm("Plan every threat in the catalogue (--all)?", default=True)

    def write(cur: Cursor) -> None:
        planned, total, n_passive = _plan_threats(cur, args.assessment_id, args.all)
        print(f"planned {planned} new finding(s) across {total} applicable threat(s) "
              f"({n_passive} passive / {total - n_passive} active)")

    run_in_transaction(args.database_url, SCHEMA, write)


def cmd_run(args: argparse.Namespace) -> None:
    """Run passive checks automatically; flag active findings for approval."""
    if args.assessment_id is None:
        args.assessment_id = _choose_assessment(args.database_url)

    ran_rows = scanning.run_assessment(args.database_url, args.assessment_id)
    for row in ran_rows:
        print(f"  [{row['ref_id']}] {row['status']}: {row['detail']}")

    def count(cur: Cursor) -> None:
        cur.execute("SELECT count(*) FROM findings WHERE assessment_id = %s AND status = 'awaiting_approval'",
                    (args.assessment_id,))
        print(f"ran {len(ran_rows)} passive check(s); {cur.fetchone()[0]} active finding(s) awaiting approval")

    run_in_transaction(args.database_url, SCHEMA, count)


def cmd_scan(args: argparse.Namespace) -> None:
    """One-shot: create + plan --all + run, with a styled summary table.

    With --profile, plans only the threats the device profile exposes."""
    profile = None
    bare = args.target_name is None and args.host is None and args.authorization is None
    if (args.profile is None and not args.properties and bare
            and device_profile.DEFAULT_PROFILE_PATH.exists()
            and ui.confirm(f"Scope the scan to your device profile "
                           f"({device_profile.DEFAULT_PROFILE_PATH})?", default=True)):
        args.profile = str(device_profile.DEFAULT_PROFILE_PATH)
    if args.profile:
        profile = device_profile.load(Path(args.profile))
        args.target_name = args.target_name or profile.name
        args.properties = ",".join(profile.properties)
        if args.host is None:
            args.host = ui.text(HOST_QUESTION) or None
        if not args.authorization:
            args.authorization = ui.text(AUTHZ_QUESTION, required=True)
    _prompt_for_target_config(args, "Scan the full EMB3D catalogue (81 threats)?")
    property_ids = [p.strip() for p in args.properties.split(",") if p.strip()]
    allow_public = _approve_host(args)
    started = time.monotonic()
    state: dict = {}

    state.update(scanning.scan(
        args.database_url, args.target_name, args.host, args.authorization, property_ids, allow_public=allow_public,
        profile_store=(lambda cur: _store_profile(cur, profile)) if profile is not None else None))
    console.print(f"[green]✓[/green] Assessment created (id {state['assessment_id']})")
    console.print(
        f"[green]✓[/green] {state['total']} threats planned "
        f"({state['n_passive']} automatable, {state['total'] - state['n_passive']} manual)"
    )
    console.print("[green]✓[/green] Passive checks run")

    assessment_id = state["assessment_id"]
    evidence_dir = EVIDENCE_DIR / str(assessment_id)
    console.print(f"[green]✓[/green] Results saved to {evidence_dir}/")
    console.print()

    table = Table(border_style="blue")
    table.add_column("TID")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Status")
    table.add_column("Detail")
    for row in state["ran_rows"]:
        style = STATUS_STYLE.get(row["status"], "")
        table.add_row(
            row["ref_id"], row["title"], row["category"] or "-",
            f"[{style}]{row['status']}[/{style}]", row["detail"] or "",
        )
    console.print(table)
    if state.get("unreachable"):
        console.print(f"\n[yellow]![/yellow] Nothing answered at {args.host} - is the device switched on, and is "
                      "that the right address? The results above say nothing about its security.")

    elapsed = time.monotonic() - started
    console.print(
        f"\n[dim]i[/dim] Scan completed in {elapsed:.2f}s — {state['gated']} threats need "
        f"manual review, see: glitched report {assessment_id}"
    )


def cmd_approve(args: argparse.Namespace) -> None:
    """Record the outcome of an operator-executed active step."""
    interactive = args.finding_id is None
    if interactive:
        assessment_id = _choose_assessment(args.database_url)
        args.finding_id = _choose_finding(args.database_url, assessment_id)
    if interactive and args.status is None:
        args.status = ui.select("Outcome", [(s, s) for s in sorted(VALID_STATUSES)],
                                default="confirmed")
    if interactive and args.detail is None:
        args.detail = ui.text("Detail (what did you observe?)") or None
    if interactive and args.evidence is None:
        args.evidence = ui.path("Evidence text or path to an artifact file (optional)") or None
    if args.status not in VALID_STATUSES:
        raise SystemExit(f"status must be one of {sorted(VALID_STATUSES)}")

    def write(cur: Cursor) -> None:
        cur.execute("SELECT assessment_id, ref_id FROM findings WHERE id = %s", (args.finding_id,))
        row = cur.fetchone()
        if row is None:
            raise SystemExit(f"no finding {args.finding_id}")
        assessment_id, ref_id = row

        evidence_path = None
        if args.evidence:
            text = Path(args.evidence).read_text() if Path(args.evidence).exists() else args.evidence
            evidence_path = str(_write_evidence(assessment_id, args.finding_id, ref_id, text))

        _update_finding(cur, args.finding_id, args.status, args.detail, evidence_path)
        print(f"finding {args.finding_id} [{ref_id}] -> {args.status}")

    run_in_transaction(args.database_url, SCHEMA, write)


def cmd_report(args: argparse.Namespace) -> None:
    """Summarise findings and evidence for an assessment."""
    if args.assessment_id is None:
        args.assessment_id = _choose_assessment(args.database_url)

    def read(cur: Cursor) -> None:
        cur.execute(
            "SELECT target_name, target_host, authz_note, created_at "
            "FROM assessments WHERE id = %s",
            (args.assessment_id,),
        )
        head = cur.fetchone()
        if head is None:
            raise SystemExit(f"no assessment {args.assessment_id}")
        name, host, authz, created = head

        print(f"Assessment {args.assessment_id}: {name}  host={host or '-'}  {created:%Y-%m-%d}")
        print(f"Authorization: {authz}")
        print("-" * 72)

        cur.execute(
            "SELECT status, count(*) FROM findings WHERE assessment_id = %s GROUP BY status",
            (args.assessment_id,),
        )
        counts = dict(cur.fetchall())
        print("Status: " + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "no findings")
        print("-" * 72)

        cur.execute(
            "SELECT ref_id, title, activity, status, detail, evidence_path "
            "FROM findings WHERE assessment_id = %s ORDER BY status, ref_id",
            (args.assessment_id,),
        )
        for ref_id, title, activity, status, detail, evidence_path in cur.fetchall():
            print(f"[{status:<17}] {ref_id:<9} ({activity}) {title}")
            if detail:
                print(f"    {detail}")
            if evidence_path:
                print(f"    evidence: {evidence_path}")

    run_in_transaction(args.database_url, SCHEMA, read)


def cmd_posture(args: argparse.Namespace) -> None:
    """
    Roll an assessment's findings up into a security-posture summary.

    Posture is reported honestly: threats still 'awaiting_approval' (not yet
    manually verified) count as unreviewed, NOT as safe. A target is only
    "clean" when everything planned has been assessed and nothing confirmed.
    """
    if args.assessment_id is None:
        args.assessment_id = _choose_assessment(args.database_url)
    state: dict = {}

    def read(cur: Cursor) -> None:
        cur.execute(
            "SELECT target_name, target_host, created_at FROM assessments WHERE id = %s",
            (args.assessment_id,),
        )
        head = cur.fetchone()
        if head is None:
            raise SystemExit(f"no assessment {args.assessment_id}")

        cur.execute(
            "SELECT status, count(*) FROM findings WHERE assessment_id = %s GROUP BY status",
            (args.assessment_id,),
        )
        counts = dict(cur.fetchall())

        # Confirmed risks, by EMB3D category, worst-covered first.
        cur.execute(
            """
            SELECT COALESCE(t.category, 'unknown') AS category, count(*) AS n
            FROM findings f
            LEFT JOIN emb3d_threats t ON t.id = f.ref_id
            WHERE f.assessment_id = %s AND f.status = 'confirmed'
            GROUP BY 1 ORDER BY 2 DESC
            """,
            (args.assessment_id,),
        )
        state["confirmed_by_category"] = cur.fetchall()
        state["head"] = head
        state["counts"] = counts

    run_in_transaction(args.database_url, SCHEMA, read)

    name, host, created = state["head"]
    counts = state["counts"]
    total = sum(counts.values())
    confirmed = counts.get("confirmed", 0)
    clean = counts.get("not_present", 0)
    inconclusive = counts.get("inconclusive", 0)
    unreviewed = counts.get("awaiting_approval", 0) + counts.get("planned", 0)
    assessed = confirmed + clean + inconclusive

    if total == 0:
        raise SystemExit(f"assessment {args.assessment_id} has no findings - run `plan` then `run` first")

    coverage = assessed / total
    if confirmed > 0:
        grade, grade_style = "AT RISK", "bold red"
    elif unreviewed > 0:
        grade, grade_style = "INCOMPLETE", "yellow"
    else:
        grade, grade_style = "CLEAN", "green"

    console.print(f"\n[bold]Security posture[/bold] - assessment {args.assessment_id}: "
                  f"{name}  host={host or '-'}  {created:%Y-%m-%d}")
    console.print(f"Grade: [{grade_style}]{grade}[/{grade_style}]   "
                  f"coverage {coverage:.0%} ({assessed}/{total} threats assessed)\n")

    table = Table(border_style="blue")
    table.add_column("Posture signal")
    table.add_column("Count", justify="right")
    table.add_row("[bold red]Confirmed risks[/bold red]", str(confirmed))
    table.add_row("[green]Clean (not present)[/green]", str(clean))
    table.add_row("[yellow]Inconclusive[/yellow]", str(inconclusive))
    table.add_row("[dim]Unreviewed (needs manual verification)[/dim]", str(unreviewed))
    console.print(table)

    if state["confirmed_by_category"]:
        console.print("\n[bold red]Confirmed risks by category:[/bold red]")
        for category, n in state["confirmed_by_category"]:
            console.print(f"  {n}  {category}")

    if unreviewed:
        console.print(f"\n[dim]i[/dim] {unreviewed} threats are not yet verified - this posture is "
                      f"partial. Work through them with: glitched approve")


# --------------------------------------------------------------------------
# Onboarding: device profile -> "what affects me"
# --------------------------------------------------------------------------

EXPOSURE_STYLE = {"cve": "bold red", "emb3d": "", "paper": "cyan", "atlas": "magenta"}


def _store_profile(cur: Cursor, profile: DeviceProfile) -> int:
    """Upsert the profile snapshot (keyed by name) and its EMB3D properties."""
    if profile.properties:
        _validate_properties(cur, profile.properties)
    cur.execute(
        """
        INSERT INTO profiles (name, yaml) VALUES (%s, %s)
        ON CONFLICT (name) DO UPDATE SET yaml = EXCLUDED.yaml, updated_at = now()
        RETURNING id
        """,
        (profile.name, profile.to_yaml()),
    )
    profile_id = cur.fetchone()[0]
    cur.execute("DELETE FROM profile_properties WHERE profile_id = %s", (profile_id,))
    for pid in profile.properties:
        cur.execute(
            "INSERT INTO profile_properties (profile_id, property_id) VALUES (%s, %s)",
            (profile_id, pid),
        )
    return profile_id


def _save_profile(profile: DeviceProfile, path: Path, database_url: str) -> int:
    """Write glitch.yaml and store the DB snapshot. Returns the profile id."""
    state: dict = {}

    def write(cur: Cursor) -> None:
        state["profile_id"] = _store_profile(cur, profile)

    run_in_transaction(database_url, SCHEMA, write)
    device_profile.save(profile, path)
    console.print(f"[green]✓[/green] Profile saved to {path}")
    return state["profile_id"]


def _load_or_new_profile(path: Path, name: str | None) -> DeviceProfile:
    if path.exists():
        return device_profile.load(path)
    if not name:
        name = ui.text("Device name (e.g. warehouse-amr-v3)", required=True)
    return DeviceProfile(name=name)


def _show_exposure(profile: DeviceProfile, profile_id: int, database_url: str, limit: int,
                   related: bool = False) -> None:
    """Print the ranked 'affects you' table, flagging anything not shown before."""
    rows = get_exposure(profile.tags, profile.properties, profile.ml, database_url,
                        components=[(c.name, c.version) for c in profile.components],
                        ros_distro=profile.ros_distro)
    # CVEs that only share an interface with the device are other products' bugs.
    hidden = [] if related else [r for r in rows if r["related"]]
    rows = [r for r in rows if r not in hidden]
    state: dict = {}

    def write(cur: Cursor) -> None:
        cur.execute("SELECT source, ref_id FROM exposure_seen WHERE profile_id = %s", (profile_id,))
        seen = set(cur.fetchall())
        # First check is a baseline - flagging everything NEW would be noise.
        state["new"] = {(r["source"], r["ref_id"]) for r in rows} - seen if seen else set()
        for r in rows:
            cur.execute(
                "INSERT INTO exposure_seen (profile_id, source, ref_id) VALUES (%s, %s, %s) "
                "ON CONFLICT DO NOTHING",
                (profile_id, r["source"], r["ref_id"]),
            )
        state["first"] = not seen

    run_in_transaction(database_url, SCHEMA, write)
    new = state["new"]

    console.print(f"\n[bold]What affects {profile.name}[/bold]  "
                  f"tags: {', '.join(profile.tags) or '-'}  "
                  f"properties: {len(profile.properties)}")
    if not rows:
        console.print("Nothing matched. Add more detail with `onboard`, "
                      "`profile import-sbom` or `profile detect`.")
        return

    counts = {s: sum(1 for r in rows if r["source"] == s) for s in ("cve", "emb3d", "paper", "atlas")}
    console.print(f"{counts['cve']} real-world CVEs · {counts['emb3d']} EMB3D device threats · "
                  f"{counts['paper']} research papers · "
                  f"{counts['atlas']} most-used ATLAS ML techniques"
                  + (f" · [bold green]{len(new)} new since last check[/bold green]" if new else ""))

    shown = sorted(rows, key=lambda r: ((r["source"], r["ref_id"]) not in new, r["rank"]))
    if limit:
        shown = shown[:limit]

    table = Table(border_style="blue")
    table.add_column("")
    table.add_column("ID", no_wrap=True)
    table.add_column("Title", max_width=48, overflow="ellipsis", no_wrap=True)
    table.add_column("Severity")
    table.add_column("Why it applies")
    for r in shown:
        style = EXPOSURE_STYLE[r["source"]]
        if r["source"] == "emb3d" and r["rank"] <= 1:
            style = "red"
        marker = "[bold green]NEW[/bold green]" if (r["source"], r["ref_id"]) in new else ""
        table.add_row(marker, f"[{style}]{r['ref_id']}[/{style}]" if style else r["ref_id"],
                      r["title"], r["severity"], r["reason"])
    console.print(table)

    if len(shown) < len(rows):
        console.print(f"[dim]… {len(rows) - len(shown)} more - use --limit 0 to show all[/dim]")
    if hidden:
        console.print(f"[dim]i {len(hidden)} CVEs that only might apply aren't shown (other products that share a "
                      "keyword, ROS packages not in your SBOM) - --related lists them, each with why.[/dim]")
    if "ros" in profile.platforms and not profile.ros_distro:
        console.print("[dim]i Set the robot's ROS distro (ros_distro: humble in glitch.yaml, or onboard again) to see "
                      "which core ROS vulnerabilities apply.[/dim]")
    if counts["cve"]:
        console.print("[dim]i CVEs match on the platform, or on an SBOM component and version in NVD's "
                      "affected ranges.[/dim]")
    if not profile.components:
        console.print("[dim]i Import an SBOM (`glitched profile import-sbom`) to check your software's "
                      "components against known CVEs.[/dim]")
    if state["first"]:
        console.print("[dim]i First check for this profile - later runs will flag what's new.[/dim]")
    console.print("[dim]i Verify these on a lab device: glitched scan --profile glitch.yaml[/dim]")


def _detect(host: str, authorization: str, name: str, allow_public: bool = False) -> DeviceProfile:
    """Connect-only probe of one declared host; operator confirms each suggestion."""
    safety.require_acknowledgement()
    safety.approve_target(host, allow_public)
    console.print(f"Probing {host} (connect-only; authorization: {authorization})")
    ports = sorted(set(COMMON_PORTS) | set(catalog.PORT_HINTS))
    probes = [_probe_port(host, port) for port in ports]
    accepted = DeviceProfile(name=name)
    suggestions = device_profile.from_probes(probes, name)
    if not suggestions:
        console.print("No open ports found - nothing to suggest.")
    if suggestions:
        picked = ui.checkbox(
            "Add these to the profile?",
            [(f"{reason} → {', '.join(s.tags + s.properties)}", i)
             for i, (reason, s) in enumerate(suggestions)],
            checked=range(len(suggestions)),
        )
        for i in picked:
            accepted = accepted.merge(suggestions[i][1])
    return accepted


def _ask_detect_target(args: argparse.Namespace) -> None:
    if not args.host:
        args.host = ui.text("Device host/IP (isolated lab only)", required=True)
    if not args.authorization:
        args.authorization = ui.text(AUTHZ_QUESTION, required=True)


def cmd_onboard(args: argparse.Namespace) -> None:
    """Describe a device once (questions, SBOM, scan) and see what affects it."""
    path = Path(args.profile)
    profile = _load_or_new_profile(path, args.name)
    if path.exists():
        console.print(f"Adding to existing profile [bold]{profile.name}[/bold] from {path}")

    console.print("\n[bold]Tell us about your device[/bold] - plain answers, no security jargon needed.")
    profile = profile.merge(device_profile.from_questionnaire(profile.name))

    sbom = ui.path("Path to an SBOM (CycloneDX or SPDX JSON) - Tab completes, blank to skip")
    if sbom:
        profile = profile.merge(device_profile.from_sbom(Path(sbom), profile.name))

    if ui.confirm("Detect services from a device on your network?", default=False):
        _ask_detect_target(args)
        profile = profile.merge(_detect(args.host, args.authorization, profile.name, args.allow_public))

    profile_id = _save_profile(profile, path, args.database_url)
    _show_exposure(profile, profile_id, args.database_url, args.limit, related=args.related)


def cmd_profile_import_sbom(args: argparse.Namespace) -> None:
    """Merge an SBOM's components and inferred tags into the profile."""
    path = Path(args.profile)
    profile = _load_or_new_profile(path, args.name or Path(args.sbom).stem)
    before = set(profile.tags) | set(profile.properties)
    profile = profile.merge(device_profile.from_sbom(Path(args.sbom), profile.name))
    added = sorted((set(profile.tags) | set(profile.properties)) - before)
    console.print(f"{len(profile.components)} components; added: {', '.join(added) or 'nothing new'}")
    _save_profile(profile, path, args.database_url)


def cmd_profile_detect(args: argparse.Namespace) -> None:
    """Suggest profile additions from a connect-only scan of one declared host."""
    path = Path(args.profile)
    profile = _load_or_new_profile(path, args.name)
    _ask_detect_target(args)
    detected = _detect(args.host, args.authorization, profile.name, args.allow_public)
    if not (detected.tags or detected.properties):
        console.print("Nothing accepted - profile unchanged.")
        return
    _save_profile(profile.merge(detected), path, args.database_url)


def cmd_exposure(args: argparse.Namespace) -> None:
    """Show what affects a profiled device, flagging anything new since last check."""
    if args.refresh:
        select: set[str] = set()
        for name in REFRESH_SOURCES:
            module = importlib.import_module(f"glitched.pipelines.{name}")
            with console.status(f"Refreshing threat intel: {name}…"):
                module.run(args.database_url)
            select.update(module.DBT_SELECT)
        with console.status("Rebuilding the warehouse (dbt)…"):
            pipeline_run.run_dbt(sorted(select), args.database_url, quiet=True)
    profile = device_profile.load(Path(args.profile))

    state: dict = {}

    def write(cur: Cursor) -> None:
        state["profile_id"] = _store_profile(cur, profile)

    run_in_transaction(args.database_url, SCHEMA, write)
    _show_exposure(profile, state["profile_id"], args.database_url, args.limit, related=args.related)


# --------------------------------------------------------------------------
# Device registry + automatic re-scanning
# --------------------------------------------------------------------------
#
# `device add` records a device you own or are authorized to test, with its
# authorization attestation. `autoscan` then re-scans every device that's due -
# passive, connect-only checks against that one host; active steps are still
# only gated for operator approval - and reports what changed since the
# device's previous scan. Run `autoscan` from cron / launchd to make it automatic.


def _validate_single_host(host: str) -> str:
    """Autoscan targets exactly one declared host: refuse CIDR ranges, lists, wildcards and IP ranges."""
    try:
        return targets.validate_single_host(host)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None


def cmd_device_add(args: argparse.Namespace) -> None:
    """Register a device for automatic re-scanning."""
    name = args.name or ui.text("Device name", required=True)
    host = _validate_single_host(args.host or ui.text("Device host/IP (isolated lab only)", required=True))
    authorization = args.authorization or ui.text(AUTHZ_QUESTION, required=True)
    profile = device_profile.load(Path(args.profile)) if args.profile else None
    safety.require_acknowledgement()
    allow_public = safety.approve_target(host, args.allow_public)

    def write(cur: Cursor) -> None:
        profile_id = _store_profile(cur, profile) if profile is not None else None
        cur.execute(
            """
            INSERT INTO devices (name, host, authz_note, profile_id, scan_interval_hours, allow_public)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (name) DO UPDATE
                SET host = EXCLUDED.host, authz_note = EXCLUDED.authz_note,
                    profile_id = EXCLUDED.profile_id, scan_interval_hours = EXCLUDED.scan_interval_hours,
                    allow_public = EXCLUDED.allow_public, enabled = true
            """,
            (name, host, authorization, profile_id, args.every, allow_public),
        )

    run_in_transaction(args.database_url, SCHEMA, write)
    scope = f"profile {profile.name} ({len(profile.properties)} properties)" if profile else "full EMB3D catalogue"
    console.print(f"[green]✓[/green] {name} ({host}) will be scanned every {args.every}h, scope: {scope}")
    console.print("[dim]i Scans run when you call `autoscan` - schedule it with cron/launchd (see README).[/dim]")


def cmd_device_list(args: argparse.Namespace) -> None:
    rows: list[tuple] = []

    def read(cur: Cursor) -> None:
        cur.execute(
            """
            SELECT d.name, d.host, d.scan_interval_hours, d.enabled, d.last_scanned_at, p.name,
                   (SELECT count(*) FROM findings f
                    WHERE f.assessment_id = (SELECT max(id) FROM assessments a WHERE a.device_id = d.id)
                      AND f.status = 'confirmed')
            FROM devices d LEFT JOIN profiles p ON p.id = d.profile_id
            ORDER BY d.name
            """
        )
        rows.extend(cur.fetchall())

    run_in_transaction(args.database_url, SCHEMA, read)
    if not rows:
        console.print("No devices registered - add one with `device add`.")
        return
    table = Table(border_style="blue")
    for column in ("Device", "Host", "Every", "Enabled", "Last scanned", "Profile", "Confirmed"):
        table.add_column(column)
    for name, host, every, enabled, last, profile, confirmed in rows:
        table.add_row(name, host, f"{every}h", "yes" if enabled else "[yellow]paused[/yellow]",
                      f"{last:%Y-%m-%d %H:%M}" if last else "never", profile or "-",
                      f"[bold red]{confirmed}[/bold red]" if confirmed else "0")
    console.print(table)


def _set_device(args: argparse.Namespace, sql: str, done: str) -> None:
    def write(cur: Cursor) -> None:
        cur.execute(sql, (args.name,))
        if cur.rowcount == 0:
            raise SystemExit(f"no device named {args.name!r}")

    run_in_transaction(args.database_url, SCHEMA, write)
    console.print(f"[green]✓[/green] {args.name} {done}")


def cmd_device_remove(args: argparse.Namespace) -> None:
    # Past assessments are kept (their device_id is cleared).
    _set_device(args, "DELETE FROM devices WHERE name = %s", "removed")


def cmd_device_pause(args: argparse.Namespace) -> None:
    _set_device(args, "UPDATE devices SET enabled = false WHERE name = %s", "paused")


def cmd_device_resume(args: argparse.Namespace) -> None:
    _set_device(args, "UPDATE devices SET enabled = true WHERE name = %s", "resumed")


def cmd_autoscan(args: argparse.Namespace) -> None:
    """
    Scan every enabled device whose interval has passed (or the named ones,
    with --device; or all, with --force). Exits 1 if any scan found a newly
    confirmed issue, so a scheduler can alert on it.
    """
    ids: list[int] = []

    def due(cur: Cursor) -> None:
        cur.execute(
            """
            SELECT id FROM devices
            WHERE enabled
              AND (%(names)s::text[] IS NULL OR name = ANY(%(names)s))
              AND (%(force)s OR last_scanned_at IS NULL
                   OR last_scanned_at <= now() - make_interval(hours => scan_interval_hours))
            ORDER BY last_scanned_at NULLS FIRST, name
            """,
            {"names": args.device or None, "force": args.force or bool(args.device)},
        )
        ids.extend(r[0] for r in cur.fetchall())

    safety.require_acknowledgement()  # never prompts when unattended - refuses instead
    run_in_transaction(args.database_url, SCHEMA, due)
    if not ids:
        console.print("No devices due for a scan.")
        return

    new_issues = 0
    for device_id in ids:
        try:
            result = scan_device(args.database_url, device_id)
        except SystemExit as exc:  # e.g. the host now resolves to an unapproved public address
            console.print(f"[yellow]![/yellow] Skipped device {device_id}: {exc.code}")
            continue
        if not result:
            console.print(f"[yellow]![/yellow] Skipped device {device_id}: another scan of it is still running")
            continue
        if result["unreachable"]:
            console.print(f"\n[yellow]![/yellow] [bold]{result['name']}[/bold]: couldn't reach {result['host']} - "
                          "is it switched on, and is that the right address? Not counted as a scan.")
            continue
        new_issues += len(result["new"])
        console.print(f"\n[bold]{result['name']}[/bold] ({result['host']}) - assessment {result['assessment_id']}: "
                      f"{len(result['confirmed'])} confirmed, {result['gated']} awaiting manual review")
        for ref_id in result["new"]:
            console.print(f"  [bold red]NEW[/bold red]   {ref_id} confirmed since the last scan")
        for ref_id in result["resolved"]:
            console.print(f"  [green]FIXED[/green] {ref_id} no longer confirmed")

    if new_issues:
        raise SystemExit(1)


def scan_plan(cur: Cursor, device_id: int) -> dict:
    """
    Exactly what scanning this device would send, before anything is sent:
    the address it resolves to, and each passive check its profile selects.
    """
    cur.execute("SELECT name, host, profile_id, allow_public FROM devices WHERE id = %s", (device_id,))
    row = cur.fetchone()
    if row is None:
        raise SystemExit(f"no device {device_id}")
    name, host, profile_id, allow_public = row
    cur.execute("SELECT property_id FROM profile_properties WHERE profile_id = %s", (profile_id,))
    property_ids = [r[0] for r in cur.fetchall()]
    if property_ids:
        cur.execute(THREATS_FOR_PROPERTIES_SQL, (property_ids,))
    else:
        cur.execute("SELECT id FROM emb3d_threats WHERE is_current")
    threats = {r[0] for r in cur.fetchall()}
    traffic = check_traffic()
    checks = [{"ref_id": ref, "title": catalog.CHECK_FINDINGS.get(ref, (ref, ""))[0], "sends": traffic[ref]}
              for ref in checks_to_run(threats, has_host=bool(host))]
    target = safety.resolve(host)
    return {
        "name": name, "host": host, "addresses": list(target.addresses),
        "public": target.public, "approved_public": allow_public,
        "refused": target.public and not allow_public,
        "checks": checks, "manual": len(threats - PASSIVE_CHECKS.keys()),
        "never": list(NEVER_SENT),
    }


def cmd_device_plan(args: argparse.Namespace) -> None:
    """What `autoscan --device NAME` would send, without sending anything."""
    state: dict = {}

    def read(cur: Cursor) -> None:
        device_id, _ = _device_id(cur, args.name)
        state.update(scan_plan(cur, device_id))

    run_in_transaction(args.database_url, SCHEMA, read)
    plan = state
    console.print(f"\n[bold]Scanning {plan['name']}[/bold] contacts only {plan['host']} "
                  f"({', '.join(plan['addresses'])}).")
    if plan["refused"]:
        console.print("[yellow]![/yellow] That's a public address that wasn't approved - a scan would refuse to run.")
    if not plan["checks"]:
        console.print("Its profile selects no passive checks, so a scan sends nothing; "
                      f"{plan['manual']} threats are listed for you to check by hand.")
    for check in plan["checks"]:
        console.print(f"\n[bold]{check['title']}[/bold] ({check['ref_id']})\n  {check['sends']}")
    console.print("\n[bold]Never sent[/bold]")
    for line in plan["never"]:
        console.print(f"  - {line}")


# --------------------------------------------------------------------------
# A device's findings (one list per robot, across scans; see glitched.findings)
# --------------------------------------------------------------------------

KIND_LABEL = {"observed": "Observed", "declared": "Declared", "known_vulnerability": "Known vuln",
              "possible": "Possible"}
FINDING_STATUS_STYLE = {"open": "bold red", "fix_applied": "yellow", "resolved": "green",
                        "accepted_risk": "dim", "not_applicable": "dim"}


def _device_id(cur: Cursor, name: str | None) -> tuple[int, str]:
    if name is None:
        cur.execute("SELECT id, name FROM devices ORDER BY name")
        rows = cur.fetchall()
        if not rows:
            raise SystemExit("no devices yet - register one with `glitched device add`")
        if len(rows) > 1:
            raise SystemExit("which device? " + ", ".join(r[1] for r in rows))
        return rows[0]
    cur.execute("SELECT id, name FROM devices WHERE name = %s", (name,))
    row = cur.fetchone()
    if row is None:
        raise SystemExit(f"no device named {name!r} - see `glitched device list`")
    return row


def cmd_findings(args: argparse.Namespace) -> None:
    """A device's findings: brought up to date, then listed most urgent first."""
    state: dict = {}

    def write(cur: Cursor) -> None:
        device_id, name = _device_id(cur, args.device)
        state["name"] = name
        state["scanned"] = robot_findings.scanned(cur, device_id)
        if state["scanned"]:  # findings change only when a scan runs
            state["rows"] = robot_findings.list_findings(cur, device_id, include_closed=args.all)

    run_in_transaction(args.database_url, SCHEMA, write)
    if not state["scanned"]:
        console.print(f"{state['name']} hasn't been scanned yet - findings appear after its first scan.\n"
                      f"See what a scan sends: glitched device plan {state['name']}\n"
                      f"Scan it:              glitched autoscan --device {state['name']}")
        return
    rows = state["rows"]
    console.print(f"\n[bold]Findings for {state['name']}[/bold]  [dim](as of its last scan)[/dim]")
    if not rows:
        console.print("Nothing open." if not args.all else "No findings yet - scan the device or add a profile.")
        return
    counts = {kind: sum(1 for r in rows if r["kind"] == kind) for kind in KIND_LABEL}
    console.print(" · ".join(f"{n} {KIND_LABEL[kind].lower()}" for kind, n in counts.items()))
    shown = rows[:args.limit] if args.limit else rows
    table = Table(border_style="blue")
    for column in ("ID", "Status", "How we know", "Part", "Finding", "Ref"):
        table.add_column(column, no_wrap=column != "Finding")
    for r in shown:
        style = FINDING_STATUS_STYLE[r["status"]]
        table.add_row(str(r["id"]), f"[{style}]{r['status'].replace('_', ' ')}[/{style}]",
                      KIND_LABEL[r["kind"]], r["part"].replace("_", " "), r["title"], r["ref_id"])
    console.print(table)
    if len(shown) < len(rows):
        console.print(f"[dim]… {len(rows) - len(shown)} more - use --limit 0 to show all[/dim]")
    console.print("[dim]i Observed = a scan saw it · Declared = your answers · Known vuln = CVE match · "
                  "Possible = fits your profile, not tested[/dim]")
    console.print("[dim]i Change one: glitched findings set <ID> fix_applied | accepted_risk --note ... | "
                  "not_applicable | open[/dim]")


def cmd_findings_set(args: argparse.Namespace) -> None:
    def write(cur: Cursor) -> None:
        robot_findings.set_status(cur, args.finding_id, args.status, args.note, args.days)

    run_in_transaction(args.database_url, SCHEMA, write)
    console.print(f"[green]✓[/green] Finding {args.finding_id}: {args.status.replace('_', ' ')}")


def cmd_ui(args: argparse.Namespace) -> None:
    """Serve the robot scan UI on 127.0.0.1 (see glitched.web)."""
    from glitched import web

    run_in_transaction(args.database_url, SCHEMA, lambda cur: None)  # fail early if the database isn't there
    web.serve(args.database_url, port=args.port, open_browser=not args.no_browser)


def cmd_findings_recheck(args: argparse.Namespace) -> None:
    state: dict = {}

    def activity(cur: Cursor) -> None:
        cur.execute("SELECT ref_id FROM device_findings WHERE id = %s", (args.finding_id,))
        row = cur.fetchone()
        if row:
            console.print(f"[dim]{catalog.CHECK_ACTIVITY.get(row[0], 'Rechecking…')}[/dim]")

    run_in_transaction(args.database_url, SCHEMA, activity)
    state.update(scanning.recheck_finding(args.database_url, args.finding_id))
    style = FINDING_STATUS_STYLE[state["to_status"]]
    console.print(f"Check: {state['status'].replace('_', ' ')} - {state['detail']}")
    console.print(f"Finding {args.finding_id}: [{style}]{state['to_status'].replace('_', ' ')}[/{style}]")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Every command and option (also read by glitched.cli_docs to write docs/cli-reference.md)."""
    parser = argparse.ArgumentParser(prog="glitched", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--database-url", default=DATABASE_URL,
                        help="PostgreSQL to use (default: the DATABASE_URL setting - see `glitched config show`)")
    parser.add_argument("-v", "--verbose", action="store_true", help="show debug logging")
    parser.add_argument("--version", action="version", version=f"glitched {glitched.__version__}")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("setup", help="create the database and load all threat intel (run once, re-run to refresh)")
    p.add_argument("--skip-nvd", action="store_true", help="skip NVD (it takes about a minute without an API key)")
    p.add_argument("--papers", action="store_true",
                   help="also load research papers (classification needs the [papers] extra and ANTHROPIC_API_KEY)")
    p.add_argument("--classify-limit", type=int, default=None, help="classify at most this many new papers")
    p.add_argument("--snapshot", default=None, metavar="FILE",
                   help="start from a snapshot (glitched snapshot export) instead of downloading")
    p.add_argument("--refresh", action="store_true", help="with --snapshot: also fetch anything newer")
    p.set_defaults(func=cmd_setup)

    p = sub.add_parser("snapshot", help="export or import a threat-intel snapshot to share with others")
    snapshot_sub = p.add_subparsers(dest="snapshot_command", required=True)
    pp = snapshot_sub.add_parser("export", help="write the raw threat intel (ATLAS, EMB3D, NVD) to a .zip")
    pp.add_argument("path", help="the .zip to write")
    pp.add_argument("--include", action="append", choices=["research", "papers"],
                    help="also include your curated CVE notes and/or research papers (repeatable)")
    pp.set_defaults(func=cmd_snapshot_export)
    pp = snapshot_sub.add_parser("import", help="load a snapshot's raw tables (use `setup --snapshot` to also build)")
    pp.add_argument("path", help="the .zip to load (from `glitched snapshot export`)")
    pp.set_defaults(func=cmd_snapshot_import)

    sub.add_parser("doctor", help="check the install; exit 1 if something is broken").set_defaults(func=cmd_doctor)
    p = sub.add_parser("debug-bundle", help="write a .zip of versions, checks and settings (no device data) "
                                             "to attach to a bug report")
    p.add_argument("--output", default=None, help="file to write (default glitched-debug-<time>.zip)")
    p.set_defaults(func=cmd_debug_bundle)
    sub.add_parser("acknowledge", help="read and accept the authorized-use notice (needed once before scanning)"
                   ).set_defaults(func=lambda args: safety.acknowledge())

    p = sub.add_parser("config", help="show or change settings (database, API keys, ...)")
    config_sub = p.add_subparsers(dest="config_command", required=True)
    config_sub.add_parser("show", help="every setting, its value (secrets hidden) and where it came from"
                          ).set_defaults(func=cmd_config_show)
    pp = config_sub.add_parser("set", help="save a setting to the config file; omit VALUE to be prompted (hidden for keys)")
    pp.add_argument("key", help="the setting, e.g. nvd_api_key (see `glitched config show`)")
    pp.add_argument("value", nargs="?", default=None, help="its value; omit to be prompted")
    pp.set_defaults(func=cmd_config_set)
    pp = config_sub.add_parser("unset", help="remove a setting from the config file")
    pp.add_argument("key", help="the setting, e.g. nvd_api_key (see `glitched config show`)")
    pp.set_defaults(func=cmd_config_unset)
    config_sub.add_parser("path", help="print the config file's location").set_defaults(func=cmd_config_path)

    sub.add_parser("properties", help="list EMB3D device properties").set_defaults(func=cmd_properties)

    profile_help = f"device profile file (default: {device_profile.DEFAULT_PROFILE_PATH})"
    limit_help = "max rows to show (0 = all)"

    p = sub.add_parser("onboard", help="describe your device (questions, SBOM, scan) "
                                        "and see which vulns affect it")
    p.add_argument("--profile", default=str(device_profile.DEFAULT_PROFILE_PATH), help=profile_help)
    p.add_argument("--name", default=None, help="device name; omit to be prompted")
    p.add_argument("--host", default=None, help="for optional scan-detect; omit to be prompted")
    p.add_argument("--authorization", default=None, help="for optional scan-detect; omit to be prompted")
    p.add_argument("--limit", type=int, default=25, help=limit_help)
    p.add_argument("--related", action="store_true",
                   help="also list CVEs in other products that share an interface (wifi, mqtt, ...)")
    p.add_argument("--allow-public", action="store_true",
                   help="allow a public (non-private) address; you must be authorized to test it")
    p.set_defaults(func=cmd_onboard)

    p = sub.add_parser("exposure", help="what affects your profiled device; flags new items")
    p.add_argument("--profile", default=str(device_profile.DEFAULT_PROFILE_PATH), help=profile_help)
    p.add_argument("--refresh", action="store_true", help="re-run the threat-intel loaders first")
    p.add_argument("--limit", type=int, default=25, help=limit_help)
    p.add_argument("--related", action="store_true",
                   help="also list CVEs in other products that share an interface (wifi, mqtt, ...)")
    p.set_defaults(func=cmd_exposure)

    p = sub.add_parser("profile", help="add to a device profile from an SBOM or a scan")
    profile_sub = p.add_subparsers(dest="profile_command", required=True)
    pp = profile_sub.add_parser("import-sbom", help="merge an SBOM (CycloneDX/SPDX JSON) or a package list "
                                                    "(dpkg-query -W, dpkg -l, pip freeze, ros2 pkg list) into the profile")
    pp.add_argument("sbom", help="the SBOM or package-list file")
    pp.add_argument("--profile", default=str(device_profile.DEFAULT_PROFILE_PATH), help=profile_help)
    pp.add_argument("--name", default=None, help="device name if creating a new profile")
    pp.set_defaults(func=cmd_profile_import_sbom)
    pp = profile_sub.add_parser("detect", help="suggest additions from a connect-only scan of one host")
    pp.add_argument("--host", default=None, help="isolated lab host; omit to be prompted")
    pp.add_argument("--authorization", default=None, help="omit to be prompted")
    pp.add_argument("--profile", default=str(device_profile.DEFAULT_PROFILE_PATH), help=profile_help)
    pp.add_argument("--name", default=None, help="device name if creating a new profile")
    pp.add_argument("--allow-public", action="store_true",
                   help="allow a public (non-private) address; you must be authorized to test it")
    pp.set_defaults(func=cmd_profile_detect)

    p = sub.add_parser("create", help="create an assessment "
                                       "(prompts interactively for anything not passed as a flag)")
    p.add_argument("--target-name", default=None, help="omit to be prompted")
    p.add_argument("--host", default=None, help="target IP/hostname (isolated lab only); omit to be prompted")
    p.add_argument("--authorization", default=None,
                   help="attestation that you own or are authorized to test this device; omit to be prompted")
    p.add_argument("--properties", default="", help="comma-separated EMB3D property ids (PID-...)")
    p.add_argument("--allow-public", action="store_true",
                   help="allow a public (non-private) address; you must be authorized to test it")
    p.set_defaults(func=cmd_create)

    p = sub.add_parser("scan", help="one-shot: create + plan + run, styled summary table "
                                     "(prompts interactively for anything not passed as a flag)")
    p.add_argument("--target-name", default=None, help="omit to be prompted")
    p.add_argument("--host", default=None, help="target IP/hostname (isolated lab only); omit to be prompted")
    p.add_argument("--authorization", default=None,
                   help="attestation that you own or are authorized to test this device; omit to be prompted")
    p.add_argument("--properties", default="",
                   help="comma-separated EMB3D property ids; omit for an interactive choice")
    p.add_argument("--profile", default=None,
                   help="glitch.yaml - scope the scan to the threats this device profile exposes")
    p.add_argument("--allow-public", action="store_true",
                   help="allow a public (non-private) address; you must be authorized to test it")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("device", help="register devices for automatic re-scanning")
    device_sub = p.add_subparsers(dest="device_command", required=True)
    pp = device_sub.add_parser("add", help="register (or update) a device you own or are authorized to test")
    pp.add_argument("--name", default=None, help="omit to be prompted")
    pp.add_argument("--host", default=None, help="one IP/hostname on an isolated lab network; omit to be prompted")
    pp.add_argument("--authorization", default=None, help=AUTHZ_QUESTION + "; omit to be prompted")
    pp.add_argument("--profile", default=None, help="glitch.yaml - scope scans to this device profile")
    pp.add_argument("--every", type=int, default=24, help="hours between scans (default 24)")
    pp.add_argument("--allow-public", action="store_true",
                   help="allow a public (non-private) address; you must be authorized to test it")
    pp.set_defaults(func=cmd_device_add)
    device_sub.add_parser("list", help="registered devices and their latest results").set_defaults(func=cmd_device_list)
    pp = device_sub.add_parser("plan", help="show exactly what scanning a device would send (sends nothing)")
    pp.add_argument("name", help="the device's name (see `glitched device list`)")
    pp.set_defaults(func=cmd_device_plan)
    for action, func, help_text in [("remove", cmd_device_remove, "stop tracking a device (past scans are kept)"),
                                    ("pause", cmd_device_pause, "skip a device in autoscan"),
                                    ("resume", cmd_device_resume, "include a paused device again")]:
        pp = device_sub.add_parser(action, help=help_text)
        pp.add_argument("name", help="the device's name (see `glitched device list`)")
        pp.set_defaults(func=func)

    p = sub.add_parser("findings", help="a registered device's findings, across scans")
    p.set_defaults(func=cmd_findings, device=None, all=False, limit=25)  # bare `findings` = `findings list`
    findings_sub = p.add_subparsers(dest="findings_command")
    pp = findings_sub.add_parser("list", help="bring a device's findings up to date and list them")
    pp.add_argument("device", nargs="?", default=None, help="device name (optional if there's only one)")
    pp.add_argument("--all", action="store_true", help="include resolved, accepted and not-applicable findings")
    pp.add_argument("--limit", type=int, default=25, help="max rows to show (0 = all)")
    pp.set_defaults(func=cmd_findings)
    pp = findings_sub.add_parser("recheck", help="re-run only the check behind an observed finding")
    pp.add_argument("finding_id", type=int, help="the finding's id (see `glitched findings list`)")
    pp.set_defaults(func=cmd_findings_recheck)
    pp = findings_sub.add_parser("set", help="change a finding's status")
    pp.add_argument("finding_id", type=int, help="the finding's id (see `glitched findings list`)")
    pp.add_argument("status", choices=robot_findings.USER_STATUSES)
    pp.add_argument("--note", default=None, help="why (required for accepted_risk)")
    pp.add_argument("--days", type=int, default=None, help="accepted_risk: ask again after this many days (90)")
    pp.set_defaults(func=cmd_findings_set)


    p = sub.add_parser("ui", help="open the robot scan UI in your browser (runs on this computer only)")
    p.add_argument("--port", type=int, default=0, help="port on 127.0.0.1 (default: any free port)")
    p.add_argument("--no-browser", action="store_true", help="print the link instead of opening a browser")
    p.set_defaults(func=cmd_ui)

    p = sub.add_parser("autoscan", help="re-scan every registered device that's due; "
                                         "exit code 1 if a new issue was confirmed")
    p.add_argument("--device", action="append", default=None, help="scan only this device now (repeatable)")
    p.add_argument("--force", action="store_true", help="scan every enabled device now, due or not")
    p.set_defaults(func=cmd_autoscan)

    p = sub.add_parser("plan", help="select applicable threats -> planned findings "
                                     "(prompts for assessment id if omitted)")
    p.add_argument("assessment_id", type=int, nargs="?", default=None, help="the assessment's id; omit to be asked")
    p.add_argument("--all", action="store_true",
                   help="plan every EMB3D threat, not just ones tied to declared properties")
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("run", help="run passive checks; gate active steps "
                                    "(prompts for assessment id if omitted)")
    p.add_argument("assessment_id", type=int, nargs="?", default=None, help="the assessment's id; omit to be asked")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("approve", help="record an operator-executed active step "
                                        "(prompts interactively for anything not passed as a flag)")
    p.add_argument("finding_id", type=int, nargs="?", default=None, help="the finding's id; omit to be asked")
    p.add_argument("--status", default=None, help=f"one of {sorted(VALID_STATUSES)}")
    p.add_argument("--detail", default=None, help="what you did and saw, in a sentence or two")
    p.add_argument("--evidence", default=None, help="evidence text or path to an artifact file")
    p.set_defaults(func=cmd_approve)

    p = sub.add_parser("report", help="summarise findings and evidence "
                                       "(prompts for assessment id if omitted)")
    p.add_argument("assessment_id", type=int, nargs="?", default=None, help="the assessment's id; omit to be asked")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("posture", help="roll findings up into a security-posture summary "
                                        "(prompts for assessment id if omitted)")
    p.add_argument("assessment_id", type=int, nargs="?", default=None, help="the assessment's id; omit to be asked")
    p.set_defaults(func=cmd_posture)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(message)s")

    if args.command is not None:
        _run_friendly(args.func, args)
        return

    # No command: keep showing the menu until the operator picks exit.
    console.print("[bold]Glitch[/bold] - robotics & IoT security\n")
    while (command := _choose_command()) != "exit":
        chosen = parser.parse_args([command])
        chosen.database_url = args.database_url
        chosen.verbose = args.verbose
        try:
            _run_friendly(chosen.func, chosen)
        except SystemExit as exc:
            if exc.code == "cancelled":
                continue
            if exc.code not in (None, 0):
                console.print(f"[yellow]{exc.code}[/yellow]")
        console.print()


def _run_friendly(func, args: argparse.Namespace) -> None:
    """Turn the common failures into one-line explanations instead of tracebacks."""
    try:
        func(args)
    except psycopg2.OperationalError as exc:
        raise SystemExit(database_help(args.database_url, exc)) from None
    except psycopg2.errors.UndefinedTable as exc:
        table = str(exc).split('"')[1] if '"' in str(exc) else "a table"
        raise SystemExit(f"{table} doesn't exist yet - run `glitched setup` first.") from None
    except KeyboardInterrupt:
        raise SystemExit("cancelled") from None
    except EOFError:
        # A question with no terminal to answer it (cron, pipes, `docker compose run -T`).
        raise SystemExit("This needs an answer but there's no terminal to ask in - run it interactively, "
                         "or pass the answers as flags (see --help).") from None


if __name__ == "__main__":
    main()
