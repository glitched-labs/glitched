"""
`glitched setup` and `glitched doctor`: get a new install working, and say
exactly what's wrong when it isn't.

  setup   create the database, load every threat-intel source, then build the
          warehouse with one dbt run (not one per source)
  doctor  check Python, the database, the loaded data and its age, the dbt
          runner, optional API keys and local folders; print a fix for each
          problem and exit 1 if anything is broken
"""

from __future__ import annotations

import argparse
import importlib
import logging
import shlex
import shutil
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import psycopg2
from rich.console import Console
from rich.table import Table

import glitched
from glitched import config
from glitched.config import secret
from glitched.db import safe_url, ensure_database, query
from glitched import intel, safety, ui
from glitched.paths import cache_home, data_home, research_notes_dir

console = Console()

# (label, pipeline module, what it adds) in load order.
SOURCES = [
    ("MITRE ATLAS", "mitre", "attacks on AI systems"),
    ("MITRE EMB3D", "emb3d", "embedded-device threats"),
    ("Curated CVE notes", "research", "hand-written robotics CVEs"),
    ("NVD", "nvd", "CVEs for robot platforms"),
]

# raw schema -> dbt selection that rebuilds what it feeds (for snapshot imports).
SCHEMA_DBT_SELECT = {
    "raw_atlas": ["source:raw_atlas+"],
    "raw_emb3d": ["source:raw_emb3d+"],
    "raw_nvd": ["source:raw_nvd+", "platform_keywords+"],
    "raw_research": ["source:raw_research+", "platform_keywords+"],
    "raw_papers": ["source:raw_papers+"],
    "raw_paper_classifications": ["source:raw_paper_classifications+"],
}

# raw schema -> public tables it feeds, for doctor's data check.
WAREHOUSE = {
    "raw_atlas": ["atlas_techniques"],
    "raw_emb3d": ["emb3d_threats"],
    "raw_research": ["research_cves"],
    "raw_nvd": ["nvd_cves"],
    "raw_papers": ["research_papers"],
}
STALE_AFTER_DAYS = 30


# --------------------------------------------------------------------------
# setup
# --------------------------------------------------------------------------


def cmd_setup(args: argparse.Namespace) -> None:
    if not args.verbose:
        logging.getLogger("glitched").setLevel(logging.WARNING)  # progress below instead

    console.print(f"[bold]Setting up Glitched[/bold] in {safe_url(args.database_url)}\n")
    try:
        ensure_database(args.database_url)
        query("SELECT 1", database_url=args.database_url)
    except psycopg2.OperationalError as exc:
        raise SystemExit(database_help(args.database_url, exc)) from exc
    console.print("[green]✓[/green] Database ready")

    intel.load()  # fail early, with the explanation, if the pipelines aren't installed
    runner = check_dbt_runner()
    if runner.status == "fail":
        raise SystemExit(f"{runner.detail}. {runner.fix}")

    loaded, failed = [], []
    if args.snapshot:
        with console.status(f"Importing snapshot {args.snapshot}…"):
            manifest = intel.load("snapshot").import_(Path(args.snapshot), args.database_url)
        schemas = sorted({t["schema"] for t in manifest["tables"]})
        console.print(f"[green]✓[/green] Snapshot from {manifest['created_at']} "
                      f"(Glitched {manifest['glitched_version']}): {', '.join(schemas)}")
        loaded += [SCHEMA_DBT_SELECT[schema] for schema in schemas]

    sources = [s for s in SOURCES if not (args.skip_nvd and s[1] == "nvd")]
    if args.papers:
        sources.append(("Research papers", "papers", "Hugging Face, arXiv and NVIDIA papers"))
    if args.snapshot and not args.refresh:
        sources = []  # the snapshot is enough; --refresh also fetches anything newer

    for label, module_name, what in sources:
        module = intel.load(module_name)
        started = time.monotonic()
        try:
            with console.status(f"Loading {label} ({what})…"):
                if module_name == "papers":
                    module.run(args.database_url, classify=_can_classify(), classify_limit=args.classify_limit)
                else:
                    module.run(args.database_url)
        except Exception as exc:  # one source failing shouldn't stop the others
            failed.append(label)
            console.print(f"[red]✗[/red] {label}: {exc}")
            continue
        loaded.append(module.DBT_SELECT)
        console.print(f"[green]✓[/green] {label} ({time.monotonic() - started:.0f}s)")

    if loaded:
        select = sorted({selector for selectors in loaded for selector in selectors})
        started = time.monotonic()
        with console.status("Building the warehouse (dbt)…"):
            intel.load("run").run_dbt(select, args.database_url, quiet=not args.verbose)
        console.print(f"[green]✓[/green] Warehouse built and tested ({time.monotonic() - started:.0f}s)")

    console.print()
    print_data_summary(args.database_url)
    if failed:
        raise SystemExit(f"\n{len(failed)} source(s) failed: {', '.join(failed)}. "
                         "Re-run `glitched setup` once the problem above is fixed.")
    console.print("\n[bold]Next:[/bold] `glitched onboard` to describe your device, "
                  "or `glitched doctor` to check everything.")


def _can_classify() -> bool:
    try:
        importlib.import_module("anthropic")
    except ImportError:
        console.print("[yellow]![/yellow] Papers will load unclassified: install the extra "
                      "with `pip install 'glitched-pipelines[papers]'`.")
        return False
    if not secret("ANTHROPIC_API_KEY"):
        console.print("[yellow]![/yellow] Papers will load unclassified: set ANTHROPIC_API_KEY "
                      "(classification costs about $0.03 per paper).")
        return False
    return True


def print_data_summary(database_url: str) -> None:
    table = Table(title="Threat intel loaded", border_style="blue")
    table.add_column("Table")
    table.add_column("Rows", justify="right")
    for tables in WAREHOUSE.values():
        for name in tables:
            table.add_row(name, str(_count(name, database_url) if _exists(name, database_url) else "-"))
    console.print(table)


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------


@dataclass
class Check:
    name: str
    status: str   # ok | warn | fail | info
    detail: str
    fix: str = ""


STATUS_MARK = {"ok": "[green]✓[/green]", "warn": "[yellow]![/yellow]",
               "fail": "[red]✗[/red]", "info": "[dim]i[/dim]"}


def run_checks(database_url: str) -> list[Check]:
    return [
        Check("Glitched", "info", f"version {glitched.__version__}, Python {sys.version.split()[0]}"),
        *check_database(database_url),
        check_dbt_runner(),
        check_acknowledged(),
        check_key("NVD_API_KEY", "NVD searches run about 10x faster with a free key",
                  "Request one at https://nvd.nist.gov/developers/request-an-api-key"),
        check_papers(),
        check_research_notes(),
        check_writable("Data folder", data_home()),
        check_writable("Cache folder", cache_home()),
    ]


def cmd_doctor(args: argparse.Namespace) -> None:
    checks = run_checks(args.database_url)
    for check in checks:
        console.print(f"{STATUS_MARK[check.status]} [bold]{check.name}[/bold]: {check.detail}")
        if check.fix and check.status in ("warn", "fail"):
            console.print(f"    [dim]→ {check.fix}[/dim]")
    failures = [c for c in checks if c.status == "fail"]
    console.print(f"\n{'All good.' if not failures else f'{len(failures)} problem(s) to fix.'}")
    if failures:
        raise SystemExit(1)


def check_database(database_url: str) -> list[Check]:
    try:
        version = query("SHOW server_version", database_url=database_url)[0]["server_version"]
    except psycopg2.OperationalError as exc:
        return [Check("Database", "fail", f"can't connect to {safe_url(database_url)}",
                      database_help(database_url, exc, short=True))]
    checks = [Check("Database", "ok", f"PostgreSQL {version} at {safe_url(database_url)}")]

    for schema, tables in WAREHOUSE.items():
        label = f"Data: {', '.join(tables)}"
        if not _exists(f"{schema}._loads", database_url) or not all(_exists(t, database_url) for t in tables):
            optional = schema in ("raw_papers", "raw_research")
            checks.append(Check(label, "info" if optional else "warn", "not loaded",
                                {"raw_papers": "glitched setup --papers",
                                 "raw_research": "Optional: set research_dir to a folder of CVE notes"}.get(schema, "glitched setup")))
            continue
        loaded_at = query(f"SELECT max(_loaded_at) AS t FROM {schema}._loads", database_url=database_url)[0]["t"]
        age = (datetime.now(timezone.utc) - loaded_at).days
        rows = sum(_count(t, database_url) for t in tables)
        stale = age > STALE_AFTER_DAYS
        checks.append(Check(label, "warn" if stale else "ok",
                            f"{rows} rows, loaded {age} day(s) ago",
                            "Refresh with `glitched setup`" if stale else ""))
    return checks


def check_dbt_runner() -> Check:
    if not intel.available():
        return Check("dbt runner", "warn", "glitched-pipelines isn't installed, so this machine can't build the data",
                     "Fine if you only read an existing database; otherwise install glitched-pipelines")
    custom, source = config.lookup("dbt_command")
    program = shlex.split(intel.load("run").dbt_command())[0]
    if shutil.which(program):
        return Check("dbt runner", "ok", f"`{program}` found" + (f" (dbt_command from {source})" if custom else ""))
    if custom:
        return Check("dbt runner", "fail", f"dbt_command program `{program}` not found ({source})",
                     "Fix dbt_command (`glitched config set dbt_command ...`), or unset it to use uv")
    return Check("dbt runner", "fail", "`uvx` not found (needed to run dbt)",
                 "Install uv: https://docs.astral.sh/uv/getting-started/installation/")


def check_acknowledged() -> Check:
    if safety.is_acknowledged():
        return Check("Authorized-use notice", "ok", "accepted")
    return Check("Authorized-use notice", "warn", "not accepted yet - scans will refuse to run",
                 "Run `glitched acknowledge` (once)")


def check_key(name: str, why: str, fix: str) -> Check:
    if secret(name):
        return Check(name, "ok", "set")
    return Check(name, "info", f"not set (optional - {why})", fix)


def check_papers() -> Check:
    try:
        importlib.import_module("anthropic")
    except ImportError:
        return Check("Paper classification", "info", "not installed (optional)",
                     "pip install 'glitched-pipelines[papers]'")
    if not secret("ANTHROPIC_API_KEY"):
        return Check("Paper classification", "info", "installed; ANTHROPIC_API_KEY not set (optional)",
                     "Set ANTHROPIC_API_KEY to classify research papers")
    return Check("Paper classification", "ok", "installed, ANTHROPIC_API_KEY set")


def check_research_notes() -> Check:
    folder = research_notes_dir()
    if not folder.is_dir():
        return Check("Curated CVE notes", "info", f"none at {folder} (optional)",
                     "Point GLITCHED_RESEARCH_DIR at a folder of CVE-*.md notes")
    return Check("Curated CVE notes", "ok", f"{len(list(folder.glob('CVE-*.md')))} notes in {folder}")


def check_writable(name: str, folder) -> Check:
    try:
        folder.mkdir(parents=True, exist_ok=True)
        probe = folder / ".write-test"
        probe.write_text("ok")
        probe.unlink()
    except OSError as exc:
        return Check(name, "fail", f"{folder} isn't writable ({exc.strerror})",
                     "Set GLITCHED_HOME to a writable folder")
    return Check(name, "ok", str(folder))


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def database_help(database_url: str, exc: Exception, short: bool = False) -> str:
    """A one-line explanation of a connection failure, with a fix."""
    reason = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
    fix = ("Is PostgreSQL running? Start it (macOS: `brew services start postgresql@17`; "
           "Docker: see step 1 of TESTING.md, or run all of Glitched with `docker compose`), "
           "or set DATABASE_URL to point at your database.")
    return fix if short else f"Can't connect to {safe_url(database_url)}: {reason}\n{fix}"


def _exists(relation: str, database_url: str) -> bool:
    return query("SELECT to_regclass(%s) IS NOT NULL AS ok", [relation], database_url=database_url)[0]["ok"]


def _count(table: str, database_url: str) -> int:
    where = " WHERE is_current" if table != "research_papers" else ""
    return query(f"SELECT count(*) AS n FROM {table}{where}", database_url=database_url)[0]["n"]


# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------


def cmd_config_show(args: argparse.Namespace) -> None:
    table = Table(border_style="blue")
    for column in ("Setting", "Value", "From", "Env variable"):
        table.add_column(column)
    for key, setting in config.SETTINGS.items():
        value, source = config.lookup(key)
        table.add_row(key, config.display(key, value), source, setting.env)
    console.print(table)
    console.print(f"[dim]Config file: {config.config_path()}[/dim]")


def cmd_config_set(args: argparse.Namespace) -> None:
    if args.key not in config.SETTINGS:
        raise SystemExit(f"unknown setting {args.key!r}; choose from: {', '.join(config.SETTINGS)}")
    setting = config.SETTINGS[args.key]
    value = args.value
    if value is None:
        # Prompting keeps secrets out of shell history.
        value = ui.password(setting.help) if setting.secret else ui.text(setting.help, required=True)
    path = config.set_value(args.key, value)
    console.print(f"[green]✓[/green] {args.key} = {config.display(args.key, value)}  ({path})")
    winner, source = config.lookup(args.key)
    if source != "config file":
        console.print(f"[yellow]![/yellow] {source} overrides the config file for {args.key}.")


def cmd_config_unset(args: argparse.Namespace) -> None:
    if args.key not in config.SETTINGS:
        raise SystemExit(f"unknown setting {args.key!r}; choose from: {', '.join(config.SETTINGS)}")
    removed = config.unset(args.key)
    console.print(f"[green]✓[/green] {args.key} removed from the config file" if removed
                  else f"{args.key} wasn't in the config file")


def cmd_config_path(args: argparse.Namespace) -> None:
    print(config.config_path())


# --------------------------------------------------------------------------
# snapshot
# --------------------------------------------------------------------------


def cmd_snapshot_export(args: argparse.Namespace) -> None:
    include = tuple(args.include or ())
    if "papers" in include:
        console.print("[yellow]![/yellow] Including research papers: abstracts come from Hugging Face, arXiv "
                      "and NVIDIA, each under its own terms - check them before sharing this file.")
    if "research" in include:
        console.print("[yellow]![/yellow] Including your curated CVE notes - only share with people who should have them.")
    with console.status("Exporting…"):
        manifest = intel.load("snapshot").export(Path(args.path), include, args.database_url)
    table = Table(title=f"Snapshot {args.path}", border_style="blue")
    table.add_column("Table")
    table.add_column("Rows", justify="right")
    for entry in manifest["tables"]:
        table.add_row(f"{entry['schema']}.{entry['table']}", str(entry["rows"]))
    console.print(table)
    if manifest.get("skipped"):
        console.print(f"[yellow]![/yellow] Not loaded here, so not included: {', '.join(manifest['skipped'])}")
    size_mb = Path(args.path).stat().st_size / 1_000_000
    console.print(f"[green]✓[/green] {args.path} ({size_mb:.1f} MB). "
                  f"Testers load it with `glitched setup --snapshot {Path(args.path).name}`.")


def cmd_snapshot_import(args: argparse.Namespace) -> None:
    """Import only (no dbt build) - `glitched setup --snapshot` is usually what you want."""
    manifest = intel.load("snapshot").import_(Path(args.path), args.database_url)
    console.print(f"[green]✓[/green] Imported {len(manifest['tables'])} tables. "
                  "Run `glitched setup --snapshot` instead to also build the warehouse.")


# --------------------------------------------------------------------------
# debug-bundle
# --------------------------------------------------------------------------


def cmd_debug_bundle(args: argparse.Namespace) -> None:
    """
    A .zip a tester can attach to a bug report: versions, doctor's checks,
    settings (secrets hidden) and the end of the dbt log. It contains no device
    addresses, profiles, scan results or evidence - and the tester can read
    every file before sending it.
    """
    import json
    import platform
    import re
    import zipfile
    from datetime import datetime, timezone
    from importlib.metadata import PackageNotFoundError, version

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = Path(args.output or f"glitched-debug-{stamp}.zip")

    def package_version(name: str) -> str:
        try:
            return version(name)
        except PackageNotFoundError:
            return "not installed"

    environment = {
        "glitched": glitched.__version__,
        "python": sys.version,
        "platform": platform.platform(),
        "packages": {name: package_version(name) for name in
                     ["glitched-pipelines", "psycopg2-binary", "rich", "questionary", "anthropic", "matplotlib"]},
    }
    checks = [{"name": c.name, "status": c.status, "detail": c.detail, "fix": c.fix}
              for c in run_checks(args.database_url)]
    settings = {key: {"value": config.display(key, value), "from": source}
                for key, (value, source) in ((k, config.lookup(k)) for k in config.SETTINGS)}

    dbt_log = cache_home() / "dbt" / "logs" / "dbt.log"
    log_tail = ""
    if dbt_log.exists():
        lines = dbt_log.read_text(errors="replace").splitlines()[-300:]
        # Hide anything that looks like a password or key, just in case.
        log_tail = "\n".join(re.sub(r"(?i)(password|passwd|api[_-]?key|token)(\S*\s*[=:]\s*)\S+",
                                     r"\1\2***", line) for line in lines)

    files = {
        "environment.json": json.dumps(environment, indent=2),
        "doctor.json": json.dumps(checks, indent=2),
        "settings.json": json.dumps(settings, indent=2),
        "dbt-log-tail.txt": log_tail or "(no dbt log yet)",
    }
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, text in files.items():
            archive.writestr(name, text)

    console.print(f"[green]✓[/green] Wrote {path}. It contains:")
    for name in files:
        console.print(f"  - {name}")
    console.print("[dim]No device addresses, profiles, scan results or evidence are included. "
                  "Open the .zip to check before you send it.[/dim]")
