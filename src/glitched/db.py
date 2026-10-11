"""Postgres helpers shared by the threat-intel loaders (mitre.py, emb3d.py)."""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from typing import Any

import psycopg2
from psycopg2.extensions import cursor as Cursor
from psycopg2.extras import RealDictCursor, execute_values

from glitched import config

logger = logging.getLogger(__name__)

# Environment, .env, config file or default - see glitched.config.
DATABASE_URL = config.get("database_url")


def ensure_database(database_url: str) -> None:
    """Create the target database if it doesn't already exist."""
    dbname = database_url.rsplit("/", 1)[-1]
    admin_url = database_url.rsplit("/", 1)[0] + "/postgres"

    conn = psycopg2.connect(admin_url)
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (dbname,))
            if cur.fetchone() is None:
                logger.info("creating database %r", dbname)
                cur.execute(f'CREATE DATABASE "{dbname}"')
    finally:
        conn.close()


def upsert(cur: Cursor, sql: str, rows: list[tuple]) -> None:
    if rows:
        execute_values(cur, sql, rows)


def query(
    sql: str,
    params: Sequence[Any] | dict[str, Any] | None = None,
    database_url: str = DATABASE_URL,
) -> list[dict[str, Any]]:
    """
    Run a read-only SQL query and return rows as dicts (column -> value).

    Always pass user/runtime values via `params` (never f-string them into
    `sql`) so psycopg2 parameterizes them and prevents SQL injection, e.g.:

        query("SELECT * FROM emb3d_threats WHERE category = %s", ["hardware"])
        query("SELECT * FROM findings WHERE assessment_id = %(aid)s", {"aid": 1})
    """
    conn = psycopg2.connect(database_url)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def run_in_transaction(database_url: str, schema: str, write: Callable[[Cursor], None]) -> None:
    """Create the schema and run `write` in one transaction (all-or-nothing)."""
    ensure_database(database_url)

    conn = psycopg2.connect(database_url)
    try:
        with conn:  # commits on success, rolls back on exception
            with conn.cursor() as cur:
                cur.execute(schema)
                write(cur)
    finally:
        conn.close()


def safe_url(database_url: str) -> str:
    """Where a database is, for messages and logs: host, port and name - never the user or password.
    Takes a URL or a key=value connection string."""
    try:
        from psycopg2.extensions import parse_dsn

        parts = parse_dsn(database_url)
    except Exception:  # noqa: BLE001 - unparseable: say nothing about it
        return "the database"
    return f"{parts.get('host') or 'localhost'}:{parts.get('port') or 5432}/{parts.get('dbname') or ''}"
