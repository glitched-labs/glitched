"""
The threat-intel pipelines are a separate, private package (`glitched_pipelines`).

The open-source CLI works without it: it reads whatever database DATABASE_URL points at.
Building or refreshing that database (`setup`, `snapshot`, `exposure --refresh`) needs the package, and
this module is the one place that imports it, so everything else gets the same clear message when it is missing.
"""

from __future__ import annotations

import importlib
from types import ModuleType

PACKAGE = "glitched_pipelines"

MISSING = (
    "This command builds the threat-intel database, which needs the private glitched-pipelines package "
    "(not installed here).\n"
    "To read an existing database instead, point Glitched at it: `glitched config set database_url ...` "
    "or set DATABASE_URL."
)


def load(name: str = "") -> ModuleType:
    """Import glitched_pipelines (or glitched_pipelines.<name>); exit with an explanation if it isn't installed."""
    try:
        package = importlib.import_module(PACKAGE)
    except ModuleNotFoundError as exc:
        if exc.name == PACKAGE:  # the package itself is missing, not one of its dependencies
            raise SystemExit(MISSING) from exc
        raise
    return importlib.import_module(f"{PACKAGE}.{name}") if name else package


def available() -> bool:
    try:
        load()
    except SystemExit:
        return False
    return True
