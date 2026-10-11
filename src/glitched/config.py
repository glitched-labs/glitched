"""
Settings and secrets.

Each setting is looked up in this order, first match wins:

  1. the environment variable (e.g. NVD_API_KEY)
  2. a `.env` file in the current folder (or a parent folder)
  3. the config file: $GLITCHED_CONFIG, else $XDG_CONFIG_HOME/glitched/config.toml,
     else ~/.config/glitched/config.toml
  4. the built-in default

`glitched config show` lists every setting with where its value came from.
The config file is written readable only by you (0600) because it can hold
API keys, and secret values are never printed.
"""

from __future__ import annotations

import json
import os
import tomllib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True)
class Setting:
    env: str
    help: str
    default: str | None = None
    secret: bool = False


SETTINGS: dict[str, Setting] = {
    "database_url": Setting("DATABASE_URL", "PostgreSQL connection string",
                            default="postgresql://localhost:5432/glitched"),
    "nvd_api_key": Setting("NVD_API_KEY", "NVD API key (optional; ~10x faster NVD loads)", secret=True),
    "anthropic_api_key": Setting("ANTHROPIC_API_KEY", "Anthropic API key (optional; research paper classification)",
                                 secret=True),
    "dbt_command": Setting("DBT_COMMAND", "how to run dbt (default: dbt-core + dbt-postgres via uvx)"),
    "research_dir": Setting("GLITCHED_RESEARCH_DIR", "folder of curated CVE-*.md notes (optional)"),
    "acknowledged": Setting("GLITCHED_ACKNOWLEDGED",
                            "version of the authorized-use notice you accepted (`glitched acknowledge`)"),
}


def config_path() -> Path:
    if os.environ.get("GLITCHED_CONFIG"):
        return Path(os.environ["GLITCHED_CONFIG"]).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base) / "glitched" / "config.toml"


def read_file() -> dict[str, str]:
    path = config_path()
    if not path.exists():
        return {}
    with path.open("rb") as f:
        return {k: str(v) for k, v in tomllib.load(f).items()}


@lru_cache(maxsize=1)
def _dotenv() -> tuple[str | None, dict[str, str]]:
    """(path, values) of the nearest .env file, read once per process."""
    try:
        from dotenv import dotenv_values, find_dotenv
    except ImportError:
        return None, {}
    path = find_dotenv(usecwd=True)
    return (path, {k: v for k, v in dotenv_values(path).items() if v}) if path else (None, {})


def lookup(key: str) -> tuple[str | None, str]:
    """(value, where it came from) for one setting."""
    setting = SETTINGS[key]
    if os.environ.get(setting.env):
        return os.environ[setting.env], f"environment ({setting.env})"
    dotenv_path, dotenv_values = _dotenv()
    if dotenv_values.get(setting.env):
        return dotenv_values[setting.env], f".env ({dotenv_path})"
    file_values = read_file()
    if file_values.get(key):
        return file_values[key], "config file"
    if setting.default is not None:
        return setting.default, "default"
    return None, "not set"


def get(key: str) -> str | None:
    return lookup(key)[0]


def secret(env_name: str) -> str | None:
    """A setting by its environment-variable name (e.g. "NVD_API_KEY")."""
    key = next(k for k, s in SETTINGS.items() if s.env == env_name)
    return get(key)


def display(key: str, value: str | None) -> str:
    """A value safe to print: secrets as set / not set, passwords in URLs hidden."""
    if value is None:
        return "-"
    if SETTINGS[key].secret:
        return "set"
    url = urlparse(value)
    if url.password:
        return value.replace(f":{url.password}@", ":***@")
    return value


def set_value(key: str, value: str) -> Path:
    if key not in SETTINGS:
        raise KeyError(key)
    values = read_file()
    values[key] = value
    return _write(values)


def unset(key: str) -> bool:
    values = read_file()
    if key not in values:
        return False
    del values[key]
    _write(values)
    return True


def _write(values: dict[str, str]) -> Path:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Glitched settings - edit with `glitched config set/unset`.",
             "# This file can hold API keys: keep it private (it's created readable only by you)."]
    # json.dumps produces a valid TOML basic string for any value.
    lines += [f"{key} = {json.dumps(values[key])}" for key in sorted(values)]
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(path, 0o600)  # also tighten a file that already existed
    return path
