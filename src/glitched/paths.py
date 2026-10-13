"""
Where Glitched keeps files outside the database.

  data home   scan evidence, generated charts
              $GLITCHED_HOME, else $XDG_DATA_HOME/glitched, else ~/.local/share/glitched
  cache home  dbt build output and logs (safe to delete)
              $XDG_CACHE_HOME/glitched, else ~/.cache/glitched

Nothing is written inside the installed package.
"""

from __future__ import annotations

import os
from pathlib import Path


def data_home() -> Path:
    if os.environ.get("GLITCHED_HOME"):
        return Path(os.environ["GLITCHED_HOME"]).expanduser()
    base = os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"
    return Path(base) / "glitched"


def cache_home() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base) / "glitched"
