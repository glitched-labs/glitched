"""
What the runner keeps between runs, in its state directory (a volume in the
container): its pairing (console address and token, readable only by the
runner's user), the pause switch, the ids of jobs it has already taken
(replay protection) and when it ran them (the hourly limit).
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

SEEN_KEEP_SECONDS = 7 * 24 * 3600


def default_dir() -> Path:
    if os.environ.get("GLITCHED_RUNNER_STATE"):
        return Path(os.environ["GLITCHED_RUNNER_STATE"])
    return Path.home() / ".local" / "share" / "glitched-runner"


@dataclass
class Pairing:
    console: str
    runner_id: int
    token: str
    allow_http: bool = False


class State:
    def __init__(self, directory: Path):
        self.dir = directory

    # -- pairing ---------------------------------------------------------------

    @property
    def _pairing_path(self) -> Path:
        return self.dir / "pairing.json"

    def save_pairing(self, pairing: Pairing) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self._pairing_path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(pairing.__dict__, handle)
        os.replace(tmp, self._pairing_path)

    def pairing(self) -> Pairing | None:
        try:
            return Pairing(**json.loads(self._pairing_path.read_text()))
        except FileNotFoundError:
            return None

    def forget_pairing(self) -> None:
        self._pairing_path.unlink(missing_ok=True)

    # -- pause switch ----------------------------------------------------------

    @property
    def paused(self) -> bool:
        return (self.dir / "paused").exists()

    def pause(self, reason: str = "") -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "paused").write_text(reason or "paused")

    def resume(self) -> None:
        (self.dir / "paused").unlink(missing_ok=True)

    # -- jobs already taken ----------------------------------------------------

    def _seen(self) -> dict[str, float]:
        try:
            return json.loads((self.dir / "seen.json").read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def take(self, job_id: str) -> bool:
        """Record a job as taken. False if it was taken before (a replay)."""
        now = time.time()
        seen = {k: v for k, v in self._seen().items() if now - v < SEEN_KEEP_SECONDS}
        if job_id in seen:
            return False
        seen[job_id] = now
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.dir / "seen.tmp"
        tmp.write_text(json.dumps(seen))
        os.replace(tmp, self.dir / "seen.json")
        return True

    def jobs_in_last_hour(self) -> int:
        now = time.time()
        return sum(1 for at in self._seen().values() if now - at < 3600)
