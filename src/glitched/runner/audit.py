"""
The runner's own record of everything it did or refused, kept on the
company's machine: one JSON object per line, each carrying the hash of the
one before, so an edited, removed or reordered entry is detected by
`glitched-runner audit --verify`. Each entry is also printed, so it shows up
in `docker logs` too.
"""

from __future__ import annotations

import hashlib
import json
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64
_lock = threading.Lock()


def _digest(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _last(path: Path) -> tuple[int, str]:
    if not path.exists():
        return 0, GENESIS
    last_line = ""
    with path.open("rb") as handle:
        for line in handle:
            if line.strip():
                last_line = line.decode()
    if not last_line:
        return 0, GENESIS
    entry = json.loads(last_line)
    return entry["seq"], entry["hash"]


class AuditLog:
    def __init__(self, path: Path, echo: bool = True):
        self.path = path
        self.echo = echo

    def record(self, event: str, **detail: Any) -> dict[str, Any]:
        with _lock:
            seq, prev = _last(self.path)
            entry = {"seq": seq + 1, "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                     "event": event, "detail": detail, "prev": prev}
            entry["hash"] = _digest(entry)
            line = json.dumps(entry, sort_keys=True)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a") as handle:
                handle.write(line + "\n")
                handle.flush()
        if self.echo:
            print(f"audit {entry['seq']} {event} {json.dumps(detail, sort_keys=True)}", file=sys.stdout, flush=True)
        return entry

    def entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]

    def verify(self) -> tuple[bool, str]:
        """Check the whole chain. Returns (ok, message)."""
        prev, expected_seq = GENESIS, 1
        try:
            entries = self.entries()
        except json.JSONDecodeError as exc:
            return False, f"a line isn't valid JSON ({exc})"
        for entry in entries:
            if entry.get("seq") != expected_seq:
                return False, f"entry {expected_seq} is missing or out of order (found {entry.get('seq')})"
            if entry.get("prev") != prev:
                return False, f"entry {expected_seq} doesn't follow the one before it"
            if _digest(entry) != entry.get("hash"):
                return False, f"entry {expected_seq} was changed after it was written"
            prev, expected_seq = entry["hash"], expected_seq + 1
        return True, f"{len(entries)} entries, chain intact"
