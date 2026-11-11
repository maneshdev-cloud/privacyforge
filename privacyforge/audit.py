"""Append-only audit log.

Every redaction/warning/block is recorded so you can prove *what
kinds* of data were kept away from an external AI — without the log
itself becoming a leak.  Entries contain only a timestamp, the data
category, the action taken, and the character length of the value.
**Values are never written to the log.**

Entries are kept in memory and, if a path is given, appended as JSON
lines to that file.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone


class AuditLog:
    def __init__(self, path: str | None = None) -> None:
        self.path = path
        self.entries: list[dict] = []

    def record(self, category: str, action: str, value_length: int) -> dict:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "category": category,
            "action": action,
            "value_length": value_length,
        }
        self.entries.append(entry)
        if self.path:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        return entry

    def summary(self) -> dict[str, int]:
        """Counts keyed by ``"CATEGORY:action"``."""
        return dict(Counter(f"{e['category']}:{e['action']}" for e in self.entries))
