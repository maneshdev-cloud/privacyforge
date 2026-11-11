"""Configurable privacy policies.

A policy decides what happens to each category of sensitive data:

* ``redact`` — replace with a vault token (default; reversible).
* ``block``  — refuse to process the text at all.
* ``warn``   — let the value through, but record a warning + audit entry.
* ``allow``  — let the value through silently (audit still notes it).

Policies are plain data: build them in code, from a dict, or from a
JSON file, e.g.::

    {"rules": {"CARD": "block", "EMAIL": "redact"}, "default_action": "warn"}
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

ACTIONS = ("redact", "block", "warn", "allow")


@dataclass
class Policy:
    rules: dict[str, str] = field(default_factory=dict)
    default_action: str = "redact"

    def __post_init__(self) -> None:
        if self.default_action not in ACTIONS:
            raise ValueError(f"unknown default_action: {self.default_action!r}")
        for category, action in self.rules.items():
            if action not in ACTIONS:
                raise ValueError(f"unknown action for {category}: {action!r}")

    def action_for(self, category: str) -> str:
        return self.rules.get(category, self.default_action)

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        return cls(
            rules=dict(data.get("rules", {})),
            default_action=data.get("default_action", "redact"),
        )

    @classmethod
    def from_json_file(cls, path: str) -> "Policy":
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))


#: Sensible out-of-the-box policy: redact everything.
DEFAULT_POLICY = Policy()
