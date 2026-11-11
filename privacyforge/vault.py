"""Reversible token vault.

When PrivacyForge redacts a value it swaps it for a placeholder token
such as ``⟦EMAIL_1⟧`` and stores the (token, value) pair here, in a
local SQLite database.  After the external AI responds, the tokens in
its response are swapped back for the originals — the model never saw
the real data, but the user still gets a readable answer.

The vault is deliberately boring: one table, no network, file lives
on your machine only (``:memory:`` is supported for tests/ephemeral
use).
"""

from __future__ import annotations

import sqlite3
import threading


class TokenVault:
    """SQLite-backed store of token -> original value mappings."""

    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mappings (
                    token    TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    value    TEXT NOT NULL UNIQUE
                )
                """
            )

    # -- writing ------------------------------------------------------
    def tokenize(self, value: str, category: str) -> str:
        """Return the token for ``value``, creating one if needed.

        The same value always maps to the same token within a vault,
        so repeated mentions stay consistent for the model.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT token FROM mappings WHERE value = ?", (value,)
            ).fetchone()
            if row:
                return row[0]
            count = self._conn.execute(
                "SELECT COUNT(*) FROM mappings WHERE category = ?", (category,)
            ).fetchone()[0]
            token = f"⟦{category}_{count + 1}⟧"
            with self._conn:
                self._conn.execute(
                    "INSERT INTO mappings (token, category, value) VALUES (?, ?, ?)",
                    (token, category, value),
                )
            return token

    # -- reading ------------------------------------------------------
    def lookup(self, token: str) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM mappings WHERE token = ?", (token,)
        ).fetchone()
        return row[0] if row else None

    def restore(self, text: str) -> str:
        """Replace every known token in ``text`` with its original value."""
        rows = self._conn.execute("SELECT token, value FROM mappings").fetchall()
        # Longest tokens first so e.g. EMAIL_10 is not clobbered by EMAIL_1.
        for token, value in sorted(rows, key=lambda r: -len(r[0])):
            text = text.replace(token, value)
        return text

    def __len__(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM mappings").fetchone()[0]

    def close(self) -> None:
        self._conn.close()
