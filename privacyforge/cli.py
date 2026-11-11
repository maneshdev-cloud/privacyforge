"""Demo CLI: protect a sample prompt, fake an AI round-trip, restore it.

Usage::

    python -m privacyforge.cli [path-to-text-file]

Without arguments it uses ``examples/sample_prompt.txt``.  The vault
and audit log are created in a temporary directory so the demo leaves
no state behind.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from .audit import AuditLog
from .middleware import protect, restore
from .policy import Policy
from .vault import TokenVault


def _default_sample() -> Path:
    return Path(__file__).resolve().parent.parent / "examples" / "sample_prompt.txt"


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    source = Path(argv[0]) if argv else _default_sample()
    text = source.read_text(encoding="utf-8")

    with tempfile.TemporaryDirectory() as tmp:
        vault = TokenVault(str(Path(tmp) / "vault.db"))
        audit = AuditLog(str(Path(tmp) / "audit.jsonl"))
        # Demo policy: block payment cards outright, redact everything else.
        policy = Policy(rules={"CARD": "block"}, default_action="redact")
        try:
            result = protect(text, policy, vault=vault, audit=audit)
        except Exception as exc:  # PrivacyBlockError — show what the policy did
            print(f"BLOCKED: {exc}")
            print(f"Audit summary: {audit.summary()}")
            return 2

        print("=== ORIGINAL (stays on your machine) ===")
        print(text)
        print("=== PROTECTED (this is what the external AI sees) ===")
        print(result.text)

        fake_ai_reply = (
            "Summary: the customer asked for a KYC update. "
            f"Follow up with {result.text.splitlines()[1].strip()}"
            if len(result.text.splitlines()) > 1
            else "Summary ready."
        )
        print("=== RESTORED AI REPLY (tokens swapped back locally) ===")
        print(restore(fake_ai_reply, vault))
        print(f"=== AUDIT SUMMARY (no values stored) ===\n{audit.summary()}")
        print(f"Vault entries: {len(vault)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
