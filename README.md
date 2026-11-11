# PrivacyForge

**A privacy layer that sits between your app and external AI APIs, so
sensitive data never leaves your machine in the first place.**

## Problem

Every prompt you send to a hosted LLM can contain emails, phone
numbers, government IDs, payment cards, API keys and passwords —
pasted in by users who have no idea where that text ends up. Once it
leaves, you cannot un-send it.

PrivacyForge fixes this at the boundary: it detects sensitive values
in outgoing text, swaps them for reversible placeholder tokens
(`⟦EMAIL_1⟧`), and keeps the token↔value mapping in a **local** vault.
The external model works with tokens; when its reply comes back, the
tokens are swapped back locally. The model never sees the real data,
but the user still gets a readable answer.

## Features

- **Detectors** for emails, Indian mobile numbers, Aadhaar
  (Verhoeff-checksum verified), PAN, payment cards (Luhn verified),
  known API-key formats (OpenAI, GitHub, AWS, Google, Slack, JWTs),
  `password = …` style assignments, and high-entropy secret tokens.
- **Reversible token vault** backed by SQLite — same value always
  maps to the same token, so references stay consistent for the model.
- **Configurable policies** per category: `redact`, `block`, `warn`,
  or `allow`.
- **Append-only audit log** proving what *categories* of data were
  withheld — the log stores timestamps, categories, actions and value
  lengths, **never the values themselves**.
- **Zero dependencies** for the core library (Python 3.10+ stdlib);
  an optional FastAPI proxy is included for HTTP use.

## How to run

```bash
# Demo: protect the sample prompt, simulate an AI round-trip, restore it
python -m privacyforge.cli

# ...or protect your own text file
python -m privacyforge.cli path/to/prompt.txt

# Tests
pip install pytest
python -m pytest

# Optional HTTP proxy
pip install fastapi uvicorn
uvicorn privacyforge.app:app
# POST /protect {"text": "..."}  -> redacted text + audit summary
# POST /restore {"text": "..."}  -> tokens swapped back
```

Library use:

```python
from privacyforge import Policy, TokenVault, AuditLog, protect, restore

vault = TokenVault("vault.db")            # local file, never leaves your machine
policy = Policy(rules={"CARD": "block"})  # refuse to send card numbers at all

result = protect(user_prompt, policy, vault=vault, audit=AuditLog("audit.jsonl"))
reply = call_external_ai(result.text)     # sees ⟦EMAIL_1⟧, not the real email
answer = restore(reply, vault)            # user sees the real values again
```

## Project structure

```
privacyforge/
    __init__.py     public API re-exports
    detectors.py    regex + checksum + entropy detectors
    vault.py        SQLite-backed reversible token store
    policy.py       per-category redact/block/warn/allow policies
    audit.py        append-only, value-free audit log
    middleware.py   protect() / restore() entry points
    cli.py          demo CLI (python -m privacyforge.cli)
    app.py          optional FastAPI proxy (guarded import)
examples/
    sample_prompt.txt   fake sensitive data for the demo
tests/
    test_detectors.py   detector + checksum tests
    test_roundtrip.py   protect -> restore round-trip, audit hygiene
    test_policy.py      block/warn/allow policy behaviour
```

## Tech

Python 3.10+ (standard library only), SQLite, optional FastAPI,
pytest for tests. Sample data in this repo is entirely fake; card and
Aadhaar test numbers use publicly known test/checksum-valid values.

## License

MIT — see `LICENSE`.
