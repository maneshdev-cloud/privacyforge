"""Optional FastAPI proxy exposing PrivacyForge over HTTP.

Run with::

    pip install fastapi uvicorn
    uvicorn privacyforge.app:app

Endpoints:

* ``POST /protect``  ``{"text": "..."}`` -> redacted text + audit summary
* ``POST /restore``  ``{"text": "..."}`` -> tokens swapped back

The import is guarded so the core package works fine without FastAPI
installed; ``app`` is simply ``None`` in that case.
"""

from __future__ import annotations

import os

from .audit import AuditLog
from .middleware import PrivacyBlockError, protect, restore
from .policy import Policy
from .vault import TokenVault

try:
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel

    _vault = TokenVault(os.environ.get("PRIVACYFORGE_VAULT_PATH", ":memory:"))
    _audit = AuditLog(os.environ.get("PRIVACYFORGE_AUDIT_PATH"))
    _policy = Policy()

    app = FastAPI(title="PrivacyForge", version="0.1.0")

    class TextIn(BaseModel):
        text: str

    @app.post("/protect")
    def protect_endpoint(payload: TextIn) -> dict:
        try:
            result = protect(payload.text, _policy, vault=_vault, audit=_audit)
        except PrivacyBlockError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {
            "text": result.text,
            "redacted": result.redacted_count,
            "warnings": result.warnings,
            "audit": _audit.summary(),
        }

    @app.post("/restore")
    def restore_endpoint(payload: TextIn) -> dict:
        return {"text": restore(payload.text, _vault)}

except ImportError:  # FastAPI not installed — core package still usable.
    app = None
