"""The middleware entry points: :func:`protect` and :func:`restore`.

Typical flow::

    vault = TokenVault("vault.db")
    result = protect(user_prompt, policy, vault=vault, audit=audit)
    response = call_some_external_ai(result.text)   # sees only tokens
    answer = restore(response, vault)               # user sees real data
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .audit import AuditLog
from .detectors import Finding, detect
from .policy import DEFAULT_POLICY, Policy
from .vault import TokenVault


class PrivacyBlockError(Exception):
    """Raised when a policy blocks a text. Carries categories, never values."""

    def __init__(self, categories: list[str]) -> None:
        self.categories = categories
        super().__init__(
            "Blocked by privacy policy; categories present: "
            + ", ".join(categories)
        )


@dataclass
class ProtectionResult:
    text: str
    findings: list[Finding]
    warnings: list[str] = field(default_factory=list)

    @property
    def redacted_count(self) -> int:
        return len(self.findings)


def protect(
    text: str,
    policy: Policy | None = None,
    vault: TokenVault | None = None,
    audit: AuditLog | None = None,
) -> ProtectionResult:
    """Apply ``policy`` to ``text`` and return the protected version.

    * ``redact`` findings are swapped for vault tokens.
    * ``warn``/``allow`` findings are left in place.
    * If any finding's action is ``block``, :class:`PrivacyBlockError`
      is raised and nothing is returned (the audit log still records
      the blocked attempt).
    """
    policy = policy or DEFAULT_POLICY
    if vault is None:  # NB: `vault or ...` would misfire — an empty vault is falsy via __len__
        vault = TokenVault()
    findings = detect(text)

    blocked: list[str] = []
    warnings: list[str] = []
    parts: list[str] = []
    cursor = 0

    for f in findings:
        action = policy.action_for(f.category)
        if audit is not None:
            audit.record(f.category, action, f.length)
        if action == "block":
            blocked.append(f.category)
            continue
        parts.append(text[cursor : f.start])
        if action == "redact":
            parts.append(vault.tokenize(f.value, f.category))
        else:  # warn / allow: value passes through
            if action == "warn":
                warnings.append(f.category)
            parts.append(f.value)
        cursor = f.end

    if blocked:
        raise PrivacyBlockError(sorted(set(blocked)))

    parts.append(text[cursor:])
    return ProtectionResult(
        text="".join(parts), findings=findings, warnings=warnings
    )


def restore(text: str, vault: TokenVault) -> str:
    """Swap vault tokens in ``text`` back to their original values."""
    return vault.restore(text)
