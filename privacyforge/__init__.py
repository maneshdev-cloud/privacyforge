"""PrivacyForge — keep sensitive data out of external AI APIs."""

from .audit import AuditLog
from .detectors import Finding, detect
from .middleware import PrivacyBlockError, ProtectionResult, protect, restore
from .policy import DEFAULT_POLICY, Policy
from .vault import TokenVault

__all__ = [
    "AuditLog",
    "DEFAULT_POLICY",
    "Finding",
    "Policy",
    "PrivacyBlockError",
    "ProtectionResult",
    "TokenVault",
    "detect",
    "protect",
    "restore",
]

__version__ = "0.1.0"
