"""Detectors for sensitive data in free text.

Two families of detectors live here:

* **Pattern detectors** — regexes tuned for concrete formats (emails,
  Indian mobile numbers, Aadhaar, PAN, payment cards, well-known API
  key shapes, ``password = ...`` style assignments).  Where a format
  has a checksum (Aadhaar -> Verhoeff, cards -> Luhn) the checksum is
  verified, which keeps false positives on random digit strings low.
* **Entropy detector** — catches long, random-looking tokens that do
  not match any known key format (session ids, bespoke secrets) using
  Shannon entropy.

Every detector returns :class:`Finding` objects with the character
span of the match so callers can redact precisely.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    """One detected piece of sensitive data."""

    category: str  # EMAIL, PHONE, AADHAAR, PAN, CARD, API_KEY, PASSWORD, SECRET
    value: str
    start: int
    end: int
    detector: str = ""

    @property
    def length(self) -> int:
        return self.end - self.start


# --------------------------------------------------------------------------
# Checksum helpers
# --------------------------------------------------------------------------

_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_valid(number: str) -> bool:
    """Return True if ``number`` (digits only) passes the Verhoeff checksum."""
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def luhn_valid(number: str) -> bool:
    """Return True if ``number`` (digits only) passes the Luhn checksum."""
    total = 0
    for i, ch in enumerate(reversed(number)):
        v = int(ch)
        if i % 2 == 1:
            v *= 2
            if v > 9:
                v -= 9
        total += v
    return total % 10 == 0


def shannon_entropy(token: str) -> float:
    """Shannon entropy of a string, in bits per character."""
    if not token:
        return 0.0
    counts: dict[str, int] = {}
    for ch in token:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(token)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# --------------------------------------------------------------------------
# Pattern detectors
# --------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_AADHAAR_GROUPED_RE = re.compile(r"(?<!\d)\d{4}[ ]\d{4}[ ]\d{4}(?!\d)")
_AADHAAR_PLAIN_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
_PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
_PAN_HOLDER_CHARS = set("PCHFATBLJG")  # valid 4th character (holder type)
_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_PHONE_IN_RE = re.compile(
    r"(?<!\d)(?:\+91[\s-]?|91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)"
)

# Well-known key formats. Each entry: (name, compiled regex).
_API_KEY_PATTERNS = [
    ("openai", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{16,}")),
    ("github-pat", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("github-fine-grained", re.compile(r"github_pat_[A-Za-z0-9_]{50,}")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]

# keyword = value style secrets; group 1 is the secret itself.
_KEYWORD_SECRET_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret)"
    r"\b\s*[:=]\s*[\"']?([A-Za-z0-9_\-.]{12,})[\"']?"
)
_PASSWORD_RE = re.compile(
    r"(?i)\b(?:password|passwd|pwd)\b\s*(?:is\s+|[:=]\s*)[\"']?([^\s\"',;]{4,})"
)

_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_-]{24,}")
ENTROPY_THRESHOLD = 4.2

# Lower number wins when two findings overlap.
_PRIORITY = {
    "AADHAAR": 0,
    "CARD": 1,
    "PAN": 2,
    "EMAIL": 3,
    "PHONE": 4,
    "API_KEY": 5,
    "PASSWORD": 6,
    "SECRET": 7,
}


def _detect_emails(text: str) -> list[Finding]:
    return [
        Finding("EMAIL", m.group(0), m.start(), m.end(), "regex:email")
        for m in _EMAIL_RE.finditer(text)
    ]


def _detect_aadhaar(text: str) -> list[Finding]:
    out = []
    for regex in (_AADHAAR_GROUPED_RE, _AADHAAR_PLAIN_RE):
        for m in regex.finditer(text):
            digits = re.sub(r"\D", "", m.group(0))
            # Aadhaar numbers never start with 0 or 1, and must pass Verhoeff.
            if digits[0] in "23456789" and verhoeff_valid(digits):
                out.append(
                    Finding("AADHAAR", m.group(0), m.start(), m.end(), "regex+verhoeff")
                )
    return out


def _detect_pan(text: str) -> list[Finding]:
    out = []
    for m in _PAN_RE.finditer(text):
        if m.group(0)[3] in _PAN_HOLDER_CHARS:
            out.append(Finding("PAN", m.group(0), m.start(), m.end(), "regex:pan"))
    return out


def _detect_cards(text: str) -> list[Finding]:
    out = []
    for m in _CARD_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and luhn_valid(digits):
            out.append(
                Finding("CARD", m.group(0), m.start(), m.end(), "regex+luhn")
            )
    return out


def _detect_phones_in(text: str) -> list[Finding]:
    out = []
    for m in _PHONE_IN_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        # Normalise: drop the 91 country code, expect a 10-digit mobile.
        if digits.startswith("91") and len(digits) == 12:
            digits = digits[2:]
        if len(digits) == 10 and digits[0] in "6789":
            out.append(
                Finding("PHONE", m.group(0), m.start(), m.end(), "regex:phone-in")
            )
    return out


def _detect_api_keys(text: str) -> list[Finding]:
    out = []
    for name, regex in _API_KEY_PATTERNS:
        for m in regex.finditer(text):
            out.append(
                Finding("API_KEY", m.group(0), m.start(), m.end(), f"regex:{name}")
            )
    for m in _KEYWORD_SECRET_RE.finditer(text):
        out.append(
            Finding(
                "API_KEY",
                m.group(1),
                m.start(1),
                m.end(1),
                "regex:keyword-assignment",
            )
        )
    return out


def _detect_passwords(text: str) -> list[Finding]:
    out = []
    for m in _PASSWORD_RE.finditer(text):
        value, end = m.group(1), m.end(1)
        # A sentence-final period belongs to the prose, not the password.
        if value.endswith("."):
            value, end = value[:-1], end - 1
        out.append(Finding("PASSWORD", value, m.start(1), end, "regex:password"))
    return out


def _detect_high_entropy(text: str) -> list[Finding]:
    out = []
    for m in _TOKEN_RE.finditer(text):
        token = m.group(0)
        has_alpha = any(c.isalpha() for c in token)
        has_digit = any(c.isdigit() for c in token)
        if has_alpha and has_digit and shannon_entropy(token) >= ENTROPY_THRESHOLD:
            out.append(
                Finding("SECRET", token, m.start(), m.end(), "entropy")
            )
    return out


_DETECTORS = [
    _detect_aadhaar,
    _detect_cards,
    _detect_pan,
    _detect_emails,
    _detect_phones_in,
    _detect_api_keys,
    _detect_passwords,
    _detect_high_entropy,
]


def detect(text: str) -> list[Finding]:
    """Detect all sensitive values in ``text``.

    Returns findings sorted by position, with overlaps resolved in
    favour of the more specific detector (e.g. a card number that also
    looks like a long digit string is reported once, as a CARD).
    """
    raw: list[Finding] = []
    for detector in _DETECTORS:
        raw.extend(detector(text))

    raw.sort(key=lambda f: (f.start, _PRIORITY.get(f.category, 99), -(f.end - f.start)))

    accepted: list[Finding] = []
    occupied_until = -1
    for f in raw:
        if f.start >= occupied_until:
            accepted.append(f)
            occupied_until = f.end
    return accepted
