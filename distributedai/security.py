# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic content-safety scanning for DistributedAI stored payloads.

Bounded, deterministic, Unicode-normalised heuristics that flag text likely to be a prompt
injection, role spoof, secret-exfiltration attempt, or an encoded/suspicious payload.

Explicitly imperfect: a clean scan does NOT establish trust — every stored payload remains
untrusted data — and a finding does not prove malice. Findings are labels used by the store
to quarantine content pending human/reviewer judgement. This module never fetches URLs,
never executes anything, and never mutates its input.
"""
from __future__ import annotations

import re
import unicodedata

# Scanning is bounded so adversarial payload size cannot turn the scanner into a DoS vector.
MAX_SCAN_CHARS = 20_000
MAX_PAYLOAD_ITEMS = 2_000
MAX_PAYLOAD_DEPTH = 32

# Finding codes (stable identifiers stored alongside quarantined records).
INSTRUCTION_OVERRIDE = "instruction_override"
ROLE_SPOOFING = "role_spoofing"
SECRET_EXFILTRATION = "secret_exfiltration"
ENCODED_PAYLOAD = "encoded_payload"
SUSPICIOUS_EXECUTION = "suspicious_execution"
MALFORMED_INPUT = "malformed_input"
OVERSIZE_INPUT = "oversize_input"

ALL_FINDINGS = (
    INSTRUCTION_OVERRIDE,
    ROLE_SPOOFING,
    SECRET_EXFILTRATION,
    ENCODED_PAYLOAD,
    SUSPICIOUS_EXECUTION,
    MALFORMED_INPUT,
    OVERSIZE_INPUT,
)

# Zero-width / joiner characters commonly used to break up trigger phrases.
_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u200e\u200f\u2060\ufeff\u00ad"))

_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    INSTRUCTION_OVERRIDE: [
        re.compile(r"\bignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\s+"
                   r"(?:instructions?|prompts?|rules?|messages?)"),
        re.compile(r"\bdisregard\s+(?:your|the|all|any)\b.{0,30}?"
                   r"(?:instructions?|rules?|guidelines?|policy|policies)"),
        re.compile(r"\bforget\s+(?:all|your|everything)\b.{0,30}?"
                   r"(?:instructions?|training|rules?|told)"),
        re.compile(r"\bnew\s+instructions?\s*:"),
        re.compile(r"\boverride\b.{0,20}?(?:instructions?|safety|rules?|restrictions?)"),
        re.compile(r"\bdo\s+not\s+follow\b.{0,40}?(?:instructions?|rules?|policy)"),
        re.compile(r"\byour?\s+(?:real|true|actual)\s+(?:instructions?|task|goal)\b"),
    ],
    ROLE_SPOOFING: [
        re.compile(r"\byou\s+are\s+now\b"),
        re.compile(r"\bact\s+as\s+(?:the\s+|an?\s+)?"
                   r"(?:system|admin(?:istrator)?|root|developer|superuser)"),
        re.compile(r"\bi\s+am\s+(?:the\s+|an?\s+)?"
                   r"(?:system|org\s*admin|admin(?:istrator)?|root|superuser)\b"),
        re.compile(r"\bas\s+(?:the\s+)?org\s*admin\b"),
        re.compile(r"<\|?\s*(?:system|assistant|im_start)\s*\|?>"),
        re.compile(r"\[\s*system\s*\]"),
        re.compile(r"\bsystem\s+prompt\b"),
        re.compile(r"\bdeveloper\s+mode\b"),
        re.compile(r"\bpretend\s+to\s+be\b"),
        re.compile(r"\bjailbreak\b"),
    ],
    SECRET_EXFILTRATION: [
        re.compile(r"\b(?:send|reveal|print|show|share|exfiltrate|leak|forward|email|post)\b"
                   r".{0,50}?\b(?:token|password|secret|credential|api\s*.?\s*key|private\s+key|"
                   r"claim\s*.?\s*token)"),
        re.compile(r"-----begin\s[a-z0-9 ]*private\skey-----"),
        re.compile(r"\bakia[0-9a-z]{16}\b"),
        re.compile(r"\bauthorization\s*:\s*bearer\s+\S+"),
        re.compile(r"\bxox[abposr]-[0-9a-z-]{10,}"),
    ],
    ENCODED_PAYLOAD: [
        re.compile(r"[a-z0-9+/=]{160,}"),                # long base64-ish run
        re.compile(r"(?:\\x[0-9a-f]{2}){24,}"),          # long \xNN escape chain
        re.compile(r"(?:%[0-9a-f]{2}){24,}"),            # long percent-encoded chain
        re.compile(r"data:[a-z0-9/+.-]+;base64,"),
        re.compile(r"\beval\s*\(\s*(?:atob|base64)"),
    ],
    SUSPICIOUS_EXECUTION: [
        re.compile(r"\brm\s+-rf?\b"),
        re.compile(r"\b(?:curl|wget)\s+(?:-\S+\s+)*https?://"),
        re.compile(r"\$\(\s*\S.{0,80}?\)"),              # shell command substitution
        re.compile(r"`[^`]{1,120}`"),                    # backtick execution
        re.compile(r"\bos\.system\s*\("),
        re.compile(r"\bsubprocess\.(?:run|popen|call|check_output)"),
        re.compile(r"\bpowershell(?:\.exe)?\s+-"),
        re.compile(r"\bjavascript:"),
        re.compile(r"[;|&]\s*(?:sh|bash|zsh)\b"),
    ],
}


def normalize(text: str) -> str:
    """Normalise text for matching: NFKC fold, strip zero-width chars, casefold,
    collapse whitespace. Input is truncated to MAX_SCAN_CHARS first so the cost is bounded."""
    if not isinstance(text, str):
        raise TypeError("normalize() expects str")
    clipped = text[:MAX_SCAN_CHARS]
    normalised = unicodedata.normalize("NFKC", clipped).translate(_ZERO_WIDTH).casefold()
    return re.sub(r"\s+", " ", normalised)


def scan_text(text: str) -> list[str]:
    """Scan one string; return sorted, de-duplicated finding codes (empty list == no findings).

    Fails closed: a non-string input is flagged as malformed rather than passed clean, and
    text longer than MAX_SCAN_CHARS is flagged oversize (the unscanned tail can never smuggle
    content through as 'clean'); the scanned prefix is still pattern-matched."""
    if not isinstance(text, str):
        return [MALFORMED_INPUT]
    if not text:
        return []
    found: set[str] = set()
    if len(text) > MAX_SCAN_CHARS:
        found.add(OVERSIZE_INPUT)
    normalised = normalize(text)
    for code, patterns in _PATTERNS.items():
        for pattern in patterns:
            if pattern.search(normalised):
                found.add(code)
                break
    return sorted(found)


def scan_payload(value: object) -> list[str]:
    """Walk a JSON-like payload (dict/list/tuple/str/scalars) and scan every string, including
    dict keys. Traversal is iterative and bounded by MAX_PAYLOAD_ITEMS / MAX_PAYLOAD_DEPTH;
    anything beyond the bound is itself flagged as an encoded/suspicious payload rather than
    silently skipped."""
    found: set[str] = set()
    stack: list[tuple[object, int]] = [(value, 0)]
    seen = 0
    while stack:
        current, depth = stack.pop()
        seen += 1
        if seen > MAX_PAYLOAD_ITEMS or depth > MAX_PAYLOAD_DEPTH:
            found.add(ENCODED_PAYLOAD)
            break
        if isinstance(current, str):
            found.update(scan_text(current))
        elif isinstance(current, dict):
            for key, item in current.items():
                if isinstance(key, str):
                    found.update(scan_text(key))
                stack.append((item, depth + 1))
        elif isinstance(current, (list, tuple, set, frozenset)):
            for item in current:
                stack.append((item, depth + 1))
        elif not isinstance(current, (int, float, bool, type(None))):
            # Fail closed: unknown/non-JSON types are flagged, never silently treated as clean.
            found.add(MALFORMED_INPUT)
    return sorted(found)


def is_suspicious(findings: list[str]) -> bool:
    return bool(findings)
