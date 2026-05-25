"""Layer 1 — Prompt normalization and obfuscation detection."""

import base64
import re
import unicodedata
from typing import Dict, List


def run_normalization(prompt: str) -> Dict:
    raw = prompt or ""
    normalized = unicodedata.normalize("NFKC", raw).lower().strip()
    normalized = re.sub(r"\s+", " ", normalized)

    flags: List[str] = []
    score = 0.0

    if re.search(r"base64|atob|b64decode|frombase64", normalized):
        flags.append("base64_reference")
        score += 12
    try:
        if len(raw) > 16 and re.fullmatch(r"[A-Za-z0-9+/=\s]{16,}", raw.strip()):
            base64.b64decode(raw.strip(), validate=True)
            flags.append("base64_payload")
            score += 18
    except Exception:
        pass

    if re.search(r"\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|%[0-9a-f]{2}", raw, re.I):
        flags.append("encoded_escape_sequences")
        score += 14

    if re.search(r"(?:[a-z][\s\.\-_]){6,}[a-z]", normalized) and len(normalized) < 120:
        flags.append("spaced_obfuscation")
        score += 10

    if re.search(r"[;&|`$(){}<>]", raw):
        flags.append("shell_metacharacters")
        score += 8

    tokens = re.findall(r"[a-z0-9]{3,}", normalized)
    suspicious_tokens = [t for t in tokens if t in {
        "eval", "exec", "sudo", "root", "payload", "exploit", "bypass", "inject",
        "override", "jailbreak", "dan", "shell", "reverse", "ptrace", "insmod",
    }]
    if suspicious_tokens:
        flags.append("suspicious_tokens")
        score += min(len(suspicious_tokens) * 4, 16)

    return {
        "layer": "normalization",
        "passed": score < 20,
        "risk_contribution": round(min(score, 25), 1),
        "normalized_preview": normalized[:120],
        "flags": flags,
        "suspicious_tokens": suspicious_tokens[:8],
    }
