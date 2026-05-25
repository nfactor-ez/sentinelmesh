"""Layer 9 — Threat intelligence correlation."""

from typing import Dict, List


def run_threat_intelligence(
    prompt: str,
    semantic: Dict,
    signatures: Dict,
    syscall: Dict,
    behavioral: Dict,
) -> Dict:
    families = []
    if semantic.get("intent_hits"):
        families.extend(h["attack_type"] for h in semantic["intent_hits"])
    if signatures.get("triggered_rules"):
        families.extend(r.get("category") for r in signatures["triggered_rules"])

    families = list(dict.fromkeys(families))[:6]
    confidence = max(
        semantic.get("confidence", 0.15),
        min(0.98, len(families) * 0.18 + behavioral.get("indicator_count", 0) * 0.05),
    )

    summary_parts = []
    if families:
        summary_parts.append(f"Correlated attack families: {', '.join(families)}")
    if syscall.get("syscall_violations"):
        syscalls = ", ".join(v["syscall"] for v in syscall["syscall_violations"][:3])
        summary_parts.append(f"Syscall abuse chain: {syscalls}")
    if not summary_parts:
        summary_parts.append("No active threat intelligence correlation")

    severity = "LOW"
    if confidence >= 0.85:
        severity = "CRITICAL"
    elif confidence >= 0.65:
        severity = "HIGH"
    elif confidence >= 0.4:
        severity = "MEDIUM"

    return {
        "layer": "threat_intelligence",
        "passed": severity in ("LOW", "MEDIUM"),
        "risk_contribution": round(confidence * 12, 1),
        "attack_families": families,
        "confidence": round(confidence, 3),
        "severity": severity,
        "threat_summary": ". ".join(summary_parts),
        "correlation_count": len(families),
    }
