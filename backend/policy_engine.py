"""Layer 7 — Runtime policy enforcement."""

from typing import Dict, List


def run_policy_engine(prompt: str, layer_outputs: List[Dict]) -> Dict:
    total_risk = sum(l.get("risk_contribution", 0) for l in layer_outputs)
    any_blocked = any(l.get("blocked") for l in layer_outputs)

    if any_blocked or total_risk >= 55:
        action = "BLOCK"
        reasoning = "Policy engine enforced deny — critical indicators present"
    elif total_risk >= 35:
        action = "QUARANTINE"
        reasoning = "Prompt quarantined pending elevated risk review"
    elif total_risk >= 20:
        action = "RESTRICTED_EXECUTION"
        reasoning = "Restricted execution — monitored sandbox only"
    else:
        action = "ALLOW"
        reasoning = "Policy checks passed — low-risk execution permitted"

    audit_entries = [
        f"POLICY_EVAL risk_aggregate={total_risk:.1f}",
        f"POLICY_DECISION action={action}",
    ]
    if any_blocked:
        audit_entries.append("POLICY_ENFORCE block_dangerous_execution=true")

    return {
        "layer": "policy_enforcement",
        "passed": action == "ALLOW",
        "risk_contribution": round(min(total_risk * 0.15, 15), 1),
        "blocked": action in ("BLOCK", "QUARANTINE"),
        "enforcement_action": action,
        "reasoning": reasoning,
        "audit_trail": audit_entries,
    }
