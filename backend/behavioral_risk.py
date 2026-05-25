"""Layer 5 — Behavioral risk correlation and attack-chain amplification."""

from typing import Dict, List


def run_behavioral_risk(layer_outputs: List[Dict]) -> Dict:
    indicators = 0
    categories = set()
    chain_bonus = 0.0

    for layer in layer_outputs:
        if layer.get("risk_contribution", 0) >= 12:
            indicators += 1
        if layer.get("triggered_rules"):
            indicators += len(layer["triggered_rules"])
        if layer.get("intent_hits"):
            for h in layer["intent_hits"]:
                categories.add(h.get("attack_type"))
        if layer.get("syscall_violations"):
            indicators += len(layer["syscall_violations"])
            if any(v.get("container_escape_relevant") for v in layer["syscall_violations"]):
                chain_bonus += 12

    if len(categories) >= 2:
        chain_bonus += 15
    if indicators >= 4:
        chain_bonus += 10

    risk = min(chain_bonus + indicators * 2.5, 30)
    return {
        "layer": "behavioral_risk",
        "passed": risk < 18,
        "risk_contribution": round(risk, 1),
        "indicator_count": indicators,
        "attack_categories": list(categories)[:6],
        "chain_amplification": round(chain_bonus, 1),
        "anomaly_multiplier": 1.0 + min(indicators * 0.08, 0.4),
    }
