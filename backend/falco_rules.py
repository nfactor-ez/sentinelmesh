"""Layer 4 — Attack signature engine (Falco-style modular rules)."""

from typing import Dict, List

from kernel_layer import FALCO_RULES
from runtime_layer import CODE_INJECTION_RULES, CONTAINER_ESCAPE_RULES

MITRE_MAP = {
    "Reverse shell": ("Reverse Shell", "TA0011"),
    "Container Escape": ("Container Escape", "TA0004"),
    "Crypto Mining": ("Crypto Mining", "TA0040"),
    "Kernel Exploit": ("Kernel Exploit", "TA0004"),
    "Privilege Escalation": ("Privilege Escalation", "TA0004"),
    "Malware Execution": ("Malware Execution", "TA0002"),
    "Persistence": ("Persistence", "TA0003"),
    "Reconnaissance": ("Reconnaissance", "TA0043"),
    "Credential Theft": ("Credential Theft", "TA0006"),
}


def _categorize_rule(name: str, desc: str) -> str:
    text = f"{name} {desc}".lower()
    if "reverse shell" in text or "bash tcp" in text:
        return "Reverse Shell"
    if "escape" in text or "docker" in text or "proc" in text:
        return "Container Escape"
    if "miner" in text or "xmrig" in text:
        return "Crypto Mining"
    if "rootkit" in text or "insmod" in text or "kernel" in text:
        return "Kernel Exploit"
    if "privilege" in text or "cap_" in text:
        return "Privilege Escalation"
    if "inject" in text or "exec" in text or "malware" in text:
        return "Malware Execution"
    if "persistence" in text or "cron" in text:
        return "Persistence"
    if "credential" in text or "password" in text:
        return "Credential Theft"
    return "Reconnaissance"


def run_attack_signatures(prompt: str) -> Dict:
    import re

    pl = prompt.lower()
    triggered: List[Dict] = []
    score = 0.0

    all_rules = []
    for r in FALCO_RULES:
        all_rules.append({**r, "source": "falco"})
    for r in CODE_INJECTION_RULES + CONTAINER_ESCAPE_RULES:
        all_rules.append({
            "rule": r["name"],
            "priority": r.get("severity", "HIGH"),
            "score": r.get("score", 25),
            "patterns": r["patterns"],
            "desc": r.get("description", ""),
            "source": "runtime",
        })

    for rule in all_rules:
        for pat in rule.get("patterns", []):
            if re.search(pat, pl, re.I):
                cat = _categorize_rule(rule.get("rule", ""), rule.get("desc", ""))
                mitre = MITRE_MAP.get(cat, ("Unknown", "TA0000"))
                triggered.append({
                    "rule": rule.get("rule"),
                    "category": cat,
                    "mitre_id": mitre[1],
                    "severity": rule.get("priority", "HIGH"),
                    "score": rule.get("score", 20),
                    "description": rule.get("desc", ""),
                    "source": rule.get("source"),
                })
                score += rule.get("score", 20) * 0.35
                break

    blocked = score >= 30
    return {
        "layer": "attack_signatures",
        "passed": not blocked,
        "risk_contribution": round(min(score, 45), 1),
        "blocked": blocked,
        "triggered_rules": triggered[:8],
        "signature_count": len(triggered),
    }
