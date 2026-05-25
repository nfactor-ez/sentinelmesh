"""Layer 3 — Semantic threat analysis (intent categories)."""

import re
from typing import Dict, List, Tuple

INTENT_CLUSTERS: List[Tuple[str, str, List[str], float]] = [
    ("Reverse Shell", "TA0011", ["reverse shell", "/dev/tcp", "bash -i", "nc -e", "socat"], 1.2),
    ("Malware Execution", "TA0002", ["malware", "ransomware", "trojan", "keylogger", "payload"], 1.15),
    ("Privilege Escalation", "TA0004", ["sudo", "privilege", "escalat", "root access", "setuid"], 1.2),
    ("Data Exfiltration", "TA0010", ["exfiltrate", "steal data", "dump database", "scrape private"], 1.1),
    ("Persistence", "TA0003", ["persistence", "cron job", "startup script", "rootkit", "insmod"], 1.15),
    ("Reconnaissance", "TA0043", ["scan network", "enumerate", "recon", "port scan", "nmap"], 1.0),
    ("Credential Theft", "TA0006", ["password", "credential", "oauth token", "gmail", "sim swap"], 1.25),
    ("Kernel Exploit", "TA0004", ["kernel exploit", "dirty cow", "eBPF abuse", "seccomp bypass"], 1.3),
    ("Device Access", "TA0008", ["access my phone", "access mobile", "read messages", "track location"], 1.35),
]


def run_semantic_analysis(prompt: str) -> Dict:
    pl = prompt.lower()
    hits: List[Dict] = []
    total = 0.0

    for attack_type, mitre, keywords, weight in INTENT_CLUSTERS:
        matched = [k for k in keywords if k in pl]
        if matched:
            conf = min(0.55 + len(matched) * 0.12, 0.98) * weight
            hits.append({
                "attack_type": attack_type,
                "mitre_id": mitre,
                "confidence": round(conf, 3),
                "matched_terms": matched,
            })
            total += conf * 18

    primary = hits[0]["attack_type"] if hits else "Benign Query"
    confidence = hits[0]["confidence"] if hits else 0.15

    return {
        "layer": "semantic_analysis",
        "passed": total < 22,
        "risk_contribution": round(min(total, 35), 1),
        "attack_type": primary,
        "confidence": confidence,
        "intent_hits": hits[:5],
        "reasoning": f"Semantic engine mapped intent to {primary}" if hits else "No high-risk semantic intent detected",
    }
