"""Layer 2 — Prompt firewall (jailbreak, injection, policy bypass)."""

import re
from typing import Dict, List

from firewall_engine import _layer_a_keyword_scan, _layer_c_jailbreak_detector, _layer_d_policy_constraints

PROMPT_PATTERNS = [
    (r"ignore\s+(all\s+)?(previous|prior)\s+instructions", "instruction_override", 22),
    (r"reveal\s+(your\s+)?(system\s+)?prompt", "system_prompt_extraction", 24),
    (r"developer\s+mode|dan\s+mode|jailbreak", "policy_bypass", 26),
    (r"pretend\s+you\s+are\s+(?:an?\s+)?(?:unrestricted|evil)", "role_manipulation", 20),
    (r"hidden\s+prompt|inject\s+into\s+system", "hidden_injection", 22),
]


def run_prompt_firewall(prompt: str) -> Dict:
    kw_score, kw_matches, kw_cats = _layer_a_keyword_scan(prompt)
    jb_score, jb_pattern = _layer_c_jailbreak_detector(prompt)
    pol_score, pol_violations, force_block = _layer_d_policy_constraints(prompt)

    triggered: List[Dict] = []
    extra = 0.0
    pl = prompt.lower()
    for regex, name, pts in PROMPT_PATTERNS:
        if re.search(regex, pl):
            triggered.append({"rule": name, "severity": "HIGH", "score": pts})
            extra += pts * 0.4

    risk = min(kw_score * 0.5 + jb_score + pol_score + extra, 40)
    blocked = force_block or risk >= 28 or jb_score >= 22

    return {
        "layer": "prompt_firewall",
        "passed": not blocked,
        "risk_contribution": round(risk, 1),
        "blocked": blocked,
        "keyword_matches": kw_matches[:6],
        "keyword_categories": kw_cats,
        "jailbreak_pattern": jb_pattern,
        "policy_violations": pol_violations,
        "triggered_rules": triggered,
        "reasoning": "Prompt firewall detected policy bypass or injection patterns" if blocked else "No critical prompt firewall violations",
    }
