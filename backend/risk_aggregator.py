"""
SentinelMesh — Full security pipeline orchestrator.
Runs normalization → prompt firewall → semantic → signatures → behavioral
→ syscall → policy → sandbox → threat intel → final verdict.
"""

import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

from firewall_engine import analyze_prompt, classify_risk
from normalization_engine import run_normalization
from prompt_firewall import run_prompt_firewall
from semantic_analysis import run_semantic_analysis
from falco_rules import run_attack_signatures
from behavioral_risk import run_behavioral_risk
from syscall_engine import run_syscall_analysis
from policy_engine import run_policy_engine
from sandbox_engine import run_sandbox_decision
from threat_intelligence import run_threat_intelligence


PIPELINE_STAGES = [
    "normalization",
    "prompt_firewall",
    "semantic_analysis",
    "attack_signatures",
    "behavioral_risk",
    "syscall_analysis",
    "policy_enforcement",
    "sandbox_decision",
    "threat_intelligence",
]


def _build_scan_logs(layers: Dict, final: Dict) -> List[Dict]:
    logs = [
        {"level": "INFO", "msg": "Prompt received by runtime defense gateway"},
        {"level": "INFO", "msg": "Normalization engine: unicode and obfuscation scan"},
    ]
    if layers["normalization"].get("flags"):
        logs.append({"level": "WARNING", "msg": f"Obfuscation flags: {', '.join(layers['normalization']['flags'][:3])}"})

    logs.append({"level": "SCAN", "msg": "Semantic threat analysis initiated"})
    if layers["semantic_analysis"].get("intent_hits"):
        hit = layers["semantic_analysis"]["intent_hits"][0]
        logs.append({"level": "ALERT", "msg": f"{hit['attack_type']} intent detected (MITRE {hit['mitre_id']})"})

    if layers["attack_signatures"].get("triggered_rules"):
        r = layers["attack_signatures"]["triggered_rules"][0]
        logs.append({"level": "ALERT", "msg": f"Signature match: {r['rule']} [{r['category']}]"})

    for v in layers["syscall_analysis"].get("syscall_violations", [])[:4]:
        logs.append({"level": "WARNING" if v["status"] == "FLAGGED" else "ALERT",
                     "msg": f"{v['syscall']} → {v['status']} (seccomp: {v['seccomp_response']})"})

    if layers["policy_enforcement"].get("enforcement_action") in ("BLOCK", "QUARANTINE"):
        logs.append({"level": "BLOCKED", "msg": f"Policy enforced: {layers['policy_enforcement']['enforcement_action']}"})

    logs.append({"level": "SECURE", "msg": f"Sandbox: {layers['sandbox_decision'].get('integrity', 'UNKNOWN')}"})
    logs.append({"level": "INFO" if final["blocked"] else "SUCCESS",
                 "msg": f"Final verdict: {final['classification']} — {'BLOCKED' if final['blocked'] else 'ALLOWED'}"})
    return logs


def run_security_pipeline(prompt: str, ml_result: Optional[dict] = None) -> Dict:
    start = time.perf_counter()
    layers: Dict = {}

    layers["normalization"] = run_normalization(prompt)
    layers["prompt_firewall"] = run_prompt_firewall(prompt)
    layers["semantic_analysis"] = run_semantic_analysis(prompt)
    layers["attack_signatures"] = run_attack_signatures(prompt)

    mid = [
        layers["prompt_firewall"],
        layers["semantic_analysis"],
        layers["attack_signatures"],
    ]
    layers["behavioral_risk"] = run_behavioral_risk(mid)
    layers["syscall_analysis"] = run_syscall_analysis(prompt)

    policy_inputs = list(mid) + [
        layers["behavioral_risk"],
        layers["syscall_analysis"],
        layers["normalization"],
    ]
    layers["policy_enforcement"] = run_policy_engine(prompt, policy_inputs)
    layers["sandbox_decision"] = run_sandbox_decision(
        layers["policy_enforcement"], policy_inputs
    )
    layers["threat_intelligence"] = run_threat_intelligence(
        prompt,
        layers["semantic_analysis"],
        layers["attack_signatures"],
        layers["syscall_analysis"],
        layers["behavioral_risk"],
    )

    ml = ml_result if ml_result is not None else analyze_prompt(prompt)

    base_score = (
        layers["normalization"].get("risk_contribution", 0)
        + layers["prompt_firewall"].get("risk_contribution", 0)
        + layers["semantic_analysis"].get("risk_contribution", 0)
        + layers["attack_signatures"].get("risk_contribution", 0)
        + layers["behavioral_risk"].get("risk_contribution", 0)
        + layers["syscall_analysis"].get("risk_contribution", 0)
        + layers["threat_intelligence"].get("risk_contribution", 0)
        + ml.get("risk_score", 0) * 0.35
    )
    multiplier = layers["behavioral_risk"].get("anomaly_multiplier", 1.0)
    risk_score = round(min(base_score * multiplier, 100), 1)

    any_blocked = any(
        layers[k].get("blocked") for k in layers
    ) or ml.get("blocked", False)
    if any_blocked:
        risk_score = max(risk_score, 52.0)

    classification = classify_risk(risk_score)
    blocked = classification in ("SUSPICIOUS", "HARMFUL", "CRITICAL") or any_blocked

    attack_type = layers["semantic_analysis"].get("attack_type", "Unknown")
    if layers["attack_signatures"].get("triggered_rules"):
        attack_type = layers["attack_signatures"]["triggered_rules"][0].get("category", attack_type)

    triggered_layers = [k for k, v in layers.items() if v.get("blocked") or v.get("risk_contribution", 0) >= 20]
    triggered_rules = []
    for key in ("prompt_firewall", "attack_signatures"):
        triggered_rules.extend(layers[key].get("triggered_rules", []))

    mitigations = []
    if blocked:
        mitigations.extend([
            "Execution halted by policy engine",
            "Sandbox namespace sealed",
            "Outbound network egress denied",
        ])
    if layers["syscall_analysis"].get("syscall_violations"):
        mitigations.append("seccomp-bpf syscall filter enforced")
    if not mitigations:
        mitigations.append("Continuous runtime monitoring active")

    latency_ms = round((time.perf_counter() - start) * 1000, 1)

    final = {
        "risk_score": risk_score,
        "classification": classification,
        "confidence": layers["threat_intelligence"].get("confidence", 0.5),
        "attack_type": attack_type,
        "blocked": blocked,
        "sandbox_decision": layers["sandbox_decision"].get("sandbox_decision", "ALLOW"),
        "triggered_layers": triggered_layers,
        "triggered_rules": triggered_rules[:10],
        "syscall_violations": layers["syscall_analysis"].get("syscall_violations", []),
        "threat_summary": layers["threat_intelligence"].get("threat_summary", ""),
        "mitigations": mitigations,
        "latency_ms": latency_ms,
        "layers": layers,
        "ml_analysis": {
            "keyword_score": ml.get("keyword_score"),
            "embedding_score": ml.get("embedding_score"),
            "jailbreak_score": ml.get("jailbreak_score"),
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    final["pipeline_logs"] = _build_scan_logs(layers, final)
    return final


def merge_pipeline_into_result(result: Dict, pipeline: Dict) -> Dict:
    """Attach enterprise pipeline fields to existing /api/firewall/hf response."""
    result["confidence"] = pipeline.get("confidence")
    result["attack_type"] = pipeline.get("attack_type") or result.get("attack_type")
    result["sandbox_decision"] = pipeline.get("sandbox_decision")
    result["triggered_layers"] = pipeline.get("triggered_layers", [])
    result["triggered_rules"] = pipeline.get("triggered_rules", [])
    result["syscall_violations"] = pipeline.get("syscall_violations", [])
    result["threat_summary"] = pipeline.get("threat_summary", "")
    result["mitigations"] = pipeline.get("mitigations", [])
    result["pipeline"] = pipeline
    result["pipeline_logs"] = pipeline.get("pipeline_logs", [])
    if pipeline.get("blocked") and not result.get("blocked"):
        result["blocked"] = True
        result["classification"] = pipeline.get("classification", result.get("classification"))
        result["risk_score"] = max(float(result.get("risk_score", 0)), float(pipeline.get("risk_score", 0)))
    return result
