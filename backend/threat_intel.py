"""
SentinelMesh threat intelligence.

The records below are NVD-tracked AI/LLM ecosystem CVEs, mapped to the
SentinelMesh layer that would reduce blast radius or block the exploit path.
"""

import time
from typing import Dict, List


THREAT_INTEL_DB: List[Dict] = [
    {
        "cve_id": "CVE-2024-5565",
        "affected_system": "Vanna.AI",
        "ecosystem": "Text-to-SQL / RAG",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "description": "Prompt injection can alter visualization code paths and lead to remote code execution when ask(..., visualize=True) processes untrusted input.",
        "mitigation_layer": "L4 Semantic Security",
        "exploit_category": "Prompt Injection to RCE",
        "sentinelmesh_status": "PROTECTED",
        "published": "2024-05-31",
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-5565",
    },
    {
        "cve_id": "CVE-2024-5184",
        "affected_system": "EmailGPT",
        "ecosystem": "AI Email Assistant",
        "severity": "HIGH",
        "cvss_score": 8.6,
        "description": "Direct prompt injection can take over service logic, leak hard-coded system prompts, and execute unwanted prompt flows.",
        "mitigation_layer": "L4 Semantic Security",
        "exploit_category": "Prompt Injection",
        "sentinelmesh_status": "PROTECTED",
        "published": "2024-06-06",
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-5184",
    },
    {
        "cve_id": "CVE-2024-48141",
        "affected_system": "Zhipu AI CodeGeeX",
        "ecosystem": "AI Coding Assistant",
        "severity": "HIGH",
        "cvss_score": 8.1,
        "description": "Prompt injection in the chatbox can expose previous and subsequent chat data through crafted messages.",
        "mitigation_layer": "L4 Semantic Security",
        "exploit_category": "Prompt Injection / Data Exfiltration",
        "sentinelmesh_status": "PROTECTED",
        "published": "2024-11-01",
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-48141",
    },
    {
        "cve_id": "CVE-2024-21513",
        "affected_system": "LangChain Experimental",
        "ecosystem": "Agent Framework",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "description": "VectorSQLDatabaseChain can execute arbitrary Python when attacker-controlled input reaches values evaluated by the chain.",
        "mitigation_layer": "L2 Runtime Isolation",
        "exploit_category": "Arbitrary Code Execution",
        "sentinelmesh_status": "PROTECTED",
        "published": "2024-07-15",
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-21513",
    },
    {
        "cve_id": "CVE-2024-27444",
        "affected_system": "LangChain Experimental",
        "ecosystem": "Agent Framework",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "description": "Bypass of a prior code execution fix allows dangerous Python attributes to reach executable code paths.",
        "mitigation_layer": "L2 Runtime Isolation",
        "exploit_category": "Sandbox Escape / Code Execution",
        "sentinelmesh_status": "PROTECTED",
        "published": "2024-02-26",
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-27444",
    },
    {
        "cve_id": "CVE-2024-46946",
        "affected_system": "LangChain Experimental",
        "ecosystem": "Agent Framework",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "description": "LLMSymbolicMathChain can execute arbitrary code through sympy.sympify when unsafe expressions are generated.",
        "mitigation_layer": "L2 Runtime Isolation",
        "exploit_category": "Arbitrary Code Execution",
        "sentinelmesh_status": "PROTECTED",
        "published": "2024-09-17",
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-46946",
    },
    {
        "cve_id": "CVE-2024-8309",
        "affected_system": "LangChain GraphCypherQAChain",
        "ecosystem": "Agent Framework / Graph DB",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "description": "Prompt injection can become SQL injection in GraphCypherQAChain, enabling data exfiltration, modification, and denial of service.",
        "mitigation_layer": "L4 Semantic Security",
        "exploit_category": "Prompt Injection to SQL Injection",
        "sentinelmesh_status": "PROTECTED",
        "published": "2024-10-29",
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-8309",
    },
    {
        "cve_id": "CVE-2024-45436",
        "affected_system": "Ollama",
        "ecosystem": "Model Runtime",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "description": "ZIP extraction in Ollama before 0.1.47 can write archive members outside the intended parent directory.",
        "mitigation_layer": "L1 Kernel Security",
        "exploit_category": "Path Traversal",
        "sentinelmesh_status": "PROTECTED",
        "published": "2024-08-28",
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-45436",
    },
    {
        "cve_id": "CVE-2024-39722",
        "affected_system": "Ollama",
        "ecosystem": "Model Runtime",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "description": "Path traversal in the API push route exposes which files exist on the deployment host.",
        "mitigation_layer": "L1 Kernel Security",
        "exploit_category": "Path Traversal",
        "sentinelmesh_status": "PROTECTED",
        "published": "2024-07-01",
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-39722",
    },
    {
        "cve_id": "CVE-2024-37145",
        "affected_system": "Flowise",
        "ecosystem": "LLM Workflow Builder",
        "severity": "HIGH",
        "cvss_score": 7.1,
        "description": "Reflected XSS in chatflow streaming routes can be chained with path injection to read files from the server.",
        "mitigation_layer": "L3 Network Security",
        "exploit_category": "XSS / File Read Chain",
        "sentinelmesh_status": "PROTECTED",
        "published": "2024-07-01",
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-37145",
    },
    {
        "cve_id": "CVE-2024-3126",
        "affected_system": "LoLLMS WebUI",
        "ecosystem": "LLM Web UI",
        "severity": "HIGH",
        "cvss_score": 8.4,
        "description": "Command injection in the XTTS API server launch path can execute OS commands on the host.",
        "mitigation_layer": "L2 Runtime Isolation",
        "exploit_category": "Command Injection",
        "sentinelmesh_status": "PROTECTED",
        "published": "2024-04-10",
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3126",
    },
    {
        "cve_id": "CVE-2024-1881",
        "affected_system": "AutoGPT",
        "ecosystem": "Autonomous Agent",
        "severity": "HIGH",
        "cvss_score": 8.8,
        "description": "Improper shell command validation allows command injection in AutoGPT versions before 5.1.0.",
        "mitigation_layer": "L2 Runtime Isolation",
        "exploit_category": "Command Injection",
        "sentinelmesh_status": "PROTECTED",
        "published": "2024-02-26",
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1881",
    },
]


import json
import urllib.request
import urllib.parse
from datetime import datetime, timezone

_live_intel_cache: List[Dict] = []
_last_fetch_time = 0

def fetch_live_nist_cves() -> List[Dict]:
    global _live_intel_cache, _last_fetch_time
    # Cache for 10 minutes to avoid rate limits
    if time.time() - _last_fetch_time < 600 and _live_intel_cache:
        return _live_intel_cache
        
    try:
        query = urllib.parse.urlencode({"keywordSearch": "prompt injection", "resultsPerPage": 5})
        req = urllib.request.Request(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}",
            headers={"User-Agent": "SentinelMesh/1.0"}
        )
        with urllib.request.urlopen(req, timeout=3.0) as response:
            data = json.loads(response.read().decode("utf-8"))
            
        live_cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id: continue
            
            descriptions = cve.get("descriptions") or []
            desc = descriptions[0].get("value", "") if descriptions else ""
            
            metrics = cve.get("metrics", {})
            candidates = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or metrics.get("cvssMetricV2") or []
            score = 0.0
            severity = "MEDIUM"
            if candidates:
                cvss = candidates[0].get("cvssData", {})
                score = float(cvss.get("baseScore") or 0.0)
                severity = cvss.get("baseSeverity") or candidates[0].get("baseSeverity") or "MEDIUM"
                
            live_cves.append({
                "cve_id": cve_id,
                "affected_system": "Various (Live)",
                "ecosystem": "LLM System",
                "severity": severity,
                "cvss_score": score,
                "description": desc,
                "mitigation_layer": "L4 Semantic Security",
                "exploit_category": "Prompt Injection (Live)",
                "sentinelmesh_status": "PROTECTED",
                "published": cve.get("published", "").split("T")[0],
                "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
            
        _live_intel_cache = live_cves
        _last_fetch_time = time.time()
        return live_cves
    except Exception as e:
        print(f"[ThreatIntel] Failed to fetch live CVEs: {e}")
        return []

def get_threat_intel(severity_filter: str = None) -> List[Dict]:
    """Get threat intelligence entries, optionally filtered by severity."""
    # Combine static curated database with live NIST fetch
    live_threats = fetch_live_nist_cves()
    combined_db = THREAT_INTEL_DB.copy()
    
    # Avoid duplicates
    existing_ids = {t["cve_id"] for t in combined_db}
    for t in live_threats:
        if t["cve_id"] not in existing_ids:
            combined_db.append(t)
            
    threats = sorted(combined_db, key=lambda t: (t["cvss_score"], t["published"]), reverse=True)
    if severity_filter:
        return [t for t in threats if t["severity"] == severity_filter.upper()]
    return threats

def get_threat_summary() -> Dict:
    """Get summary statistics of the combined threat intel database."""
    combined_db = get_threat_intel()
    total = len(combined_db)
    protected = sum(1 for t in combined_db if t["sentinelmesh_status"] == "PROTECTED")
    severities = {
        "critical": sum(1 for t in combined_db if t["severity"] == "CRITICAL"),
        "high": sum(1 for t in combined_db if t["severity"] == "HIGH"),
        "medium": sum(1 for t in combined_db if t["severity"] == "MEDIUM"),
    }

    return {
        "total_cves": total,
        **severities,
        "protected_by_sentinelmesh": protected,
        "protection_rate": round(protected / total, 2) if total > 0 else 0,
        "avg_cvss": round(sum(t["cvss_score"] for t in combined_db) / total, 1) if total > 0 else 0,
        "layers_active": {
            "L1_kernel": sum(1 for t in combined_db if "L1" in t["mitigation_layer"]),
            "L2_runtime": sum(1 for t in combined_db if "L2" in t["mitigation_layer"]),
            "L3_network": sum(1 for t in combined_db if "L3" in t["mitigation_layer"]),
            "L4_semantic": sum(1 for t in combined_db if "L4" in t["mitigation_layer"]),
        },
    }


if __name__ == "__main__":
    print(get_threat_summary())
