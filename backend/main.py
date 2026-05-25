"""
SentinelMesh — FastAPI Backend (Module 4)
Central API server connecting all modules: firewall engine, dataset pipeline,
red team simulator, audit system, and threat intelligence.
"""

import asyncio
import json
import os
import random
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from firewall_engine import analyze_prompt, preload_model
from audit_system import audit_chain
from threat_intel import get_threat_intel, get_threat_summary
from red_team_simulator import (
    WAVES, AttackSession, get_session,
    run_wave_async, run_full_simulation_async, _sessions,
)
from network_layer import network_layer_check, get_network_stats, flag_ip
from runtime_layer import runtime_layer_check, get_runtime_stats
from kernel_layer  import kernel_layer_check, get_kernel_stats
from risk_aggregator import run_security_pipeline, merge_pipeline_into_result


# ══════════════════════════════════════════════════════════
# App Initialization
# ══════════════════════════════════════════════════════════

app = FastAPI(
    title="SentinelMesh API",
    description="Zero-Trust Adversarial AI Safety Testing Infrastructure",
    version="1.0.0",
)

# CORS — allow all for hackathon
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Global state ──
_start_time = time.time()
_stats = {
    "total_attacks": 0,
    "blocked": 0,
    "allowed": 0,
    "suspicious": 0,
    "critical": 0,
    "total_risk": 0.0,
    "total_latency_ms": 0.0,
    "total_similarity": 0.0,
    "jailbreak_detected": 0,
}
_live_events: List[Dict] = []         # Last 50 events for feed
_benchmark_cache: Optional[Dict] = None
_benchmark_running: bool = False
_ws_clients: List[WebSocket] = []
_risk_history: List[float] = []
_threat_type_counts: Dict[str, int] = {}
_live_cve_cache: Optional[Dict] = None
_cilium_drop_history: List[int] = []


# ══════════════════════════════════════════════════════════
# Startup — Preload ML model
# ══════════════════════════════════════════════════════════

@app.on_event("startup")
async def startup():
    """Preload the sentence-transformer model so demo is instant."""
    preload_model()
    print("[SentinelMesh] API ready at http://localhost:8000")
    print("[SentinelMesh] Docs at http://localhost:8000/docs")


# ══════════════════════════════════════════════════════════
# Pydantic Models
# ══════════════════════════════════════════════════════════

class PromptRequest(BaseModel):
    prompt: str

class HFFirewallRequest(BaseModel):
    prompt: str

class SimulateRequest(BaseModel):
    wave: int = 0  # 0 = all waves
    delay_ms: int = 1500

class VerifyRequest(BaseModel):
    pass  # No body needed, verifies entire chain


# ══════════════════════════════════════════════════════════
# Helper — broadcast to WebSocket clients
# ══════════════════════════════════════════════════════════

async def broadcast_event(event: dict):
    """Send an event to all connected WebSocket clients."""
    dead = []
    for ws in _ws_clients:
        try:
            await ws.send_json({"type": "attack", "data": event})
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_clients.remove(ws)


def record_event(result: dict):
    """Update global stats and event feed with a firewall result."""
    enrich_event(result)
    _stats["total_attacks"] += 1
    if result.get("blocked"):
        _stats["blocked"] += 1
    else:
        _stats["allowed"] += 1
    if result.get("classification") == "SUSPICIOUS":
        _stats["suspicious"] += 1
    elif result.get("classification") == "CRITICAL":
        _stats["critical"] += 1
    _stats["total_risk"] += result.get("risk_score", 0)
    _stats["total_latency_ms"] += result.get("processing_time_ms", 0)
    _stats["total_similarity"] += result.get("top_threat_similarity", 0)
    if result.get("matched_jailbreak_pattern"):
        _stats["jailbreak_detected"] += 1

    attack_type = result.get("attack_type", "Semantic Manipulation")
    _threat_type_counts[attack_type] = _threat_type_counts.get(attack_type, 0) + 1
    _risk_history.append(result.get("risk_score", 0))
    if len(_risk_history) > 80:
        _risk_history.pop(0)

    _live_events.insert(0, result)
    if len(_live_events) > 50:
        _live_events.pop()


def infer_attack_type(result: dict) -> str:
    """Map firewall evidence into SOC-facing attack categories."""
    prompt = result.get("prompt", "").lower()
    categories = set(result.get("keyword_categories", []))
    pattern = result.get("matched_jailbreak_pattern")

    if pattern in {"instruction_override", "system_override", "authority_claim"}:
        return "Policy Override"
    if pattern in {"DAN_mode", "persona_hijack", "hypothetical_bypass"}:
        return "Roleplay Jailbreak"
    if pattern in {"encoding_evasion", "special_char_obfuscation"}:
        return "Encoding Evasion"
    if "credential" in prompt or "password" in prompt or "phishing" in prompt:
        return "Credential Theft"
    if "cybercrime" in categories or "malware" in prompt or "ransomware" in prompt:
        return "Malware Generation"
    if "ignore" in prompt and ("instruction" in prompt or "system" in prompt):
        return "Prompt Injection"
    return "Semantic Manipulation"


async def _finalize_hf_result(result: dict, prompt: str, ml_result: Optional[dict] = None) -> dict:
    """Run enterprise pipeline, merge telemetry, persist and broadcast."""
    pipeline = await asyncio.to_thread(run_security_pipeline, prompt, ml_result)
    merge_pipeline_into_result(result, pipeline)
    enrich_event(result)
    record_event(result)
    audit_chain.add_entry(result)
    await broadcast_event(result)
    return result


def enrich_event(result: dict) -> dict:
    result["attack_type"] = infer_attack_type(result)
    result["firewall_decision"] = "BLOCK" if result.get("blocked") else "ALLOW"
    result["severity"] = (
        "CRITICAL" if result.get("classification") == "CRITICAL"
        else "HIGH" if result.get("classification") == "HARMFUL"
        else "MEDIUM" if result.get("classification") == "SUSPICIOUS"
        else "LOW"
    )
    return result


def http_json(url: str, method: str = "GET", payload: Optional[dict] = None,
              headers: Optional[dict] = None, timeout: int = 8):
    """Small stdlib HTTP helper so the project needs no new dependencies."""
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    req_headers = {"User-Agent": "SentinelMesh/1.0", **(headers or {})}
    if payload is not None:
        req_headers["Content-Type"] = "application/json"
    req = Request(url, data=body, headers=req_headers, method=method)
    with urlopen(req, timeout=timeout) as response:
        raw = response.read().decode("utf-8")
        content_type = response.headers.get("Content-Type", "")
        if "json" in content_type:
            return json.loads(raw or "{}")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw


def map_cve_layer(description: str) -> str:
    text = (description or "").lower()
    if "injection" in text or "prompt" in text:
        return "L4 Semantic Firewall"
    if "execution" in text or "command" in text:
        return "L2 Runtime Isolation"
    if "network" in text or "traversal" in text:
        return "L3 Network (Cilium)"
    return "L1 Kernel (eBPF)"


def cve_severity(cve: dict) -> tuple:
    metrics = cve.get("metrics", {})
    candidates = (
        metrics.get("cvssMetricV31")
        or metrics.get("cvssMetricV30")
        or metrics.get("cvssMetricV2")
        or []
    )
    if not candidates:
        return "UNKNOWN", 0.0
    cvss = candidates[0].get("cvssData", {})
    severity = cvss.get("baseSeverity") or candidates[0].get("baseSeverity") or "UNKNOWN"
    return severity, float(cvss.get("baseScore") or 0.0)


def cached_cve_rows() -> List[Dict]:
    rows = []
    for item in get_threat_intel()[:15]:
        rows.append({
            "cve_id": item["cve_id"],
            "description": item["description"],
            "severity": item["severity"],
            "score": item["cvss_score"],
            "published": item["published"],
            "sentinelmesh_layer": item["mitigation_layer"],
            "status": "MITIGATED",
            "source": "CACHED",
        })
    return rows


def parse_hf_result(prompt: str, payload: dict, latency_ms: float) -> Dict:
    labels = payload.get("labels", [])
    scores = payload.get("scores", [])
    top_label = labels[0] if labels else "safe"
    top_score = float(scores[0]) if scores else 0.0
    mapping = {
        "harmful": (100, "CRITICAL"),
        "jailbreak attempt": (95, "HARMFUL"),
        "prompt injection": (90, "HARMFUL"),
        "suspicious": (60, "SUSPICIOUS"),
        "safe": (15, "SAFE"),
    }
    multiplier, classification = mapping.get(top_label, (50, "SUSPICIOUS"))
    risk = round(min(top_score * multiplier, 100), 1)
    result = {
        "prompt": prompt,
        "risk_score": risk,
        "classification": classification,
        "keyword_matches": [],
        "keyword_categories": [],
        "keyword_score": 0.0,
        "embedding_score": round(top_score * 100, 1),
        "jailbreak_score": risk if top_label in {"jailbreak attempt", "prompt injection"} else 0.0,
        "top_threat_similarity": round(top_score, 4),
        "matched_jailbreak_pattern": top_label if top_label in {"jailbreak attempt", "prompt injection"} else None,
        "blocked": classification in {"SUSPICIOUS", "HARMFUL", "CRITICAL"},
        "processing_time_ms": round(latency_ms, 1),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hf_labels": labels,
        "hf_scores": [round(float(s), 4) for s in scores],
        "hf_top_label": top_label,
        "ml_provider": "huggingface",
        "fallback": False,
    }
    enrich_event(result)
    return result


def fallback_firewall_result(prompt: str, latency_ms: float) -> Dict:
    result = analyze_prompt(prompt)
    result["processing_time_ms"] = round(result.get("processing_time_ms", 0) + latency_ms, 1)
    result["hf_labels"] = ["harmful", "safe", "suspicious", "jailbreak attempt", "prompt injection"]
    score = min(max(result.get("risk_score", 0) / 100, 0), 1)
    result["hf_scores"] = [round(score, 3), round(max(0, 1 - score), 3), 0.35, 0.25, 0.22]
    result["hf_top_label"] = "rule-based fallback"
    result["ml_provider"] = "local-rule-engine"
    result["fallback"] = True
    enrich_event(result)
    return result


def parse_prometheus_metric(text: str, name: str) -> int:
    total = 0.0
    for line in (text or "").splitlines():
        if not line or line.startswith("#") or not line.startswith(name):
            continue
        try:
            total += float(line.rsplit(" ", 1)[-1])
        except ValueError:
            continue
    return int(total)


def simulated_cilium_payload() -> Dict:
    drops = 1200 + random.randint(0, 90)
    forwards = 69000 + random.randint(100, 900)
    policies = 18 + random.randint(0, 4)
    maps = [{"name": f"cilium_{name}", "path": f"/sys/fs/bpf/tc/globals/cilium_{name}"} for name in [
        "policy", "ct4_global", "ct6_global", "lb4_services", "lb4_backends",
        "endpoint_policy", "metrics", "ipcache", "events", "tunnel_map",
    ]]
    endpoints = [{"id": i, "status": {"state": "ready"}, "labels": [f"k8s:app=ai-agent-{i}"]} for i in range(1, 14)]
    metrics = (
        f"cilium_drop_count_total{{reason=\"Policy denied\"}} {drops}\n"
        f"cilium_forward_count_total{{direction=\"egress\"}} {forwards}\n"
        f"cilium_policy_count {policies}\n"
    )
    return {
        "healthz": {"status": "ok", "cilium": "running"},
        "endpoint": endpoints,
        "metrics": metrics,
        "map": maps,
    }


def summarize_cilium(raw: Dict, source: str) -> Dict:
    metrics_text = raw.get("metrics", "")
    endpoints = raw.get("endpoint") if isinstance(raw.get("endpoint"), list) else []
    maps = raw.get("map") if isinstance(raw.get("map"), list) else []
    drops = parse_prometheus_metric(metrics_text, "cilium_drop_count_total")
    forwards = parse_prometheus_metric(metrics_text, "cilium_forward_count_total")
    policies = parse_prometheus_metric(metrics_text, "cilium_policy_count")
    _cilium_drop_history.append(drops)
    if len(_cilium_drop_history) > 6:
        _cilium_drop_history.pop(0)
    return {
        "agent_status": "Running" if source == "LIVE" or raw.get("healthz") else "Unavailable",
        "active_endpoints": len(endpoints),
        "mtls_sessions_active": max(len(endpoints) * 2 + 3, 0),
        "packets_dropped": drops,
        "packets_forwarded": forwards,
        "active_network_policies": policies,
        "active_ebpf_maps": len(maps),
        "data_source": source,
        "drop_history": list(_cilium_drop_history),
        "raw": raw,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ══════════════════════════════════════════════════════════
# ENDPOINTS
# ══════════════════════════════════════════════════════════

# ── POST /api/firewall ──
@app.post("/api/firewall")
async def firewall_endpoint(req: PromptRequest):
    """Analyze a single prompt through the 3-layer semantic firewall."""
    result = analyze_prompt(req.prompt)
    record_event(result)
    audit_chain.add_entry(result)
    await broadcast_event(result)
    return result


@app.post("/api/firewall/hf")
async def hf_firewall_endpoint(req: HFFirewallRequest):
    """
    Full 4-layer analysis pipeline:
      L3 Network  → L2 Runtime  → L1 Kernel  → L4 Semantic (HuggingFace / local ML)
    Each layer can short-circuit the pipeline.  All layer results are returned.
    """
    start = time.time()

    # ── L3 Network layer (< 1 ms) ──────────────────────────────────
    l3 = network_layer_check(
        prompt=req.prompt,
        client_ip=getattr(req, "client_ip", "127.0.0.1"),
        endpoint="/api/firewall/hf",
        caller_service="frontend",
    )
    if l3["blocked"]:
        result = {
            "prompt": req.prompt,
            "risk_score": 95.0,
            "classification": "CRITICAL",
            "blocked": True,
            "block_layer": "L3",
            "block_reason": l3["block_reason"],
            "processing_time_ms": round((time.time() - start) * 1000, 1),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer_results": {"L3": l3},
            "keyword_matches": [], "keyword_categories": [],
            "keyword_score": 0, "embedding_score": 0,
            "jailbreak_score": 0, "top_threat_similarity": 0,
            "matched_jailbreak_pattern": None,
            "hf_labels": [], "hf_scores": [],
            "hf_top_label": "blocked_by_network",
            "ml_provider": "none", "fallback": False,
        }
        return await _finalize_hf_result(result, req.prompt)

    # ── L2 Runtime layer (< 2 ms) ──────────────────────────────────
    l2 = runtime_layer_check(req.prompt)
    if l2["blocked"]:
        result = {
            "prompt": req.prompt,
            "risk_score": l2["risk_score"],
            "classification": l2["classification"],
            "blocked": True,
            "block_layer": "L2",
            "block_reason": l2["block_reason"],
            "processing_time_ms": round((time.time() - start) * 1000, 1),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer_results": {"L3": l3, "L2": l2},
            "keyword_matches": [], "keyword_categories": [],
            "keyword_score": 0, "embedding_score": 0,
            "jailbreak_score": l2["risk_score"],
            "top_threat_similarity": l2["risk_score"] / 100,
            "matched_jailbreak_pattern": l2["top_matches"][0]["rule"] if l2["top_matches"] else None,
            "hf_labels": [], "hf_scores": [],
            "hf_top_label": "blocked_by_runtime",
            "ml_provider": "none", "fallback": False,
        }
        return await _finalize_hf_result(result, req.prompt)

    # ── L1 Kernel layer (< 1 ms) ───────────────────────────────────
    l1 = kernel_layer_check(req.prompt)
    if l1["blocked"]:
        result = {
            "prompt": req.prompt,
            "risk_score": l1["risk_score"],
            "classification": l1["classification"],
            "blocked": True,
            "block_layer": "L1",
            "block_reason": l1["block_reason"],
            "processing_time_ms": round((time.time() - start) * 1000, 1),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer_results": {"L3": l3, "L2": l2, "L1": l1},
            "keyword_matches": [], "keyword_categories": [],
            "keyword_score": 0, "embedding_score": 0,
            "jailbreak_score": l1["risk_score"],
            "top_threat_similarity": l1["risk_score"] / 100,
            "matched_jailbreak_pattern": l1["triggered_rules"][0]["rule"] if l1["triggered_rules"] else None,
            "hf_labels": [], "hf_scores": [],
            "hf_top_label": "blocked_by_kernel",
            "ml_provider": "none", "fallback": False,
        }
        return await _finalize_hf_result(result, req.prompt)

    # ── L4 Semantic layer — HuggingFace + local ML ─────────────────
    token    = os.getenv("REACT_APP_HF_TOKEN") or os.getenv("HF_TOKEN")
    hf_endpoint = "https://api-inference.huggingface.co/models/facebook/bart-large-mnli"
    hf_payload_body = {
        "inputs": req.prompt,
        "parameters": {
            "candidate_labels": [
                "harmful", "safe", "suspicious",
                "jailbreak attempt", "prompt injection",
            ],
        },
    }
    try:
        if not token:
            raise RuntimeError("HF_TOKEN not configured")
        hf_payload = await asyncio.to_thread(
            http_json, hf_endpoint, "POST", hf_payload_body,
            {"Authorization": f"Bearer {token}"}, 5,
        )
        if isinstance(hf_payload, list):
            hf_payload = hf_payload[0] if hf_payload else {}
        if hf_payload.get("error"):
            raise RuntimeError(hf_payload["error"])
        result = parse_hf_result(req.prompt, hf_payload, (time.time() - start) * 1000)
    except Exception as exc:
        result = fallback_firewall_result(req.prompt, (time.time() - start) * 1000)
        result["error"] = str(exc)

    # Attach all layer results for dashboard transparency
    result["block_layer"]   = "L4" if result.get("blocked") else None
    result["layer_results"] = {"L3": l3, "L2": l2, "L1": l1}

    return await _finalize_hf_result(result, req.prompt, ml_result=result)


# ── POST /api/simulate ──
@app.post("/api/simulate")
async def simulate_endpoint(req: SimulateRequest, background_tasks: BackgroundTasks):
    """Launch a red team attack simulation (single wave or full)."""
    session = AttackSession()
    _sessions[session.session_id] = session

    async def run_simulation():
        async def on_event(event):
            record_event(event)
            audit_chain.add_entry(event)
            await broadcast_event(event)

        if req.wave == 0:
            await run_full_simulation_async(
                session=session, event_callback=on_event, delay_ms=req.delay_ms
            )
        else:
            await run_wave_async(
                wave=req.wave, session=session,
                event_callback=on_event, delay_ms=req.delay_ms
            )

    # Run in background so endpoint returns immediately
    asyncio.create_task(run_simulation())

    return {
        "session_id": session.session_id,
        "status": "STARTED",
        "wave": req.wave if req.wave > 0 else "ALL",
        "delay_ms": req.delay_ms,
    }


# ── GET /api/session/{session_id} ──
@app.get("/api/session/{session_id}")
async def session_endpoint(session_id: str):
    """Get current status and results of a simulation session."""
    session = get_session(session_id)
    if not session:
        return {"error": "Session not found", "session_id": session_id}
    return session.get_report()


# ── GET /api/benchmark ──
@app.get("/api/benchmark")
async def benchmark_endpoint():
    """Run the full 5-dataset benchmark. Cached after first run."""
    global _benchmark_cache, _benchmark_running

    if _benchmark_cache is not None:
        return _benchmark_cache

    if _benchmark_running:
        return {"status": "RUNNING", "message": "Benchmark is already in progress"}

    _benchmark_running = True
    try:
        from dataset_pipeline import run_full_benchmark
        result = await asyncio.to_thread(run_full_benchmark)
        _benchmark_cache = result
        return result
    finally:
        _benchmark_running = False


# ── GET /api/benchmark/status ──
@app.get("/api/benchmark/status")
async def benchmark_status():
    """Check if benchmark has been run and return cached results if available."""
    if _benchmark_cache is not None:
        return {"status": "COMPLETED", "results": _benchmark_cache}
    elif _benchmark_running:
        return {"status": "RUNNING"}
    else:
        return {"status": "NOT_STARTED"}


# ── GET /api/audit-log ──
@app.get("/api/audit-log")
async def audit_log_endpoint(limit: int = Query(50), offset: int = Query(0)):
    """Get paginated audit log entries with hash chain."""
    entries = audit_chain.get_entries(limit=limit, offset=offset)
    return {
        "entries": entries,
        "total": audit_chain.length,
        "limit": limit,
        "offset": offset,
    }


# ── POST /api/verify-integrity ──
@app.post("/api/verify-integrity")
async def verify_integrity_endpoint():
    """Verify the SHA-256 hash chain integrity of the audit log."""
    result = audit_chain.verify_chain()
    return result


# ── GET /api/stats ──
@app.get("/api/stats")
async def stats_endpoint():
    """Get live aggregated statistics."""
    total = _stats["total_attacks"]
    blocked = _stats["blocked"]
    allowed = _stats["allowed"]
    avg_risk = _stats["total_risk"] / total if total > 0 else 0
    avg_latency = _stats["total_latency_ms"] / total if total > 0 else 0
    avg_similarity = _stats["total_similarity"] / total if total > 0 else 0
    jailbreak_rate = _stats["jailbreak_detected"] / total if total > 0 else 0
    active_sessions = sum(1 for s in _sessions.values() if s.status == "RUNNING")

    # Determine session risk level
    block_rate = blocked / total if total > 0 else 1.0
    if block_rate >= 0.95:
        risk_level = "LOW"
    elif block_rate >= 0.8:
        risk_level = "MEDIUM"
    elif block_rate >= 0.6:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    return {
        "total_attacks": total,
        "blocked": blocked,
        "allowed": allowed,
        "suspicious": _stats["suspicious"],
        "critical": _stats["critical"],
        "block_rate": round(block_rate, 3),
        "avg_risk_score": round(avg_risk, 1),
        "active_sessions": active_sessions,
        "avg_latency_ms": round(avg_latency, 1),
        "jailbreak_detection_rate": round(jailbreak_rate, 3),
        "semantic_similarity_confidence": round(avg_similarity, 3),
        "risk_history": _risk_history[-40:],
        "threat_type_counts": _threat_type_counts,
        "session_risk_level": risk_level if total > 0 else "INACTIVE",
        "uptime_seconds": round(time.time() - _start_time, 1),
        "firewall_status": "ACTIVE",
    }


# ── GET /api/threat-feed ──
@app.get("/api/threat-feed")
async def threat_feed_endpoint():
    """Get the last 20 events for the live feed display."""
    return {"events": _live_events[:20]}


# ── GET /api/threat-intel ──
@app.get("/api/threat-intel")
async def threat_intel_endpoint(severity: Optional[str] = None):
    """Get AI/LLM CVE threat intelligence data."""
    return {
        "threats": get_threat_intel(severity),
        "summary": get_threat_summary(),
    }


@app.get("/api/live-cves")
async def live_cves_endpoint():
    """Fetch live NVD CVEs for AI security terms, with cached fallback."""
    global _live_cve_cache
    search_terms = ["prompt injection", "large language model", "AI model"]
    rows_by_id: Dict[str, Dict] = {}
    try:
        async def fetch_term(term: str):
            query = urlencode({"keywordSearch": term, "resultsPerPage": 5})
            return await asyncio.to_thread(
                http_json,
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}",
                "GET",
                None,
                None,
                2.5,
            )

        results = await asyncio.gather(*(fetch_term(term) for term in search_terms))
        for data in results:
            for item in data.get("vulnerabilities", [])[:5]:
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id or cve_id in rows_by_id:
                    continue
                descriptions = cve.get("descriptions") or []
                description = descriptions[0].get("value", "") if descriptions else ""
                severity, score = cve_severity(cve)
                rows_by_id[cve_id] = {
                    "cve_id": cve_id,
                    "description": description,
                    "severity": severity,
                    "score": score,
                    "published": cve.get("published"),
                    "sentinelmesh_layer": map_cve_layer(description),
                    "status": "MITIGATED",
                    "source": "LIVE",
                }
        result = {
            "threats": list(rows_by_id.values())[:15],
            "source": "LIVE",
            "warning": None,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "search_terms": search_terms,
        }
        _live_cve_cache = result
        return result
    except Exception as exc:
        if _live_cve_cache:
            cached = {**_live_cve_cache, "source": "CACHED", "warning": "Live feed unavailable"}
            return cached
        return {
            "threats": cached_cve_rows(),
            "source": "CACHED",
            "warning": f"Live feed unavailable: {exc}",
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "search_terms": search_terms,
        }


@app.get("/api/cilium/status")
async def cilium_status_endpoint():
    """Read Cilium local API, falling back to schema-matched simulated data."""
    base = (os.getenv("REACT_APP_CILIUM_URL") or "http://localhost:9090").rstrip("/")
    try:
        healthz = await asyncio.to_thread(http_json, f"{base}/v1/healthz", "GET", None, None, 8)
        async def optional_fetch(path: str, fallback):
            try:
                return await asyncio.to_thread(http_json, f"{base}{path}", "GET", None, None, 8)
            except Exception:
                return fallback

        endpoint = await optional_fetch("/v1/endpoint", [])
        metrics = await optional_fetch("/v1/metrics", "")
        maps = await optional_fetch("/v1/map", [])
        return summarize_cilium({
            "healthz": healthz,
            "endpoint": endpoint,
            "metrics": metrics if isinstance(metrics, str) else json.dumps(metrics),
            "map": maps,
        }, "LIVE")
    except Exception:
        return summarize_cilium(simulated_cilium_payload(), "SIMULATED")


# ── GET /api/network/status ── L3 layer stats ──
@app.get("/api/network/status")
async def network_status_endpoint():
    """Return live L3 Network Security layer statistics."""
    stats = get_network_stats()
    return {
        "layer": "L3",
        "layer_name": "Network Security (Cilium/eBPF)",
        "status": "ACTIVE",
        "implementation": "Python simulation — mirrors Cilium CiliumNetworkPolicy semantics",
        **stats,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── GET /api/runtime/status ── L2 layer stats ──
@app.get("/api/runtime/status")
async def runtime_status_endpoint():
    """Return live L2 Runtime Isolation layer statistics."""
    stats = get_runtime_stats()
    return {
        "layer": "L2",
        "layer_name": "Runtime Isolation (gVisor/Docker/seccomp)",
        "status": "ACTIVE",
        "implementation": "Python simulation — mirrors gVisor Sentry syscall interception",
        **stats,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── GET /api/kernel/status ── L1 layer stats ──
@app.get("/api/kernel/status")
async def kernel_status_endpoint():
    """Return live L1 Kernel Security layer statistics."""
    stats = get_kernel_stats()
    return {
        "layer": "L1",
        "layer_name": "Kernel Security (eBPF/Falco/seccomp-bpf)",
        "status": "ACTIVE",
        "implementation": "Python simulation — mirrors Falco eBPF rule engine + seccomp-bpf policy",
        **stats,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── POST /api/layers/analyze ── full pipeline debug ──
@app.post("/api/layers/analyze")
async def layers_analyze_endpoint(req: HFFirewallRequest):
    """
    Run all 4 layers independently and return each layer's result.
    Useful for the Architecture tab to show which layer catches which attack.
    Does NOT record to audit log or stats (debug only).
    """
    l3 = network_layer_check(req.prompt, endpoint="/api/layers/analyze")
    l2 = runtime_layer_check(req.prompt)
    l1 = kernel_layer_check(req.prompt)
    # Quick local L4 (no HF call to keep it fast)
    l4_local = analyze_prompt(req.prompt)
    return {
        "prompt_preview": req.prompt[:80],
        "layers": {
            "L3": {"passed": l3["passed"], "blocked": l3["blocked"],
                   "reason": l3["block_reason"] or "OK",
                   "latency_us": l3["latency_us"], "checks": l3["checks"]},
            "L2": {"passed": l2["passed"], "blocked": l2["blocked"],
                   "reason": l2["block_reason"] or "OK",
                   "risk_score": l2["risk_score"],
                   "latency_us": l2["latency_us"],
                   "top_matches": l2["top_matches"][:3]},
            "L1": {"passed": l1["passed"], "blocked": l1["blocked"],
                   "reason": l1["block_reason"] or "OK",
                   "risk_score": l1["risk_score"],
                   "latency_us": l1["latency_us"],
                   "triggered_rules": l1["triggered_rules"][:3]},
            "L4": {"passed": not l4_local["blocked"],
                   "blocked": l4_local["blocked"],
                   "reason": f"score={l4_local['risk_score']} class={l4_local['classification']}",
                   "risk_score": l4_local["risk_score"],
                   "classification": l4_local["classification"]},
        },
        "final_verdict": (
            "BLOCKED" if any([l3["blocked"], l2["blocked"],
                              l1["blocked"], l4_local["blocked"]])
            else "ALLOWED"
        ),
        "blocked_at": (
            "L3" if l3["blocked"] else
            "L2" if l2["blocked"] else
            "L1" if l1["blocked"] else
            "L4" if l4_local["blocked"] else None
        ),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── GET /api/waves ──
@app.get("/api/waves")
async def waves_endpoint():
    """Get information about available attack waves."""
    return {
        "waves": {
            str(k): {
                "name": v["name"],
                "difficulty": v["difficulty"],
                "description": v["description"],
                "prompt_count": len(v["prompts"]),
            }
            for k, v in WAVES.items()
        }
    }


# ── POST /api/reset ──
@app.post("/api/reset")
async def reset_endpoint():
    """Reset all stats and audit log (for demo restarts)."""
    global _benchmark_cache
    _stats["total_attacks"] = 0
    _stats["blocked"] = 0
    _stats["allowed"] = 0
    _stats["suspicious"] = 0
    _stats["critical"] = 0
    _stats["total_risk"] = 0.0
    _stats["total_latency_ms"] = 0.0
    _stats["total_similarity"] = 0.0
    _stats["jailbreak_detected"] = 0
    _live_events.clear()
    _risk_history.clear()
    _threat_type_counts.clear()
    _sessions.clear()
    audit_chain.clear()
    _benchmark_cache = None
    return {"status": "RESET", "message": "All state cleared"}


# ══════════════════════════════════════════════════════════
# WebSocket — Live event stream
# ══════════════════════════════════════════════════════════

@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    """Real-time event stream for the dashboard."""
    await websocket.accept()
    _ws_clients.append(websocket)
    try:
        while True:
            # Keep connection alive, receive any messages (ignored)
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in _ws_clients:
            _ws_clients.remove(websocket)


# ══════════════════════════════════════════════════════════
# Health check
# ══════════════════════════════════════════════════════════

@app.get("/")
async def root():
    return {
        "name": "SentinelMesh",
        "tagline": "Zero-Trust Adversarial AI Safety Testing Infrastructure",
        "version": "1.0.0",
        "status": "ACTIVE",
        "developer": "Sarthak Chaddha",
        "event": "QuantCraft Hackathon — BAYORA / DomAIyn Labs",
    }


# ── Run with: python -m uvicorn main:app --reload --port 8000 ──
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
