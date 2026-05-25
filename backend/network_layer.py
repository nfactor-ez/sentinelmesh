"""
SentinelMesh — L3 Network Security Layer
Simulates Cilium + eBPF network-level enforcement:
  - Token-bucket rate limiting per client IP
  - IP reputation scoring (known bad ASNs / ranges)
  - Request pattern analysis (scan detection, flooding)
  - Service mesh policy (which caller can call which endpoint)
  - mTLS session tracking
  - Content-Length / payload bomb detection

All decisions happen BEFORE L4 (semantic) analysis.
In production this logic lives inside eBPF XDP/TC programs
compiled into the Linux kernel; here it runs in Python to make
the concept testable on any OS.
"""

import re
import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════
# Rate Limiter — Token Bucket per (ip, endpoint)
# ═══════════════════════════════════════════════════════════

class _TokenBucket:
    """Thread-safe token bucket rate limiter."""
    def __init__(self, capacity: int, refill_rate: float):
        self._capacity = capacity      # max tokens
        self._tokens = capacity
        self._rate = refill_rate       # tokens / second
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, tokens: int = 1) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self._tokens = min(self._capacity,
                               self._tokens + elapsed * self._rate)
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False


_rate_buckets: Dict[str, _TokenBucket] = {}
_rate_lock = threading.Lock()

# Default policy: 30 req/s burst-10 for normal clients
RATE_LIMIT_CAPACITY   = 30
RATE_LIMIT_REFILL     = 10.0   # tokens/second
RATE_LIMIT_STRICT_CAP = 5      # for flagged IPs


def _get_bucket(client_ip: str, strict: bool = False) -> _TokenBucket:
    key = f"{'s' if strict else 'n'}:{client_ip}"
    with _rate_lock:
        if key not in _rate_buckets:
            cap    = RATE_LIMIT_STRICT_CAP if strict else RATE_LIMIT_CAPACITY
            refill = 1.0 if strict else RATE_LIMIT_REFILL
            _rate_buckets[key] = _TokenBucket(cap, refill)
        return _rate_buckets[key]


# ═══════════════════════════════════════════════════════════
# IP Reputation — block known-bad CIDR ranges
# ═══════════════════════════════════════════════════════════

# Known bad IP prefixes (Tor exit nodes, Shodan scanners, abuse ranges).
# In production Cilium pulls these from Threat Intel feeds via CiliumNetworkPolicy.
BAD_IP_PREFIXES: List[str] = [
    "185.220.",   # Tor exit nodes
    "199.87.",    # Shodan scanners
    "198.235.",   # known bulk scanners
    "89.248.",    # Shodan
    "93.174.",    # bulletproof hosting
    "5.188.",     # abuse hosting
    "91.92.",     # known C2 range
    "194.165.",   # spam/abuse
]

# IPs we've already flagged locally this session
_flagged_ips: Dict[str, Dict] = {}
_flagged_lock = threading.Lock()


def _ip_reputation(client_ip: str) -> Tuple[bool, str]:
    """Returns (is_bad, reason). Bad IPs are rate-limited or blocked."""
    for prefix in BAD_IP_PREFIXES:
        if client_ip.startswith(prefix):
            return True, f"IP in known-bad range {prefix}*"
    with _flagged_lock:
        if client_ip in _flagged_ips:
            info = _flagged_ips[client_ip]
            return True, f"Previously flagged: {info['reason']}"
    return False, ""


def flag_ip(client_ip: str, reason: str):
    """Mark an IP as suspicious for this session."""
    with _flagged_lock:
        _flagged_ips[client_ip] = {
            "reason": reason,
            "flagged_at": datetime.now(timezone.utc).isoformat(),
        }


# ═══════════════════════════════════════════════════════════
# Scan / Flood Pattern Detection
# ═══════════════════════════════════════════════════════════

# Sliding-window request counters per IP (last 60 s)
_request_windows: Dict[str, deque] = defaultdict(deque)
_windows_lock = threading.Lock()
SCAN_WINDOW_SECONDS = 60
SCAN_THRESHOLD      = 100   # >100 requests / 60 s = port scan / flood
BURST_WINDOW        = 5     # burst in 5 s
BURST_THRESHOLD     = 20    # >20 req / 5 s = burst attack


def _detect_scan(client_ip: str) -> Tuple[bool, str]:
    now = time.monotonic()
    with _windows_lock:
        q = _request_windows[client_ip]
        q.append(now)
        # Expire old entries
        while q and (now - q[0]) > SCAN_WINDOW_SECONDS:
            q.popleft()
        total_60s = len(q)
        burst_5s  = sum(1 for t in q if (now - t) <= BURST_WINDOW)

    if burst_5s >= BURST_THRESHOLD:
        return True, f"Burst flood: {burst_5s} requests in {BURST_WINDOW}s"
    if total_60s >= SCAN_THRESHOLD:
        return True, f"Scan pattern: {total_60s} requests in {SCAN_WINDOW_SECONDS}s"
    return False, ""


# ═══════════════════════════════════════════════════════════
# Service Mesh Policy  (which service → which endpoint)
# ═══════════════════════════════════════════════════════════

# Allowed caller → endpoint mappings.
# In production these are CiliumNetworkPolicy resources.
MESH_POLICY: Dict[str, List[str]] = {
    "frontend":     ["/api/firewall", "/api/firewall/hf", "/api/stats",
                     "/api/threat-feed", "/api/audit-log", "/api/live-cves",
                     "/api/verify-integrity", "/api/simulate", "/ws/live",
                     "/api/benchmark", "/api/benchmark/status", "/api/waves",
                     "/api/cilium/status", "/api/network/status",
                     "/api/runtime/status", "/api/kernel/status"],
    "red-team-agent": ["/api/firewall", "/api/firewall/hf"],
    "monitor":      ["/api/stats", "/api/threat-feed"],
    "admin":        ["*"],   # wildcard
    "unknown":      ["/api/firewall/hf", "/"],  # minimal public access
}


def _check_mesh_policy(caller_service: str, endpoint: str) -> Tuple[bool, str]:
    """Returns (allowed, reason)."""
    allowed_paths = MESH_POLICY.get(caller_service,
                                     MESH_POLICY["unknown"])
    if "*" in allowed_paths:
        return True, ""
    if endpoint in allowed_paths:
        return True, ""
    # Prefix match
    for path in allowed_paths:
        if endpoint.startswith(path.rstrip("*")):
            return True, ""
    return False, f"Mesh policy: '{caller_service}' not permitted to call {endpoint}"


# ═══════════════════════════════════════════════════════════
# mTLS Session Registry
# ═══════════════════════════════════════════════════════════

_mtls_sessions: Dict[str, Dict] = {}
_mtls_lock = threading.Lock()


def register_mtls_session(session_id: str, client_cert_cn: str,
                          service_identity: str):
    """Register a verified mTLS session."""
    with _mtls_lock:
        _mtls_sessions[session_id] = {
            "client_cert_cn":   client_cert_cn,
            "service_identity": service_identity,
            "established_at":   datetime.now(timezone.utc).isoformat(),
            "verified":         True,
        }


def verify_mtls_session(session_id: Optional[str]) -> Tuple[bool, Dict]:
    """Returns (valid, session_info). Missing session_id is treated as
    unverified (allowed but tagged for stricter downstream checks)."""
    if not session_id:
        return False, {"reason": "No mTLS session header present"}
    with _mtls_lock:
        session = _mtls_sessions.get(session_id)
    if not session:
        return False, {"reason": f"Unknown session {session_id}"}
    return True, session


# ═══════════════════════════════════════════════════════════
# Payload Validation
# ═══════════════════════════════════════════════════════════

MAX_PROMPT_BYTES   = 32_768    # 32 KB — anything larger is a payload bomb
MAX_PROMPT_LINES   = 500


def _validate_payload(prompt: str) -> Tuple[bool, str]:
    """Reject oversized payloads before they hit the ML model."""
    byte_len = len(prompt.encode("utf-8"))
    if byte_len > MAX_PROMPT_BYTES:
        return False, (f"Payload bomb: {byte_len:,} bytes "
                       f"(limit {MAX_PROMPT_BYTES:,})")
    if prompt.count("\n") > MAX_PROMPT_LINES:
        return False, (f"Payload bomb: {prompt.count(chr(10))} lines "
                       f"(limit {MAX_PROMPT_LINES})")
    return True, ""


# ═══════════════════════════════════════════════════════════
# Suspicious Header / Request Patterns
# ═══════════════════════════════════════════════════════════

SUSPICIOUS_UA_PATTERNS = [
    r"sqlmap", r"nikto", r"nmap", r"masscan", r"zgrab",
    r"nuclei", r"gobuster", r"dirbuster", r"metasploit",
    r"burpsuite", r"hydra", r"medusa", r"wfuzz",
]
_UA_RE = re.compile("|".join(SUSPICIOUS_UA_PATTERNS), re.IGNORECASE)


def _check_user_agent(ua: str) -> Tuple[bool, str]:
    if not ua:
        return False, ""   # Missing UA is suspicious but not blocked
    m = _UA_RE.search(ua)
    if m:
        return True, f"Scanner user-agent detected: {m.group()}"
    return False, ""


# ═══════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════

def network_layer_check(
    prompt: str,
    client_ip: str   = "127.0.0.1",
    endpoint: str    = "/api/firewall/hf",
    caller_service: str = "frontend",
    user_agent: str  = "",
    session_id: Optional[str] = None,
) -> Dict:
    """
    Run the full L3 network security check.
    Returns a standardised result dict.
    """
    start = time.monotonic()
    checks: List[Dict] = []
    blocked = False
    block_reason = ""

    # ── 1. IP reputation ────────────────────────────────────
    bad_ip, ip_reason = _ip_reputation(client_ip)
    checks.append({"check": "ip_reputation", "passed": not bad_ip,
                   "detail": ip_reason or "clean"})
    if bad_ip:
        # Don't hard-block known bad IPs — apply strict rate limiting instead
        strict_bucket = _get_bucket(client_ip, strict=True)
        if not strict_bucket.consume():
            blocked = True
            block_reason = f"Rate limit exceeded for flagged IP: {ip_reason}"

    # ── 2. Rate limit ────────────────────────────────────────
    if not blocked:
        bucket = _get_bucket(client_ip, strict=bad_ip)
        if not bucket.consume():
            blocked = True
            block_reason = f"Rate limit exceeded from {client_ip}"
            flag_ip(client_ip, "Rate limit violation")
        checks.append({"check": "rate_limit", "passed": not blocked,
                       "detail": "within limit" if not blocked else block_reason})

    # ── 3. Scan / flood detection ────────────────────────────
    if not blocked:
        is_scan, scan_reason = _detect_scan(client_ip)
        checks.append({"check": "scan_detection", "passed": not is_scan,
                       "detail": scan_reason or "no flood pattern"})
        if is_scan:
            blocked = True
            block_reason = scan_reason
            flag_ip(client_ip, scan_reason)

    # ── 4. Service mesh policy ───────────────────────────────
    if not blocked:
        allowed, mesh_reason = _check_mesh_policy(caller_service, endpoint)
        checks.append({"check": "mesh_policy", "passed": allowed,
                       "detail": mesh_reason or f"{caller_service} → {endpoint} allowed"})
        if not allowed:
            blocked = True
            block_reason = mesh_reason

    # ── 5. mTLS session ─────────────────────────────────────
    mtls_valid, mtls_info = verify_mtls_session(session_id)
    checks.append({"check": "mtls_session", "passed": mtls_valid,
                   "detail": mtls_info.get("reason", "session verified")
                             if not mtls_valid
                             else f"verified CN={mtls_info.get('client_cert_cn','?')}"})
    # mTLS failure is a WARNING, not a hard block, in demo mode

    # ── 6. Payload validation ────────────────────────────────
    if not blocked:
        payload_ok, payload_reason = _validate_payload(prompt)
        checks.append({"check": "payload_size", "passed": payload_ok,
                       "detail": payload_reason or f"{len(prompt)} chars — OK"})
        if not payload_ok:
            blocked = True
            block_reason = payload_reason

    # ── 7. User-agent ────────────────────────────────────────
    if not blocked:
        bad_ua, ua_reason = _check_user_agent(user_agent)
        checks.append({"check": "user_agent", "passed": not bad_ua,
                       "detail": ua_reason or "user-agent clean"})
        if bad_ua:
            blocked = True
            block_reason = ua_reason
            flag_ip(client_ip, ua_reason)

    latency_us = (time.monotonic() - start) * 1_000_000   # microseconds

    return {
        "layer":          "L3",
        "layer_name":     "Network Security (Cilium/eBPF)",
        "passed":         not blocked,
        "blocked":        blocked,
        "block_reason":   block_reason,
        "checks":         checks,
        "client_ip":      client_ip,
        "mtls_valid":     mtls_valid,
        "caller_service": caller_service,
        "latency_us":     round(latency_us, 1),
        "timestamp":      datetime.now(timezone.utc).isoformat(),
    }


def get_network_stats() -> Dict:
    """Return current L3 metrics for the dashboard."""
    with _rate_lock:
        active_buckets = len(_rate_buckets)
    with _windows_lock:
        tracked_ips = len(_request_windows)
    with _flagged_lock:
        flagged_count = len(_flagged_ips)
    with _mtls_lock:
        sessions = len(_mtls_sessions)
    return {
        "active_rate_buckets": active_buckets,
        "tracked_ips":         tracked_ips,
        "flagged_ips":         flagged_count,
        "mtls_sessions":       sessions,
        "policies_loaded":     len(MESH_POLICY),
        "bad_ip_ranges":       len(BAD_IP_PREFIXES),
        "rate_limit_capacity": RATE_LIMIT_CAPACITY,
        "rate_limit_refill":   RATE_LIMIT_REFILL,
    }


# ── Self-test ──
if __name__ == "__main__":
    results = [
        network_layer_check("Hello world"),
        network_layer_check("hack the bank", client_ip="185.220.101.1"),
        network_layer_check("x" * 40_000),   # payload bomb
        network_layer_check("test", user_agent="sqlmap/1.6"),
    ]
    for r in results:
        print(f"[{r['layer']}] passed={r['passed']} | "
              f"blocked={r['blocked']} | reason={r['block_reason'] or 'OK'} | "
              f"{r['latency_us']:.0f}µs")
