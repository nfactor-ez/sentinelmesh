"""Layer 6 — Syscall threat analysis and seccomp simulation."""

import re
from typing import Dict, List

SYSCALL_DB = {
    "execve": {"status": "BLOCKED", "risk": "CRITICAL", "impact": "process execution", "escape": True},
    "ptrace": {"status": "DENIED", "risk": "CRITICAL", "impact": "process tracing", "escape": True},
    "bpf": {"status": "BLOCKED", "risk": "HIGH", "impact": "eBPF program load", "escape": True},
    "connect": {"status": "FLAGGED", "risk": "HIGH", "impact": "outbound network", "escape": False},
    "socket": {"status": "FLAGGED", "risk": "HIGH", "impact": "socket creation", "escape": False},
    "mmap": {"status": "RESTRICTED", "risk": "MEDIUM", "impact": "memory mapping", "escape": False},
    "openat": {"status": "MONITORED", "risk": "LOW", "impact": "file access", "escape": False},
    "write": {"status": "MONITORED", "risk": "LOW", "impact": "file write", "escape": False},
    "clone": {"status": "RESTRICTED", "risk": "MEDIUM", "impact": "process fork", "escape": False},
    "init_module": {"status": "BLOCKED", "risk": "CRITICAL", "impact": "kernel module load", "escape": True},
    "unshare": {"status": "BLOCKED", "risk": "HIGH", "impact": "namespace escape", "escape": True},
}

SYSCALL_PATTERNS = [
    (r"\bexecve\s*\(", "execve"),
    (r"\bptrace\s*\(", "ptrace"),
    (r"\bbpf\s*\(", "bpf"),
    (r"\bconnect\s*\(", "connect"),
    (r"\bsocket\s*\(", "socket"),
    (r"\bmmap\s*\(", "mmap"),
    (r"\bopenat\s*\(", "openat"),
    (r"\binit_module\s*\(", "init_module"),
    (r"\bunshare\s*\(", "unshare"),
    (r"reverse\s+shell|/dev/tcp", "connect"),
    (r"insmod|modprobe", "init_module"),
]


def run_syscall_analysis(prompt: str) -> Dict:
    pl = prompt.lower()
    violations: List[Dict] = []
    score = 0.0

    seen = set()
    for regex, syscall in SYSCALL_PATTERNS:
        if syscall in seen:
            continue
        if re.search(regex, pl, re.I):
            seen.add(syscall)
            meta = SYSCALL_DB.get(syscall, {"status": "MONITORED", "risk": "MEDIUM"})
            violations.append({
                "syscall": f"{syscall}()",
                "status": meta["status"],
                "risk": meta["risk"],
                "impact": meta["impact"],
                "container_escape_relevant": meta.get("escape", False),
                "seccomp_response": "EPERM" if meta["status"] in ("BLOCKED", "DENIED") else "AUDIT",
            })
            weight = {"CRITICAL": 22, "HIGH": 14, "MEDIUM": 8, "LOW": 3}.get(meta["risk"], 5)
            score += weight

    blocked = any(v["status"] in ("BLOCKED", "DENIED") for v in violations) or score >= 24
    return {
        "layer": "syscall_analysis",
        "passed": not blocked,
        "risk_contribution": round(min(score, 40), 1),
        "blocked": blocked,
        "syscall_violations": violations,
        "seccomp_mode": "MODE_STRICT" if blocked else "MODE_FILTER",
    }
